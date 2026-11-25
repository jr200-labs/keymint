package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/emergency"
)

func TestTelegramWrappingKeyRestrictedToRelayIdentity(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	file := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(file, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{TelegramRelays: map[string]config.TelegramRelay{
		"owner": {RelaySubject: "system:serviceaccount:relays:owner", OperatorSubject: "operator", WrappingKeyFile: file},
	}}
	reviewer := &fakeReviewer{subjectByToken: map[string]string{"relay": "system:serviceaccount:relays:owner", "padd": "padd", "operator": "operator"}}
	srv := newTelegramTestServer(t, cfg, reviewer)
	for token, want := range map[string]int{"relay": http.StatusOK, "padd": http.StatusForbidden, "operator": http.StatusForbidden} {
		req := httptest.NewRequest(http.MethodGet, "/telegram-relays/owner/wrapping-key", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp := httptest.NewRecorder()
		srv.Routes().ServeHTTP(resp, req)
		if resp.Code != want || resp.Header().Get("Cache-Control") != "no-store" || bytes.Equal(resp.Body.Bytes(), key) != (want == http.StatusOK) {
			t.Fatalf("wrapping key request for role %s returned %d", token, resp.Code)
		}
	}
}

func TestTelegramApprovalCreatesBoundPasskeyAndRejectsUnverifiedCalls(t *testing.T) {
	dir := t.TempDir()
	control := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32))
	controlFile := filepath.Join(dir, "control")
	if err := os.WriteFile(controlFile, []byte(control), 0o600); err != nil {
		t.Fatal(err)
	}
	var received []telegramAction
	var receivedMu sync.Mutex
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input telegramAction
		if r.URL.Path != "/v1/enrollment" || r.Header.Get("Authorization") != "Bearer "+control ||
			json.NewDecoder(r.Body).Decode(&input) != nil {
			http.Error(w, "unexpected relay request", http.StatusBadRequest)
			return
		}
		receivedMu.Lock()
		received = append(received, input)
		receivedMu.Unlock()
		writeJSON(w, telegramStatus{State: "qr", LoginURL: "tg://login?token=YWJj", ExpiresAt: time.Now().Add(time.Minute)})
	}))
	t.Cleanup(upstream.Close)
	cfg := &config.Config{
		Passkeys: &config.PasskeyConfig{
			RPID: "keys.example", RPDisplayName: "Keymint", RPOrigins: []string{"https://keys.example"},
			VerificationURL: "https://keys.example", StateFile: filepath.Join(dir, "passkeys.json"),
		},
		EmergencyStateFile: filepath.Join(dir, "emergency.db"),
		EmergencyProfiles:  map[string]config.EmergencyProfile{"passkey": {Provider: "approval", Authentication: "webauthn"}},
		Allowlist:          []config.AllowEntry{{Subject: "operator", EmergencyProfiles: []string{"passkey"}}},
		TelegramRelays: map[string]config.TelegramRelay{
			"owner": {OwnerID: 42, OperatorSubject: "operator", ApprovalProfile: "passkey", URL: upstream.URL, RelaySubject: "relay", ControlKeyFile: controlFile},
		},
	}
	reviewer := &fakeReviewer{subjectByToken: map[string]string{"operator": "operator", "relay": "relay"}}
	key := seedTelegramPasskey(t, cfg.Passkeys.StateFile)
	service, err := emergency.New(cfg, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	srv := newTelegramTestServer(t, cfg, reviewer, service)
	client := *defaultTelegramRelayClient
	client.Transport = upstream.Client().Transport
	srv.telegramRelayClient = &client
	handler := srv.Routes()
	request := func(method, path, role string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+role)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		return resp
	}
	const enroll = "/telegram-enrollments/owner"
	if resp := request(http.MethodPost, enroll, "relay"); resp.Code != http.StatusForbidden {
		t.Fatalf("relay could request owner approval: %d", resp.Code)
	}
	resp := request(http.MethodPost, enroll, "operator")
	var solution emergency.Session
	digest, label := telegramApproval("owner", cfg.TelegramRelays["owner"])
	if resp.Code != http.StatusOK || json.Unmarshal(resp.Body.Bytes(), &solution) != nil ||
		solution.State != emergency.AwaitingPasskey || solution.ApprovalDigest != digest || solution.ApprovalLabel != label {
		t.Fatalf("bound approval missing: %d %s", resp.Code, resp.Body)
	}
	for _, action := range []string{"start", "commit", "cancel"} {
		if resp := request(http.MethodPost, enroll+"/"+solution.ID+"/"+action, "operator"); resp.Code != http.StatusForbidden {
			t.Fatalf("unverified %s returned %d", action, resp.Code)
		}
	}
	if resp := request(http.MethodGet, enroll+"/"+solution.ID+"/qr", "operator"); resp.Code != http.StatusForbidden {
		t.Fatalf("unverified QR access returned %d", resp.Code)
	}

	verifyTelegramPasskey(t, service, solution.VerificationURI, key)
	path := enroll + "/" + solution.ID
	if response := request(http.MethodPost, path+"/commit", "operator"); response.Code != http.StatusConflict {
		t.Fatalf("commit before start returned %d", response.Code)
	}
	if response := request(http.MethodPost, path+"/start", "operator"); response.Code != http.StatusOK ||
		strings.Contains(response.Body.String(), "tg://") {
		t.Fatalf("start returned %d or exposed the login URL", response.Code)
	}
	if response := request(http.MethodGet, path+"/qr", "operator"); response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("approved QR returned %d", response.Code)
	}
	if response := request(http.MethodPost, path+"/commit", "operator"); response.Code != http.StatusOK {
		t.Fatalf("approved commit returned %d", response.Code)
	}
	if err := service.Revoke(context.Background(), "operator", solution.ID); err != nil {
		t.Fatal(err)
	}
	if response := request(http.MethodPost, path+"/commit", "operator"); response.Code != http.StatusForbidden {
		t.Fatalf("revoked commit returned %d", response.Code)
	}
	receivedMu.Lock()
	defer receivedMu.Unlock()
	if len(received) != 3 || received[0].Action != "start" || received[1].Action != "status" ||
		received[2].Action != "commit" || received[2].ID != solution.ID || received[2].OwnerID != 42 {
		t.Fatal("relay received incorrect enrollment actions")
	}
}

func seedTelegramPasskey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	state, err := json.Marshal(map[string]any{
		"id": []byte("operator-id"), "name": "operator", "display_name": "Operator",
		"credentials": []webauthn.Credential{{ID: []byte("test-credential"), PublicKey: public, Flags: webauthn.NewCredentialFlags(5)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, state, 0o600); err != nil {
		t.Fatal(err)
	}
	return key
}

func verifyTelegramPasskey(t *testing.T, service *emergency.Service, uri string, key *ecdsa.PrivateKey) {
	t.Helper()
	_, token, _ := strings.Cut(uri, "#")
	options, err := service.PasskeyOptions("operator", token)
	if err != nil {
		t.Fatal(err)
	}
	var public struct {
		Options struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	encoded, err := json.Marshal(options["public_key"])
	if err != nil || json.Unmarshal(encoded, &public) != nil || public.Options.Challenge == "" {
		t.Fatal("missing passkey challenge")
	}
	client, err := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": public.Options.Challenge, "origin": "https://keys.example"})
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte("keys.example"))
	authenticator := append(rp[:], 5, 0, 0, 0, 1)
	clientHash := sha256.Sum256(client)
	payload := sha256.Sum256(append(append([]byte{}, authenticator...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, payload[:])
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	id := enc([]byte("test-credential"))
	assertion, err := json.Marshal(map[string]any{"id": id, "rawId": id, "type": "public-key", "response": map[string]string{
		"clientDataJSON": enc(client), "authenticatorData": enc(authenticator), "signature": enc(signature),
	}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://keys.example/verify", bytes.NewReader(assertion))
	if err := service.VerifyPasskey("operator", token, request); err != nil {
		t.Fatal(err)
	}
}

func TestTelegramQRRenderedOnlyForLiveTelegramLogin(t *testing.T) {
	status := telegramStatus{State: "qr", LoginURL: "tg://login?token=YWJj", ExpiresAt: time.Now().Add(time.Minute)}
	resp := httptest.NewRecorder()
	writeTelegramQR(resp, status, false)
	if resp.Code != http.StatusOK || resp.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("QR response: %d %s", resp.Code, resp.Header().Get("Content-Type"))
	}
	if _, err := png.DecodeConfig(resp.Body); err != nil {
		t.Fatal(err)
	}
	terminal := httptest.NewRecorder()
	writeTelegramQR(terminal, status, true)
	if terminal.Code != http.StatusOK || !strings.HasPrefix(terminal.Header().Get("Content-Type"), "text/plain") ||
		!strings.Contains(terminal.Body.String(), "█") || strings.Contains(terminal.Body.String(), status.LoginURL) {
		t.Fatal("terminal QR should contain a scannable grid and omit the login URL")
	}
	for _, url := range []string{"https://login?token=YWJj", "tg://login?token=YWJj&token=YWJj", "tg://login?token="} {
		resp := httptest.NewRecorder()
		status.LoginURL = url
		writeTelegramQR(resp, status, false)
		if resp.Code != http.StatusConflict && resp.Code != http.StatusBadGateway {
			t.Fatalf("unexpected response to invalid QR: %d", resp.Code)
		}
	}
}

func TestReadTelegramKeyRejectsMalformedOrOversizedFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "key")
	for _, input := range []string{"xx", strings.Repeat("a", 129), base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		if err := os.WriteFile(file, []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readTelegramKey(file); err == nil {
			t.Fatal("invalid key file accepted")
		}
	}
}

func newTelegramTestServer(t *testing.T, cfg *config.Config, reviewer *fakeReviewer, services ...*emergency.Service) *Server {
	t.Helper()
	srv, err := New(cfg, func(context.Context, config.Key, TokenScope) (string, time.Time, error) {
		t.Fatal("unrelated mint operation")
		return "", time.Time{}, nil
	}, reviewer, nil, services...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	return srv
}
