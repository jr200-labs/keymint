package emergency

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/jr200-labs/keymint/internal/config"
)

// Synthetic authenticator fixtures use real signatures and protocol encodings;
// no browser, physical authenticator, upstream network or private user key.
func passkeyResponse(t *testing.T, service *Service, token string, key *ecdsa.PrivateKey, registration bool, origin string, signCount uint32) *http.Request {
	t.Helper()
	challenge := service.ceremonies[token].data.Challenge
	kind := "webauthn.get"
	if registration {
		kind = "webauthn.create"
	}
	client, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": false})
	rp := sha256.Sum256([]byte("keys.example"))
	auth := append([]byte{}, rp[:]...)
	flag := byte(5)
	if registration {
		flag |= 64
	}
	auth = append(auth, flag)
	auth = binary.BigEndian.AppendUint32(auth, signCount)
	id := []byte("synthetic-passkey-id")
	enc := base64.RawURLEncoding.EncodeToString
	response := map[string]any{"clientDataJSON": enc(client)}
	if registration {
		auth = append(auth, make([]byte, 16)...)
		size := make([]byte, 2)
		binary.BigEndian.PutUint16(size, uint16(len(id)))
		auth = append(auth, size...)
		auth = append(auth, id...)
		cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: key.X.FillBytes(make([]byte, 32)), -3: key.Y.FillBytes(make([]byte, 32))})
		if err != nil {
			t.Fatal(err)
		}
		auth = append(auth, cose...)
		attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth})
		if err != nil {
			t.Fatal(err)
		}
		response["attestationObject"] = enc(attestation)
		response["transports"] = []string{"internal"}
	} else {
		hash := sha256.Sum256(client)
		signed := sha256.Sum256(append(append([]byte{}, auth...), hash[:]...))
		signature, err := ecdsa.SignASN1(rand.Reader, key, signed[:])
		if err != nil {
			t.Fatal(err)
		}
		response["authenticatorData"] = enc(auth)
		response["signature"] = enc(signature)
	}
	body, _ := json.Marshal(map[string]any{"id": enc(id), "rawId": enc(id), "type": "public-key", "response": response, "clientExtensionResults": map[string]any{}})
	return httptest.NewRequest("POST", "https://keys.example/verify", bytes.NewReader(body))
}
func TestPasskeyEnrollmentAuthenticationAndOriginRejection(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "totp")
	if err := os.WriteFile(secret, []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Passkeys: &config.PasskeyConfig{RPID: "keys.example", RPDisplayName: "Keymint", RPOrigins: []string{"https://keys.example"}, VerificationURL: "https://keys.example", StateFile: filepath.Join(dir, "passkeys.json")}, EmergencyProfiles: map[string]config.EmergencyProfile{
		"totp": {Provider: "kubernetes", TOTPSecretFile: secret}, "passkey": {Provider: "kubernetes", Authentication: "webauthn"},
		"approval": {Provider: "approval", Authentication: "webauthn"},
	}, Allowlist: []config.AllowEntry{{Subject: "caller", EmergencyProfiles: []string{"totp", "passkey", "approval"}}}}
	service, err := New(cfg, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Close() }()
	service.now = func() time.Time { return time.Unix(59, 0) }
	proof, err := service.Create(context.Background(), "caller", "totp", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.VerifyTOTP("caller", proof.ID, "287082"); err != nil {
		t.Fatal(err)
	}
	enrollment, err := service.BeginPasskeyEnrollment("caller", proof.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, token, _ := strings.Cut(enrollment.VerificationURI, "#")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.VerifyPasskey("caller", token, passkeyResponse(t, service, token, key, true, "https://keys.example", 1)); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"https://keys.example", "https://other.example"} {
		session, err := service.Create(context.Background(), "caller", "passkey", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		_, token, _ = strings.Cut(session.VerificationURI, "#")
		request := passkeyResponse(t, service, token, key, false, origin, 2)
		err = service.VerifyPasskey("caller", token, request)
		if origin == "https://keys.example" {
			if err != nil {
				t.Fatal(err)
			}
			if err = service.Authorize("caller", session.ID); err != nil {
				t.Fatal(err)
			}
		} else if err == nil {
			t.Fatal("wrong origin accepted")
		}
	}
	for _, counter := range []uint32{1, 2} {
		session, err := service.Create(context.Background(), "caller", "passkey", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		_, token, _ := strings.Cut(session.VerificationURI, "#")
		request := passkeyResponse(t, service, token, key, false, "https://keys.example", counter)
		if err := service.VerifyPasskey("caller", token, request); err == nil || !strings.Contains(err.Error(), "counter") {
			t.Fatalf("non-advancing counter %d returned %v", counter, err)
		}
		if err := service.Authorize("caller", session.ID); err == nil {
			t.Fatal("non-advancing counter authorized session")
		}
	}
	ctx := context.Background()
	digest := strings.Repeat("a", 64)
	if _, err := service.CreateApproval(ctx, "caller", "approval", 5*time.Minute, digest, strings.Repeat("a", 3001)); err == nil {
		t.Fatal("accepted unreviewable request")
	}
	for _, invalidTTL := range []time.Duration{5*time.Minute - time.Second, time.Hour + time.Second} {
		if _, err := service.CreateApproval(ctx, "caller", "approval", invalidTTL, digest, "Read count"); err == nil {
			t.Fatalf("accepted out-of-range TTL %s", invalidTTL)
		}
	}
	for _, tt := range []struct{ requested, expected time.Duration }{{0, 5 * time.Minute}, {time.Hour, time.Hour}} {
		approval, err := service.CreateApproval(ctx, "caller", "approval", tt.requested, digest, strings.Repeat("a", 3000))
		if err != nil || approval.ExpiresAt.Sub(service.now()) != tt.expected {
			t.Fatalf("approval for %s = expiry %v, err %v", tt.requested, approval.ExpiresAt, err)
		}
		if tt.requested == time.Hour {
			_, token, _ := strings.Cut(approval.VerificationURI, "#")
			created := service.now()
			service.now = func() time.Time { return created.Add(10 * time.Minute) }
			if _, err := service.PasskeyOptions("caller", token); err != nil {
				t.Fatalf("one-hour approval ceremony expired early: %v", err)
			}
			service.now = func() time.Time { return approval.ExpiresAt }
			if _, err := service.PasskeyOptions("caller", token); err == nil {
				t.Fatal("expired approval ceremony was still available")
			}
			service.now = func() time.Time { return created }
		}
	}
	approval, err := service.CreateApproval(ctx, "caller", "approval", 5*time.Minute, digest, "Review request")
	if err != nil {
		t.Fatal(err)
	}
	_, approvalToken, _ := strings.Cut(approval.VerificationURI, "#")
	options, err := service.PasskeyOptions("caller", approvalToken)
	if err != nil || !reflect.DeepEqual(options["approval_duration_minutes"], []int{5, 15, 30, 60}) || options["default_approval_duration_minutes"] != 5 {
		t.Fatalf("approval duration options = %v, error = %v", options["approval_duration_minutes"], err)
	}
	approvalRequest := passkeyResponse(t, service, approvalToken, key, false, "https://keys.example", 3)
	approvalRequest.Header.Set(ApprovalDurationHeader, "90")
	if err := service.VerifyPasskey("caller", approvalToken, approvalRequest); err == nil {
		t.Fatal("accepted a duration above the profile maximum")
	}
	approvalRequest.Header.Set(ApprovalDurationHeader, "30")
	if err := service.VerifyPasskey("caller", approvalToken, approvalRequest); err != nil {
		t.Fatal(err)
	}
	active, err := service.Get(ctx, "caller", approval.ID)
	if err != nil || active.State != Active || !active.ExpiresAt.Equal(service.now().Add(30*time.Minute)) || active.ApprovalDigest != digest {
		t.Fatalf("owner-selected approval = %v, error = %v", active, err)
	}
	enrollment, err = service.BeginPasskeyEnrollment("caller", proof.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, token, _ = strings.Cut(enrollment.VerificationURI, "#")
	if err = service.Revoke(context.Background(), "caller", proof.ID); err != nil {
		t.Fatal(err)
	}
	err = service.VerifyPasskey("caller", token, httptest.NewRequest("POST", "/verify", nil))
	if err == nil || !strings.Contains(err.Error(), "proof is no longer active") {
		t.Fatalf("revoked enrollment proof: %v", err)
	}

}
