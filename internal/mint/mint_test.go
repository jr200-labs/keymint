package mint

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// generateTestKey produces a fresh small RSA key. 2048 is the GitHub
// default; we use 2048 here so the JWT signature shape matches prod
// even if the test runs slightly slower.
func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

func TestParsePrivateKey_PKCS1(t *testing.T) {
	key := generateTestKey(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	got, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	rsaKey, ok := got.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("ParsePrivateKey returned %T, want *rsa.PrivateKey", got)
	}
	if rsaKey.N.Cmp(key.N) != 0 {
		t.Errorf("parsed key modulus mismatch")
	}
}

func TestParsePrivateKey_PKCS8(t *testing.T) {
	key := generateTestKey(t)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	got, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	rsaKey, ok := got.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("ParsePrivateKey returned %T, want *rsa.PrivateKey", got)
	}
	if rsaKey.N.Cmp(key.N) != 0 {
		t.Errorf("parsed key modulus mismatch")
	}
}

func TestParsePrivateKey_Ed25519PKCS8(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	got, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	edKey, ok := got.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("ParsePrivateKey returned %T, want ed25519.PrivateKey", got)
	}
	if !edKey.Equal(priv) {
		t.Errorf("parsed ed25519 key does not match original")
	}
}

func TestSignAppJWT_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	signed, err := signAppJWT(7777, priv, now)
	if err != nil {
		t.Fatalf("signAppJWT: %v", err)
	}
	parsed, err := jwt.Parse(signed, func(tok *jwt.Token) (interface{}, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", tok.Header["alg"])
		}
		return pub, nil
	})
	if err != nil {
		t.Fatalf("jwt.Parse: %v", err)
	}
	if !parsed.Valid {
		t.Errorf("ed25519-signed JWT did not validate")
	}
}

func TestParsePrivateKey_BadInput(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", []byte{}},
		{"not pem", []byte("not a key")},
		{"wrong block type", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePrivateKey(tc.in); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

func TestSignAppJWT_ClaimsRoundTrip(t *testing.T) {
	key := generateTestKey(t)
	now := time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC)

	signed, err := signAppJWT(12345, key, now)
	if err != nil {
		t.Fatalf("signAppJWT: %v", err)
	}

	parsed, err := jwt.Parse(signed, func(_ *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("jwt.Parse: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims wrong type: %T", parsed.Claims)
	}

	wantIss := float64(12345)
	if claims["iss"] != wantIss {
		t.Errorf("iss = %v, want %v", claims["iss"], wantIss)
	}

	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if int64(iat) != now.Add(-60*time.Second).Unix() {
		t.Errorf("iat = %v, want %v", iat, now.Add(-60*time.Second).Unix())
	}
	if int64(exp) != now.Add(jwtLifetime).Unix() {
		t.Errorf("exp = %v, want %v", exp, now.Add(jwtLifetime).Unix())
	}
}

func TestMint_HappyPath(t *testing.T) {
	key := generateTestKey(t)

	// Stand up a fake GitHub API that validates the JWT and returns a token.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/app/installations/678/access_tokens" {
			t.Errorf("path = %s", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("missing Bearer prefix in Authorization: %q", auth)
		}
		// Verify the JWT signature with the matching public key — proves
		// the caller signed with the right private key.
		signed := strings.TrimPrefix(auth, "Bearer ")
		if _, err := jwt.Parse(signed, func(_ *jwt.Token) (interface{}, error) {
			return &key.PublicKey, nil
		}); err != nil {
			t.Errorf("server-side JWT verify: %v", err)
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(Token{
			Token:     "ghs_synthetic_token",
			ExpiresAt: time.Now().Add(time.Hour),
		})
	}))
	defer server.Close()

	got, err := Mint(context.Background(), Request{
		AppID:          12345,
		InstallationID: 678,
		PrivateKey:     key,
		APIBaseURL:     server.URL,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if got.Token != "ghs_synthetic_token" {
		t.Errorf("token = %q, want %q", got.Token, "ghs_synthetic_token")
	}
}

func TestMint_GitHubError(t *testing.T) {
	key := generateTestKey(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer server.Close()

	_, err := Mint(context.Background(), Request{
		AppID:          12345,
		InstallationID: 678,
		PrivateKey:     key,
		APIBaseURL:     server.URL,
	})
	if err == nil {
		t.Fatalf("expected error for 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention 401: %v", err)
	}
}

func TestClockOffset_PerEndpoint(t *testing.T) {
	// Two pretend GHE endpoints with very different clocks. After
	// minting against each, their cached offsets must remain distinct
	// — a sick clock on one endpoint must not poison the other.
	clockOffsets = sync.Map{} // reset

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", time.Now().Add(2*time.Hour).UTC().Format(time.RFC1123))
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(Token{Token: "t1", ExpiresAt: time.Now().Add(time.Hour)})
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// "good" clock: matches local
		w.Header().Set("Date", time.Now().UTC().Format(time.RFC1123))
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(Token{Token: "t2", ExpiresAt: time.Now().Add(time.Hour)})
	}))
	defer server2.Close()

	key := generateTestKey(t)
	for _, srv := range []string{server1.URL, server2.URL} {
		if _, err := Mint(context.Background(), Request{
			AppID: 1, InstallationID: 1, PrivateKey: key, APIBaseURL: srv,
		}); err != nil {
			t.Fatalf("mint to %s: %v", srv, err)
		}
	}

	off1 := loadClockOffset(server1.URL)
	off2 := loadClockOffset(server2.URL)
	if off1 < time.Hour {
		t.Errorf("server1 offset = %v, expected ≥ 1h drift", off1)
	}
	// off2 should be near zero (a few seconds at most)
	if off2 > 10*time.Second || off2 < -10*time.Second {
		t.Errorf("server2 offset = %v, expected near zero", off2)
	}
	// Most importantly: distinct.
	if off1 == off2 {
		t.Errorf("offsets collapsed to a single value (%v); per-endpoint scoping broken", off1)
	}
}

func TestEgressSemaphore_BoundsConcurrency(t *testing.T) {
	// Synthetic experiment: spawn many concurrent acquires and
	// confirm we never exceed the cap. release one, the next can
	// proceed.
	if cap(egressSem) != egressConcurrency {
		t.Fatalf("egressSem capacity = %d, want %d", cap(egressSem), egressConcurrency)
	}

	releases := make([]func(), 0, egressConcurrency)
	for i := 0; i < egressConcurrency; i++ {
		release, err := acquireEgress(context.Background())
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		releases = append(releases, release)
	}

	// One more must block; assert it via a short context timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := acquireEgress(ctx); err == nil {
		t.Errorf("expected acquire to block + ctx.Done, got nil error")
	}

	// Release all — fresh acquire should succeed immediately.
	for _, r := range releases {
		r()
	}
	release, err := acquireEgress(context.Background())
	if err != nil {
		t.Errorf("post-release acquire: %v", err)
	}
	release()
}

func TestMint_ValidatesRequiredFields(t *testing.T) {
	key := generateTestKey(t)
	cases := []struct {
		name string
		req  Request
	}{
		{"missing key", Request{AppID: 1, InstallationID: 1}},
		{"missing app id", Request{InstallationID: 1, PrivateKey: key}},
		{"missing install id", Request{AppID: 1, PrivateKey: key}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Mint(context.Background(), tc.req); err == nil {
				t.Errorf("expected error")
			}
		})
	}
}
