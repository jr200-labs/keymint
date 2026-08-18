package emergency

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type fakeIssuer struct{ revoked string }

func (issuer *fakeIssuer) Issue(_ context.Context, namespace, serviceAccount string, ttl time.Duration, existing string) (string, string, time.Time, error) {
	if namespace != "operators" || serviceAccount != "breakglass-admin" || ttl <= 0 {
		return "", "", time.Time{}, os.ErrInvalid
	}
	if existing == "" {
		existing = "bound-secret"
	}
	return "kubernetes-token", existing, time.Unix(900, 0), nil
}

func (issuer *fakeIssuer) Revoke(_ context.Context, _ string, secret string) error {
	issuer.revoked = secret
	return nil
}

func TestKubernetesSessionRequiresTOTPAndRevokesBoundToken(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "totp")
	// RFC 6238 SHA-1 test secret; the 8-digit vector at t=59 is 94287082,
	// therefore its six-digit authenticator form is 287082.
	if err := os.WriteFile(secretPath, []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Keys: map[string]config.Key{"routine": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/dev/null"}},
		EmergencyProfiles: map[string]config.EmergencyProfile{
			"cluster-admin": {Provider: "kubernetes", Namespace: "operators", ServiceAccount: "breakglass-admin", TOTPSecretFile: secretPath},
		},
		Allowlist: []config.AllowEntry{{Subject: "system:serviceaccount:agents:relay", EmergencyProfiles: []string{"cluster-admin"}}},
	}
	issuer := &fakeIssuer{}
	service := New(cfg, http.DefaultClient, issuer)
	service.now = func() time.Time { return time.Unix(59, 0) }

	session, err := service.Create(context.Background(), "system:serviceaccount:agents:relay", "cluster-admin", 10*time.Minute)
	if err != nil || session.State != AwaitingTOTP {
		t.Fatalf("create = %#v, %v", session, err)
	}
	if _, err := service.Credential(context.Background(), "system:serviceaccount:agents:relay", session.ID); err == nil {
		t.Fatal("credential issued before human verification")
	}
	if _, err := service.VerifyTOTP("system:serviceaccount:agents:relay", session.ID, "287082"); err != nil {
		t.Fatal(err)
	}
	credential, err := service.Credential(context.Background(), "system:serviceaccount:agents:relay", session.ID)
	if err != nil || credential.Token != "kubernetes-token" {
		t.Fatalf("credential = %#v, %v", credential, err)
	}
	if err := service.Revoke(context.Background(), "system:serviceaccount:agents:relay", session.ID); err != nil {
		t.Fatal(err)
	}
	if issuer.revoked != "bound-secret" {
		t.Fatalf("revoked %q", issuer.revoked)
	}
}

func TestKubernetesSessionCanUseGitHubDeviceAuthentication(t *testing.T) {
	githubRevoked := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/login/device/code":
			_ = json.NewEncoder(writer).Encode(map[string]any{"device_code": "device", "user_code": "ABCD-EFGH", "verification_uri": "https://github.com/login/device", "expires_in": 900, "interval": 5})
		case request.Method == http.MethodPost && request.URL.Path == "/login/oauth/access_token":
			_ = json.NewEncoder(writer).Encode(map[string]string{"access_token": "github-user-token"})
		case request.Method == http.MethodGet && request.URL.Path == "/user":
			_ = json.NewEncoder(writer).Encode(map[string]int64{"id": 42})
		case request.Method == http.MethodDelete && request.URL.Path == "/applications/client/token":
			githubRevoked = true
			writer.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client := server.Client()
	transport := client.Transport
	client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		copy := request.Clone(request.Context())
		copy.URL.Scheme, copy.URL.Host = "http", server.Listener.Addr().String()
		return transport.RoundTrip(copy)
	})
	cfg := &config.Config{
		Keys: map[string]config.Key{"routine": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/dev/null"}},
		EmergencyProfiles: map[string]config.EmergencyProfile{
			"cluster-admin-passkey": {Provider: "kubernetes", Authentication: "github_device", Namespace: "operators", ServiceAccount: "breakglass-admin", ClientID: "client", ClientSecret: "secret", AllowedUserIDs: []int64{42}, Scopes: []string{"read:user"}, APIBaseURL: server.URL},
		},
		Allowlist: []config.AllowEntry{{Subject: "allowed", EmergencyProfiles: []string{"cluster-admin-passkey"}}},
	}
	issuer := &fakeIssuer{}
	service := New(cfg, client, issuer)
	session, err := service.Create(context.Background(), "allowed", "cluster-admin-passkey", 10*time.Minute)
	if err != nil || session.State != AwaitingGitHub {
		t.Fatalf("create = %#v, %v", session, err)
	}
	session, err = service.Get(context.Background(), "allowed", session.ID)
	if err != nil || session.State != Active {
		t.Fatalf("authenticate = %#v, %v", session, err)
	}
	credential, err := service.Credential(context.Background(), "allowed", session.ID)
	if err != nil || credential.Token != "kubernetes-token" {
		t.Fatalf("credential = %#v, %v", credential, err)
	}
	if err := service.Revoke(context.Background(), "allowed", session.ID); err != nil {
		t.Fatal(err)
	}
	if !githubRevoked || issuer.revoked != "bound-secret" {
		t.Fatalf("revoked GitHub=%v Kubernetes=%q", githubRevoked, issuer.revoked)
	}
}

func TestProfileIsHiddenFromUnallowedWorkload(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"routine": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/dev/null"}},
		EmergencyProfiles: map[string]config.EmergencyProfile{
			"cluster-admin": {Provider: "kubernetes", Namespace: "operators", ServiceAccount: "breakglass-admin", TOTPSecretFile: "/dev/null"},
		},
		Allowlist: []config.AllowEntry{{Subject: "allowed", EmergencyProfiles: []string{"cluster-admin"}}},
	}
	service := New(cfg, http.DefaultClient, &fakeIssuer{})
	if profiles := service.Profiles("other"); len(profiles) != 0 {
		t.Fatalf("profiles = %#v", profiles)
	}
}

func TestGitHubCredentialIsRevokedRemotely(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		user, password, ok := request.BasicAuth()
		if request.Method != http.MethodDelete || request.URL.Path != "/applications/client/token" || !ok || user != "client" || password != "secret" {
			t.Fatalf("unexpected revoke request: %s %s %q %q", request.Method, request.URL.Path, user, password)
		}
		called = true
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	profile := config.EmergencyProfile{Provider: "github_user", ClientID: "client", ClientSecret: "secret", AllowedUserIDs: []int64{1}, Scopes: []string{"repo"}, APIBaseURL: server.URL}
	service := New(&config.Config{EmergencyProfiles: map[string]config.EmergencyProfile{"operator": profile}}, server.Client(), nil)
	service.sessions["E-1"] = &Session{ID: "E-1", Profile: "operator", Provider: "github_user", State: Active, accessToken: "personal", ExpiresAt: time.Unix(1, 0)}
	service.now = func() time.Time { return time.Unix(2, 0) }
	if err := service.Prune(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("GitHub revoke endpoint was not called")
	}
	if service.sessions["E-1"] != nil {
		t.Fatal("expired session was retained after successful revocation")
	}
}
