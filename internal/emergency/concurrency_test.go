package emergency

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
)

func TestOAuthPollRejectsCompletionAfterRevoke(t *testing.T) {
	started, finish := make(chan struct{}), make(chan struct{})
	var revocations atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/device/code":
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "device", "user_code": "code", "verification_uri": "https://example.invalid", "interval": 5})
		case "/login/oauth/access_token":
			close(started)
			<-finish
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "orphan-token"})
		case "/user":
			_ = json.NewEncoder(w).Encode(map[string]int64{"id": 42})
		case "/applications/client/token":
			revocations.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	client := upstream.Client()
	transport := client.Transport
	client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		clone.URL.Scheme, clone.URL.Host = "http", upstream.Listener.Addr().String()
		return transport.RoundTrip(clone)
	})
	cfg := &config.Config{EmergencyProfiles: map[string]config.EmergencyProfile{"operator": {Provider: "github_user", ClientID: "client", ClientSecret: "secret", AllowedUserIDs: []int64{42}, APIBaseURL: upstream.URL}}, Allowlist: []config.AllowEntry{{Subject: "allowed", EmergencyProfiles: []string{"operator"}}}}
	svc, err := New(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	session, err := svc.Create(context.Background(), "allowed", "operator", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		session Session
		err     error
	}
	done := make(chan result, 1)
	go func() { got, err := svc.Get(context.Background(), "allowed", session.ID); done <- result{got, err} }()
	<-started
	if err := svc.Revoke(context.Background(), "allowed", session.ID); err != nil {
		t.Fatal(err)
	}
	close(finish)
	got := <-done
	if got.err == nil {
		t.Fatal("late OAuth completion accepted")
	}
	if revocations.Load() != 1 {
		t.Fatalf("late token revocations=%d", revocations.Load())
	}
	if err := svc.Prune(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := svc.cleanup.list(context.Background())
	if err != nil || len(records) != 0 {
		t.Fatalf("cleanup=%v error=%v", records, err)
	}
}

type reviewTargetIssuer struct{ namespace, account string }

func (i *reviewTargetIssuer) Issue(_ context.Context, ns, sa string, ttl time.Duration, existing string) (string, string, time.Time, error) {
	i.namespace, i.account = ns, sa
	return "token", "secret", time.Now().Add(ttl), nil
}
func (i *reviewTargetIssuer) Revoke(context.Context, string, string) error { return nil }

func TestReloadInvalidatesChangedProfile(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "totp")
	if err := os.WriteFile(secret, []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{EmergencyProfiles: map[string]config.EmergencyProfile{"operator": {Provider: "kubernetes", Namespace: "operators", ServiceAccount: "limited", TOTPSecretFile: secret}}, Allowlist: []config.AllowEntry{{Subject: "allowed", EmergencyProfiles: []string{"operator"}}}}
	issuer := &reviewTargetIssuer{}
	svc, err := New(cfg, http.DefaultClient, issuer)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	svc.now = func() time.Time { return time.Unix(59, 0) }
	session, err := svc.Create(context.Background(), "allowed", "operator", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerifyTOTP("allowed", session.ID, "287082"); err != nil {
		t.Fatal(err)
	}
	updated := &config.Config{EmergencyProfiles: map[string]config.EmergencyProfile{"operator": {Provider: "kubernetes", Namespace: "admin", ServiceAccount: "cluster-admin", TOTPSecretFile: secret}}, Allowlist: cfg.Allowlist}
	svc.Reload(updated)
	if _, err := svc.Credential(context.Background(), "allowed", session.ID); err == nil {
		t.Fatal("changed authority accepted old authentication")
	}
	if issuer.account != "" {
		t.Fatal("issuer called for invalidated session")
	}
}
