package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/emergency"
	"github.com/jr200-labs/keymint/internal/githubsecret"
	"github.com/jr200-labs/keymint/internal/releasekey"
	"golang.org/x/crypto/nacl/box"
)

func TestReleaseSealingUsesVerifiedScopedDestination(t *testing.T) {
	for _, tc := range []struct {
		name   string
		scope  githubsecret.Scope
		denied bool
		status int
	}{
		{"legacy repository", "", false, 200}, {"repository", githubsecret.Repository, false, 200},
		{"organization", githubsecret.Organization, false, 200},
		{"organization caller substitution", githubsecret.Organization, false, 400}, {"organization opt-in missing", githubsecret.Organization, true, 403},
		{"invalid scope", "environment", false, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signing := base64.StdEncoding.EncodeToString(append(append([]byte{}, private...), public...))
			keyPath := filepath.Join(t.TempDir(), "signing")
			if err := os.WriteFile(keyPath, []byte(signing), 0600); err != nil {
				t.Fatal(err)
			}
			repoPublic, repoPrivate, err := box.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			orgPublic, orgPrivate, err := box.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				expected, key, id, token := "/repos/owner/repo/actions/secrets/public-key", repoPublic, "repo-key", "scoped"
				if tc.scope == githubsecret.Organization {
					expected, key, id, token = "/orgs/owner/actions/secrets/public-key", orgPublic, "org-key", "synthetic"
				}
				if r.URL.Path != expected || r.Header.Get("Authorization") != "Bearer "+token {
					t.Errorf("lookup path=%s", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"key_id": id, "key": base64.StdEncoding.EncodeToString(key[:])})
			}))
			defer upstream.Close()
			old := http.DefaultTransport
			http.DefaultTransport = upstream.Client().Transport
			defer func() { http.DefaultTransport = old }()
			scopes := []githubsecret.Scope{githubsecret.Repository, githubsecret.Organization}
			if tc.denied {
				scopes = nil
				keyPath = "/must-not-read"
			}
			cfg := &config.Config{Keys: map[string]config.Key{"installation": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/unused", APIBaseURL: upstream.URL}}, ReleaseKeys: map[string]config.ReleaseKey{"signing": {GitHubKey: "installation", Kind: "sparkle_ed25519", SecretScopes: scopes, Repositories: []string{"owner/repo"}, PrivateKeyFile: keyPath, SecretName: "SPARKLE_EDDSA_PRIVATE_KEY"}}, Allowlist: []config.AllowEntry{{Subject: "caller", ReleaseKeys: []string{"signing"}}}}
			em, id := activeEmergency(t, cfg, upstream.URL)
			m := testMetrics(t)
			srv, err := New(cfg, func(_ context.Context, _ config.Key, scope TokenScope) (string, time.Time, error) {
				if tc.scope == githubsecret.Organization {
					t.Error("organization lookup must use the human session, not mint App authority")
				}
				if len(scope.Repositories) != 1 || scope.Repositories[0] != "repo" || scope.Permissions["secrets"] != "read" {
					t.Errorf("scope=%#v", scope)
				}
				return "scoped", time.Now().Add(time.Hour), nil
			}, &fakeReviewer{subjectByToken: map[string]string{"valid": "caller"}}, m, em)
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Stop()
			input := `{"github_owner":"owner","github_repository":"repo","secret_scope":"` + string(tc.scope) + `"}`
			if tc.name == "organization caller substitution" {
				input = strings.TrimSuffix(input, "}") + `,"destination_key_id":"repo-key","destination_public_key":"caller-key"}`
			}
			req := httptest.NewRequest("POST", "/emergency/sessions/"+id+"/seal-release-key", strings.NewReader(input))
			req.Header.Set("Authorization", "Bearer valid")
			response := httptest.NewRecorder()
			srv.Routes().ServeHTTP(response, req)
			outcome := "error"
			if tc.status == 200 {
				outcome = "success"
			}
			if got := counterValue(m.OperationsTotal.WithLabelValues("release_seal", outcome)); got != 1 {
				t.Errorf("sealing observation=%v", got)
			}
			if response.Code != tc.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if tc.status != 200 {
				if calls != 0 && tc.name != "organization caller substitution" {
					t.Fatal("denied target performed lookup")
				}
				return
			}
			var sealed releasekey.Sealed
			if err := json.Unmarshal(response.Body.Bytes(), &sealed); err != nil {
				t.Fatal(err)
			}
			wantScope := tc.scope
			if wantScope == "" {
				wantScope = githubsecret.Repository
			}
			if sealed.Target != (githubsecret.Target{Owner: "owner", Repository: "repo", Scope: wantScope}) {
				t.Fatalf("unbound result: %#v", sealed.Target)
			}
			ciphertext, err := base64.StdEncoding.DecodeString(sealed.EncryptedValue)
			if err != nil {
				t.Fatal(err)
			}
			key, secret, otherKey, otherSecret := repoPublic, repoPrivate, orgPublic, orgPrivate
			if tc.scope == githubsecret.Organization {
				key, secret, otherKey, otherSecret = orgPublic, orgPrivate, repoPublic, repoPrivate
			}
			plain, ok := box.OpenAnonymous(nil, ciphertext, key, secret)
			if !ok || string(plain) != signing {
				t.Fatal("intended destination cannot decrypt")
			}
			if _, ok := box.OpenAnonymous(nil, ciphertext, otherKey, otherSecret); ok {
				t.Fatal("ciphertext crossed secret scopes")
			}
			if strings.Contains(response.Body.String(), signing) || strings.Contains(response.Body.String(), "synthetic") {
				t.Fatal("sealing response exposed credential material")
			}
		})
	}
}

func TestReleaseLookupCannotOutliveAuthorizationOrCrossAuthorities(t *testing.T) {
	for _, mode := range []string{"revoked", "api_mismatch", "wrong_project", "upstream_denied", "reload"} {
		t.Run(mode, func(t *testing.T) {
			var em *emergency.Service
			var srv *Server
			var cfg *config.Config
			var id string
			calls := 0
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if mode == "revoked" {
					if err := em.Revoke(context.Background(), "caller", id); err != nil {
						t.Error(err)
					}
				}
				if mode == "reload" {
					next := *cfg
					next.ReleaseKeys = map[string]config.ReleaseKey{}
					next.Allowlist = []config.AllowEntry{{Subject: "caller", EmergencyProfiles: []string{"human"}}}
					if err := srv.Reload(&next); err != nil {
						t.Error(err)
					}
				}
				if mode == "upstream_denied" {
					w.WriteHeader(403)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "id", "key": base64.StdEncoding.EncodeToString(make([]byte, 32))})
			}))
			defer upstream.Close()
			old := http.DefaultTransport
			http.DefaultTransport = upstream.Client().Transport
			defer func() { http.DefaultTransport = old }()
			cfg = &config.Config{EmergencyStateFile: filepath.Join(t.TempDir(), "events.db"), Keys: map[string]config.Key{"installation": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/unused", APIBaseURL: upstream.URL}}, ReleaseKeys: map[string]config.ReleaseKey{"signing": {GitHubKey: "installation", Kind: "sparkle_ed25519", SecretName: "SPARKLE_EDDSA_PRIVATE_KEY", SecretScopes: []githubsecret.Scope{githubsecret.Organization}, Repositories: []string{"owner/repo"}, PrivateKeyFile: "/must-not-read"}}, Allowlist: []config.AllowEntry{{Subject: "caller", ReleaseKeys: []string{"signing"}}}}
			sessionBase := upstream.URL
			if mode == "api_mismatch" {
				sessionBase = "https://different.example/api/v3"
			}
			em, id = activeEmergency(t, cfg, sessionBase)
			m := testMetrics(t)
			var err error
			srv, err = New(cfg, func(context.Context, config.Key, TokenScope) (string, time.Time, error) {
				t.Error("unexpected installation token")
				return "", time.Time{}, nil
			}, &fakeReviewer{subjectByToken: map[string]string{"valid": "caller"}}, m, em)
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Stop()
			project := "repo"
			if mode == "wrong_project" {
				project = "other"
			}
			req := httptest.NewRequest("POST", "/emergency/sessions/"+id+"/seal-release-key", strings.NewReader(`{"github_owner":"owner","github_repository":"`+project+`","secret_scope":"organization"}`))
			req.Header.Set("Authorization", "Bearer valid")
			result := httptest.NewRecorder()
			srv.Routes().ServeHTTP(result, req)
			want := 409
			if mode == "api_mismatch" || mode == "wrong_project" {
				want = 403
			}
			if mode == "upstream_denied" {
				want = 502
			}
			if got := counterValue(m.OperationsTotal.WithLabelValues("release_seal", "error")); got != 1 {
				t.Errorf("failure observation=%v", got)
			}
			if mode == "upstream_denied" && counterValue(m.OperationsTotal.WithLabelValues("release_lookup", "error")) != 1 {
				t.Error("missing upstream lookup failure observation")
			}
			if result.Code != want {
				t.Fatalf("status=%d want=%d body=%s", result.Code, want, result.Body.String())
			}
			if (mode == "api_mismatch" || mode == "wrong_project") && calls != 0 {
				t.Fatal("credential sent to a forbidden authority or project")
			}
		})
	}
}
