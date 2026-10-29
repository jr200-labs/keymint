package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/emergency"
)

type emergencyTransport func(*http.Request) (*http.Response, error)

func (f emergencyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func activeEmergency(t *testing.T, cfg *config.Config) (*emergency.Service, string) {
	t.Helper()
	cfg.EmergencyProfiles = map[string]config.EmergencyProfile{"human": {Provider: "github_user", ClientID: "test", ClientSecret: "test", AllowedUserIDs: []int64{1}, Scopes: []string{"repo"}}}
	cfg.Allowlist[0].EmergencyProfiles = []string{"human"}
	client := &http.Client{Transport: emergencyTransport(func(r *http.Request) (*http.Response, error) {
		body := `{"device_code":"test","user_code":"test","interval":5}`
		if strings.HasSuffix(r.URL.Path, "access_token") {
			body = `{"access_token":"synthetic"}`
		}
		if r.URL.Path == "/user" {
			body = `{"id":1}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	em, err := emergency.New(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = em.Close() })
	session, err := em.Create(context.Background(), "caller", "human", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = em.Get(context.Background(), "caller", session.ID); err != nil {
		t.Fatal(err)
	}
	return em, session.ID
}

func TestReleaseDestinationRejectsCallerSubstitution(t *testing.T) {
	resolved := false
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo/actions/secrets/public-key" || r.Header.Get("Authorization") != "Bearer scoped" {
			t.Errorf("unexpected repository lookup: %s", r.URL.Path)
		}
		resolved = true
		_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "trusted-id", "key": "trusted-key"})
	}))
	defer upstream.Close()
	old := http.DefaultTransport
	http.DefaultTransport = upstream.Client().Transport
	defer func() { http.DefaultTransport = old }()
	cfg := &config.Config{Keys: map[string]config.Key{"installation": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/unused", APIBaseURL: upstream.URL}}, ReleaseKeys: map[string]config.ReleaseKey{"signing": {GitHubKey: "installation", Repositories: []string{"owner/repo"}, PrivateKeyFile: "/must-not-read"}}, Allowlist: []config.AllowEntry{{Subject: "caller", ReleaseKeys: []string{"signing"}}}}
	em, id := activeEmergency(t, cfg)
	srv, err := New(cfg, func(_ context.Context, _ config.Key, scope TokenScope) (string, time.Time, error) {
		if len(scope.Repositories) != 1 || scope.Repositories[0] != "repo" || scope.Permissions["secrets"] != "read" {
			t.Errorf("unexpected lookup scope: %#v", scope)
		}
		return "scoped", time.Now().Add(time.Hour), nil
	}, &fakeReviewer{subjectByToken: map[string]string{"valid": "caller"}}, nil, em)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	request := httptest.NewRequest("POST", "/emergency/sessions/"+id+"/seal-release-key", strings.NewReader(`{"github_owner":"owner","github_repository":"repo","destination_key_id":"caller-id","destination_public_key":"caller-key"}`))
	request.Header.Set("Authorization", "Bearer valid")
	response := httptest.NewRecorder()
	srv.Routes().ServeHTTP(response, request)
	if !resolved || response.Code != 400 {
		t.Fatalf("resolved=%v status=%d body=%s", resolved, response.Code, response.Body.String())
	}
}
