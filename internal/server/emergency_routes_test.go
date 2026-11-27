package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/emergency"
)

func TestEmergencyRoutesAuthenticateAndReportOutcomes(t *testing.T) {
	cfg := &config.Config{Allowlist: []config.AllowEntry{{Subject: "caller"}}}
	em, id := activeEmergency(t, cfg)
	srv, err := New(cfg, func(context.Context, config.Key, TokenScope) (string, time.Time, error) { return "", time.Time{}, nil }, &fakeReviewer{subjectByToken: map[string]string{"valid": "caller"}}, nil, em)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	tests := []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/emergency/profiles", "", 200},
		{"POST", "/emergency/sessions", `{"profile":"human"}`, 200},
		{"GET", "/emergency/sessions/" + id, "", 200},
		{"POST", "/emergency/sessions/" + id + "/verify", `{"code":"000000"}`, 401},
		{"POST", "/emergency/sessions/" + id + "/credential", "", 200},
		{"POST", "/emergency/sessions/" + id + "/seal-release-key", `{"github_owner":"owner","github_repository":"repo"}`, 403},
		{"GET", "/emergency/events?wait=0s", "", 200},
		{"POST", "/emergency/passkeys/enrollments", `{"proof_session_id":"` + id + `"}`, 403},
		{"GET", "/emergency/passkeys/ceremonies/missing", "", 404},
		{"POST", "/emergency/passkeys/ceremonies/missing", `{}`, 401},
		{"DELETE", "/emergency/sessions/" + id, "", 204},
	}
	for index, tc := range tests {
		for _, authenticated := range []bool{false, true} {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", index+1)
			if authenticated {
				req.Header.Set("Authorization", "Bearer valid")
			}
			response := httptest.NewRecorder()
			srv.Routes().ServeHTTP(response, req)
			want := 401
			if authenticated {
				want = tc.status
			}
			if response.Code != want {
				t.Errorf("%s %s authenticated=%v status=%d want=%d body=%s", tc.method, tc.path, authenticated, response.Code, want, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Error("sensitive endpoint permits caching")
			}
		}
	}
}

func TestEmergencyRevokeRetriesBeforePublishingTerminalEvent(t *testing.T) {
	ctx := context.Background()
	revocations := 0
	available := false
	client := &http.Client{Transport: emergencyTransport(func(r *http.Request) (*http.Response, error) {
		status := http.StatusOK
		body := ""
		switch {
		case r.Method == http.MethodDelete:
			revocations++
			status = http.StatusNoContent
			if !available {
				status = http.StatusServiceUnavailable
			}
		case r.URL.Path == "/login/device/code":
			body = `{"device_code":"code","user_code":"user","verification_uri":"https://github.com/login/device","interval":5}`
		case r.URL.Path == "/login/oauth/access_token":
			body = `{"access_token":"synthetic","scope":"repo"}`
		case r.URL.Path == "/user":
			body = `{"id":1}`
		default:
			t.Errorf("unexpected upstream route %q", r.URL.Path)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	cfg := &config.Config{
		EmergencyProfiles: map[string]config.EmergencyProfile{"human": {
			Provider: "github_user", ClientID: "app", ClientSecret: "secret", AllowedUserIDs: []int64{1}, Scopes: []string{"repo"},
		}},
		Allowlist: []config.AllowEntry{{Subject: "caller", EmergencyProfiles: []string{"human"}}},
	}
	em, err := emergency.New(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = em.Close() }()
	session, err := em.Create(ctx, "caller", "human", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := em.Get(ctx, "caller", session.ID); err != nil || got.State != emergency.Active {
		t.Fatalf("authentication state=%s err=%v", got.State, err)
	}
	srv, err := New(cfg, func(context.Context, config.Key, TokenScope) (string, time.Time, error) {
		return "", time.Time{}, nil
	}, &fakeReviewer{subjectByToken: map[string]string{"valid": "caller"}}, nil, em)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	deleteSession := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/emergency/sessions/"+session.ID, nil)
		req.Header.Set("Authorization", "Bearer valid")
		response := httptest.NewRecorder()
		srv.Routes().ServeHTTP(response, req)
		return response
	}
	if response := deleteSession(); response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "pending") {
		t.Fatalf("first revocation returned %d %s", response.Code, response.Body.String())
	}
	if err := em.Prune(ctx); !errors.Is(err, emergency.ErrRevocationPending) || revocations != 2 {
		t.Fatalf("after one retry: revocations=%d err=%v", revocations, err)
	}
	page, err := em.Events(ctx, "caller", "", 0)
	if err != nil || len(page.Events) != 3 || page.Events[2].Type != "session.revocation_pending" {
		t.Fatalf("events before confirmation=%+v err=%v", page.Events, err)
	}
	available = true
	if err := em.Prune(ctx); err != nil || revocations != 3 {
		t.Fatalf("after successful retry: revocations=%d err=%v", revocations, err)
	}
	page, err = em.Events(ctx, "caller", page.NextCursor, 0)
	if err != nil || len(page.Events) != 1 || page.Events[0].Type != "session.revoked" {
		t.Fatalf("events after confirmation=%+v err=%v", page.Events, err)
	}
	if response := deleteSession(); response.Code != http.StatusNotFound {
		t.Fatalf("missing session returned %d", response.Code)
	}
}
