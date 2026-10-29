package server

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
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
