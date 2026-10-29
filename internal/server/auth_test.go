package server

import (
	"context"
	"github.com/jr200-labs/keymint/internal/config"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type countedReviewer struct{ calls atomic.Int32 }

func (r *countedReviewer) Review(context.Context, string) (string, bool, error) {
	r.calls.Add(1)
	return "caller", true, nil
}
func TestMintAndEmergencyShareAuthenticationCache(t *testing.T) {
	cfg := &config.Config{Keys: map[string]config.Key{"key": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/unused"}}, Allowlist: []config.AllowEntry{{Subject: "caller", Keys: []string{"key"}}}}
	em, _ := activeEmergency(t, cfg)
	reviewer := &countedReviewer{}
	srv, err := New(cfg, func(context.Context, config.Key, TokenScope) (string, time.Time, error) {
		return "synthetic", time.Now().Add(time.Hour), nil
	}, reviewer, nil, em)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	for _, route := range []struct{ method, path string }{{"GET", "/emergency/profiles"}, {"POST", "/token/key"}} {
		req := httptest.NewRequest(route.method, route.path, nil)
		req.Header.Set("Authorization", "Bearer shared")
		response := httptest.NewRecorder()
		srv.Routes().ServeHTTP(response, req)
		if response.Code != 200 {
			t.Fatalf("%s status=%d", route.path, response.Code)
		}
	}
	if reviewer.calls.Load() != 1 {
		t.Fatalf("TokenReview calls=%d", reviewer.calls.Load())
	}
}
