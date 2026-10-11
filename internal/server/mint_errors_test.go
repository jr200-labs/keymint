package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/mint"
)

func TestMintPermissionRejectionIsActionable(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, body            string
		status                int
		wantCode, wantMessage string
	}{
		{"permissions", `{"message":"The permissions requested are not granted to this installation.","token":"upstream-secret"}`, 422, "github_permissions_not_granted", "approve"},
		{"unrelated validation", `{"message":"private upstream detail upstream-secret"}`, 500, "", "mint failed"},
		{"malformed", `upstream-secret`, 500, "", "mint failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = io.WriteString(w, test.body)
			}))
			defer upstream.Close()
			cfg := &config.Config{
				Keys:      map[string]config.Key{"org-a": {AppID: 1, InstallationID: 2, PrivateKeyFile: "/x"}},
				Allowlist: []config.AllowEntry{{Subject: "system:serviceaccount:agents:agent-runner", Keys: []string{"org-a"}}},
			}
			srv := newTestServer(t, cfg, func(ctx context.Context, key config.Key, scope TokenScope) (string, time.Time, error) {
				token, err := mint.Mint(ctx, mint.Request{AppID: key.AppID, InstallationID: key.InstallationID, PrivateKey: privateKey, Permissions: scope.Permissions, APIBaseURL: upstream.URL, HTTPClient: upstream.Client()})
				return token.Token, token.ExpiresAt, fmt.Errorf("exchange token: %w", err)
			}, &fakeReviewer{subjectByToken: map[string]string{"sa-token": "system:serviceaccount:agents:agent-runner"}})
			defer srv.Close()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/token/org-a", strings.NewReader(`{"permissions":{"contents":"write","checks":"read"}}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer sa-token")
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			var got struct {
				Error string `json:"error"`
				Code  string `json:"code"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != test.status || got.Code != test.wantCode || !strings.Contains(got.Error, test.wantMessage) {
				t.Fatalf("status=%d response=%+v", resp.StatusCode, got)
			}
			if strings.Contains(got.Error, "upstream-secret") || strings.Contains(got.Error, "sa-token") {
				t.Fatalf("secret leaked: %+v", got)
			}
			if test.wantCode != "" && (!strings.Contains(got.Error, "org-a") || !strings.Contains(got.Error, "checks=read, contents=write")) {
				t.Fatalf("missing key or requested permissions: %+v", got)
			}
		})
	}
}
