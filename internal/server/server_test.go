package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
)

// fakeReviewer is a TokenReviewer that returns canned values without
// hitting any actual k8s API.
type fakeReviewer struct {
	subjectByToken map[string]string
	err            error
}

func (f *fakeReviewer) Review(_ context.Context, token string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	subj, ok := f.subjectByToken[token]
	if !ok {
		return "", errors.New("unauthorized")
	}
	return subj, nil
}

func newTestServer(t *testing.T, cfg *config.Config, mint MintFunc, reviewer TokenReviewer) *httptest.Server {
	t.Helper()
	srv, err := New(cfg, mint, reviewer)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return httptest.NewServer(srv.Routes())
}

func TestHealthz(t *testing.T) {
	cfg := &config.Config{Keys: map[string]config.Key{"x": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}}}
	srv := newTestServer(t, cfg,
		func(_ context.Context, _ config.Key) (string, time.Time, error) { return "", time.Time{}, nil },
		&fakeReviewer{},
	)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestMint_HappyPath(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{
			"whengas": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"},
		},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:nclaw:nclaw-runner", Keys: []string{"whengas"}},
		},
	}
	expires := time.Date(2026, 4, 25, 13, 0, 0, 0, time.UTC)
	mint := func(_ context.Context, k config.Key) (string, time.Time, error) {
		if k.AppID != 1 {
			t.Errorf("got AppID %d, want 1", k.AppID)
		}
		return "ghs_synthetic", expires, nil
	}
	reviewer := &fakeReviewer{
		subjectByToken: map[string]string{"valid-sa-token": "system:serviceaccount:nclaw:nclaw-runner"},
	}

	srv := newTestServer(t, cfg, mint, reviewer)
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/token/whengas", nil)
	req.Header.Set("Authorization", "Bearer valid-sa-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	var got mintResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Token != "ghs_synthetic" {
		t.Errorf("token = %q", got.Token)
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Errorf("expires = %v, want %v", got.ExpiresAt, expires)
	}
}

func TestMint_MissingAuth(t *testing.T) {
	cfg := &config.Config{Keys: map[string]config.Key{"whengas": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}}}
	srv := newTestServer(t, cfg,
		func(_ context.Context, _ config.Key) (string, time.Time, error) { return "", time.Time{}, nil },
		&fakeReviewer{},
	)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/token/whengas", "", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestMint_TokenReviewRejects(t *testing.T) {
	cfg := &config.Config{Keys: map[string]config.Key{"whengas": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}}}
	reviewer := &fakeReviewer{}
	srv := newTestServer(t, cfg,
		func(_ context.Context, _ config.Key) (string, time.Time, error) { return "", time.Time{}, nil },
		reviewer,
	)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token/whengas", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestMint_SubjectNotInAllowlist(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"whengas": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:other:other", Keys: []string{"whengas"}},
		},
	}
	reviewer := &fakeReviewer{
		subjectByToken: map[string]string{"caller-token": "system:serviceaccount:nclaw:nclaw-runner"},
	}
	srv := newTestServer(t, cfg,
		func(_ context.Context, _ config.Key) (string, time.Time, error) { return "", time.Time{}, nil },
		reviewer,
	)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token/whengas", nil)
	req.Header.Set("Authorization", "Bearer caller-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestMint_SubjectAllowedButWrongKey(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{
			"whengas":    {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"},
			"jr200-labs": {AppID: 2, InstallationID: 2, PrivateKeyFile: "/y"},
		},
		Allowlist: []config.AllowEntry{
			// authorized for whengas only
			{Subject: "system:serviceaccount:nclaw:nclaw-runner", Keys: []string{"whengas"}},
		},
	}
	reviewer := &fakeReviewer{
		subjectByToken: map[string]string{"sa-token": "system:serviceaccount:nclaw:nclaw-runner"},
	}
	srv := newTestServer(t, cfg,
		func(_ context.Context, _ config.Key) (string, time.Time, error) { return "ghs_x", time.Now(), nil },
		reviewer,
	)
	defer srv.Close()

	// Asking for jr200-labs should 403 — same subject, different key.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token/jr200-labs", nil)
	req.Header.Set("Authorization", "Bearer sa-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestMint_UnknownKey(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"whengas": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:nclaw:nclaw-runner", Keys: []string{"whengas"}},
		},
	}
	reviewer := &fakeReviewer{
		subjectByToken: map[string]string{"sa-token": "system:serviceaccount:nclaw:nclaw-runner"},
	}
	srv := newTestServer(t, cfg,
		func(_ context.Context, _ config.Key) (string, time.Time, error) { return "ghs_x", time.Now(), nil },
		reviewer,
	)
	defer srv.Close()

	// "ghost" not in cfg.Keys, but allowlist doesn't even cover it →
	// caller is rejected at allowlist (403), not 404.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token/ghost", nil)
	req.Header.Set("Authorization", "Bearer sa-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestMint_MintFailureBecomes500(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"whengas": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:nclaw:nclaw-runner", Keys: []string{"whengas"}},
		},
	}
	reviewer := &fakeReviewer{
		subjectByToken: map[string]string{"sa-token": "system:serviceaccount:nclaw:nclaw-runner"},
	}
	failingMint := func(_ context.Context, _ config.Key) (string, time.Time, error) {
		return "", time.Time{}, errors.New("synthetic mint failure")
	}
	srv := newTestServer(t, cfg, failingMint, reviewer)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token/whengas", nil)
	req.Header.Set("Authorization", "Bearer sa-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestNew_Validation(t *testing.T) {
	mint := func(_ context.Context, _ config.Key) (string, time.Time, error) { return "", time.Time{}, nil }
	rev := &fakeReviewer{}

	if _, err := New(nil, mint, rev); err == nil {
		t.Errorf("expected error for nil cfg")
	}
	if _, err := New(&config.Config{}, nil, rev); err == nil {
		t.Errorf("expected error for nil mint")
	}
	if _, err := New(&config.Config{}, mint, nil); err == nil {
		t.Errorf("expected error for nil reviewer")
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		hdr    string
		want   string
		wantOk bool
	}{
		{"Bearer abc123", "abc123", true},
		{"Bearer  spaces  ", "spaces", true},
		{"Basic abc", "", false},
		{"", "", false},
		{"Bearer ", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.hdr, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/x", nil)
			if tc.hdr != "" {
				r.Header.Set("Authorization", tc.hdr)
			}
			got, ok := bearerToken(r)
			if ok != tc.wantOk {
				t.Errorf("ok = %v, want %v", ok, tc.wantOk)
			}
			if strings.TrimSpace(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
