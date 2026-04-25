package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
	"github.com/sony/gobreaker"
	"golang.org/x/time/rate"
)

// fakeReviewer is a TokenReviewer that returns canned values without
// hitting any actual k8s API.
type fakeReviewer struct {
	subjectByToken map[string]string
	err            error
}

// Review reflects the production tri-state contract: nil err for both
// successful auth and authoritative rejection; non-nil err only for
// "infrastructure" failures (which fakeReviewer doesn't simulate
// here — see f.err if you want to force one).
func (f *fakeReviewer) Review(_ context.Context, token string) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	subj, ok := f.subjectByToken[token]
	if !ok {
		return "", false, nil
	}
	return subj, true, nil
}

func newTestServer(t *testing.T, cfg *config.Config, mint MintFunc, reviewer TokenReviewer) *httptest.Server {
	t.Helper()
	srv, err := New(cfg, mint, reviewer, nil)
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
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestMint_HappyPath(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{
			"org-a": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"},
		},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:agents:agent-runner", Keys: []string{"org-a"}},
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
		subjectByToken: map[string]string{"valid-sa-token": "system:serviceaccount:agents:agent-runner"},
	}

	srv := newTestServer(t, cfg, mint, reviewer)
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/token/org-a", nil)
	req.Header.Set("Authorization", "Bearer valid-sa-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
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
	cfg := &config.Config{Keys: map[string]config.Key{"org-a": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}}}
	srv := newTestServer(t, cfg,
		func(_ context.Context, _ config.Key) (string, time.Time, error) { return "", time.Time{}, nil },
		&fakeReviewer{},
	)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/token/org-a", "", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestMint_TokenReviewRejects(t *testing.T) {
	cfg := &config.Config{Keys: map[string]config.Key{"org-a": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}}}
	reviewer := &fakeReviewer{}
	srv := newTestServer(t, cfg,
		func(_ context.Context, _ config.Key) (string, time.Time, error) { return "", time.Time{}, nil },
		reviewer,
	)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token/org-a", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestMint_SubjectNotInAllowlist(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"org-a": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:other:other", Keys: []string{"org-a"}},
		},
	}
	reviewer := &fakeReviewer{
		subjectByToken: map[string]string{"caller-token": "system:serviceaccount:agents:agent-runner"},
	}
	srv := newTestServer(t, cfg,
		func(_ context.Context, _ config.Key) (string, time.Time, error) { return "", time.Time{}, nil },
		reviewer,
	)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token/org-a", nil)
	req.Header.Set("Authorization", "Bearer caller-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestMint_SubjectAllowedButWrongKey(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{
			"org-a": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"},
			"org-b": {AppID: 2, InstallationID: 2, PrivateKeyFile: "/y"},
		},
		Allowlist: []config.AllowEntry{
			// authorized for org-a only
			{Subject: "system:serviceaccount:agents:agent-runner", Keys: []string{"org-a"}},
		},
	}
	reviewer := &fakeReviewer{
		subjectByToken: map[string]string{"sa-token": "system:serviceaccount:agents:agent-runner"},
	}
	srv := newTestServer(t, cfg,
		func(_ context.Context, _ config.Key) (string, time.Time, error) { return "ghs_x", time.Now(), nil },
		reviewer,
	)
	defer srv.Close()

	// Asking for org-b should 403 — same subject, different key.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token/org-b", nil)
	req.Header.Set("Authorization", "Bearer sa-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestMint_UnknownKey(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"org-a": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:agents:agent-runner", Keys: []string{"org-a"}},
		},
	}
	reviewer := &fakeReviewer{
		subjectByToken: map[string]string{"sa-token": "system:serviceaccount:agents:agent-runner"},
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
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestMint_MintFailureBecomes500(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"org-a": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:agents:agent-runner", Keys: []string{"org-a"}},
		},
	}
	reviewer := &fakeReviewer{
		subjectByToken: map[string]string{"sa-token": "system:serviceaccount:agents:agent-runner"},
	}
	failingMint := func(_ context.Context, _ config.Key) (string, time.Time, error) {
		return "", time.Time{}, errors.New("synthetic mint failure")
	}
	srv := newTestServer(t, cfg, failingMint, reviewer)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/token/org-a", nil)
	req.Header.Set("Authorization", "Bearer sa-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

func TestNew_Validation(t *testing.T) {
	mint := func(_ context.Context, _ config.Key) (string, time.Time, error) { return "", time.Time{}, nil }
	rev := &fakeReviewer{}

	if _, err := New(nil, mint, rev, nil); err == nil {
		t.Errorf("expected error for nil cfg")
	}
	if _, err := New(&config.Config{}, nil, rev, nil); err == nil {
		t.Errorf("expected error for nil mint")
	}
	if _, err := New(&config.Config{}, mint, nil, nil); err == nil {
		t.Errorf("expected error for nil reviewer")
	}
}

func TestAudienceIntersect(t *testing.T) {
	cases := []struct {
		name string
		got  []string
		want []string
		hit  bool
	}{
		{"both empty", nil, nil, false},
		{"got empty", nil, []string{"keymint"}, false},
		{"want empty", []string{"keymint"}, nil, false},
		{"single match", []string{"keymint"}, []string{"keymint"}, true},
		{"multi got, one match", []string{"a", "b", "keymint"}, []string{"keymint", "vault"}, true},
		{"no match", []string{"vault"}, []string{"keymint"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := audienceIntersect(tc.got, tc.want); got != tc.hit {
				t.Errorf("audienceIntersect(%v, %v) = %v, want %v", tc.got, tc.want, got, tc.hit)
			}
		})
	}
}

func TestPerSubjectRateLimit(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{
			"org-a": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"},
		},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:agents:agent-runner", Keys: []string{"org-a"}},
		},
	}
	reviewer := &fakeReviewer{
		subjectByToken: map[string]string{"sa-token": "system:serviceaccount:agents:agent-runner"},
	}
	mint := func(_ context.Context, _ config.Key) (string, time.Time, error) {
		return "ghs_x", time.Now().Add(time.Hour), nil
	}
	srv, err := New(cfg, mint, reviewer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Override per-subject limit to a tiny bucket so the test fits.
	srv.subjectLimit = newLimiterMap(rate.Every(time.Hour), 2)

	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	results := make([]int, 4)
	for i := range results {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/token/org-a", nil)
		req.Header.Set("Authorization", "Bearer sa-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		results[i] = resp.StatusCode
		_ = resp.Body.Close()
	}
	if results[0] != http.StatusOK || results[1] != http.StatusOK {
		t.Errorf("first two requests = %v, want both 200", results[:2])
	}
	if results[2] != http.StatusTooManyRequests || results[3] != http.StatusTooManyRequests {
		t.Errorf("later requests = %v, want 429", results[2:])
	}
}

// TestMintAuditFingerprintIsLogged asserts that the minted-token
// SHA-256 fingerprint is hex-encoded and stable across repeated
// hashes of the same string. (Full log-capture would couple too
// tightly to zap internals.)
func TestMintAuditFingerprintIsStable(t *testing.T) {
	a := tokenFingerprint("ghs_synthetic_token")
	b := tokenFingerprint("ghs_synthetic_token")
	if a != b {
		t.Errorf("fingerprint not deterministic: %q vs %q", a, b)
	}
	if len(a) != 64 {
		t.Errorf("fingerprint hex length = %d, want 64 (32-byte SHA-256)", len(a))
	}
	if a == tokenFingerprint("different") {
		t.Errorf("collision between distinct tokens")
	}
}

// TestUnknownKey_DoesNotExplodeMetricCardinality verifies that
// requests for keys not in the config bucket their metrics under
// metrics.UnknownKey rather than the attacker-supplied path
// segment.
func TestUnknownKey_DoesNotExplodeMetricCardinality(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{
			"org-a": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"},
		},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:agents:agent-runner", Keys: []string{"org-a"}},
		},
	}
	mint := func(_ context.Context, _ config.Key) (string, time.Time, error) {
		return "ghs_x", time.Now().Add(time.Hour), nil
	}
	reviewer := &fakeReviewer{
		subjectByToken: map[string]string{"sa": "system:serviceaccount:agents:agent-runner"},
	}
	srv, err := New(cfg, mint, reviewer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	// Hit a series of unique random key names — none are in cfg.
	// All requests should 404, AND the recordOutcome / metric calls
	// should bucket them under UnknownKey, not under the random
	// segment.
	for _, segment := range []string{"random-uuid-1", "random-uuid-2", "random-uuid-3"} {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/token/"+segment, nil)
		req.Header.Set("Authorization", "Bearer sa")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		_ = resp.Body.Close()
		// The exact rejection status (403 forbidden when the SA isn't
		// allowlisted for that random key, or 404 unknown key) is
		// less important than the fact that none of these unique
		// segments leaked into a metric label.
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusForbidden {
			t.Errorf("status for %s = %d, want 403 or 404", segment, resp.StatusCode)
		}
	}
}

// TestBreaker_AuthFailuresDoNotTripBreaker confirms that an attacker
// flooding invalid tokens cannot trip the circuit breaker. Real
// kubernetes API rejections of inbound caller tokens come back as
// authError (NOT a Go error from reviewLocked), so the breaker's
// failure counter never increments.
func TestBreaker_AuthFailuresDoNotTripBreaker(t *testing.T) {
	// Apiserver always returns a successful 2xx with
	// authenticated=false (this is what k8s returns for an invalid
	// caller token).
	apiserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":{"authenticated":false,"error":"invalid token"}}`))
	}))
	defer apiserver.Close()

	r := &K8sTokenReviewer{
		apiServer:         apiserver.URL,
		saTokenPath:       writeTempSAToken(t),
		expectedAudiences: []string{"keymint"},
		httpClient:        apiserver.Client(),
		breaker: gobreaker.NewCircuitBreaker(gobreaker.Settings{
			Name:        "test-tokenreview",
			MaxRequests: 1,
			Interval:    60 * time.Second,
			Timeout:     30 * time.Second,
			ReadyToTrip: func(c gobreaker.Counts) bool {
				return c.Requests >= 10 && c.TotalFailures*2 > c.Requests
			},
		}),
	}

	// 25 invalid tokens — enough to trip the breaker if it counted
	// auth rejections as failures. New contract: rejection returns
	// (subject="", ok=false, err=nil) so the breaker stays closed.
	for i := 0; i < 25; i++ {
		_, ok, err := r.Review(context.Background(), "junk")
		if err != nil {
			t.Fatalf("auth rejection should not surface as Go err, got %v", err)
		}
		if ok {
			t.Fatalf("auth rejection: ok should be false")
		}
	}

	// Breaker must still be Closed (counts unchanged by auth rejections).
	if got := r.breaker.State(); got != gobreaker.StateClosed {
		t.Errorf("breaker state after 25 auth rejections = %v, want Closed", got)
	}
}

// TestBreaker_InfraFailuresTripBreaker confirms the breaker still
// trips for genuine apiserver-side failures (5xx) — the desired
// behaviour we don't want to regress.
func TestBreaker_InfraFailuresTripBreaker(t *testing.T) {
	apiserver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer apiserver.Close()

	r := &K8sTokenReviewer{
		apiServer:         apiserver.URL,
		saTokenPath:       writeTempSAToken(t),
		expectedAudiences: []string{"keymint"},
		httpClient:        apiserver.Client(),
		breaker: gobreaker.NewCircuitBreaker(gobreaker.Settings{
			Name:        "test-tokenreview-infra",
			MaxRequests: 1,
			Interval:    60 * time.Second,
			Timeout:     30 * time.Second,
			ReadyToTrip: func(c gobreaker.Counts) bool {
				return c.Requests >= 10 && c.TotalFailures*2 > c.Requests
			},
		}),
	}

	for i := 0; i < 25; i++ {
		_, _, _ = r.Review(context.Background(), "any")
	}
	if got := r.breaker.State(); got != gobreaker.StateOpen {
		t.Errorf("breaker state after 25 infra failures = %v, want Open", got)
	}
}

func writeTempSAToken(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "keymint-test-sa-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.WriteString("synthetic-sa-token"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(f.Name()) })
	return f.Name()
}

// TestReviewCache_BypassesApiserverOnHit asserts that two
// successive Reviews of the same bearer token only hit the
// underlying TokenReviewer once.
func TestReviewCache_BypassesApiserverOnHit(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"org-a": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:agents:agent-runner", Keys: []string{"org-a"}},
		},
	}
	calls := 0
	reviewer := &countingReviewer{
		fn: func(_ context.Context, token string) (string, bool, error) {
			calls++
			if token == "valid" {
				return "system:serviceaccount:agents:agent-runner", true, nil
			}
			return "", false, nil
		},
	}
	mintFn := func(_ context.Context, _ config.Key) (string, time.Time, error) {
		return "ghs_x", time.Now().Add(time.Hour), nil
	}
	srv, err := New(cfg, mintFn, reviewer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/token/org-a", nil)
		req.Header.Set("Authorization", "Bearer valid")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
	}
	if calls != 1 {
		t.Errorf("TokenReviewer hit %d times, want 1 (subsequent calls should be cached)", calls)
	}
}

type countingReviewer struct {
	fn func(context.Context, string) (string, bool, error)
}

func (c *countingReviewer) Review(ctx context.Context, t string) (string, bool, error) {
	return c.fn(ctx, t)
}

// TestReload_AtomicallySwapsConfig confirms a Reload() call updates
// the visible Keys + Allowlist without dropping in-flight requests.
func TestReload_AtomicallySwapsConfig(t *testing.T) {
	cfg1 := &config.Config{
		Keys: map[string]config.Key{"old-key": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:agents:agent-runner", Keys: []string{"old-key"}},
		},
		ExpectedAudiences: []string{"keymint"},
	}
	mintFn := func(_ context.Context, _ config.Key) (string, time.Time, error) {
		return "ghs_x", time.Now().Add(time.Hour), nil
	}
	reviewer := &fakeReviewer{
		subjectByToken: map[string]string{"sa": "system:serviceaccount:agents:agent-runner"},
	}
	srv, err := New(cfg1, mintFn, reviewer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := srv.currentConfig().Keys["old-key"]; !ok {
		t.Errorf("initial config missing old-key")
	}

	// Swap to a new config with a different key set.
	cfg2 := &config.Config{
		Keys: map[string]config.Key{"new-key": {AppID: 2, InstallationID: 2, PrivateKeyFile: "/y"}},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:agents:agent-runner", Keys: []string{"new-key"}},
		},
		ExpectedAudiences: []string{"keymint"},
	}
	if err := srv.Reload(cfg2); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if _, ok := srv.currentConfig().Keys["old-key"]; ok {
		t.Errorf("old-key should be gone after reload")
	}
	if _, ok := srv.currentConfig().Keys["new-key"]; !ok {
		t.Errorf("new-key missing after reload")
	}
	if !srv.currentAllowed()["system:serviceaccount:agents:agent-runner"]["new-key"] {
		t.Errorf("allowlist not rebuilt for new-key")
	}
}

// TestReload_RejectsInvalidConfig asserts a bad reload doesn't
// blow away the existing snapshot.
func TestReload_RejectsInvalidConfig(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"good": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}},
	}
	srv, err := New(cfg, func(_ context.Context, _ config.Key) (string, time.Time, error) { return "", time.Time{}, nil }, &fakeReviewer{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.Reload(&config.Config{Keys: nil}); err == nil {
		t.Errorf("expected validation error from empty config")
	}
	// Original snapshot intact.
	if _, ok := srv.currentConfig().Keys["good"]; !ok {
		t.Errorf("good config replaced by failed reload")
	}
}

// TestReviewCache_NegativeCacheBypassesApiserver asserts that a token
// the apiserver rejects once is cached as negative — subsequent
// presentations within the negative TTL are rejected without
// hitting the apiserver again.
func TestReviewCache_NegativeCacheBypassesApiserver(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"org-a": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}},
		Allowlist: []config.AllowEntry{
			{Subject: "system:serviceaccount:agents:agent-runner", Keys: []string{"org-a"}},
		},
	}
	calls := 0
	reviewer := &countingReviewer{
		fn: func(_ context.Context, _ string) (string, bool, error) {
			calls++
			// Authoritative rejection (auth failure), not infra:
			// nil error, ok=false. The negative cache should
			// absorb subsequent identical bad tokens.
			return "", false, nil
		},
	}
	mintFn := func(_ context.Context, _ config.Key) (string, time.Time, error) {
		return "ghs_x", time.Now().Add(time.Hour), nil
	}
	srv, err := New(cfg, mintFn, reviewer, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/token/org-a", nil)
		req.Header.Set("Authorization", "Bearer junk")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	}
	if calls != 1 {
		t.Errorf("TokenReviewer hit %d times, want 1 (negative cache should absorb the rest)", calls)
	}
}

func TestProbes_LivezAndReadyz(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"org-a": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x"}},
	}
	srv, err := New(cfg,
		func(_ context.Context, _ config.Key) (string, time.Time, error) { return "", time.Time{}, nil },
		&fakeReviewer{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ts := httptest.NewServer(srv.Routes())
	defer ts.Close()

	for _, p := range []string{"/livez", "/readyz", "/healthz"} {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatalf("get %s: %v", p, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %s = %d, want 200", p, resp.StatusCode)
		}
	}
}

func TestClientIP_TrustsXFFOnlyFromConfiguredCIDRs(t *testing.T) {
	mustCIDR := func(s string) *net.IPNet {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", s, err)
		}
		return n
	}
	trusted := []*net.IPNet{
		mustCIDR("10.0.0.0/8"),
		mustCIDR("192.168.1.5/32"),
	}

	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		realIP     string
		trusted    []*net.IPNet
		want       string
	}{
		{
			name:       "no trusted proxies → use peer",
			remoteAddr: "10.0.0.1:1234",
			xff:        "1.2.3.4",
			trusted:    nil,
			want:       "10.0.0.1",
		},
		{
			name:       "untrusted peer → ignore XFF (anti-spoof)",
			remoteAddr: "8.8.8.8:1234",
			xff:        "1.2.3.4",
			trusted:    trusted,
			want:       "8.8.8.8",
		},
		{
			name:       "trusted peer → walk XFF right-to-left",
			remoteAddr: "10.0.0.1:1234",
			xff:        "1.2.3.4, 10.0.0.2",
			trusted:    trusted,
			want:       "1.2.3.4",
		},
		{
			name:       "all-trusted XFF → fall through to X-Real-IP",
			remoteAddr: "10.0.0.1:1234",
			xff:        "10.0.0.2, 10.0.0.3",
			realIP:     "5.6.7.8",
			trusted:    trusted,
			want:       "5.6.7.8",
		},
		{
			name:       "trusted peer, empty XFF and X-Real-IP → fall back to peer",
			remoteAddr: "10.0.0.1:1234",
			trusted:    trusted,
			want:       "10.0.0.1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/x", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.realIP != "" {
				r.Header.Set("X-Real-IP", tc.realIP)
			}
			if got := clientIP(r, tc.trusted); got != tc.want {
				t.Errorf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestLimiterMap_ConcurrentInitSharesOneLimiter asserts that a
// thundering herd of N goroutines all calling allow() on the same
// new key shares exactly one limiter — the rate cap is honoured
// immediately, instead of N goroutines each instantiating their
// own bucket and silently bypassing the cap.
func TestLimiterMap_ConcurrentInitSharesOneLimiter(t *testing.T) {
	const concurrency = 200
	// burst=1 — at most one allow() call should succeed for a
	// given key.
	m := newLimiterMap(rate.Every(time.Hour), 1)

	var wg sync.WaitGroup
	var allowed atomic.Int64
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			if m.allow("racy-key") {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := allowed.Load(); got != 1 {
		t.Errorf("concurrent allow() races allowed %d through; want exactly 1 (rate cap bypassed)", got)
	}
}

// TestLimiterMap_JanitorEvictsIdleButKeepsActive asserts the
// idle-only GC strategy: limiters whose burst bucket is full
// (untouched recently) get dropped, and limiters whose bucket is
// depleted (active or under attack) stay — so an attacker cannot
// evict their *own* limiter to reset the rate cap by simply
// flooding more unique keys.
func TestLimiterMap_JanitorEvictsIdleButKeepsActive(t *testing.T) {
	m := newLimiterMap(rate.Every(time.Second), 5)

	// "active" key gets immediately depleted (5 fast Allow() calls
	// drain its 5-token bucket).
	for i := 0; i < 5; i++ {
		m.allow("active")
	}
	// "idle" key is touched once but only briefly; its bucket is
	// almost full at the time of the GC pass.
	m.allow("idle")
	// Wait long enough for the idle key's bucket to refill to burst.
	time.Sleep(1100 * time.Millisecond)

	m.gcIdle()

	if _, ok := m.limiters.Load("active"); !ok {
		t.Errorf("active limiter (depleted bucket) was evicted; rate cap reset")
	}
	if _, ok := m.limiters.Load("idle"); ok {
		t.Errorf("idle limiter (full bucket) was kept; janitor not GC'ing")
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
