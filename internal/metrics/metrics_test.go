package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// once protects against double-registration if multiple tests try to
// build a Metrics — promauto / MustRegister panics on duplicates.
var once sync.Once
var shared *Metrics

func newOnce(t *testing.T) *Metrics {
	t.Helper()
	once.Do(func() {
		shared = New()
	})
	return shared
}

func TestNew_Registers(t *testing.T) {
	m := newOnce(t)
	if m == nil {
		t.Fatalf("New returned nil")
	}
	// Increment counters / observe histograms so metrics materialize in
	// the registry — vector instruments only render once they have at
	// least one observation.
	m.MintRequestsTotal.WithLabelValues(OutcomeSuccess, "org-a").Inc()
	m.MintDuration.WithLabelValues("org-a").Observe(0.1)
	m.TokenReviewsTotal.WithLabelValues(TokenReviewAccepted).Inc()
	m.GitHubAPILatency.WithLabelValues("201").Observe(0.05)
	m.JWTClockOffsetSeconds.Set(0.0)
	m.MintInFlight.Inc()

	srv := httptest.NewServer(Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("get /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	got := string(body)

	for _, want := range []string{
		"keymint_mint_requests_total",
		"keymint_mint_duration_seconds",
		"keymint_mint_in_flight",
		"keymint_tokenreviews_total",
		"keymint_github_api_latency_seconds",
		"keymint_jwt_clock_offset_seconds",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("metric %q not found in /metrics output", want)
		}
	}
}

func TestOutcomeLabels(t *testing.T) {
	// Every constant should be a valid label value (non-empty, no whitespace).
	for _, v := range []string{
		OutcomeSuccess,
		OutcomeBadAuth,
		OutcomeTokenReviewError,
		OutcomeForbidden,
		OutcomeUnknownKey,
		OutcomeMintError,
		OutcomeRateLimited,
		TokenReviewAccepted,
		TokenReviewRejected,
	} {
		if v == "" || strings.ContainsAny(v, " \t\n") {
			t.Errorf("invalid label value %q", v)
		}
	}
}

// Reset isn't normally needed in production but is useful for tests
// that want a clean slate. Verify it compiles + works.
func TestRegistry_DefaultGather(t *testing.T) {
	newOnce(t)
	got, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(got) == 0 {
		t.Errorf("default registry gathered zero metric families")
	}
}
