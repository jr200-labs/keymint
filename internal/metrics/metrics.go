// Package metrics exposes Prometheus metrics for the keymint service.
//
// One Metrics value is constructed at process startup via New() and
// passed through to handlers/services that need to record observations.
// The metrics are registered against the default Prometheus registry,
// which the /metrics HTTP handler returned by Handler() scrapes.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "keymint"

// Outcome label values for mint requests.
const (
	OutcomeSuccess          = "success"
	OutcomeBadAuth          = "bad_auth"
	OutcomeTokenReviewError = "tokenreview_error"
	OutcomeForbidden        = "forbidden"
	OutcomeUnknownKey       = "unknown_key"
	OutcomeMintError        = "mint_error"
	OutcomeRateLimited      = "rate_limited"
)

// TokenReviewResult label values.
const (
	TokenReviewAccepted = "accepted"
	TokenReviewRejected = "rejected"
)

// UnknownKey is the sentinel label value used when a request asks
// for a key that is not in the keymint config. Using a fixed string
// instead of the attacker-controlled URL segment keeps Prometheus
// label cardinality bounded.
const UnknownKey = "unknown_key"

// CacheResult label values for TokenReviewCacheTotal.
const (
	CacheHit  = "hit"
	CacheMiss = "miss"
)

// Metrics holds all Prometheus instruments for the keymint binary.
type Metrics struct {
	// MintRequestsTotal counts inbound mint requests by outcome and key.
	MintRequestsTotal *prometheus.CounterVec

	// MintDuration measures end-to-end /token/<key> handler latency.
	MintDuration *prometheus.HistogramVec

	// MintInFlight is the count of currently-in-flight mint requests.
	MintInFlight prometheus.Gauge

	// TokenReviewsTotal counts every TokenReview round-trip by result.
	TokenReviewsTotal *prometheus.CounterVec

	// GitHubAPILatency measures /access_tokens round-trip time, by HTTP status.
	GitHubAPILatency *prometheus.HistogramVec

	// JWTClockOffsetSeconds is the most recent observed clock drift between
	// keymint and GitHub, in seconds. Negative means keymint is ahead.
	JWTClockOffsetSeconds prometheus.Gauge

	// TokenReviewCacheTotal counts TokenReview lookups by result
	// ("hit" / "miss"). Operators graph hit ratio to see how
	// effectively the cache is shielding the apiserver.
	TokenReviewCacheTotal *prometheus.CounterVec

	// GitHubRateLimitRemaining mirrors the X-RateLimit-Remaining
	// header from the most recent /access_tokens response, labelled
	// by GitHub API base URL so public github.com and any GHE hosts
	// are tracked separately.
	GitHubRateLimitRemaining *prometheus.GaugeVec

	// GitHubRateLimitResetUnix mirrors the X-RateLimit-Reset header
	// (Unix-seconds epoch when the bucket refills).
	GitHubRateLimitResetUnix *prometheus.GaugeVec

	// GitHubBreakerState exposes the gobreaker state around the
	// /access_tokens call: 0=closed, 1=half-open, 2=open.
	GitHubBreakerState prometheus.Gauge
}

// New constructs and registers the metrics against the default
// Prometheus registry.
func New() *Metrics {
	m := &Metrics{
		MintRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "mint_requests_total",
				Help:      "Inbound /token/<key> requests by outcome and key.",
			},
			[]string{"outcome", "key"},
		),
		MintDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "mint_duration_seconds",
				Help:      "End-to-end /token/<key> handler latency.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"key"},
		),
		MintInFlight: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "mint_in_flight",
				Help:      "Currently in-flight mint requests.",
			},
		),
		TokenReviewsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "tokenreviews_total",
				Help:      "TokenReview round-trips against the kubernetes API by result.",
			},
			[]string{"result"},
		),
		GitHubAPILatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "github_api_latency_seconds",
				Help:      "Latency of POST /app/installations/<id>/access_tokens calls, by HTTP status.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"status"},
		),
		JWTClockOffsetSeconds: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "jwt_clock_offset_seconds",
				Help:      "Most recent observed clock drift between this pod and GitHub (seconds).",
			},
		),
		TokenReviewCacheTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "tokenreview_cache_total",
				Help:      "TokenReview cache lookups by result (hit/miss).",
			},
			[]string{"result"},
		),
		GitHubRateLimitRemaining: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "github_ratelimit_remaining",
				Help:      "GitHub X-RateLimit-Remaining for the most recent /access_tokens response, by API base URL.",
			},
			[]string{"api_base_url"},
		),
		GitHubRateLimitResetUnix: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "github_ratelimit_reset_unix",
				Help:      "GitHub X-RateLimit-Reset (Unix epoch seconds) for the most recent /access_tokens response.",
			},
			[]string{"api_base_url"},
		),
		GitHubBreakerState: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "github_breaker_state",
				Help:      "Circuit breaker state around GitHub /access_tokens: 0=closed, 1=half-open, 2=open.",
			},
		),
	}

	prometheus.MustRegister(
		m.MintRequestsTotal,
		m.MintDuration,
		m.MintInFlight,
		m.TokenReviewsTotal,
		m.GitHubAPILatency,
		m.JWTClockOffsetSeconds,
		m.TokenReviewCacheTotal,
		m.GitHubRateLimitRemaining,
		m.GitHubRateLimitResetUnix,
		m.GitHubBreakerState,
	)

	return m
}

// Handler returns the http.Handler that exposes the registered metrics
// in Prometheus text format.
func Handler() http.Handler { return promhttp.Handler() }
