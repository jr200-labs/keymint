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
	}

	prometheus.MustRegister(
		m.MintRequestsTotal,
		m.MintDuration,
		m.MintInFlight,
		m.TokenReviewsTotal,
		m.GitHubAPILatency,
		m.JWTClockOffsetSeconds,
	)

	return m
}

// Handler returns the http.Handler that exposes the registered metrics
// in Prometheus text format.
func Handler() http.Handler { return promhttp.Handler() }
