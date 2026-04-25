// Package server implements keymint's in-cluster HTTP service mode.
//
// The server exposes one endpoint:
//
//	POST /token/<key>
//	Authorization: Bearer <kubernetes-sa-projected-token>
//
// The handler:
//
//  1. Verifies the inbound bearer token by calling the cluster's
//     TokenReview API; this returns the resolved ServiceAccount
//     subject (`system:serviceaccount:<ns>:<name>`).
//  2. Looks up the resolved subject in the keymint config allowlist
//     and confirms it is permitted to mint for <key>.
//  3. Calls the injected MintFunc to produce a fresh installation
//     token and returns it as JSON.
//
// TokenReview is invoked by raw HTTP against the in-pod kubernetes
// API discovery info — keeping client-go out of keymint's dependency
// graph. The keymint pod itself needs RBAC for
// `tokenreviews.authentication.k8s.io: create`; that ClusterRole is
// supplied by the deploy manifest.
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru/v2"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/metrics"
	"github.com/sony/gobreaker"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// tracer is the OTel tracer used for spans emitted by this package.
var tracer trace.Tracer = otel.Tracer("github.com/jr200-labs/keymint/internal/server")

// MintFunc is the contract for producing an installation token given
// a Key entry. It is injected so this package does not depend on
// internal/mint or internal/sops directly.
type MintFunc func(ctx context.Context, key config.Key) (token string, expiresAt time.Time, err error)

// configSnapshot is an immutable view of the config + the
// pre-computed allowedSubject lookup, swapped atomically when
// the operator hot-reloads keymint's config.yaml.
type configSnapshot struct {
	cfg            *config.Config
	allowedSubject map[string]map[string]bool // subject -> keys -> true
}

// reviewCache caches successful TokenReview lookups for a short TTL,
// keyed by the SHA-256 of the bearer token (so the raw token never
// sits in memory as a map key). Drastically reduces apiserver
// authentication traffic for bursty callers; the TTL is short
// enough that revoked SAs lose access quickly.
const (
	reviewCacheSize = 4096
	reviewCacheTTL  = 60 * time.Second
)

type reviewCache struct {
	cache *expirable.LRU[string, string]
}

func newReviewCache() *reviewCache {
	return &reviewCache{
		cache: expirable.NewLRU[string, string](reviewCacheSize, nil, reviewCacheTTL),
	}
}

func (c *reviewCache) hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (c *reviewCache) get(token string) (string, bool) {
	return c.cache.Get(c.hashToken(token))
}

func (c *reviewCache) put(token, subject string) {
	c.cache.Add(c.hashToken(token), subject)
}

// Server holds wired-up HTTP server state.
type Server struct {
	snapshot      atomic.Pointer[configSnapshot]
	mint          MintFunc
	tokenReviewer TokenReviewer
	preAuthLimit  *limiterMap // per-IP, evaluated before auth
	subjectLimit  *limiterMap // per-resolved-SA, evaluated after auth
	reviewCache   *reviewCache
	metrics       *metrics.Metrics
}

// limiterMap holds a per-key rate.Limiter behind an LRU so a slow
// flood of unique keys (random IPs, invalid auth) cannot grow the
// map without bound.
//
// Each Server keeps two — one keyed by remote IP (cheap pre-auth
// gate) and one keyed by the resolved ServiceAccount subject
// (post-auth, generous).
type limiterMap struct {
	cache *lru.Cache[string, *rate.Limiter]
	rps   rate.Limit
	burst int
}

// limiterMapSize is the per-instance cap. Once exceeded the
// least-recently-used limiter is evicted; a new one for that key
// is allocated on the next observation.
const limiterMapSize = 4096

func newLimiterMap(rps rate.Limit, burst int) *limiterMap {
	c, err := lru.New[string, *rate.Limiter](limiterMapSize)
	if err != nil {
		// lru.New only fails on size <= 0 — treat as a programmer error.
		panic(fmt.Sprintf("server: limiterMap LRU init: %v", err))
	}
	return &limiterMap{cache: c, rps: rps, burst: burst}
}

func (m *limiterMap) allow(key string) bool {
	if l, ok := m.cache.Get(key); ok {
		return l.Allow()
	}
	l := rate.NewLimiter(m.rps, m.burst)
	m.cache.Add(key, l)
	return l.Allow()
}

// TokenReviewer abstracts the k8s TokenReview call so tests can
// substitute a fake.
//
// The implementation MUST honour the operator-supplied audience list
// when calling the kubernetes API, so a stolen SA token bound to a
// different audience cannot be replayed against keymint.
type TokenReviewer interface {
	Review(ctx context.Context, token string) (subject string, err error)
}

// New builds a Server. The reviewer argument is nil-friendly for
// tests; in production callers pass NewK8sTokenReviewer. The metrics
// argument may be nil — handlers handle that gracefully so unit tests
// don't have to construct a metrics registry.
func New(cfg *config.Config, mint MintFunc, reviewer TokenReviewer, m *metrics.Metrics) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("server: cfg is required")
	}
	if mint == nil {
		return nil, errors.New("server: mint is required")
	}
	if reviewer == nil {
		return nil, errors.New("server: reviewer is required")
	}

	s := &Server{
		mint:          mint,
		tokenReviewer: reviewer,
		// Pre-auth (per-IP): tight bucket. Anonymous floods here just
		// burn the attacker's own bucket and never reach the
		// kubernetes TokenReview API.
		preAuthLimit: newLimiterMap(rate.Limit(10), 20),
		// Post-auth (per-subject): generous bucket for legitimate
		// authenticated callers minting frequently.
		subjectLimit: newLimiterMap(rate.Limit(100), 200),
		reviewCache:  newReviewCache(),
		metrics:      m,
	}
	s.snapshot.Store(buildSnapshot(cfg))
	return s, nil
}

// buildSnapshot precomputes the subject -> keys allow map for fast
// lookup at request time.
func buildSnapshot(cfg *config.Config) *configSnapshot {
	allowed := make(map[string]map[string]bool, len(cfg.Allowlist))
	for _, e := range cfg.Allowlist {
		if allowed[e.Subject] == nil {
			allowed[e.Subject] = make(map[string]bool)
		}
		for _, k := range e.Keys {
			allowed[e.Subject][k] = true
		}
	}
	return &configSnapshot{cfg: cfg, allowedSubject: allowed}
}

// Reload swaps in a new validated config atomically. Returns an
// error if the new config fails validation; the existing snapshot
// is left unchanged in that case so a bad reload cannot break a
// running server.
func (s *Server) Reload(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("server: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("server: reload validation: %w", err)
	}
	s.snapshot.Store(buildSnapshot(cfg))
	return nil
}

// snapshot accessors used by handlers.
func (s *Server) currentConfig() *config.Config { return s.snapshot.Load().cfg }
func (s *Server) currentAllowed() map[string]map[string]bool {
	return s.snapshot.Load().allowedSubject
}

// Routes returns an http.Handler that serves keymint's API.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token/{key}", s.handleMint)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if s.currentConfig() == nil {
		writeJSONError(w, http.StatusInternalServerError, "config missing")
		return
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		if _, err := os.Stat(saTokenPath); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "sa token missing")
			return
		}
		if _, err := os.Stat(saCAPath); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "sa ca missing")
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

type mintResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (s *Server) handleMint(w http.ResponseWriter, r *http.Request) {
	keyName := r.PathValue("key")

	// Sanitize the path segment to a bounded label value for metrics
	// + spans. Without this, an attacker hitting /token/<random-uuid>
	// in a loop would explode Prometheus label cardinality and OOM
	// the pod. The unsanitized name still appears in the user-facing
	// error message and structured log fields where cardinality is
	// not a concern.
	metricKey := metrics.UnknownKey
	if _, ok := s.currentConfig().Keys[keyName]; ok {
		metricKey = keyName
	}

	// Open a span for the whole handler. Span attributes are filled in
	// as we learn more (subject, outcome).
	ctx, span := tracer.Start(r.Context(), "server.handleMint",
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(attribute.String("keymint.key", metricKey)),
	)
	defer span.End()

	start := time.Now()
	if s.metrics != nil {
		s.metrics.MintInFlight.Inc()
		defer s.metrics.MintInFlight.Dec()
		defer func() {
			s.metrics.MintDuration.WithLabelValues(metricKey).Observe(time.Since(start).Seconds())
		}()
	}

	log := zap.L().With(zap.String("key", keyName), zap.String("remote", r.RemoteAddr))

	// Pre-auth rate limit: per-remote-IP. Cheap, scoped to attacker so
	// flooders cannot exhaust authenticated callers' budget.
	if !s.preAuthLimit.allow(remoteIP(r)) {
		s.recordOutcome(span, metricKey, metrics.OutcomeRateLimited)
		span.SetStatus(codes.Error, "rate limited (pre-auth)")
		writeJSONError(w, http.StatusTooManyRequests, "too many requests")
		return
	}

	// 1. Extract bearer token
	bearer, ok := bearerToken(r)
	if !ok {
		s.recordOutcome(span, metricKey, metrics.OutcomeBadAuth)
		span.SetStatus(codes.Error, "missing bearer")
		writeJSONError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
		return
	}

	// 2. Validate via TokenReview (audience-bound, SA token re-read).
	//    A short-lived cache shields the apiserver from bursts;
	//    entries expire after reviewCacheTTL so revoked SAs lose
	//    access promptly.
	subject, cacheHit := s.reviewCache.get(bearer)
	if cacheHit {
		s.recordCacheLookup(metrics.CacheHit)
	} else {
		s.recordCacheLookup(metrics.CacheMiss)
		var err error
		subject, err = s.tokenReviewer.Review(ctx, bearer)
		if err != nil {
			if s.metrics != nil {
				s.metrics.TokenReviewsTotal.WithLabelValues(metrics.TokenReviewRejected).Inc()
			}
			s.recordOutcome(span, metricKey, metrics.OutcomeTokenReviewError)
			span.RecordError(err)
			span.SetStatus(codes.Error, "tokenreview failed")
			log.Warn("tokenreview failed", zap.Error(err))
			writeJSONError(w, http.StatusUnauthorized, "tokenreview rejected the bearer token")
			return
		}
		if s.metrics != nil {
			s.metrics.TokenReviewsTotal.WithLabelValues(metrics.TokenReviewAccepted).Inc()
		}
		s.reviewCache.put(bearer, subject)
	}
	span.SetAttributes(attribute.String("k8s.serviceaccount.subject", subject))
	log = log.With(zap.String("subject", subject))

	// Post-auth rate limit: per-subject. Caps any single legitimate
	// service that goes haywire.
	if !s.subjectLimit.allow(subject) {
		s.recordOutcome(span, metricKey, metrics.OutcomeRateLimited)
		span.SetStatus(codes.Error, "rate limited (per-subject)")
		writeJSONError(w, http.StatusTooManyRequests, "too many requests")
		return
	}

	// 3. Allowlist check
	if !s.subjectMayMint(subject, keyName) {
		s.recordOutcome(span, metricKey, metrics.OutcomeForbidden)
		span.SetStatus(codes.Error, "forbidden")
		log.Warn("subject not permitted")
		writeJSONError(w, http.StatusForbidden, fmt.Sprintf("subject %q not permitted to mint key %q", subject, keyName))
		return
	}

	// 4. Look up key (already validated when computing metricKey, but
	// keep an explicit branch for the 404 outcome).
	keyEntry, ok := s.currentConfig().Keys[keyName]
	if !ok {
		s.recordOutcome(span, metricKey, metrics.OutcomeUnknownKey)
		span.SetStatus(codes.Error, "unknown key")
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("key %q not found", keyName))
		return
	}

	// 5. Mint
	token, expiresAt, err := s.mint(ctx, keyEntry)
	if err != nil {
		s.recordOutcome(span, metricKey, metrics.OutcomeMintError)
		span.RecordError(err)
		span.SetStatus(codes.Error, "mint failed")
		log.Error("mint failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "mint failed")
		return
	}
	s.recordOutcome(span, metricKey, metrics.OutcomeSuccess)
	span.SetStatus(codes.Ok, "")
	log.Info("minted")

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(mintResponse{Token: token, ExpiresAt: expiresAt}); err != nil {
		log.Error("encode response failed", zap.Error(err))
	}
}

// recordOutcome stamps the span with the outcome attribute and bumps
// the corresponding metric counter. Both are nil-safe so tests don't
// have to set up either.
func (s *Server) recordOutcome(span trace.Span, keyName, outcome string) {
	span.SetAttributes(attribute.String("keymint.outcome", outcome))
	if s.metrics != nil {
		s.metrics.MintRequestsTotal.WithLabelValues(outcome, keyName).Inc()
	}
}

func (s *Server) recordCacheLookup(result string) {
	if s.metrics != nil {
		s.metrics.TokenReviewCacheTotal.WithLabelValues(result).Inc()
	}
}

func (s *Server) subjectMayMint(subject, key string) bool {
	keys, ok := s.currentAllowed()[subject]
	if !ok {
		return false
	}
	return keys[key]
}

// remoteIP returns the IP portion of r.RemoteAddr, or the whole
// string if it does not parse as host:port. Good enough for keying
// the per-IP rate limiter; not used for authorization.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// bearerToken extracts a bearer token from the Authorization header.
// Returns (token, true) if present and well-formed.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if tok == "" {
		return "", false
	}
	return tok, true
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}

// --- Kubernetes TokenReview client (stdlib HTTP, no client-go) -----

const (
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// K8sTokenReviewer talks to the in-cluster Kubernetes API to validate
// inbound bearer tokens via the TokenReview API.
type K8sTokenReviewer struct {
	apiServer         string
	saTokenPath       string // re-read on every call — kubelet rotates this file
	expectedAudiences []string
	httpClient        *http.Client
	breaker           *gobreaker.CircuitBreaker
}

// NewK8sTokenReviewer constructs a reviewer using the standard
// in-pod service account credentials. Returns an error if the pod
// is not running with a mounted service account.
//
// expectedAudiences is mandatory. It is forwarded to the TokenReview
// API as Spec.Audiences so the caller's token is verified to have
// been issued for one of these audiences. Operators must configure
// the keymint pod and its callers to use a matching projected SA
// volume audience.
func NewK8sTokenReviewer(expectedAudiences []string) (*K8sTokenReviewer, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("server: KUBERNETES_SERVICE_HOST/PORT not set — not running in-cluster?")
	}
	if len(expectedAudiences) == 0 {
		return nil, errors.New("server: expected_audiences must be non-empty (set in keymint config)")
	}

	caBytes, err := os.ReadFile(saCAPath)
	if err != nil {
		return nil, fmt.Errorf("server: read CA cert: %w", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("server: ca.crt is not a valid PEM")
	}

	// Sanity-check that the SA token file exists and is readable now;
	// the actual content is re-read per call so kubelet rotation
	// (typical projected-volume default ~1h) does not silently expire
	// our cached token.
	if _, err := os.Stat(saTokenPath); err != nil {
		return nil, fmt.Errorf("server: stat service account token: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		},
		// Bound resource consumption when talking to the apiserver.
		// Without these, defaults leak idle conns under apiserver
		// slowness and TLS handshakes cost CPU under sudden load.
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}

	// Circuit breaker around TokenReview. If the apiserver degrades
	// (consistently slow or 5xx), open the breaker and fail-fast for
	// 30s so we don't pile up 10-second-stalled goroutines and exhaust
	// the request handling pool.
	cb := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "kubernetes-tokenreview",
		MaxRequests: 1,
		Interval:    60 * time.Second,
		Timeout:     30 * time.Second,
		ReadyToTrip: func(c gobreaker.Counts) bool {
			// Trip when failure ratio is high *and* we've seen enough
			// requests for it to be statistically meaningful.
			return c.Requests >= 10 && c.TotalFailures*2 > c.Requests
		},
	})

	return &K8sTokenReviewer{
		apiServer:         fmt.Sprintf("https://%s", net.JoinHostPort(host, port)),
		saTokenPath:       saTokenPath,
		expectedAudiences: append([]string(nil), expectedAudiences...),
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
		breaker: cb,
	}, nil
}

type tokenReviewRequest struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Spec       tokenReviewRequestSpec `json:"spec"`
}

type tokenReviewRequestSpec struct {
	Token     string   `json:"token"`
	Audiences []string `json:"audiences,omitempty"`
}

type tokenReviewResponse struct {
	Status struct {
		Authenticated bool `json:"authenticated"`
		User          struct {
			Username string `json:"username"`
		} `json:"user"`
		Audiences []string `json:"audiences,omitempty"`
		Error     string   `json:"error,omitempty"`
	} `json:"status"`
}

// reviewResult carries the outcome of one TokenReview call. We
// separate infra failures (returned as the outer Go error so the
// circuit breaker counts them) from caller-side auth rejections
// (carried in authError so the breaker doesn't count an attacker's
// invalid tokens against its failure budget).
type reviewResult struct {
	subject   string
	authError error
}

// Review POSTs a TokenReview to the API server and returns the
// resolved username on success. The pod's own SA token is re-read
// from disk on each call so kubelet-rotated projected tokens stay
// valid for the lifetime of the process. Wrapped in a circuit
// breaker so the handler fails fast when the apiserver degrades —
// but caller-side auth rejections are NOT counted as breaker
// failures, so a flood of invalid tokens cannot trip it and DoS
// legitimate callers.
func (r *K8sTokenReviewer) Review(ctx context.Context, token string) (string, error) {
	out, err := r.breaker.Execute(func() (interface{}, error) {
		return r.reviewLocked(ctx, token)
	})
	if err != nil {
		// Infra-level failure or breaker open.
		return "", err
	}
	res := out.(reviewResult)
	if res.authError != nil {
		// Caller's token was rejected by the apiserver. Surface to
		// the handler as an error, but the breaker already saw a
		// successful call so its failure counter is untouched.
		return "", res.authError
	}
	return res.subject, nil
}

// reviewLocked is the inner implementation invoked by the circuit breaker.
// It returns:
//   - (reviewResult{subject:...}, nil)             on a successfully validated token
//   - (reviewResult{authError:...}, nil)           on a token the apiserver rejected
//   - (reviewResult{}, err)                        on infra failure (breaker counts this)
func (r *K8sTokenReviewer) reviewLocked(ctx context.Context, token string) (reviewResult, error) {
	body, err := json.Marshal(tokenReviewRequest{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec: tokenReviewRequestSpec{
			Token:     token,
			Audiences: r.expectedAudiences,
		},
	})
	if err != nil {
		return reviewResult{}, fmt.Errorf("server: marshal tokenreview: %w", err)
	}

	saTokenBytes, err := os.ReadFile(r.saTokenPath)
	if err != nil {
		return reviewResult{}, fmt.Errorf("server: read sa token: %w", err)
	}
	saToken := strings.TrimSpace(string(saTokenBytes))

	url := r.apiServer + "/apis/authentication.k8s.io/v1/tokenreviews"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return reviewResult{}, fmt.Errorf("server: build tokenreview request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+saToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return reviewResult{}, fmt.Errorf("server: tokenreview POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return reviewResult{}, fmt.Errorf("server: read tokenreview response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		// Apiserver-side issue (HTTP 5xx, our SA token is wrong, etc.).
		// 401/403 here would mean keymint's own SA token is bad — that
		// IS an infra problem the breaker should react to.
		return reviewResult{}, fmt.Errorf("server: tokenreview returned %d: %s", resp.StatusCode, string(respBody))
	}

	var out tokenReviewResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return reviewResult{}, fmt.Errorf("server: parse tokenreview response: %w", err)
	}

	// From here on, the apiserver gave us a normal 2xx + parseable
	// body. Anything wrong with the *caller's* token is an auth
	// rejection, NOT an infra failure — surface it via authError so
	// the breaker doesn't count it.
	if !out.Status.Authenticated {
		msg := out.Status.Error
		if msg == "" {
			msg = "tokenreview not authenticated"
		}
		return reviewResult{authError: fmt.Errorf("server: %s", msg)}, nil
	}
	if !audienceIntersect(out.Status.Audiences, r.expectedAudiences) {
		return reviewResult{authError: fmt.Errorf("server: tokenreview returned audiences %v, none match expected %v", out.Status.Audiences, r.expectedAudiences)}, nil
	}
	if out.Status.User.Username == "" {
		return reviewResult{authError: errors.New("server: tokenreview returned empty username")}, nil
	}
	return reviewResult{subject: out.Status.User.Username}, nil
}

// audienceIntersect returns true if any audience in got is also in
// want. Empty got is treated as a mismatch — if the operator asked
// for audience binding we require the apiserver to return one.
func audienceIntersect(got, want []string) bool {
	if len(got) == 0 || len(want) == 0 {
		return false
	}
	have := make(map[string]struct{}, len(got))
	for _, a := range got {
		have[a] = struct{}{}
	}
	for _, a := range want {
		if _, ok := have[a]; ok {
			return true
		}
	}
	return false
}
