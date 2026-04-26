// Package mint signs GitHub App JWTs and exchanges them for short-lived
// installation access tokens via the GitHub REST API.
//
// The flow follows GitHub's documented two-step app authentication:
//
//  1. Sign a JWT with the App's RSA private key. iss=appID, exp ≤ 10min.
//     https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app
//  2. POST that JWT to /app/installations/{id}/access_tokens. Receive
//     a 1-hour installation token.
//     https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app
//
// This package is small and dependency-light on purpose: a single
// public Mint function that takes a Request and returns a Token. Both
// CLI mode (operator runs `keymint mint <key>`) and Service mode
// (in-cluster broker handles inbound HTTP) call into Mint.
package mint

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sony/gobreaker/v2"
)

// defaultHTTPClient has explicit Transport tuning so we don't inherit
// http.DefaultClient / DefaultTransport behaviour: 2 idle conns per
// host (the stdlib default) is far too low for a token broker that
// fans out to api.github.com under any meaningful load.
var defaultHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	},
}

// egressConcurrency caps the number of in-flight POSTs to GitHub
// per distinct API base URL. Public github.com and each GitHub
// Enterprise host get their own semaphore so a slow / hung GHE
// instance cannot starve token minting against unrelated healthy
// endpoints. The PER-endpoint cap is intentionally generous (50)
// since the breaker provides the real overload protection.
const egressConcurrency = 50

// egressSems is a sync.Map keyed by API base URL → chan struct{}
// (the per-endpoint semaphore). Lazily allocated.
var egressSems sync.Map

// githubBreakers is a sync.Map keyed by API base URL →
// *gobreaker.CircuitBreaker. Same partitioning rationale as
// egressSems: a degraded GHE host must not trip a breaker shared
// with public github.com.
var githubBreakers sync.Map

func breakerForAPI(apiBase string) *gobreaker.CircuitBreaker[exchangeResult] {
	if v, ok := githubBreakers.Load(apiBase); ok {
		return v.(*gobreaker.CircuitBreaker[exchangeResult])
	}
	cb := gobreaker.NewCircuitBreaker[exchangeResult](gobreaker.Settings{
		Name:        "github-access-tokens:" + apiBase,
		MaxRequests: 1,
		Interval:    60 * time.Second,
		Timeout:     30 * time.Second,
		ReadyToTrip: func(c gobreaker.Counts) bool {
			// Trip when ≥10 attempts and >50% failed.
			return c.Requests >= 10 && c.TotalFailures*2 > c.Requests
		},
	})
	actual, loaded := githubBreakers.LoadOrStore(apiBase, cb)
	if loaded {
		return actual.(*gobreaker.CircuitBreaker[exchangeResult])
	}
	return cb
}

// GithubBreakerState exposes the WORST current state across all
// per-endpoint breakers (Open beats HalfOpen beats Closed). The
// metric reporter callers map: 0 closed / 1 half-open / 2 open.
func GithubBreakerState() gobreaker.State {
	worst := gobreaker.StateClosed
	githubBreakers.Range(func(_, v any) bool {
		st := v.(*gobreaker.CircuitBreaker[exchangeResult]).State()
		if st > worst {
			worst = st
		}
		return true
	})
	return worst
}

// acquireEgress blocks until an outbound slot is available on the
// per-endpoint semaphore for apiBase, or ctx is cancelled. Returns
// a release func.
func acquireEgress(ctx context.Context, apiBase string) (func(), error) {
	v, _ := egressSems.LoadOrStore(apiBase, make(chan struct{}, egressConcurrency))
	sem := v.(chan struct{})
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// DefaultGitHubAPI is the public GitHub REST API base URL. Override
// via Request.APIBaseURL to point at GitHub Enterprise Server.
const DefaultGitHubAPI = "https://api.github.com"

// jwtLifetime is how long the App JWT is valid before exchange. GitHub
// rejects JWTs older than 10 minutes; we set a slightly shorter window
// to leave headroom for clock skew.
const jwtLifetime = 9 * time.Minute

// clockOffsets holds the most recently observed clock drift, in
// seconds, between local time and each distinct GitHub API endpoint
// keymint talks to. Keyed by the resolved API base URL — public
// github.com and GitHub Enterprise Server installs each have their
// own offset so a sick GHE clock cannot poison signing for other
// endpoints.
var clockOffsets sync.Map // map[string]int64

// Request describes a single token-mint operation.
type Request struct {
	// AppID is the numeric GitHub App ID.
	AppID int64

	// InstallationID is the numeric installation ID for the org/user
	// the token should act on behalf of.
	InstallationID int64

	// PrivateKey is the App's signing key. Either *rsa.PrivateKey
	// (signed with RS256) or ed25519.PrivateKey (signed with EdDSA)
	// is accepted; ParsePrivateKey returns the right concrete type
	// for whichever PEM the operator supplies. Both algorithms are
	// supported by GitHub Apps.
	PrivateKey crypto.PrivateKey

	// APIBaseURL overrides the GitHub API base URL. Empty means use
	// DefaultGitHubAPI. Use this to target GitHub Enterprise Server.
	APIBaseURL string

	// HTTPClient overrides the HTTP client used for the access_tokens
	// exchange. Empty means use http.DefaultClient. Useful for tests
	// and for callers that want to inject custom transports.
	HTTPClient *http.Client

	// OnRateLimit, if non-nil, is invoked once per successful
	// /access_tokens response with the values parsed out of the
	// X-RateLimit-Remaining and X-RateLimit-Reset headers. Allows
	// the caller (typically the service-mode entrypoint) to push
	// the values into Prometheus without coupling the mint package
	// to the metrics package.
	OnRateLimit func(apiBase string, remaining int64, resetAt time.Time)
}

// Token is a minted installation access token.
type Token struct {
	// Token is the bearer token string. Use as
	//   Authorization: token <Token>
	// against the GitHub REST API.
	Token string `json:"token"`

	// ExpiresAt is when GitHub will reject this token. Always 1h from
	// mint, but the field comes back from the API so we trust it
	// rather than computing locally.
	ExpiresAt time.Time `json:"expires_at"`
}

// ParsePrivateKey decodes a PEM-encoded GitHub App private key.
// Accepts:
//
//   - "RSA PRIVATE KEY"  (PKCS#1)         — RSA only, the legacy GitHub default
//   - "PRIVATE KEY"      (PKCS#8)         — RSA or Ed25519 (current GitHub default for Ed25519 Apps)
//   - "OPENSSH PRIVATE KEY" — explicitly rejected (unsupported by x509)
//
// Returned value is either *rsa.PrivateKey or ed25519.PrivateKey;
// signAppJWT inspects the concrete type at signing time.
func ParsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("mint: no PEM block found in input")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("mint: parse PKCS1: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("mint: parse PKCS8: %w", err)
		}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case ed25519.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("mint: PKCS8 key is %T, want *rsa.PrivateKey or ed25519.PrivateKey", key)
		}
	default:
		return nil, fmt.Errorf("mint: unsupported PEM block type %q", block.Type)
	}
}

// Mint signs a fresh App JWT and exchanges it for a 1-hour
// installation access token.
func Mint(ctx context.Context, req Request) (Token, error) {
	if req.PrivateKey == nil {
		return Token{}, errors.New("mint: PrivateKey is required")
	}
	if req.AppID == 0 {
		return Token{}, errors.New("mint: AppID is required")
	}
	if req.InstallationID == 0 {
		return Token{}, errors.New("mint: InstallationID is required")
	}

	apiBase := req.APIBaseURL
	if apiBase == "" {
		apiBase = DefaultGitHubAPI
	}

	now := time.Now().Add(loadClockOffset(apiBase))
	signed, err := signAppJWT(req.AppID, req.PrivateKey, now)
	if err != nil {
		return Token{}, err
	}

	return exchangeForInstallationToken(ctx, signed, req, apiBase)
}

// loadClockOffset returns the cached drift for apiBase, or 0 if
// none has been observed yet.
func loadClockOffset(apiBase string) time.Duration {
	v, ok := clockOffsets.Load(apiBase)
	if !ok {
		return 0
	}
	return time.Duration(v.(int64)) * time.Second
}

// storeClockOffset records the most recent drift observation for
// apiBase, scoped per-endpoint so a misconfigured GHE instance
// cannot pollute signing for unrelated endpoints.
func storeClockOffset(apiBase string, offset time.Duration) {
	clockOffsets.Store(apiBase, int64(offset.Seconds()))
}

// signAppJWT produces a JWT signed with the App's private key,
// suitable for use as a Bearer token against the
// /app/installations/... endpoints. RSA keys sign with RS256;
// Ed25519 keys sign with EdDSA. GitHub accepts both.
func signAppJWT(appID int64, key crypto.PrivateKey, now time.Time) (string, error) {
	claims := jwt.MapClaims{
		// "iat" — issued-at. Set 60s in the past to tolerate small
		// clock skew between us and GitHub.
		"iat": now.Add(-60 * time.Second).Unix(),
		// "exp" — expiry. GitHub caps this at 10min; we set 9min to
		// leave headroom.
		"exp": now.Add(jwtLifetime).Unix(),
		// "iss" — issuer. The App ID.
		"iss": appID,
	}

	var (
		method jwt.SigningMethod
		signer any
	)
	switch k := key.(type) {
	case *rsa.PrivateKey:
		method = jwt.SigningMethodRS256
		signer = k
	case ed25519.PrivateKey:
		method = jwt.SigningMethodEdDSA
		signer = k
	default:
		return "", fmt.Errorf("mint: unsupported key type %T (want *rsa.PrivateKey or ed25519.PrivateKey)", key)
	}

	token := jwt.NewWithClaims(method, claims)
	signed, err := token.SignedString(signer)
	if err != nil {
		return "", fmt.Errorf("mint: sign JWT: %w", err)
	}
	return signed, nil
}

// exchangeForInstallationToken POSTs the App JWT to the access_tokens
// endpoint and parses the resulting installation token.
//
// The HTTP round-trip is wrapped in a circuit breaker so that a
// sustained GitHub outage fails fast rather than piling up egress
// slots on stalled connections. Only infra-level failures count
// (5xx, transport errors); 4xx (e.g. 401 because the JWT/PEM is
// wrong) is an operator config bug, not GitHub being down, and is
// surfaced to the caller WITHOUT incrementing the breaker's
// failure counter.
func exchangeForInstallationToken(ctx context.Context, appJWT string, req Request, apiBase string) (Token, error) {
	res, err := breakerForAPI(apiBase).Execute(func() (exchangeResult, error) {
		return doExchangeForInstallationToken(ctx, appJWT, req, apiBase)
	})
	if err != nil {
		return Token{}, err
	}
	if res.callerErr != nil {
		// 4xx response — surfaced as an error but not counted as a
		// breaker failure.
		return Token{}, res.callerErr
	}
	return res.token, nil
}

// exchangeResult mirrors reviewResult on the server side: the inner
// callerErr is for 4xx-style problems we don't want to count
// against the breaker.
type exchangeResult struct {
	token     Token
	callerErr error
}

func doExchangeForInstallationToken(ctx context.Context, appJWT string, req Request, apiBase string) (exchangeResult, error) {
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", apiBase, req.InstallationID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return exchangeResult{}, fmt.Errorf("mint: build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+appJWT)
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := req.HTTPClient
	if client == nil {
		client = defaultHTTPClient
	}

	release, err := acquireEgress(ctx, apiBase)
	if err != nil {
		return exchangeResult{}, fmt.Errorf("mint: acquire egress slot: %w", err)
	}
	defer release()

	resp, err := client.Do(httpReq)
	if err != nil {
		return exchangeResult{}, fmt.Errorf("mint: POST access_tokens: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if dateHdr := resp.Header.Get("Date"); dateHdr != "" {
		if ghTime, err := time.Parse(time.RFC1123, dateHdr); err == nil {
			storeClockOffset(apiBase, time.Until(ghTime))
		}
	}

	if req.OnRateLimit != nil {
		remaining, _ := strconv.ParseInt(resp.Header.Get("X-RateLimit-Remaining"), 10, 64)
		resetUnix, _ := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64)
		var resetAt time.Time
		if resetUnix > 0 {
			resetAt = time.Unix(resetUnix, 0)
		}
		req.OnRateLimit(apiBase, remaining, resetAt)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return exchangeResult{}, fmt.Errorf("mint: read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		// 4xx is generally a caller-side problem (bad JWT, wrong
		// installation, suspended app) and shouldn't trip the
		// breaker. 5xx is GitHub-side. The exception is 429
		// "Too Many Requests" / secondary rate limits — keymint
		// continuing to hammer at full throttle would invite
		// harder, longer-lasting bans, so 429 is reported as an
		// infra failure that the breaker counts and opens on.
		errMsg := fmt.Errorf("mint: GitHub returned %d: %s", resp.StatusCode, string(body))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return exchangeResult{}, errMsg
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return exchangeResult{callerErr: errMsg}, nil
		}
		return exchangeResult{}, errMsg
	}

	var tok Token
	if err := json.Unmarshal(body, &tok); err != nil {
		return exchangeResult{}, fmt.Errorf("mint: parse response: %w", err)
	}
	return exchangeResult{token: tok}, nil
}
