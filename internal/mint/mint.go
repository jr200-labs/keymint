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
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

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

	// PrivateKey is the App's RSA private key. Callers parse this from
	// PEM via ParsePrivateKey before calling Mint.
	PrivateKey *rsa.PrivateKey

	// APIBaseURL overrides the GitHub API base URL. Empty means use
	// DefaultGitHubAPI. Use this to target GitHub Enterprise Server.
	APIBaseURL string

	// HTTPClient overrides the HTTP client used for the access_tokens
	// exchange. Empty means use http.DefaultClient. Useful for tests
	// and for callers that want to inject custom transports.
	HTTPClient *http.Client
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

// ParsePrivateKey decodes a PEM-encoded RSA private key. Accepts both
// PKCS1 ("RSA PRIVATE KEY") and PKCS8 ("PRIVATE KEY") encodings —
// GitHub hands out PKCS1 by default but the field is wider in
// practice.
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
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
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("mint: PKCS8 key is %T, not RSA", key)
		}
		return rsaKey, nil
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

// signAppJWT produces a JWT signed with the App's private key, suitable
// for use as a Bearer token against the /app/installations/... endpoints.
func signAppJWT(appID int64, key *rsa.PrivateKey, now time.Time) (string, error) {
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

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("mint: sign JWT: %w", err)
	}
	return signed, nil
}

// exchangeForInstallationToken POSTs the App JWT to the access_tokens
// endpoint and parses the resulting installation token.
func exchangeForInstallationToken(ctx context.Context, appJWT string, req Request, apiBase string) (Token, error) {
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", apiBase, req.InstallationID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return Token{}, fmt.Errorf("mint: build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+appJWT)
	httpReq.Header.Set("Accept", "application/vnd.github+json")
	httpReq.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := req.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return Token{}, fmt.Errorf("mint: POST access_tokens: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if dateHdr := resp.Header.Get("Date"); dateHdr != "" {
		if ghTime, err := time.Parse(time.RFC1123, dateHdr); err == nil {
			storeClockOffset(apiBase, time.Until(ghTime))
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Token{}, fmt.Errorf("mint: read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return Token{}, fmt.Errorf("mint: GitHub returned %d: %s", resp.StatusCode, string(body))
	}

	var tok Token
	if err := json.Unmarshal(body, &tok); err != nil {
		return Token{}, fmt.Errorf("mint: parse response: %w", err)
	}
	return tok, nil
}
