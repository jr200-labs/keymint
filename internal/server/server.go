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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
	"go.uber.org/zap"
)

// MintFunc is the contract for producing an installation token given
// a Key entry. It is injected so this package does not depend on
// internal/mint or internal/sops directly.
type MintFunc func(ctx context.Context, key config.Key) (token string, expiresAt time.Time, err error)

// Server holds wired-up HTTP server state.
type Server struct {
	cfg            *config.Config
	mint           MintFunc
	tokenReviewer  TokenReviewer
	allowedSubject map[string]map[string]bool // subject -> keys -> true
}

// TokenReviewer abstracts the k8s TokenReview call so tests can
// substitute a fake.
type TokenReviewer interface {
	Review(ctx context.Context, token string) (subject string, err error)
}

// New builds a Server. The reviewer argument is nil-friendly for
// tests; in production callers pass NewK8sTokenReviewer.
func New(cfg *config.Config, mint MintFunc, reviewer TokenReviewer) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("server: cfg is required")
	}
	if mint == nil {
		return nil, errors.New("server: mint is required")
	}
	if reviewer == nil {
		return nil, errors.New("server: reviewer is required")
	}

	allowed := make(map[string]map[string]bool, len(cfg.Allowlist))
	for _, e := range cfg.Allowlist {
		if allowed[e.Subject] == nil {
			allowed[e.Subject] = make(map[string]bool)
		}
		for _, k := range e.Keys {
			allowed[e.Subject][k] = true
		}
	}

	return &Server{
		cfg:            cfg,
		mint:           mint,
		tokenReviewer:  reviewer,
		allowedSubject: allowed,
	}, nil
}

// Routes returns an http.Handler that serves keymint's API.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token/{key}", s.handleMint)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
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
	log := zap.L().With(zap.String("key", keyName), zap.String("remote", r.RemoteAddr))

	// 1. Extract bearer token
	bearer, ok := bearerToken(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
		return
	}

	// 2. Validate via TokenReview
	subject, err := s.tokenReviewer.Review(r.Context(), bearer)
	if err != nil {
		log.Warn("tokenreview failed", zap.Error(err))
		writeJSONError(w, http.StatusUnauthorized, "tokenreview rejected the bearer token")
		return
	}
	log = log.With(zap.String("subject", subject))

	// 3. Allowlist check
	if !s.subjectMayMint(subject, keyName) {
		log.Warn("subject not permitted")
		writeJSONError(w, http.StatusForbidden, fmt.Sprintf("subject %q not permitted to mint key %q", subject, keyName))
		return
	}

	// 4. Look up key
	keyEntry, ok := s.cfg.Keys[keyName]
	if !ok {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("key %q not found", keyName))
		return
	}

	// 5. Mint
	token, expiresAt, err := s.mint(r.Context(), keyEntry)
	if err != nil {
		log.Error("mint failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "mint failed")
		return
	}
	log.Info("minted")

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(mintResponse{Token: token, ExpiresAt: expiresAt}); err != nil {
		log.Error("encode response failed", zap.Error(err))
	}
}

func (s *Server) subjectMayMint(subject, key string) bool {
	keys, ok := s.allowedSubject[subject]
	if !ok {
		return false
	}
	return keys[key]
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
	apiServer  string
	saToken    string
	httpClient *http.Client
}

// NewK8sTokenReviewer constructs a reviewer using the standard
// in-pod service account credentials. Returns an error if the pod
// is not running with a mounted service account.
func NewK8sTokenReviewer() (*K8sTokenReviewer, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("server: KUBERNETES_SERVICE_HOST/PORT not set — not running in-cluster?")
	}

	caBytes, err := os.ReadFile(saCAPath)
	if err != nil {
		return nil, fmt.Errorf("server: read CA cert: %w", err)
	}
	rootCAs := x509.NewCertPool()
	if !rootCAs.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("server: ca.crt is not a valid PEM")
	}

	saTokenBytes, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, fmt.Errorf("server: read service account token: %w", err)
	}

	return &K8sTokenReviewer{
		apiServer: fmt.Sprintf("https://%s:%s", host, port),
		saToken:   strings.TrimSpace(string(saTokenBytes)),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    rootCAs,
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}, nil
}

type tokenReviewRequest struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Spec       tokenReviewRequestSpec `json:"spec"`
}

type tokenReviewRequestSpec struct {
	Token string `json:"token"`
}

type tokenReviewResponse struct {
	Status struct {
		Authenticated bool `json:"authenticated"`
		User          struct {
			Username string `json:"username"`
		} `json:"user"`
		Error string `json:"error,omitempty"`
	} `json:"status"`
}

// Review POSTs a TokenReview to the API server and returns the
// resolved username on success.
func (r *K8sTokenReviewer) Review(ctx context.Context, token string) (string, error) {
	body, err := json.Marshal(tokenReviewRequest{
		APIVersion: "authentication.k8s.io/v1",
		Kind:       "TokenReview",
		Spec:       tokenReviewRequestSpec{Token: token},
	})
	if err != nil {
		return "", fmt.Errorf("server: marshal tokenreview: %w", err)
	}

	url := r.apiServer + "/apis/authentication.k8s.io/v1/tokenreviews"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("server: build tokenreview request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+r.saToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("server: tokenreview POST: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("server: read tokenreview response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("server: tokenreview returned %d: %s", resp.StatusCode, string(respBody))
	}

	var out tokenReviewResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", fmt.Errorf("server: parse tokenreview response: %w", err)
	}
	if !out.Status.Authenticated {
		if out.Status.Error != "" {
			return "", fmt.Errorf("server: tokenreview not authenticated: %s", out.Status.Error)
		}
		return "", errors.New("server: tokenreview not authenticated")
	}
	if out.Status.User.Username == "" {
		return "", errors.New("server: tokenreview returned empty username")
	}
	return out.Status.User.Username, nil
}
