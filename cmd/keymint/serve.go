package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/logging"
	keymintMetrics "github.com/jr200-labs/keymint/internal/metrics"
	"github.com/jr200-labs/keymint/internal/mint"
	"github.com/jr200-labs/keymint/internal/server"
	"github.com/jr200-labs/keymint/internal/tracing"
	"github.com/jr200-labs/keymint/internal/version"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// newServeCmd implements `keymint serve` — the in-cluster HTTP service
// mode. Wires the keymint config to the server package, validates
// inbound bearer tokens via Kubernetes TokenReview, and mints
// installation tokens for callers in the SA allowlist.
func newServeCmd() *cobra.Command {
	var (
		listen          string
		metricsListen   string
		configPath      string
		mintTimeout     time.Duration
		shutdownTimeout time.Duration
		logLevel        string
		logHuman        bool
		certFile        string
		keyFile         string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run keymint as an HTTP service (in-cluster mode)",
		Long: `Run keymint as an HTTP server. Validates inbound requests by
calling the Kubernetes TokenReview API with the caller's bearer token
and checking the resolved ServiceAccount against the allowlist in the
keymint config. Mints an installation token and returns it as JSON.

API:

    POST /token/<key>
    Authorization: Bearer <kubernetes-sa-projected-token>
    -> 200 { "token": "ghs_...", "expires_at": "..." }
    -> 401 missing/invalid bearer
    -> 403 subject not permitted to mint <key>
    -> 500 internal error

    GET /healthz -> 200

This mode is intended to run inside a Kubernetes cluster with the
"tokenreviews.authentication.k8s.io: create" RBAC permission. App
private keys are read from filesystem paths (mounted Secret), not from
SOPS files.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			logging.Setup(logLevel, logHuman)
			log := zap.L()

			// OTel: turns on if OTEL_EXPORTER_OTLP_ENDPOINT is set, else no-op.
			tracingResult, err := tracing.Setup(context.Background(), "keymint", version.Version)
			if err != nil {
				return err
			}
			defer func() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
				defer cancel()
				if err := tracingResult.Shutdown(shutdownCtx); err != nil {
					log.Error("tracing shutdown failed", zap.Error(err))
				}
			}()

			m := keymintMetrics.New()

			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}

			reviewer, err := server.NewK8sTokenReviewer()
			if err != nil {
				return err
			}

			var cacheMu sync.RWMutex
			type cachedToken struct {
				Token     string
				ExpiresAt time.Time
			}
			keyCache := make(map[string]*rsa.PrivateKey)
			tokenCache := make(map[string]cachedToken)

			mintFn := func(ctx context.Context, k config.Key) (string, time.Time, error) {
				cacheKey := fmt.Sprintf("%d-%d", k.AppID, k.InstallationID)

				cacheMu.RLock()
				if ct, ok := tokenCache[cacheKey]; ok && time.Now().Add(5*time.Minute).Before(ct.ExpiresAt) {
					cacheMu.RUnlock()
					return ct.Token, ct.ExpiresAt, nil
				}
				privateKey := keyCache[cacheKey]
				cacheMu.RUnlock()

				ctx, cancel := context.WithTimeout(ctx, mintTimeout)
				defer cancel()

				if privateKey == nil {
					pemBytes, err := readPEM(ctx, k)
					if err != nil {
						return "", time.Time{}, err
					}
					privateKey, err = mint.ParsePrivateKey(pemBytes)
					if err != nil {
						return "", time.Time{}, err
					}
					cacheMu.Lock()
					keyCache[cacheKey] = privateKey
					cacheMu.Unlock()
				}

				tok, err := mint.Mint(ctx, mint.Request{
					AppID:          k.AppID,
					InstallationID: k.InstallationID,
					PrivateKey:     privateKey,
					APIBaseURL:     k.APIBaseURL,
				})
				if err != nil {
					return "", time.Time{}, err
				}

				cacheMu.Lock()
				tokenCache[cacheKey] = cachedToken{
					Token:     tok.Token,
					ExpiresAt: tok.ExpiresAt,
				}
				cacheMu.Unlock()

				return tok.Token, tok.ExpiresAt, nil
			}

			srv, err := server.New(cfg, mintFn, reviewer, m)
			if err != nil {
				return err
			}

			httpServer := &http.Server{
				Addr:              listen,
				Handler:           srv.Routes(),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       120 * time.Second,
			}

			// /metrics on a separate listener — keeps it off the public
			// API path and makes it easy to scope via NetworkPolicy.
			metricsMux := http.NewServeMux()
			metricsMux.Handle("GET /metrics", keymintMetrics.Handler())
			metricsServer := &http.Server{
				Addr:              metricsListen,
				Handler:           metricsMux,
				ReadHeaderTimeout: 10 * time.Second,
			}

			log.Info("keymint serve starting",
				zap.String("listen", listen),
				zap.String("metrics_listen", metricsListen),
				zap.Int("keys", len(cfg.Keys)),
				zap.Int("allowlist_entries", len(cfg.Allowlist)),
			)

			errCh := make(chan error, 2)
			go func() {
				if certFile != "" && keyFile != "" {
					log.Info("serving with TLS")
					errCh <- httpServer.ListenAndServeTLS(certFile, keyFile)
				} else {
					log.Warn("serving plaintext HTTP (no TLS config provided)")
					errCh <- httpServer.ListenAndServe()
				}
			}()
			go func() {
				errCh <- metricsServer.ListenAndServe()
			}()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

			select {
			case err := <-errCh:
				if err != nil && !errors.Is(err, http.ErrServerClosed) {
					return err
				}
			case sig := <-sigCh:
				log.Info("shutting down gracefully...", zap.String("signal", sig.String()))
				ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
				defer cancel()
				if err := httpServer.Shutdown(ctx); err != nil {
					return err
				}
				if err := metricsServer.Shutdown(ctx); err != nil {
					log.Error("metrics shutdown failed", zap.Error(err))
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&listen, "listen", ":9999", "HTTP listen address for the API")
	cmd.Flags().StringVar(&metricsListen, "metrics-listen", ":9100", "HTTP listen address for /metrics (Prometheus)")
	cmd.Flags().StringVar(&configPath, "config", "/etc/keymint/config.yaml", "path to keymint config")
	cmd.Flags().DurationVar(&mintTimeout, "mint-timeout", 30*time.Second, "per-mint timeout (PEM read + JWT + GitHub round-trip)")
	cmd.Flags().DurationVar(&shutdownTimeout, "shutdown-timeout", 15*time.Second, "graceful shutdown grace period")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log level: disabled|panic|fatal|error|warn|info|debug|trace")
	cmd.Flags().BoolVar(&logHuman, "log-human", false, "human-readable log format (default: JSON)")
	cmd.Flags().StringVar(&certFile, "tls-cert", "", "path to TLS certificate file")
	cmd.Flags().StringVar(&keyFile, "tls-key", "", "path to TLS private key file")
	return cmd
}
