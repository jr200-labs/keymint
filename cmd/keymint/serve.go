package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/logging"
	"github.com/jr200-labs/keymint/internal/server"
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
		configPath      string
		mintTimeout     time.Duration
		shutdownTimeout time.Duration
		logLevel        string
		logHuman        bool
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

			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}

			reviewer, err := server.NewK8sTokenReviewer()
			if err != nil {
				return err
			}

			mintFn := func(ctx context.Context, k config.Key) (string, time.Time, error) {
				ctx, cancel := context.WithTimeout(ctx, mintTimeout)
				defer cancel()
				tok, err := mintForKey(ctx, k)
				if err != nil {
					return "", time.Time{}, err
				}
				return tok.Token, tok.ExpiresAt, nil
			}

			srv, err := server.New(cfg, mintFn, reviewer)
			if err != nil {
				return err
			}

			httpServer := &http.Server{
				Addr:              listen,
				Handler:           srv.Routes(),
				ReadHeaderTimeout: 10 * time.Second,
			}

			log.Info("keymint serve starting",
				zap.String("listen", listen),
				zap.Int("keys", len(cfg.Keys)),
				zap.Int("allowlist_entries", len(cfg.Allowlist)),
			)

			err = httpServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&listen, "listen", ":9999", "HTTP listen address")
	cmd.Flags().StringVar(&configPath, "config", "/etc/keymint/config.yaml", "path to keymint config")
	cmd.Flags().DurationVar(&mintTimeout, "mint-timeout", 30*time.Second, "per-mint timeout (PEM read + JWT + GitHub round-trip)")
	cmd.Flags().DurationVar(&shutdownTimeout, "shutdown-timeout", 15*time.Second, "graceful shutdown grace period (reserved)")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log level: disabled|panic|fatal|error|warn|info|debug|trace")
	cmd.Flags().BoolVar(&logHuman, "log-human", false, "human-readable log format (default: JSON)")
	return cmd
}
