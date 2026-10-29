package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/jr200-labs/keymint/internal/broker"
	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/emergency"
	"github.com/jr200-labs/keymint/internal/logging"
	keymintMetrics "github.com/jr200-labs/keymint/internal/metrics"
	"github.com/jr200-labs/keymint/internal/mint"
	"github.com/jr200-labs/keymint/internal/server"
	"github.com/jr200-labs/keymint/internal/tracing"
	"github.com/jr200-labs/keymint/internal/version"
	"github.com/sony/gobreaker/v2"
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

			if len(cfg.EmergencyProfiles) > 0 && cfg.EmergencyStateFile == "" {
				return errors.New("serve: emergency_state_file is required for recoverable credential revocation")
			}

			reviewer, err := server.NewK8sTokenReviewer(cfg.ExpectedAudiences)
			if err != nil {
				return err
			}

			tokens, err := broker.New(cfg, broker.Options{Timeout: mintTimeout, Metrics: m})
			if err != nil {
				return err
			}
			defer tokens.Close()

			issuer, err := emergency.NewKubernetesIssuer()
			if err != nil {
				return err
			}

			emergencyService, err := emergency.New(cfg, &http.Client{Timeout: 15 * time.Second}, issuer, m)
			if err != nil {
				return err
			}
			defer func() {
				if err := emergencyService.Close(); err != nil {
					log.Error("close emergency event state", zap.Error(err))
				}
			}()
			srv, err := server.New(cfg, tokens.Mint, reviewer, m, emergencyService)
			if err != nil {
				return err
			}

			defer srv.Stop()
			httpServer := &http.Server{
				Addr:              listen,
				Handler:           srv.Routes(),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      35 * time.Second,
				IdleTimeout:       120 * time.Second,
			}

			// /metrics on a separate listener — keeps it off the public
			// API path and makes it easy to scope via NetworkPolicy.
			// Same Slowloris-mitigating timeouts as the API server so
			// internal scrapers / scanners cannot tie up the listener.
			metricsMux := http.NewServeMux()
			metricsMux.Handle("GET /metrics", keymintMetrics.Handler())
			metricsServer := &http.Server{
				Addr:              metricsListen,
				Handler:           metricsMux,
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				WriteTimeout:      30 * time.Second,
				IdleTimeout:       120 * time.Second,
			}

			// Hot-reload: watch the config file for changes and call
			// srv.Reload on each Write. fsnotify also fires Rename
			// (which is what kubectl apply / kustomize secret-rotate
			// look like under the hood) — re-establish the watch in
			// that case.
			watcherStop := make(chan struct{})
			go watchConfigFile(configPath, watcherStop, func() {
				started := time.Now()
				outcome := "error"
				defer func() {
					m.OperationsTotal.WithLabelValues("config_reload", outcome).Inc()
					m.OperationDuration.WithLabelValues("config_reload").Observe(time.Since(started).Seconds())
				}()
				newCfg, err := config.Load(configPath)
				if err != nil {
					log.Error("config reload failed; keeping previous config", zap.Error(err))
					return
				}
				if err := srv.ValidateReload(newCfg); err != nil {
					log.Error("config reload requires restart or correction", zap.Error(err))
					return
				}
				if err := tokens.Reload(newCfg); err != nil {
					log.Error("config reload watcher reconciliation failed", zap.Error(err))
					return
				}
				if err := srv.Reload(newCfg); err != nil {
					log.Error("config reload validation failed; keeping previous config", zap.Error(err))
					return
				}
				outcome = "success"
				log.Info("config hot-reloaded",
					zap.Int("keys", len(newCfg.Keys)),
					zap.Int("allowlist_entries", len(newCfg.Allowlist)),
				)
			})
			defer close(watcherStop)

			// Pump the GitHub breaker state into a Prometheus gauge
			// so operators can alert when it opens.
			breakerStop := make(chan struct{})
			go pumpGitHubBreakerState(m, breakerStop)
			defer close(breakerStop)

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

				// Shut both servers down concurrently so the metrics
				// listener doesn't lose its grace window when the API
				// listener uses up the full deadline.
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					if err := httpServer.Shutdown(ctx); err != nil {
						log.Error("api shutdown failed", zap.Error(err))
					}
				}()
				go func() {
					defer wg.Done()
					if err := metricsServer.Shutdown(ctx); err != nil {
						log.Error("metrics shutdown failed", zap.Error(err))
					}
				}()
				wg.Wait()
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

// watchConfigFile runs an fsnotify loop on the parent directory of
// the given path, invoking onChange whenever the target file (or
// the kubernetes ConfigMap/Secret `..data` symlink) is created or
// rewritten.
//
// We watch the directory rather than the file directly because
// kubernetes mounts ConfigMaps/Secrets via an atomic symlink swap:
//
//	/etc/keymint/config.yaml -> ..data/config.yaml
//	/etc/keymint/..data      -> ..2026_04_25_03_07_00.123456789
//
// On rotation kubelet creates a new timestamped directory, atomically
// swings the ..data symlink to it, and removes the old one. A direct
// w.Add(/etc/keymint/config.yaml) would receive a Rename or Remove
// for the old inode and never see the new one (re-Add can race the
// brief window where the symlink target doesn't exist). Watching the
// parent and filtering on the target filename / ..data sidesteps the
// race entirely.
func watchConfigFile(path string, stop <-chan struct{}, onChange func()) {
	dir := filepath.Dir(path)
	target := filepath.Base(path)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		zap.L().Error("config watcher init failed", zap.Error(err))
		return
	}
	defer func() { _ = w.Close() }()

	if err := w.Add(dir); err != nil {
		zap.L().Error("config watcher add failed",
			zap.String("dir", dir), zap.Error(err))
		return
	}

	// Debounce: kubelet's ConfigMap/Secret update fires several
	// fsnotify events in rapid succession (..data symlink swap,
	// permission changes, etc.). Reset a quiet-period timer on
	// each matching event and only fire onChange once it expires
	// without further activity. Means the reload runs against the
	// fully-settled new state rather than intermediate snapshots.
	var debounce *time.Timer
	defer func() {
		if debounce != nil {
			debounce.Stop()
		}
	}()

	for {
		var debounceCh <-chan time.Time
		if debounce != nil {
			debounceCh = debounce.C
		}
		select {
		case <-stop:
			return
		case <-debounceCh:
			debounce = nil
			onChange()
		case event, ok := <-w.Events:
			if !ok {
				return
			}
			base := filepath.Base(event.Name)
			// Only react to the file we care about. ConfigMap /
			// Secret atomic-swap fires Create on ..data; an
			// in-place edit (rare in k8s, common in dev) fires
			// Write on the target.
			if base != target && base != "..data" {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}
			// (Re)arm the debounce timer.
			if debounce == nil {
				debounce = time.NewTimer(configReloadDebounce)
			} else {
				if !debounce.Stop() {
					select {
					case <-debounce.C:
					default:
					}
				}
				debounce.Reset(configReloadDebounce)
			}
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			zap.L().Warn("config watcher error", zap.Error(err))
		}
	}
}

// configReloadDebounce is the quiet period the watcher waits after
// the most recent matching fsnotify event before invoking onChange.
const configReloadDebounce = 500 * time.Millisecond

// pumpGitHubBreakerState publishes mint.GithubBreakerState() into
// the Prometheus gauge every few seconds. Cheap, lockless reads.
func pumpGitHubBreakerState(m *keymintMetrics.Metrics, stop <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	publish := func() {
		for endpoint, state := range mint.GithubBreakerStates() {
			m.GitHubEndpointBreakerState.WithLabelValues(endpoint).Set(float64(state))
		}
		switch mint.GithubBreakerState() {
		case gobreaker.StateClosed:
			m.GitHubBreakerState.Set(0)
		case gobreaker.StateHalfOpen:
			m.GitHubBreakerState.Set(1)
		case gobreaker.StateOpen:
			m.GitHubBreakerState.Set(2)
		}
	}
	publish()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			publish()
		}
	}
}
