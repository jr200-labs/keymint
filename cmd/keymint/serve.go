package main

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/logging"
	keymintMetrics "github.com/jr200-labs/keymint/internal/metrics"
	"github.com/jr200-labs/keymint/internal/mint"
	"github.com/jr200-labs/keymint/internal/server"
	"github.com/jr200-labs/keymint/internal/tracing"
	"github.com/jr200-labs/keymint/internal/version"
	"github.com/sony/gobreaker/v2"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

// keyCacheEntry remembers a parsed signing key (RSA or Ed25519)
// plus the mtime/size of the file it came from so we can detect
// operator-driven rotations of the underlying mounted Secret
// without restarting the pod.
type keyCacheEntry struct {
	key   crypto.PrivateKey
	mtime time.Time
	size  int64
}

// cachedToken is the in-memory copy of an installation token + its
// GitHub-reported expiry.
type cachedToken struct {
	Token     string
	ExpiresAt time.Time
}

// Token freshness thresholds. The 5-min cutoff bounds the staleness
// we will hand back; below that we kick off a background refresh.
// Below 1 min we block until the refresh completes — at that point
// the existing token is too close to expiry to risk handing out.
const (
	freshFor          = 5 * time.Minute
	backgroundRefresh = 1 * time.Minute

	// refreshFailureCooldown — after a background refresh fails
	// (typically because GitHub is down or the breaker is open),
	// suppress further background refreshes for this window so we
	// don't spawn a goroutine + log a warning per inbound request.
	// The next request after the cooldown re-attempts.
	refreshFailureCooldown = 15 * time.Second

	// Cache sizing. Both the parsed-key cache and the issued-token
	// cache key entries by (AppID, InstallationID, APIBaseURL,
	// PrivateKeyFile, fsnotify generation). PEM/secret rotations
	// produce stale keys with new generations; the LRU+TTL bounds
	// memory so accumulated stale entries never leak.
	keyCacheSize   = 256
	keyCacheTTL    = 24 * time.Hour
	tokenCacheSize = 1024
	tokenCacheTTL  = 70 * time.Minute // GitHub installation tokens live 1h
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

			reviewer, err := server.NewK8sTokenReviewer(cfg.ExpectedAudiences)
			if err != nil {
				return err
			}

			// Bounded caches: TTL-based eviction so PEM rotations
			// (each yields a new generation in cacheKey) don't
			// accumulate stale entries forever, and a hard size
			// cap as a defence-in-depth against unbounded key churn.
			keyCache := expirable.NewLRU[string, keyCacheEntry](keyCacheSize, nil, keyCacheTTL)
			tokenCache := expirable.NewLRU[string, cachedToken](tokenCacheSize, nil, tokenCacheTTL)
			var sf singleflight.Group
			// refreshCooldownUntil tracks the wall-clock time before
			// which a background refresh for a given cacheKey should
			// be skipped, after a previous refresh attempt failed.
			// Prevents the goroutine + log stampede described in the
			// "thundering herd against a closed circuit" failure mode.
			var refreshCooldownUntil sync.Map // cacheKey -> time.Time

			// pemGeneration is bumped whenever fsnotify reports a
			// PEM directory has changed. The hot mintFn path folds
			// the current value into its cache key so a rotation
			// invalidates cached tokens for that PEM without the
			// cost of an os.Stat on every inbound HTTP request.
			pemGenerations := pemGenerationTracker{}
			pemGenerations.start(cfg, log)

			// loadKey reads the PEM file, parses it, and caches the
			// result keyed by `cacheKey`. Honours operator-driven
			// rotation by comparing the on-disk file's mtime+size
			// against the cached version.
			loadKey := func(ctx context.Context, cacheKey string, k config.Key) (crypto.PrivateKey, error) {
				path := k.PrivateKeyFile
				if path == "" {
					return nil, fmt.Errorf("serve: key %q: private_key_file required in service mode", cacheKey)
				}
				st, err := os.Stat(path)
				if err != nil {
					return nil, fmt.Errorf("serve: stat key file %s: %w", path, err)
				}

				if cached, hit := keyCache.Get(cacheKey); hit && cached.mtime.Equal(st.ModTime()) && cached.size == st.Size() {
					return cached.key, nil
				}

				pemBytes, err := readPEM(ctx, k)
				if err != nil {
					return nil, err
				}
				priv, err := mint.ParsePrivateKey(pemBytes)
				if err != nil {
					return nil, err
				}
				keyCache.Add(cacheKey, keyCacheEntry{key: priv, mtime: st.ModTime(), size: st.Size()})
				return priv, nil
			}

			// doMint runs the full PEM-load + JWT + GitHub round-trip
			// once and caches the result. Always called under
			// singleflight so concurrent callers for the same key
			// collapse into one outbound request.
			doMint := func(ctx context.Context, cacheKey string, k config.Key) (cachedToken, error) {
				ctx, cancel := context.WithTimeout(ctx, mintTimeout)
				defer cancel()

				priv, err := loadKey(ctx, cacheKey, k)
				if err != nil {
					return cachedToken{}, err
				}
				tok, err := mint.Mint(ctx, mint.Request{
					AppID:          k.AppID,
					InstallationID: k.InstallationID,
					PrivateKey:     priv,
					APIBaseURL:     k.APIBaseURL,
					OnRateLimit: func(apiBase string, remaining int64, resetAt time.Time) {
						m.GitHubRateLimitRemaining.WithLabelValues(apiBase).Set(float64(remaining))
						if !resetAt.IsZero() {
							m.GitHubRateLimitResetUnix.WithLabelValues(apiBase).Set(float64(resetAt.Unix()))
						}
					},
				})
				if err != nil {
					return cachedToken{}, err
				}
				ct := cachedToken{Token: tok.Token, ExpiresAt: tok.ExpiresAt}
				tokenCache.Add(cacheKey, ct)
				return ct, nil
			}

			mintFn := func(ctx context.Context, k config.Key) (string, time.Time, error) {
				// Cache key MUST disambiguate every dimension that
				// could affect the minted token. AppID + InstallID
				// alone collide if two configs reuse the same
				// numeric IDs against different API endpoints or
				// different PEM files. Include APIBaseURL, PEM path,
				// and a generation counter that fsnotify increments
				// on rotation so that operator-driven Secret swaps
				// immediately invalidate cached tokens — without
				// imposing an os.Stat syscall on every inbound HTTP
				// request.
				gen := pemGenerations.current(k.PrivateKeyFile)
				cacheKey := fmt.Sprintf("%d|%d|%s|%s|%d",
					k.AppID, k.InstallationID, k.APIBaseURL,
					k.PrivateKeyFile, gen)

				ct, hasToken := tokenCache.Get(cacheKey)

				if hasToken {
					timeLeft := time.Until(ct.ExpiresAt)
					switch {
					case timeLeft > freshFor:
						// Fast path — comfortably within validity.
						return ct.Token, ct.ExpiresAt, nil

					case timeLeft > backgroundRefresh:
						// Background refresh: hand back the still-valid
						// cached token and kick off an async refresh
						// (singleflight collapses concurrent triggers).
						//
						// Skip the spawn entirely if a recent attempt
						// failed and we're still inside its cooldown —
						// otherwise an open-circuit GitHub outage
						// produces one goroutine + warning log per
						// inbound request.
						if v, ok := refreshCooldownUntil.Load(cacheKey); ok {
							if time.Now().Before(v.(time.Time)) {
								return ct.Token, ct.ExpiresAt, nil
							}
						}
						go func() {
							ctx, cancel := context.WithTimeout(context.Background(), mintTimeout)
							defer cancel()
							_, err, _ := sf.Do(cacheKey, func() (any, error) {
								return doMint(ctx, cacheKey, k)
							})
							if err != nil {
								refreshCooldownUntil.Store(cacheKey,
									time.Now().Add(refreshFailureCooldown))
								zap.L().Warn("background refresh failed",
									zap.String("cache_key", cacheKey),
									zap.Duration("cooldown", refreshFailureCooldown),
									zap.Error(err))
							} else {
								refreshCooldownUntil.Delete(cacheKey)
							}
						}()
						return ct.Token, ct.ExpiresAt, nil
					}
					// Otherwise fall through and synchronously refresh.
				}

				v, err, _ := sf.Do(cacheKey, func() (any, error) {
					// Re-check cache under singleflight — a parallel
					// caller may have just refreshed it.
					if ct, ok := tokenCache.Get(cacheKey); ok && time.Until(ct.ExpiresAt) > backgroundRefresh {
						return ct, nil
					}

					// Detach from the inbound HTTP context: singleflight
					// shares the result with all coalesced waiters, so
					// if the *first* caller disconnects, its
					// context.Canceled would otherwise propagate to
					// every other live waiter and fail their requests.
					// context.WithoutCancel preserves trace/baggage
					// values but drops Done/Err; doMint applies
					// mintTimeout internally.
					return doMint(context.WithoutCancel(ctx), cacheKey, k)
				})
				if err != nil {
					// Synchronous refresh failed (GitHub timeout, 5xx,
					// etc.). If the previously cached token has any
					// life left at all, prefer handing it back over
					// failing the request — callers can use it now
					// and the next call will retry the refresh.
					stale, hasStale := tokenCache.Get(cacheKey)
					if hasStale && time.Until(stale.ExpiresAt) > 0 {
						zap.L().Warn("synchronous refresh failed; serving previously-cached token",
							zap.String("cache_key", cacheKey),
							zap.Duration("remaining", time.Until(stale.ExpiresAt)),
							zap.Error(err))
						return stale.Token, stale.ExpiresAt, nil
					}
					return "", time.Time{}, err
				}
				ct = v.(cachedToken)
				return ct.Token, ct.ExpiresAt, nil
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
				newCfg, err := config.Load(configPath)
				if err != nil {
					log.Error("config reload failed; keeping previous config", zap.Error(err))
					return
				}
				if err := srv.Reload(newCfg); err != nil {
					log.Error("config reload validation failed; keeping previous config", zap.Error(err))
					return
				}
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

// pemGenerationTracker keeps a per-PEM-file generation counter that
// fsnotify-driven goroutines bump whenever the file's content
// changes on disk. mintFn folds the current generation into its
// cache key so a rotation immediately invalidates cached tokens —
// without paying an os.Stat per inbound HTTP request the way the
// previous mtime-on-the-hot-path implementation did.
//
// One watcher is started per distinct directory containing a
// configured PEM. The watcher uses the same parent-directory +
// "..data" filter pattern as the config watcher so kubernetes
// Secret atomic-symlink swaps are handled correctly.
type pemGenerationTracker struct {
	gens sync.Map // path (string) -> *atomic.Uint64
}

// current returns the generation counter for the given PEM path,
// creating it lazily. The hot mintFn path calls this on every
// request — it is a sync.Map.Load + atomic.Uint64.Load, no syscalls.
func (t *pemGenerationTracker) current(path string) uint64 {
	if path == "" {
		return 0
	}
	v, ok := t.gens.Load(path)
	if !ok {
		fresh := new(atomic.Uint64)
		actual, loaded := t.gens.LoadOrStore(path, fresh)
		if !loaded {
			v = fresh
		} else {
			v = actual
		}
	}
	return v.(*atomic.Uint64).Load()
}

// bump atomically increments the generation counter for path,
// allocating one if it doesn't exist yet.
func (t *pemGenerationTracker) bump(path string) {
	v, ok := t.gens.Load(path)
	if !ok {
		fresh := new(atomic.Uint64)
		actual, loaded := t.gens.LoadOrStore(path, fresh)
		if !loaded {
			v = fresh
		} else {
			v = actual
		}
	}
	v.(*atomic.Uint64).Add(1)
}

// start launches one fsnotify watcher per distinct directory that
// contains a PEM file referenced from the config. Goroutines run
// for the life of the process; restart not required for new keys
// added to the config (those would prompt a config reload, which
// in turn calls start again — start is idempotent per directory).
func (t *pemGenerationTracker) start(cfg *config.Config, log *zap.Logger) {
	dirs := map[string]map[string]struct{}{} // dir -> set(target basenames)
	for _, k := range cfg.Keys {
		if k.PrivateKeyFile == "" {
			continue
		}
		dir := filepath.Dir(k.PrivateKeyFile)
		base := filepath.Base(k.PrivateKeyFile)
		if dirs[dir] == nil {
			dirs[dir] = map[string]struct{}{}
		}
		dirs[dir][base] = struct{}{}
	}
	for dir, targets := range dirs {
		go t.watchDir(dir, targets, log)
	}
}

// watchDir runs fsnotify on dir. On Write/Create for any file in
// targets (or the kubernetes "..data" symlink) it bumps every
// matching PEM's generation counter — invalidating cached tokens
// minted against the prior content. Same parent-dir +
// debounce-the-burst pattern as watchConfigFile.
func (t *pemGenerationTracker) watchDir(dir string, targets map[string]struct{}, log *zap.Logger) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error("pem watcher init failed", zap.String("dir", dir), zap.Error(err))
		return
	}
	defer func() { _ = w.Close() }()
	if err := w.Add(dir); err != nil {
		log.Error("pem watcher add failed", zap.String("dir", dir), zap.Error(err))
		return
	}
	for {
		event, ok := <-w.Events
		if !ok {
			return
		}
		base := filepath.Base(event.Name)
		// "..data" → swap of the whole mounted Secret. Bump every
		// target in this directory.
		if base == "..data" && event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
			for tgt := range targets {
				t.bump(filepath.Join(dir, tgt))
			}
			continue
		}
		if _, isTarget := targets[base]; isTarget && event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
			t.bump(event.Name)
		}
	}
}

// pumpGitHubBreakerState publishes mint.GithubBreakerState() into
// the Prometheus gauge every few seconds. Cheap, lockless reads.
func pumpGitHubBreakerState(m *keymintMetrics.Metrics, stop <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	publish := func() {
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
