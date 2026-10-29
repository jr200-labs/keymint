// Package broker owns installation-token freshness, refresh and signing-key
// rotation behind Mint, Reload and Close. No HTTP handler or CLI owns its state.
package broker

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/logging"
	"github.com/jr200-labs/keymint/internal/metrics"
	"github.com/jr200-labs/keymint/internal/mint"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
	"maps"
	"os"
	"slices"
	"sync"
	"time"
)

const (
	freshFor         = 5 * time.Minute
	synchronousBelow = time.Minute
	cooldown         = 15 * time.Second
)

type freshness uint8

const (
	expired freshness = iota
	nearExpiry
	refreshing
	fresh
)

func freshnessOf(remaining time.Duration) freshness {
	switch {
	case remaining <= 0:
		return expired
	case remaining <= synchronousBelow:
		return nearExpiry
	case remaining <= freshFor:
		return refreshing
	default:
		return fresh
	}
}

type cachedToken struct {
	Token     string
	ExpiresAt time.Time
}
type keyCacheEntry struct {
	key   crypto.PrivateKey
	mtime time.Time
	size  int64
}
type Options struct {
	Timeout time.Duration
	Metrics *metrics.Metrics
}
type Broker struct {
	mu              sync.Mutex
	closed          bool
	active, workers sync.WaitGroup
	ctx             context.Context
	cancel          context.CancelFunc
	timeout         time.Duration
	metrics         *metrics.Metrics
	now             func() time.Time
	exchange        func(context.Context, mint.Request) (mint.Token, error)
	keys            *expirable.LRU[string, keyCacheEntry]
	tokens          *expirable.LRU[string, cachedToken]
	cooldowns       *expirable.LRU[string, time.Time]
	generations     pemGenerationTracker
	flights         singleflight.Group
	background      sync.Map
}

func New(cfg *config.Config, options Options) (*Broker, error) {
	if options.Timeout <= 0 {
		options.Timeout = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Broker{ctx: ctx, cancel: cancel, timeout: options.Timeout, metrics: options.Metrics, now: time.Now, exchange: mint.Mint,
		keys: expirable.NewLRU[string, keyCacheEntry](256, nil, 24*time.Hour), tokens: expirable.NewLRU[string, cachedToken](1024, nil, 70*time.Minute), cooldowns: expirable.NewLRU[string, time.Time](1024, nil, cooldown)}
	if err := b.Reload(cfg); err != nil {
		b.Close()
		return nil, err
	}
	return b, nil
}
func (b *Broker) Reload(cfg *config.Config) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return errors.New("token broker is closed")
	}
	for name, key := range cfg.Keys {
		if key.PrivateKeyFile == "" {
			return fmt.Errorf("service key %q requires private_key_file", name)
		}
	}
	return b.generations.reload(cfg, zap.L())
}
func (b *Broker) Close() {
	b.mu.Lock()
	b.closed = true
	b.cancel()
	b.mu.Unlock()
	b.active.Wait()
	b.workers.Wait()
	b.generations.close()
}
func (b *Broker) Mint(ctx context.Context, key config.Key, scope mint.Scope) (string, time.Time, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return "", time.Time{}, errors.New("token broker is closed")
	}
	b.active.Add(1)
	b.mu.Unlock()
	defer b.active.Done()
	scope.Repositories = slices.Clone(scope.Repositories)
	scope.Permissions = maps.Clone(scope.Permissions)
	if err := scope.Validate(); err != nil {
		return "", time.Time{}, err
	}
	encoded, _ := json.Marshal(scope)
	id := fmt.Sprintf("%d|%d|%s|%s|%d|%x", key.AppID, key.InstallationID, key.APIBaseURL, key.PrivateKeyFile, b.generations.current(key.PrivateKeyFile), sha256.Sum256(encoded))
	current, exists := b.tokens.Get(id)
	if exists {
		switch freshnessOf(current.ExpiresAt.Sub(b.now())) {
		case fresh:
			b.count("fresh")
			return current.Token, current.ExpiresAt, nil
		case refreshing:
			b.count("refreshing")
			until, waiting := b.cooldowns.Get(id)
			if !waiting || !b.now().Before(until) {
				if _, running := b.background.LoadOrStore(id, struct{}{}); !running {
					b.workers.Add(1)
					go func() {
						defer b.workers.Done()
						defer b.background.Delete(id)
						_, err := b.refresh(context.WithoutCancel(ctx), id, key, scope, true)
						if err != nil {
							b.cooldowns.Add(id, b.now().Add(cooldown))
							logging.FromContext(ctx).Warn("background token refresh failed", zap.Error(err))
						} else {
							b.cooldowns.Remove(id)
						}
					}()
				}
			}
			return current.Token, current.ExpiresAt, nil
		}
	}
	result, err := b.refresh(context.WithoutCancel(ctx), id, key, scope, false)
	if err != nil {
		if stale, ok := b.tokens.Get(id); ok && stale.ExpiresAt.After(b.now()) {
			b.count("fallback")
			logging.FromContext(ctx).Warn("token refresh failed; serving valid cached token", zap.Error(err))
			return stale.Token, stale.ExpiresAt, nil
		}
		return "", time.Time{}, err
	}
	return result.Token, result.ExpiresAt, nil
}
func (b *Broker) count(outcome string) {
	if b.metrics != nil {
		b.metrics.OperationsTotal.WithLabelValues("token_cache", outcome).Inc()
	}
}
func (b *Broker) refresh(ctx context.Context, id string, key config.Key, scope mint.Scope, force bool) (cachedToken, error) {
	value, err, _ := b.flights.Do(id, func() (any, error) {
		if !force {
			if token, ok := b.tokens.Get(id); ok && token.ExpiresAt.Sub(b.now()) > synchronousBelow {
				return token, nil
			}
		}
		return b.issue(ctx, id, key, scope)
	})
	if err != nil {
		return cachedToken{}, err
	}
	return value.(cachedToken), nil
}
func (b *Broker) issue(ctx context.Context, id string, key config.Key, scope mint.Scope) (result cachedToken, err error) {
	started := time.Now()
	defer func() { b.metrics.ObserveOperation("token_refresh", started, err) }()
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	stop := context.AfterFunc(b.ctx, cancel)
	defer stop()
	private, err := b.loadKey(id, key.PrivateKeyFile)
	if err != nil {
		return result, err
	}
	token, err := b.exchange(ctx, mint.Request{AppID: key.AppID, InstallationID: key.InstallationID, PrivateKey: private, APIBaseURL: key.APIBaseURL, Repositories: scope.Repositories, Permissions: scope.Permissions,
		OnExchange: func(base, status string, duration time.Duration) {
			if b.metrics != nil {
				b.metrics.GitHubAPILatency.WithLabelValues(status, base).Observe(duration.Seconds())
			}
		},
		OnClockOffset: func(base string, offset time.Duration) {
			if b.metrics != nil {
				b.metrics.JWTClockOffsetSeconds.WithLabelValues(base).Set(offset.Seconds())
			}
		},
		OnRateLimit: func(base string, remaining int64, reset time.Time) {
			if b.metrics != nil {
				b.metrics.GitHubRateLimitRemaining.WithLabelValues(base).Set(float64(remaining))
				if !reset.IsZero() {
					b.metrics.GitHubRateLimitResetUnix.WithLabelValues(base).Set(float64(reset.Unix()))
				}
			}
		},
	})
	if err != nil {
		return result, err
	}
	if token.Token == "" || !token.ExpiresAt.After(b.now()) {
		return result, errors.New("upstream returned an empty or expired installation token")
	}
	result = cachedToken{token.Token, token.ExpiresAt}
	b.tokens.Add(id, result)
	return result, nil
}
func (b *Broker) loadKey(id, path string) (crypto.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if cached, ok := b.keys.Get(id); ok && cached.mtime.Equal(info.ModTime()) && cached.size == info.Size() {
		return cached.key, nil
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := mint.ParsePrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	b.keys.Add(id, keyCacheEntry{key, info.ModTime(), info.Size()})
	return key, nil
}
