package broker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/mint"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testBroker(t *testing.T) (*Broker, config.Key, *atomic.Int64) {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "app.pem")
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)}), 0600); err != nil {
		t.Fatal(err)
	}
	key := config.Key{AppID: 1, InstallationID: 1, PrivateKeyFile: path}
	b, err := New(&config.Config{Keys: map[string]config.Key{"app": key}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	clock := &atomic.Int64{}
	clock.Store(time.Now().UnixNano())
	b.now = func() time.Time { return time.Unix(0, clock.Load()) }
	return b, key, clock
}
func TestMintCoalescesMissesAndBoundsFallback(t *testing.T) {
	b, key, clock := testBroker(t)
	var calls atomic.Int32
	var fail atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	b.exchange = func(ctx context.Context, request mint.Request) (mint.Token, error) {
		n := calls.Add(1)
		if n == 1 {
			close(entered)
			<-release
		}
		if fail.Load() {
			return mint.Token{}, errors.New("offline")
		}
		return mint.Token{Token: fmt.Sprintf("token-%d", n), ExpiresAt: b.now().Add(time.Hour)}, nil
	}
	var workers sync.WaitGroup
	for range 20 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			token, _, err := b.Mint(context.Background(), key, mint.Scope{})
			if err != nil || token != "token-1" {
				t.Errorf("token=%s error=%v", token, err)
			}
		}()
	}
	<-entered
	close(release)
	workers.Wait()
	if calls.Load() != 1 {
		t.Fatalf("mint calls=%d", calls.Load())
	}
	scoped, _, err := b.Mint(context.Background(), key, mint.Scope{Repositories: []string{"one"}})
	if err != nil || scoped == "token-1" {
		t.Fatal("scope shared broad cached token")
	}
	fail.Store(true)
	clock.Add(int64(59*time.Minute + 30*time.Second))
	if token, _, err := b.Mint(context.Background(), key, mint.Scope{}); err != nil || token != "token-1" {
		t.Fatal("valid fallback unavailable")
	}
	clock.Add(int64(time.Minute))
	if _, _, err := b.Mint(context.Background(), key, mint.Scope{}); err == nil {
		t.Fatal("expired fallback returned")
	}
}
func TestBackgroundRefreshIsSingleAndHonorsCooldown(t *testing.T) {
	b, key, clock := testBroker(t)
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	b.exchange = func(ctx context.Context, request mint.Request) (mint.Token, error) {
		n := calls.Add(1)
		if n == 2 {
			close(entered)
			<-release
			return mint.Token{}, errors.New("offline")
		}
		return mint.Token{Token: fmt.Sprintf("token-%d", n), ExpiresAt: b.now().Add(time.Hour)}, nil
	}
	if _, _, err := b.Mint(context.Background(), key, mint.Scope{}); err != nil {
		t.Fatal(err)
	}
	clock.Add(int64(56 * time.Minute))
	for range 20 {
		if token, _, err := b.Mint(context.Background(), key, mint.Scope{}); err != nil || token != "token-1" {
			t.Fatal("refresh did not serve valid cache")
		}
	}
	<-entered
	close(release)
	b.workers.Wait()
	if _, _, err := b.Mint(context.Background(), key, mint.Scope{}); err != nil {
		t.Fatal(err)
	}
	b.workers.Wait()
	if calls.Load() != 2 {
		t.Fatal("failed refresh ignored cooldown")
	}
	clock.Add(int64(16 * time.Second))
	_, _, _ = b.Mint(context.Background(), key, mint.Scope{})
	b.workers.Wait()
	if token, _, err := b.Mint(context.Background(), key, mint.Scope{}); err != nil || token != "token-3" {
		t.Fatal("cooldown did not recover")
	}
}
func TestCloseCancelsOutstandingMint(t *testing.T) {
	b, key, _ := testBroker(t)
	entered := make(chan struct{})
	b.exchange = func(ctx context.Context, _ mint.Request) (mint.Token, error) {
		close(entered)
		<-ctx.Done()
		return mint.Token{}, ctx.Err()
	}
	done := make(chan error, 1)
	go func() { _, _, err := b.Mint(context.Background(), key, mint.Scope{}); done <- err }()
	<-entered
	b.Close()
	if err := <-done; err == nil {
		t.Fatal("shutdown did not cancel exchange")
	}
	if _, _, err := b.Mint(context.Background(), key, mint.Scope{}); err == nil {
		t.Fatal("closed broker accepted request")
	}
}
