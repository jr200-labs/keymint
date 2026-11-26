package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/fsnotify/fsnotify"
)

func TestServiceConfigRequiresRecoverableEmergencyStorage(t *testing.T) {
	base := "expected_audiences: [keymint]\nkeys:\n  app:\n    app_id: 1\n    install_id: 2\n    private_key_file: /run/key.pem\n"
	emergency := "emergency_profiles:\n  ops:\n    provider: kubernetes\n    namespace: ops\n    service_account: admin\n    totp_secret_file: /run/totp\n"
	for _, tc := range []struct {
		name, yaml string
		valid      bool
	}{{"routine", base, true}, {"missing cleanup", base + emergency, false}, {"durable", base + emergency + "emergency_state_file: /data/events.db\n", true}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := loadServiceConfig(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}

func TestConfigWatcherDebouncesOnlyMatchingEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		events := make(chan fsnotify.Event)
		stop := make(chan struct{})
		done := make(chan struct{})
		var reloads atomic.Int32
		go func() {
			defer close(done)
			watchConfigEvents("config.yaml", events, nil, stop, func() { reloads.Add(1) })
		}()
		defer func() { close(stop); <-done }()
		send := func(name string, op fsnotify.Op) {
			events <- fsnotify.Event{Name: name, Op: op}
			synctest.Wait()
		}
		send("unrelated", fsnotify.Write)
		send("config.yaml", fsnotify.Chmod)
		time.Sleep(configReloadDebounce)
		synctest.Wait()
		if got := reloads.Load(); got != 0 {
			t.Fatalf("unrelated events reloaded %d times", got)
		}
		send("config.yaml", fsnotify.Write)
		time.Sleep(configReloadDebounce / 2)
		send("..data", fsnotify.Create)
		time.Sleep(configReloadDebounce / 2)
		synctest.Wait()
		if reloads.Load() != 0 {
			t.Fatal("reloaded before the final event settled")
		}
		time.Sleep(configReloadDebounce)
		synctest.Wait()
		if got := reloads.Load(); got != 1 {
			t.Fatalf("burst reloaded %d times, want 1", got)
		}
		send("config.yaml", fsnotify.Create)
		time.Sleep(configReloadDebounce)
		synctest.Wait()
		if got := reloads.Load(); got != 2 {
			t.Fatalf("separate update reloaded %d times, want 2", got)
		}
	})
}

func TestListenerStartupFailureStopsSiblingBeforeReturn(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	api := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	defer func() { _ = api.Close() }()
	metrics := &http.Server{Addr: listener.Addr().String()}
	defer func() { _ = metrics.Close() }()
	errs := make(chan error, 2)
	go func() { errs <- api.Serve(listener) }()
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	go func() { errs <- metrics.ListenAndServe() }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := awaitHTTPShutdown(ctx, errs, time.Second, api, metrics); err == nil {
		t.Fatal("expected the metrics bind error")
	}
	select {
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("unexpected API shutdown error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("API listener outlived startup error")
	}
}
