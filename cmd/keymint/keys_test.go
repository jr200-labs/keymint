package main

import (
	"github.com/jr200-labs/keymint/internal/config"
	"go.uber.org/zap"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReloadWatchesNewPEMPaths(t *testing.T) {
	tracker := &pemGenerationTracker{}
	defer tracker.close()
	if err := tracker.reload(&config.Config{}, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "app.pem")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tracker.reload(&config.Config{Keys: map[string]config.Key{"new": {PrivateKeyFile: path}}}, zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	generation := tracker.current(path)
	if err := os.WriteFile(path, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if tracker.current(path) > generation {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("newly configured key rotation was not observed")
}
