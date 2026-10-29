package broker

import (
	"fmt"
	"github.com/fsnotify/fsnotify"
	"github.com/jr200-labs/keymint/internal/config"
	"go.uber.org/zap"
	"path/filepath"
	"sync"
	"sync/atomic"
)

type pemGenerationTracker struct {
	gens    sync.Map
	mu      sync.Mutex
	watcher *fsnotify.Watcher
	targets map[string]map[string]bool
	workers sync.WaitGroup
}

func (t *pemGenerationTracker) current(path string) uint64 {
	value, _ := t.gens.LoadOrStore(filepath.Clean(path), new(atomic.Uint64))
	return value.(*atomic.Uint64).Load()
}
func (t *pemGenerationTracker) bump(path string) {
	value, _ := t.gens.LoadOrStore(filepath.Clean(path), new(atomic.Uint64))
	value.(*atomic.Uint64).Add(1)
}
func (t *pemGenerationTracker) reload(cfg *config.Config, log *zap.Logger) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.watcher == nil {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return err
		}
		t.watcher = watcher
		t.workers.Add(1)
		go t.watch(watcher, log)
	}
	desired := map[string]map[string]bool{}
	for _, key := range cfg.Keys {
		if key.PrivateKeyFile == "" {
			continue
		}
		dir := filepath.Dir(key.PrivateKeyFile)
		if desired[dir] == nil {
			desired[dir] = map[string]bool{}
		}
		desired[dir][filepath.Base(key.PrivateKeyFile)] = true
	}
	var added []string
	for dir := range desired {
		if t.targets[dir] != nil {
			continue
		}
		if err := t.watcher.Add(dir); err != nil {
			for _, rollback := range added {
				_ = t.watcher.Remove(rollback)
			}
			return fmt.Errorf("watch key directory: %w", err)
		}
		added = append(added, dir)
	}
	for dir := range t.targets {
		if desired[dir] == nil {
			_ = t.watcher.Remove(dir)
		}
	}
	t.targets = desired
	for dir, targets := range desired {
		for target := range targets {
			t.bump(filepath.Join(dir, target))
		}
	}
	return nil
}
func (t *pemGenerationTracker) watch(w *fsnotify.Watcher, log *zap.Logger) {
	defer t.workers.Done()
	for {
		select {
		case event, ok := <-w.Events:
			if !ok {
				return
			}
			t.mu.Lock()
			targets := t.targets[filepath.Dir(event.Name)]
			if filepath.Base(event.Name) == "..data" || targets[filepath.Base(event.Name)] {
				for target := range targets {
					t.bump(filepath.Join(filepath.Dir(event.Name), target))
				}
			}
			t.mu.Unlock()
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			log.Error("key watcher error; invalidating cached keys", zap.Error(err))
			t.mu.Lock()
			for dir, targets := range t.targets {
				for target := range targets {
					t.bump(filepath.Join(dir, target))
				}
			}
			t.mu.Unlock()
		}
	}
}
func (t *pemGenerationTracker) close() {
	t.mu.Lock()
	w := t.watcher
	t.mu.Unlock()
	if w != nil {
		_ = w.Close()
		t.workers.Wait()
	}
}
