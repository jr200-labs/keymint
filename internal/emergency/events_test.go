package emergency

import (
	"context"
	"github.com/jr200-labs/keymint/internal/config"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestEventStoreReplaysAndInvalidatesSessionsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "events.db")
	store, err := openEventStore(path)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(time.Minute).UTC()
	if err := store.append(ctx, Event{Type: "session.created", SessionID: "E-1", Subject: "padd", Profile: "github-personal", Provider: "github_user", State: AwaitingGitHub, ExpiresAt: expires}); err != nil {
		t.Fatal(err)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := openEventStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.close() })
	page, err := reopened.watch(ctx, "padd", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 || page.Events[0].Type != "session.created" || page.Events[1].Type != "session.invalidated" || page.NextCursor != reopened.cursor(page.Events[1].ID) {
		t.Fatalf("events = %+v, cursor = %s", page.Events, page.NextCursor)
	}
}

func TestEventStoreWatchWakesForNewEvent(t *testing.T) {
	store, err := openEventStore("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.close() })
	result := make(chan EventPage, 1)
	go func() {
		page, _ := store.watch(context.Background(), "padd", "", time.Second)
		result <- page
	}()
	time.Sleep(10 * time.Millisecond)
	if err := store.append(context.Background(), Event{Type: "session.revoked", SessionID: "E-1", Subject: "padd", State: State("revoked"), ExpiresAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	select {
	case page := <-result:
		if len(page.Events) != 1 || page.Events[0].Type != "session.revoked" {
			t.Fatalf("events = %+v", page.Events)
		}
	case <-time.After(time.Second):
		t.Fatal("watch did not wake")
	}
}

func TestFailedActivationEventDoesNotAuthorizeSession(t *testing.T) {
	service, err := New(&config.Config{}, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	session := &Session{ID: "session", subject: "caller", State: AwaitingTOTP, ExpiresAt: time.Now().Add(time.Minute)}
	service.sessions[session.ID] = session
	_, err = service.events.db.Exec(`CREATE TRIGGER reject_activation BEFORE INSERT ON emergency_events WHEN NEW.type='session.activated' BEGIN SELECT RAISE(ABORT,'injected journal failure'); END`)
	if err != nil {
		t.Fatal(err)
	}
	service.mu.Lock()
	err = service.transitionLocked(context.Background(), session, Active, "session.activated")
	service.mu.Unlock()
	if err == nil {
		t.Fatal("journal failure ignored")
	}
	if err = service.Authorize("caller", session.ID); err == nil {
		t.Fatal("unjournaled activation authorized")
	}
}

func TestRevocationRecordsTerminalState(t *testing.T) {
	service, err := New(&config.Config{}, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	service.sessions["session"] = &Session{ID: "session", subject: "caller", State: Active, ExpiresAt: time.Now().Add(time.Minute)}
	if err = service.Revoke(context.Background(), "caller", "session"); err != nil {
		t.Fatal(err)
	}
	page, err := service.Events(context.Background(), "caller", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 1 || page.Events[0].State != Revoked {
		t.Fatalf("events=%+v", page.Events)
	}
	if err = service.events.invalidateOpenSessions(context.Background()); err != nil {
		t.Fatal(err)
	}
	page, err = service.Events(context.Background(), "caller", page.NextCursor, 0)
	if err != nil || len(page.Events) != 0 {
		t.Fatal("revoked session treated as unfinished")
	}
}
