package emergency

import (
	"context"
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
