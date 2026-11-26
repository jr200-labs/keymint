package emergency

import (
	"context"
	"fmt"
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
	defer func() { _ = service.Close() }()
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
	defer func() { _ = service.Close() }()
	service.sessions["session"] = &Session{ID: "session", subject: "caller", State: Active, ExpiresAt: time.Now().Add(time.Minute)}
	if err = service.Revoke(context.Background(), "caller", "session"); err != nil {
		t.Fatal(err)
	}
	page, err := service.Events(context.Background(), "caller", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 || page.Events[0].State != RevocationPending || page.Events[1].State != Revoked {
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

func TestPruneJournalsExpirationOnce(t *testing.T) {
	for _, failFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail_first=%t", failFirst), func(t *testing.T) {
			service, err := New(&config.Config{}, http.DefaultClient, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = service.Close() })
			ctx := context.Background()
			service.sessions["session"] = &Session{ID: "session", subject: "caller", State: Active, ExpiresAt: time.Now().Add(-time.Minute)}
			if failFirst {
				_, err = service.events.db.Exec(`CREATE TRIGGER reject_expiry BEFORE INSERT ON emergency_events
					WHEN NEW.type='session.expired' BEGIN SELECT RAISE(ABORT,'injected journal failure'); END`)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err = service.Get(ctx, "caller", "session"); (err != nil) != failFirst {
				t.Fatalf("get returned %v", err)
			}
			if failFirst {
				if _, err := service.events.db.Exec(`DROP TRIGGER reject_expiry`); err != nil {
					t.Fatal(err)
				}
			}
			if err := service.Prune(ctx); err != nil {
				t.Fatal(err)
			}
			page, err := service.Events(ctx, "caller", "", 0)
			if err != nil || len(page.Events) != 1 || page.Events[0].Type != "session.expired" {
				t.Fatalf("events=%+v error=%v", page.Events, err)
			}
			if _, err := service.Get(ctx, "caller", "session"); err == nil {
				t.Fatal("expired session survived pruning")
			}
		})
	}
}

func TestJournalRetentionKeepsLiveAndPendingCleanupHistory(t *testing.T) {
	ctx := context.Background()
	svc, err := New(&config.Config{EmergencyStateFile: filepath.Join(t.TempDir(), "events.db"), EmergencyJournalRetention: "24h"}, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.events.close() }()
	now := time.Now()
	svc.now = func() time.Time { return now }
	older := now.Add(-48 * time.Hour)
	writeEvent := func(id, kind string, state State, at time.Time) {
		t.Helper()
		if err := svc.events.append(ctx, Event{SessionID: id, Subject: "caller", Type: kind,
			State: state, OccurredAt: at, ExpiresAt: older.Add(time.Minute), ApprovalDigest: "digest"}); err != nil {
			t.Fatal(err)
		}
	}
	writeEvent("gone", "session.created", AwaitingPasskey, older)
	writeEvent("gone", "session.revoked", Revoked, older)
	writeEvent("live", "session.activated", Active, older)
	writeEvent("queued", "session.invalidated", Invalidated, older)
	if err := svc.cleanup.put(ctx, cleanupRecord{ID: "queued", Due: older}); err != nil {
		t.Fatal(err)
	}
	writeEvent("recent", "session.created", AwaitingPasskey, older)
	writeEvent("recent", "session.expired", Expired, now.Add(-time.Hour))
	if err := svc.PruneJournal(ctx); err != nil {
		t.Fatal(err)
	}
	page, err := svc.Events(ctx, "caller", svc.events.cursor(1), 0)
	if err != nil || !page.HistoryTruncated || len(page.Events) != 4 ||
		page.Events[0].SessionID != "live" || page.Events[1].SessionID != "queued" {
		t.Fatalf("unexpected retained page: %+v, error=%v", page, err)
	}
	for _, table := range []string{"emergency_session_state", "emergency_approvals", "emergency_events"} {
		var count int
		if err := svc.events.db.QueryRow("SELECT COUNT(*) FROM " + table + " WHERE session_id='gone'").Scan(&count); err != nil || count != 0 {
			t.Fatalf("gone still present in %s: %d, %v", table, count, err)
		}
	}
	after, err := svc.Events(ctx, "caller", page.NextCursor, 0)
	if err != nil || after.HistoryTruncated || len(after.Events) != 0 {
		t.Fatalf("unexpected page after retained history: %+v, error=%v", after, err)
	}
	if err := svc.PruneJournal(ctx); err != nil {
		t.Fatal(err)
	}
}
