package emergency

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const maxEventPage = 100

type Event struct {
	ID         int64     `json:"id"`
	Type       string    `json:"type"`
	SessionID  string    `json:"session_id"`
	Profile    string    `json:"profile"`
	Provider   string    `json:"provider"`
	State      State     `json:"state"`
	ExpiresAt  time.Time `json:"expires_at"`
	OccurredAt time.Time `json:"occurred_at"`
	Subject    string    `json:"-"`
}

type EventPage struct {
	Events     []Event `json:"events"`
	NextCursor string  `json:"next_cursor"`
}

type eventStore struct {
	db     *sql.DB
	mu     sync.Mutex
	notify chan struct{}
	stream string
}

func openEventStore(path string) (*eventStore, error) {
	dsn := ":memory:"
	if path == "" {
		// Unit tests and emergency-disabled configurations need no durable file.
	} else if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create emergency event state directory: %w", err)
	} else {
		dsn = path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open emergency event state: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &eventStore{db: db, notify: make(chan struct{})}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS emergency_session_state (
session_id TEXT PRIMARY KEY, subject TEXT NOT NULL, profile TEXT NOT NULL,
provider TEXT NOT NULL, state TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS emergency_events (
id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT NOT NULL, type TEXT NOT NULL,
session_id TEXT NOT NULL, profile TEXT NOT NULL, provider TEXT NOT NULL,
state TEXT NOT NULL, expires_at INTEGER NOT NULL, occurred_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS emergency_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS emergency_events_subject_id ON emergency_events(subject, id);`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate emergency event state: %w", err)
	}
	if err := db.QueryRow(`SELECT value FROM emergency_metadata WHERE key = 'stream_id'`).Scan(&store.stream); errors.Is(err, sql.ErrNoRows) {
		value := make([]byte, 16)
		if _, err := rand.Read(value); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("create emergency event stream ID: %w", err)
		}
		store.stream = hex.EncodeToString(value)
		if _, err := db.Exec(`INSERT INTO emergency_metadata(key, value) VALUES ('stream_id', ?)`, store.stream); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("persist emergency event stream ID: %w", err)
		}
	} else if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read emergency event stream ID: %w", err)
	}
	if err := store.invalidateOpenSessions(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (store *eventStore) close() error { return store.db.Close() }

func (store *eventStore) append(ctx context.Context, event Event) error {
	if event.SessionID == "" || event.Subject == "" || event.Type == "" {
		return errors.New("emergency event type, subject, and session are required")
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `INSERT INTO emergency_events
(subject, type, session_id, profile, provider, state, expires_at, occurred_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, event.Subject, event.Type, event.SessionID, event.Profile, event.Provider, event.State, event.ExpiresAt.UnixMilli(), event.OccurredAt.UnixMilli()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO emergency_session_state
(session_id, subject, profile, provider, state, expires_at) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(session_id) DO UPDATE SET state = excluded.state, expires_at = excluded.expires_at`,
		event.SessionID, event.Subject, event.Profile, event.Provider, event.State, event.ExpiresAt.UnixMilli()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	store.signal()
	return nil
}

func (store *eventStore) watch(ctx context.Context, subject, after string, wait time.Duration) (EventPage, error) {
	if wait < 0 {
		wait = 0
	}
	if wait > 30*time.Second {
		wait = 30 * time.Second
	}
	store.mu.Lock()
	notify := store.notify
	store.mu.Unlock()
	afterID := store.parseCursor(after)
	page, err := store.list(ctx, subject, afterID)
	if err != nil || len(page.Events) != 0 || wait == 0 {
		return page, err
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return EventPage{}, ctx.Err()
	case <-timer.C:
	case <-notify:
	}
	return store.list(ctx, subject, afterID)
}

func (store *eventStore) list(ctx context.Context, subject string, after int64) (EventPage, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT id, type, session_id, profile, provider, state, expires_at, occurred_at
FROM emergency_events WHERE subject = ? AND id > ? ORDER BY id LIMIT ?`, subject, after, maxEventPage)
	if err != nil {
		return EventPage{}, err
	}
	defer func() { _ = rows.Close() }()
	page := EventPage{Events: []Event{}, NextCursor: store.cursor(after)}
	for rows.Next() {
		var event Event
		var expiresAt, occurredAt int64
		if err := rows.Scan(&event.ID, &event.Type, &event.SessionID, &event.Profile, &event.Provider, &event.State, &expiresAt, &occurredAt); err != nil {
			return EventPage{}, err
		}
		event.ExpiresAt = time.UnixMilli(expiresAt).UTC()
		event.OccurredAt = time.UnixMilli(occurredAt).UTC()
		page.Events = append(page.Events, event)
		page.NextCursor = store.cursor(event.ID)
	}
	return page, rows.Err()
}

func (store *eventStore) cursor(id int64) string {
	return store.stream + ":" + strconv.FormatInt(id, 10)
}

func (store *eventStore) parseCursor(cursor string) int64 {
	stream, value, ok := strings.Cut(cursor, ":")
	if !ok || stream != store.stream {
		return 0
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id < 0 {
		return 0
	}
	return id
}

func (store *eventStore) invalidateOpenSessions(ctx context.Context) error {
	rows, err := store.db.QueryContext(ctx, `SELECT session_id, subject, profile, provider, expires_at
FROM emergency_session_state WHERE state NOT IN ('expired', 'revoked', 'invalidated')`)
	if err != nil {
		return err
	}
	var events []Event
	for rows.Next() {
		var event Event
		var expiresAt int64
		if err := rows.Scan(&event.SessionID, &event.Subject, &event.Profile, &event.Provider, &expiresAt); err != nil {
			_ = rows.Close()
			return err
		}
		event.Type, event.State = "session.invalidated", Invalidated
		event.ExpiresAt, event.OccurredAt = time.UnixMilli(expiresAt).UTC(), time.Now().UTC()
		events = append(events, event)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, event := range events {
		if err := store.append(ctx, event); err != nil {
			return fmt.Errorf("invalidate restored emergency session: %w", err)
		}
	}
	return nil
}

func (store *eventStore) signal() {
	store.mu.Lock()
	close(store.notify)
	store.notify = make(chan struct{})
	store.mu.Unlock()
}
