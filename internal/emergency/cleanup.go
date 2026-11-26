package emergency

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
)

// Cleanup material is encrypted separately from the credential-free event
// stream. A record is committed before credentials can leave the broker and is
// deleted only after remote revocation succeeds. One process owns this store.
type cleanupStore struct {
	db     *sql.DB
	cipher cipher.AEAD
}
type cleanupRecord struct {
	ID      string
	Profile config.EmergencyProfile
	Token   string
	Secret  string
	Due     time.Time
}

func openCleanupStore(db *sql.DB, statePath string) (*cleanupStore, error) {
	key := make([]byte, 32)
	if statePath == "" {
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
	} else {
		path := statePath + ".cleanup-key"
		value, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			if _, err = rand.Read(key); err != nil {
				return nil, err
			}
			f, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if createErr != nil {
				return nil, createErr
			}
			_, err = f.Write(key)
			if err == nil {
				err = f.Sync()
			}
			err = errors.Join(err, f.Close())
			if err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		} else {
			key = value
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("cleanup encryption key must be accessible only to its owner")
		}
	}
	if len(key) != 32 {
		return nil, errors.New("invalid cleanup encryption key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS emergency_cleanup (session_id TEXT PRIMARY KEY, sealed BLOB NOT NULL)`); err != nil {
		return nil, err
	}
	return &cleanupStore{db: db, cipher: aead}, nil
}

type CleanupStatus struct {
	Pending     []string             `json:"pending"`
	Quarantined []QuarantinedCleanup `json:"quarantined"`
}

type QuarantinedCleanup struct {
	SessionID     string    `json:"session_id"`
	QuarantinedAt time.Time `json:"quarantined_at"`
}

// InspectCleanup reads only record metadata and does not require the encryption key.
func InspectCleanup(ctx context.Context, statePath string) (CleanupStatus, error) {
	status := CleanupStatus{Pending: []string{}, Quarantined: []QuarantinedCleanup{}}
	db, err := openExistingStateDB(statePath, "ro")
	if err != nil {
		return status, err
	}
	defer func() { _ = db.Close() }()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return status, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT session_id FROM emergency_cleanup ORDER BY session_id`)
	if err != nil {
		return status, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return status, err
		}
		status.Pending = append(status.Pending, id)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return status, err
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='emergency_cleanup_quarantine')`).Scan(&exists); err != nil || !exists {
		return status, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT session_id,quarantined_at FROM emergency_cleanup_quarantine ORDER BY id`)
	if err != nil {
		return status, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var record QuarantinedCleanup
		var timestamp int64
		if err := rows.Scan(&record.SessionID, &timestamp); err != nil {
			return status, err
		}
		record.QuarantinedAt = time.Unix(timestamp, 0).UTC()
		status.Quarantined = append(status.Quarantined, record)
	}
	return status, rows.Err()
}

func openExistingStateDB(statePath, mode string) (*sql.DB, error) {
	if statePath == "" {
		return nil, errors.New("an existing emergency state file is required")
	}
	path, err := filepath.Abs(statePath)
	if err != nil {
		return nil, err
	}
	dsn := url.URL{Scheme: "file", Path: path, RawQuery: "mode=" + mode + "&_pragma=busy_timeout(5000)"}
	return sql.Open("sqlite", dsn.String())
}

// QuarantineCleanup moves encrypted cleanup records out of the retry queue.
// The service must be stopped so it cannot repopulate records from memory.
// An empty session ID selects every outstanding record.
func QuarantineCleanup(ctx context.Context, statePath, sessionID string) (int64, error) {
	db, err := openExistingStateDB(statePath, "rw")
	if err != nil {
		return 0, err
	}
	defer func() { _ = db.Close() }()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS emergency_cleanup_quarantine (
		id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, sealed BLOB NOT NULL, quarantined_at INTEGER NOT NULL
	)`); err != nil {
		return 0, err
	}
	filter := " WHERE session_id = ?"
	args := []any{sessionID}
	if sessionID == "" {
		filter, args = "", nil
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO emergency_cleanup_quarantine(session_id,sealed,quarantined_at)
		SELECT session_id,sealed,unixepoch() FROM emergency_cleanup`+filter, args...)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if count == 0 && sessionID != "" {
		return 0, fmt.Errorf("no pending cleanup record for session %q", sessionID)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM emergency_cleanup`+filter, args...); err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

func (store *cleanupStore) put(ctx context.Context, record cleanupRecord) error {
	value, err := json.Marshal(record)
	if err != nil {
		return err
	}
	nonce := make([]byte, store.cipher.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	sealed := store.cipher.Seal(nonce, nonce, value, []byte(record.ID))
	_, err = store.db.ExecContext(ctx, `INSERT INTO emergency_cleanup(session_id,sealed) VALUES (?,?) ON CONFLICT(session_id) DO UPDATE SET sealed=excluded.sealed`, record.ID, sealed)
	return err
}
func (store *cleanupStore) remove(ctx context.Context, id string) error {
	_, err := store.db.ExecContext(ctx, `DELETE FROM emergency_cleanup WHERE session_id=?`, id)
	return err
}
func (store *cleanupStore) list(ctx context.Context) ([]cleanupRecord, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT session_id,sealed FROM emergency_cleanup`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var records []cleanupRecord
	for rows.Next() {
		var id string
		var sealed []byte
		if err = rows.Scan(&id, &sealed); err != nil {
			return nil, err
		}
		record, err := store.unseal(id, sealed)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}
func (store *cleanupStore) unseal(id string, sealed []byte) (cleanupRecord, error) {
	var record cleanupRecord
	n := store.cipher.NonceSize()
	if len(sealed) < n {
		return record, fmt.Errorf("invalid encrypted cleanup record for session %q", id)
	}
	value, err := store.cipher.Open(nil, sealed[:n], sealed[n:], []byte(id))
	if err != nil {
		return record, fmt.Errorf("decrypt cleanup record for session %q: %w", id, err)
	}
	err = json.Unmarshal(value, &record)
	return record, err
}

func (service *Service) revokeTrackedCredential(ctx context.Context, credential revokedCredential) error {
	var sealed []byte
	err := service.cleanup.db.QueryRowContext(ctx, `SELECT sealed FROM emergency_cleanup WHERE session_id=?`, credential.id).Scan(&sealed)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Some sessions revoke before issuing a tracked credential.
	case err != nil:
		return err
	default:
		record, err := service.cleanup.unseal(credential.id, sealed)
		if err != nil {
			return err
		}
		credential = revokedCredential{id: record.ID, profile: record.Profile, token: record.Token, secret: record.Secret}
	}
	return service.revokeCredential(ctx, credential)
}

func (service *Service) rememberCredential(ctx context.Context, id string, profile config.EmergencyProfile, token, secret string, due time.Time) error {
	// Materialize file-backed OAuth identity before persisting cleanup, so a
	// subsequent configuration or Secret rotation cannot retarget revocation.
	if token != "" {
		clientID, clientSecret, ids, err := githubIdentity(profile)
		if err != nil {
			return err
		}
		profile.ClientID, profile.ClientSecret, profile.AllowedUserIDs = clientID, clientSecret, ids
		profile.ClientIDFile, profile.ClientSecretFile, profile.AllowedUserIDsFile = "", "", ""
	}
	return service.cleanup.put(ctx, cleanupRecord{ID: id, Profile: profile, Token: token, Secret: secret, Due: due})
}
func (service *Service) drainCleanup(ctx context.Context, all bool) error {
	return service.drainCleanupExcept(ctx, all, nil)
}

func (service *Service) drainCleanupExcept(ctx context.Context, all bool, attempted map[string]bool) error {
	defer service.observeCleanup()
	records, err := service.cleanup.list(ctx)
	if err != nil {
		return err
	}
	var result error
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		service.mu.Lock()
		session, live := service.sessions[record.ID]
		busy := live && session.operation != idle
		pending := live && session.State == RevocationPending
		authorized := live && !terminal(session.State) && !pending
		service.mu.Unlock()
		// The live revocation path owns pending sessions so it can publish
		// the terminal event after cleanup succeeds.
		if busy || attempted[record.ID] || (!all && pending) {
			continue
		}
		if !all && authorized && record.Due.After(service.now()) {
			continue
		}
		if err := service.revokeCredential(ctx, revokedCredential{id: record.ID, profile: record.Profile, token: record.Token, secret: record.Secret}); err != nil {
			result = errors.Join(result, fmt.Errorf("cleanup session %q: %w", record.ID, err))
		}
	}
	return result
}

func (service *Service) observeCleanup() {
	if service.metrics == nil {
		return
	}
	records, err := service.cleanup.list(context.Background())
	if err != nil {
		return
	}
	due, oldest := 0, 0.0
	service.mu.Lock()
	for _, record := range records {
		session := service.sessions[record.ID]
		if session == nil || terminal(session.State) || session.State == RevocationPending || !record.Due.After(service.now()) {
			due++
			if age := service.now().Sub(record.Due).Seconds(); age > oldest {
				oldest = age
			}
		}
	}
	service.mu.Unlock()
	service.metrics.CleanupRecords.Set(float64(len(records)))
	service.metrics.CleanupDue.Set(float64(due))
	service.metrics.CleanupOldestSeconds.Set(oldest)
}
