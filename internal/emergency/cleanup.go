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
	"os"
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
		n := store.cipher.NonceSize()
		if len(sealed) < n {
			return nil, errors.New("invalid encrypted cleanup record")
		}
		value, err := store.cipher.Open(nil, sealed[:n], sealed[n:], []byte(id))
		if err != nil {
			return nil, fmt.Errorf("decrypt cleanup record: %w", err)
		}
		var record cleanupRecord
		if err = json.Unmarshal(value, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
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
		service.mu.Unlock()
		if busy {
			continue
		}
		if !all && live && !terminal(session.State) && session.State != RevocationPending && record.Due.After(service.now()) {
			continue
		}
		if err := service.revokeCredential(ctx, revokedCredential{id: record.ID, profile: record.Profile, token: record.Token, secret: record.Secret}); err != nil {
			result = errors.Join(result, err)
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
		if session == nil || !record.Due.After(service.now()) {
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
