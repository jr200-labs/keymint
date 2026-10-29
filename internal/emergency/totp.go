package emergency

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// The budget and replay watermark belong to the underlying secret, so neither
// a new session nor another profile referencing that secret resets protection.
func (service *Service) verifyTOTPCode(secret, code string) error {
	identity := sha256.Sum256([]byte(strings.ToUpper(strings.ReplaceAll(secret, " ", ""))))
	key := hex.EncodeToString(identity[:])
	now := service.now()
	tx, err := service.events.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var started, last int64
	var attempts int
	err = tx.QueryRow(`SELECT started,attempts,last_step FROM emergency_totp WHERE identity=?`, key).Scan(&started, &attempts, &last)
	if errors.Is(err, sql.ErrNoRows) {
		started = now.Unix()
		last = -1
	} else if err != nil {
		return err
	}
	if now.Unix()-started >= 30 {
		started = now.Unix()
		attempts = 0
	}
	if attempts >= 5 {
		return errors.New("TOTP authentication is temporarily rate limited")
	}
	attempts++
	step, valid := totpStep(secret, code, now)
	accepted := valid && step > last
	if accepted {
		last = step
	}
	if _, err = tx.Exec(`INSERT INTO emergency_totp(identity,started,attempts,last_step) VALUES (?,?,?,?) ON CONFLICT(identity) DO UPDATE SET started=excluded.started,attempts=excluded.attempts,last_step=excluded.last_step`, key, started, attempts, last); err != nil {
		return err
	}
	// Only stale authentication identities are pruned; live budgets survive.
	if _, err = tx.Exec(`DELETE FROM emergency_totp WHERE started < ? AND last_step < ?`, now.Add(-24*time.Hour).Unix(), now.Unix()/30-3); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if !accepted {
		return errors.New("invalid or already used TOTP code")
	}
	return nil
}
