package emergency

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// The budget and replay watermark belong to the underlying secret, so neither
// a new session nor another profile referencing that secret resets protection.
const (
	totpFailureWindow = 24 * time.Hour
	maxTOTPFailures   = 10
)

func (service *Service) verifyTOTPCode(secret, code string) (result error) {
	defer func(start time.Time) {
		service.metrics.ObserveOperation("totp_verify", start, result)
	}(time.Now())
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	decoded, err := encoding.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil || len(decoded) < 16 {
		return errors.New("invalid TOTP secret")
	}
	secret = encoding.EncodeToString(decoded)
	identity := sha256.Sum256([]byte(secret))
	key := hex.EncodeToString(identity[:])
	now := service.now()
	tx, err := service.events.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var failureStarted int64
	var failures int
	cutoff := now.Add(-totpFailureWindow).Unix()
	err = tx.QueryRow(`SELECT started,failures FROM emergency_totp_failures WHERE identity=?`, key).Scan(&failureStarted, &failures)
	switch {
	case errors.Is(err, sql.ErrNoRows), err == nil && failureStarted <= cutoff:
		failureStarted, failures = now.Unix(), 0
	case err != nil:
		return err
	}
	if failures >= maxTOTPFailures {
		return errors.New("TOTP authentication failure limit reached")
	}
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
	} else {
		if _, err = tx.Exec(`INSERT INTO emergency_totp_failures(identity,started,failures) VALUES (?,?,?) ON CONFLICT(identity) DO UPDATE SET started=excluded.started,failures=excluded.failures`, key, failureStarted, failures+1); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(`INSERT INTO emergency_totp(identity,started,attempts,last_step) VALUES (?,?,?,?) ON CONFLICT(identity) DO UPDATE SET started=excluded.started,attempts=excluded.attempts,last_step=excluded.last_step`, key, started, attempts, last); err != nil {
		return err
	}
	// Only stale authentication identities are pruned; live budgets survive.
	if _, err = tx.Exec(`DELETE FROM emergency_totp WHERE started < ? AND last_step < ?`, now.Add(-24*time.Hour).Unix(), now.Unix()/30-3); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM emergency_totp_failures WHERE started <= ?`, cutoff); err != nil {
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
