package emergency

import (
	"github.com/jr200-labs/keymint/internal/config"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTOTPRejectsReplayAndSharesAttemptBudget(t *testing.T) {
	service, err := New(&config.Config{}, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Close() }()
	service.now = func() time.Time { return time.Unix(59, 0) }
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if err = service.verifyTOTPCode(secret, "287082"); err != nil {
		t.Fatal(err)
	}
	if err = service.verifyTOTPCode(secret, "287082"); err == nil {
		t.Fatal("replayed timestep accepted")
	}
	for range 3 {
		if err = service.verifyTOTPCode(secret, "000000"); err == nil {
			t.Fatal("invalid code accepted")
		}
	}
	if err = service.verifyTOTPCode(secret, "287082"); err == nil {
		t.Fatal("exhausted identity budget reset")
	}
	if validTOTP("", "000000", service.now()) {
		t.Fatal("empty secret accepted")
	}
}

func TestTOTPFailureLimitSurvivesShortWindowsAndRestart(t *testing.T) {
	cfg := &config.Config{EmergencyStateFile: filepath.Join(t.TempDir(), "events.db")}
	service, err := New(cfg, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := time.Unix(59-24*60*60, 0)
	now := first
	service.now = func() time.Time { return now }
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for range maxTOTPFailures {
		if err = service.verifyTOTPCode(secret, "invalid"); err == nil || err.Error() != "invalid or already used TOTP code" {
			t.Fatalf("unexpected verification result: %v", err)
		}
		now = now.Add(30 * time.Second)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	service, err = New(cfg, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	now = first.Add(totpFailureWindow - time.Second)
	service.now = func() time.Time { return now }
	if err := service.verifyTOTPCode(strings.ToLower(secret), "287082"); err == nil || err.Error() != "TOTP authentication failure limit reached" {
		t.Fatalf("persisted limit missing: %v", err)
	}
	now = first.Add(totpFailureWindow)
	if err := service.verifyTOTPCode(secret, "287082"); err != nil {
		t.Fatalf("valid code blocked after the window: %v", err)
	}
}
