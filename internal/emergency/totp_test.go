package emergency

import (
	"github.com/jr200-labs/keymint/internal/config"
	"net/http"
	"testing"
	"time"
)

func TestTOTPRejectsReplayAndSharesAttemptBudget(t *testing.T) {
	service, err := New(&config.Config{}, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
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
