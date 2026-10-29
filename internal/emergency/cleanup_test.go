package emergency

import (
	"context"
	"github.com/jr200-labs/keymint/internal/config"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func cleanupClient(status *int, calls *int) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		*calls++
		return &http.Response{StatusCode: *status, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
}
func TestCleanupRecoversAfterCrashAndRetries(t *testing.T) {
	cfg := &config.Config{EmergencyStateFile: filepath.Join(t.TempDir(), "events.db")}
	status, calls := 503, 0
	client := cleanupClient(&status, &calls)
	service, err := New(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := config.EmergencyProfile{Provider: "github_user", ClientID: "client", ClientSecret: "private-secret", AllowedUserIDs: []int64{1}}
	if err = service.rememberCredential(context.Background(), "session", profile, "sensitive-token", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var sealed []byte
	if err = service.events.db.QueryRow(`SELECT sealed FROM emergency_cleanup`).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sealed), "sensitive-token") || strings.Contains(string(sealed), "private-secret") {
		t.Fatal("plaintext cleanup material persisted")
	}
	// Close storage only: simulate a process loss with no graceful revocation.
	if err = service.events.close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := New(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if calls != 1 {
		t.Fatalf("recovery attempts=%d", calls)
	}
	status = 204
	if err = recovered.Prune(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := recovered.cleanup.list(context.Background())
	if err != nil || len(records) != 0 || calls != 2 {
		t.Fatalf("records=%v calls=%d error=%v", records, calls, err)
	}
}
func TestCloseRevokesFutureCredentials(t *testing.T) {
	status, calls := 204, 0
	service, err := New(&config.Config{}, cleanupClient(&status, &calls), nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := config.EmergencyProfile{ClientID: "client", ClientSecret: "secret", AllowedUserIDs: []int64{1}}
	if err = service.rememberCredential(context.Background(), "session", profile, "token", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = service.Close(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("revocations=%d", calls)
	}
}

func TestProfileRemovalRetainsFailedCleanup(t *testing.T) {
	status, calls := 503, 0
	profile := config.EmergencyProfile{Provider: "github_user", ClientID: "original", ClientSecret: "original-secret", AllowedUserIDs: []int64{1}}
	cfg := &config.Config{EmergencyProfiles: map[string]config.EmergencyProfile{"human": profile}, Allowlist: []config.AllowEntry{{Subject: "caller", EmergencyProfiles: []string{"human"}}}}
	service, err := New(cfg, cleanupClient(&status, &calls), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	service.sessions["session"] = &Session{ID: "session", Profile: "human", subject: "caller", State: Active, ExpiresAt: time.Now().Add(time.Hour), accessToken: "token"}
	if err = service.rememberCredential(context.Background(), "session", profile, "token", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	service.Reload(&config.Config{})
	if calls != 1 {
		t.Fatalf("removal attempts=%d", calls)
	}
	if err = service.Authorize("caller", "session"); err == nil {
		t.Fatal("removed profile still authorized")
	}
	status = 204
	if err = service.Prune(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := service.cleanup.list(context.Background())
	if err != nil || len(records) != 0 || calls != 2 {
		t.Fatalf("records=%v calls=%d error=%v", records, calls, err)
	}
}
