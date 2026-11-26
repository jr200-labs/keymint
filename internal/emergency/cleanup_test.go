package emergency

import (
	"context"
	"errors"
	"github.com/jr200-labs/keymint/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"io"
	"net/http"
	"os"
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
	defer func() { _ = recovered.Close() }()
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
	defer func() { _ = service.Close() }()
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

type failingIssuer struct{ secret, revoked string }

func (i *failingIssuer) Issue(_ context.Context, _, _ string, _ time.Duration, secret string) (string, string, time.Time, error) {
	i.secret = secret
	return "", secret, time.Time{}, io.ErrUnexpectedEOF
}
func (i *failingIssuer) Revoke(_ context.Context, _ string, secret string) error {
	i.revoked = secret
	return nil
}
func TestPartialIssuanceRetainsCleanup(t *testing.T) {
	issuer := &failingIssuer{}
	service, err := New(&config.Config{}, http.DefaultClient, issuer)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Close() }()
	session := &Session{ID: "session", subject: "caller", State: Active, ExpiresAt: time.Now().Add(time.Hour), profile: config.EmergencyProfile{Provider: "kubernetes", Namespace: "ops", ServiceAccount: "admin"}}
	service.sessions[session.ID] = session
	if _, err = service.Credential(context.Background(), "caller", session.ID); err == nil {
		t.Fatal("failed issuance accepted")
	}
	first := issuer.secret
	if first == "" || session.boundSecret != first {
		t.Fatal("cleanup identity not reserved before issuance")
	}
	if _, err = service.Credential(context.Background(), "caller", session.ID); err == nil {
		t.Fatal("failed retry accepted")
	}
	if issuer.secret != first {
		t.Fatal("retry leaked another Secret")
	}
	if err = service.Revoke(context.Background(), "caller", session.ID); err != nil {
		t.Fatal(err)
	}
	if issuer.revoked != first {
		t.Fatal("partial Secret was not revoked")
	}
}

func TestCleanupFailureUsesConfiguredLogger(t *testing.T) {
	core, observed := observer.New(zap.ErrorLevel)
	restore := zap.ReplaceGlobals(zap.New(core))
	defer restore()
	status, calls := 503, 0
	profile := config.EmergencyProfile{Provider: "github_user", ClientID: "client", ClientSecret: "secret", AllowedUserIDs: []int64{1}}
	service, err := New(&config.Config{}, cleanupClient(&status, &calls), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = service.Close() }()
	service.sessions["session"] = &Session{ID: "session", Profile: "removed", subject: "caller", State: Active, profile: profile}
	if err = service.rememberCredential(context.Background(), "session", profile, "token", "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	service.Reload(&config.Config{})
	if observed.FilterMessage("retry credential cleanup after config reload").Len() != 1 {
		t.Fatal("cleanup error bypassed configured zap logger")
	}
}

func TestQuarantineCleanupRepairsStartupAfterKeyLoss(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{EmergencyStateFile: filepath.Join(t.TempDir(), "events.db")}
	status, calls := 204, 0
	client := cleanupClient(&status, &calls)
	service, err := New(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := config.EmergencyProfile{ClientID: "client", ClientSecret: "secret", AllowedUserIDs: []int64{1}}
	for _, id := range []string{"first", "second"} {
		if err := service.rememberCredential(ctx, id, profile, "token", "", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := service.events.close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.EmergencyStateFile + ".cleanup-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg, client, nil); err == nil || !strings.Contains(err.Error(), "decrypt cleanup record") {
		t.Fatalf("expected startup failure after key loss, got %v", err)
	}
	if count, err := QuarantineCleanup(ctx, cfg.EmergencyStateFile, "first"); err != nil || count != 1 {
		t.Fatalf("quarantine one = %d, %v", count, err)
	}
	if count, err := QuarantineCleanup(ctx, cfg.EmergencyStateFile, ""); err != nil || count != 1 {
		t.Fatalf("quarantine remaining = %d, %v", count, err)
	}
	recovered, err := New(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recovered.Close() })
	var archived int
	if err := recovered.events.db.QueryRow(`SELECT COUNT(*) FROM emergency_cleanup_quarantine`).Scan(&archived); err != nil || archived != 2 || calls != 0 {
		t.Fatalf("archived=%d revocations=%d error=%v", archived, calls, err)
	}
}

func TestCleanupStatusReadsPendingAndArchivedWithoutEncryptionKey(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "events.db")
	svc, err := New(&config.Config{EmergencyStateFile: path}, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"pending", "archived"} {
		if err := svc.cleanup.put(ctx, cleanupRecord{ID: id, Token: "hidden"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.events.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := QuarantineCleanup(ctx, path, "archived"); err != nil {
		t.Fatal(err)
	}
	keyPath := path + ".cleanup-key"
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	status, err := InspectCleanup(ctx, path)
	if err != nil || len(status.Pending) != 1 || status.Pending[0] != "pending" ||
		len(status.Quarantined) != 1 || status.Quarantined[0].SessionID != "archived" || status.Quarantined[0].QuarantinedAt.IsZero() {
		t.Fatalf("unexpected status: %+v, error=%v", status, err)
	}
	if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspection changed key file: %v", err)
	}
}

func TestFailedGitHubActivationKeepsCleanupDueWithOriginalIdentity(t *testing.T) {
	ctx := context.Background()
	secretFile := filepath.Join(t.TempDir(), "oauth-secret")
	if err := os.WriteFile(secretFile, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{EmergencyProfiles: map[string]config.EmergencyProfile{"operator": {
		Provider: "github_user", ClientID: "app", ClientSecretFile: secretFile, AllowedUserIDs: []int64{42},
	}}, Allowlist: []config.AllowEntry{{Subject: "caller", EmergencyProfiles: []string{"operator"}}}}
	revocations := 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		status, body := 200, ""
		switch r.URL.Path {
		case "/login/device/code":
			body = `{"device_code":"code","user_code":"user","verification_uri":"https://github.com/login/device"}`
		case "/login/oauth/access_token":
			body = `{"access_token":"token"}`
		case "/user":
			if err := os.WriteFile(secretFile, []byte("rotated"), 0600); err != nil {
				return nil, err
			}
			body = `{"id":42}`
		case "/applications/app/token":
			revocations++
			if _, secret, _ := r.BasicAuth(); secret != "original" {
				t.Error("revocation used the rotated OAuth secret")
			}
			status = http.StatusServiceUnavailable
			if revocations > 1 {
				status = http.StatusNotFound
			}
		default:
			t.Errorf("unexpected upstream request to %q", r.URL.Path)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	svc, err := New(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	session, err := svc.Create(ctx, "caller", "operator", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.events.db.Exec(`CREATE TRIGGER reject_activation BEFORE INSERT ON emergency_events
		WHEN NEW.type='session.activated' BEGIN SELECT RAISE(ABORT,'injected journal failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, "caller", session.ID); err == nil || revocations != 1 {
		t.Fatalf("failed activation = %v, revocation attempts = %d", err, revocations)
	}
	record, err := svc.cleanup.get(ctx, session.ID)
	if err != nil || record.Due.After(svc.now()) || record.Profile.ClientSecret != "original" {
		t.Fatalf("cleanup identity or due time changed: due=%v err=%v", record.Due, err)
	}
	if err := svc.Prune(ctx); err != nil || revocations != 2 {
		t.Fatalf("immediately due cleanup retry = %v, attempts = %d", err, revocations)
	}
	records, err := svc.cleanup.list(ctx)
	if err != nil || len(records) != 0 {
		t.Fatalf("upstream 404 left a tracked record: count=%d err=%v", len(records), err)
	}
}

type testCleanupIssuer struct {
	issue  func()
	revoke func() error
}

func (i testCleanupIssuer) Issue(_ context.Context, _, _ string, _ time.Duration, secret string) (string, string, time.Time, error) {
	if i.issue != nil {
		i.issue()
	}
	return "cluster-token", secret, time.Now().Add(time.Minute), nil
}

func (i testCleanupIssuer) Revoke(context.Context, string, string) error {
	return i.revoke()
}

func TestCredentialCleanupAfterMidIssuanceExpiryClearsSession(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	secretFile := filepath.Join(t.TempDir(), "oauth-secret")
	if err := os.WriteFile(secretFile, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	profile := config.EmergencyProfile{Provider: "kubernetes", Namespace: "ops", ServiceAccount: "admin",
		ClientID: "app", ClientSecretFile: secretFile, AllowedUserIDs: []int64{42}}
	githubRevokes, kubeRevokes := 0, 0
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		githubRevokes++
		if _, secret, _ := r.BasicAuth(); secret != "original" {
			t.Error("expiry cleanup used the rotated OAuth identity")
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
	})}
	issuer := testCleanupIssuer{
		issue: func() { now = now.Add(2 * time.Minute) },
		revoke: func() error {
			kubeRevokes++
			return nil
		},
	}
	svc, err := New(&config.Config{}, client, issuer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	svc.now = func() time.Time { return now }
	session := &Session{ID: "id", subject: "caller", profile: profile, State: Active, accessToken: "token", ExpiresAt: now.Add(time.Minute)}
	svc.sessions[session.ID] = session
	if err := svc.rememberCredential(ctx, session.ID, profile, session.accessToken, "", session.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte("rotated"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Credential(ctx, "caller", session.ID); err == nil || !strings.Contains(err.Error(), "session changed") {
		t.Fatalf("issuance should fail after expiry: %v", err)
	}
	if session.accessToken != "" || session.boundSecret != "" {
		t.Fatal("successfully revoked credentials still in session")
	}
	if err := svc.Prune(ctx); err != nil || githubRevokes != 1 || kubeRevokes != 1 {
		t.Fatalf("unexpected cleanup: GitHub=%d Kubernetes=%d err=%v", githubRevokes, kubeRevokes, err)
	}
}

func TestCleanupRestartPreservesOverdueAge(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{EmergencyStateFile: filepath.Join(t.TempDir(), "events.db")}
	status, calls := 503, 0
	client := cleanupClient(&status, &calls)
	svc, err := New(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	overdue := time.Now().Add(-time.Hour)
	profile := config.EmergencyProfile{ClientID: "client", ClientSecret: "secret", AllowedUserIDs: []int64{1}}
	if err := svc.rememberCredential(ctx, "overdue", profile, "token", "", overdue); err != nil {
		t.Fatal(err)
	}
	if err := svc.events.close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := New(cfg, client, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recovered.Close() })
	record, err := recovered.cleanup.get(ctx, "overdue")
	if err != nil || !record.Due.Equal(overdue) || calls != 1 {
		t.Fatalf("overdue cleanup changed across restart: due=%v calls=%d err=%v", record.Due, calls, err)
	}
}

func TestCleanupRetriesKubernetesAfterGitHubAlreadyRevoked(t *testing.T) {
	ctx := context.Background()
	githubRevokes, kubeRevokes := 0, 0
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		githubRevokes++
		status := http.StatusNoContent
		if githubRevokes > 1 {
			status = http.StatusNotFound
		}
		return &http.Response{StatusCode: status, Body: http.NoBody}, nil
	})}
	issuer := testCleanupIssuer{revoke: func() error {
		kubeRevokes++
		if kubeRevokes == 1 {
			return errors.New("Kubernetes temporarily unavailable")
		}
		return nil
	}}
	svc, err := New(&config.Config{}, client, issuer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	profile := config.EmergencyProfile{Provider: "kubernetes", ClientID: "client", ClientSecret: "secret", AllowedUserIDs: []int64{42}}
	session := &Session{ID: "id", subject: "caller", profile: profile, State: Active, accessToken: "token", boundSecret: "bound", ExpiresAt: time.Now().Add(time.Minute)}
	svc.sessions[session.ID] = session
	if err := svc.rememberCredential(ctx, session.ID, profile, session.accessToken, session.boundSecret, session.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := svc.Revoke(ctx, "caller", session.ID); !errors.Is(err, ErrRevocationPending) {
		t.Fatalf("first revoke = %v", err)
	}
	if err := svc.Prune(ctx); err != nil || githubRevokes != 2 || kubeRevokes != 2 {
		t.Fatalf("prune = %v, GitHub attempts=%d, Kubernetes attempts=%d", err, githubRevokes, kubeRevokes)
	}
	page, err := svc.Events(ctx, "caller", "", 0)
	if err != nil || len(page.Events) != 2 || page.Events[1].Type != "session.revoked" {
		t.Fatalf("revocation not confirmed: events=%+v err=%v", page.Events, err)
	}
}
