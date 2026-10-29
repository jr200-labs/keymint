package emergency

import (
	"context"
	"github.com/jr200-labs/keymint/internal/config"
	"net/http"
	"testing"
	"time"
)

func TestTerminalStatesCannotReactivate(t *testing.T) {
	for _, from := range []State{Revoked, Expired, Invalidated} {
		for _, to := range []State{Active, RevocationPending, AwaitingGitHub, AwaitingTOTP, AwaitingPasskey} {
			if transitionAllowed(from, to) {
				t.Errorf("allowed %s -> %s", from, to)
			}
		}
	}
}

type blockingIssuer struct{ started, finish chan struct{} }

func (i *blockingIssuer) Issue(_ context.Context, _, _ string, _ time.Duration, secret string) (string, string, time.Time, error) {
	close(i.started)
	<-i.finish
	return "token", secret, time.Now().Add(time.Minute), nil
}
func (i *blockingIssuer) Revoke(context.Context, string, string) error { return nil }
func TestIssuanceDoesNotBlockOtherSessionsAndRejectsReload(t *testing.T) {
	issuer := &blockingIssuer{make(chan struct{}), make(chan struct{})}
	service, err := New(&config.Config{}, http.DefaultClient, issuer)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	profile := config.EmergencyProfile{Provider: "kubernetes", Namespace: "ops", ServiceAccount: "limited"}
	service.sessions["issuing"] = &Session{ID: "issuing", subject: "caller", profile: profile, State: Active, ExpiresAt: time.Now().Add(time.Minute)}
	service.sessions["other"] = &Session{ID: "other", subject: "caller", profile: profile, State: Active, ExpiresAt: time.Now().Add(time.Minute)}
	done := make(chan error, 1)
	go func() { _, err := service.Credential(context.Background(), "caller", "issuing"); done <- err }()
	<-issuer.started
	authorized := make(chan error, 1)
	go func() { authorized <- service.Authorize("caller", "other") }()
	select {
	case err := <-authorized:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("network I/O held registry lock")
	}
	service.Reload(&config.Config{})
	close(issuer.finish)
	if err := <-done; err == nil {
		t.Fatal("late credential returned after invalidation")
	}
}
