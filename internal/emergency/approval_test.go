package emergency

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
)

func TestApprovalRedemptionIsBoundAndOneUse(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{EmergencyStateFile: filepath.Join(t.TempDir(), "emergency.db")}
	service, err := New(cfg, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Existing passkey tests cover the ceremony. Start from its resulting
	// state to isolate the authorization and durable redemption checks.
	session := &Session{ID: "E-test", subject: "padd", Profile: "rest", Provider: "approval",
		State: AwaitingPasskey, ExpiresAt: time.Now().Add(time.Minute),
		ApprovalDigest: strings.Repeat("a", 64)}
	service.sessions[session.ID] = session
	if err := service.record(ctx, "session.created", session); err != nil {
		t.Fatal(err)
	}
	if err := service.RedeemApproval(ctx, session.subject, session.ID, session.ApprovalDigest); err == nil {
		t.Fatal("pending approval was redeemed")
	}
	if err := service.transitionLocked(ctx, session, Active, eventFor(Active)); err != nil {
		t.Fatal(err)
	}
	if err := service.Authorize(session.subject, session.ID); err == nil {
		t.Fatal("REST approval authorized release-key sealing")
	}
	if _, err := service.Credential(ctx, session.subject, session.ID); err == nil {
		t.Fatal("REST approval issued a credential")
	}
	if err := service.RedeemApproval(ctx, "other-workload", session.ID, session.ApprovalDigest); err == nil {
		t.Fatal("wrong workload redeemed approval")
	}
	if err := service.RedeemApproval(ctx, session.subject, session.ID, strings.Repeat("b", 64)); err == nil {
		t.Fatal("different request redeemed approval")
	}
	redemptions := make(chan error, 2)
	for range 2 {
		go func() {
			redemptions <- service.RedeemApproval(ctx, session.subject, session.ID, session.ApprovalDigest)
		}()
	}
	first, second := <-redemptions, <-redemptions
	if (first == nil) == (second == nil) {
		t.Fatalf("expected exactly one redemption, got %v and %v", first, second)
	}
	// Emulate an abrupt restart by closing the journal without draining it.
	if err := service.events.close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(cfg, http.DefaultClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := restarted.events.close(); err != nil {
			t.Errorf("close restarted emergency journal: %v", err)
		}
	})
	var redeemed int
	if err := restarted.events.db.QueryRow(`SELECT redeemed FROM emergency_approvals WHERE session_id = ?`, session.ID).Scan(&redeemed); err != nil || redeemed != 1 {
		t.Fatalf("durable redemption = %d, %v", redeemed, err)
	}
	if err := restarted.RedeemApproval(ctx, session.subject, session.ID, session.ApprovalDigest); err == nil {
		t.Fatal("restarted broker accepted the old grant")
	}
}
