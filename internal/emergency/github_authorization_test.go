package emergency

import (
	"github.com/jr200-labs/keymint/internal/config"
	"testing"
	"time"
)

func TestGitHubAuthorizationRequiresOwnedActiveUserSession(t *testing.T) {
	now := time.Now()
	for _, mode := range []string{"active", "kubernetes", "expired", "revoked", "foreign", "closed", "profile_restricted", "session_restricted"} {
		t.Run(mode, func(t *testing.T) {
			session := &Session{ID: "id", subject: "caller", State: Active, ExpiresAt: now.Add(time.Minute), accessToken: "synthetic", profile: config.EmergencyProfile{Provider: "github_user", Scopes: []string{"repo", "admin:org"}, APIBaseURL: "https://github.example/api/v3"}}
			service := &Service{now: func() time.Time { return now }, sessions: map[string]*Session{"id": session}}
			switch mode {
			case "kubernetes":
				session.profile.Provider = "kubernetes"
			case "expired":
				session.ExpiresAt = now
			case "revoked":
				session.State = Revoked
			case "foreign":
				session.subject = "other"
			case "profile_restricted":
				session.profile.Scopes = []string{"repo"}
			case "session_restricted":
				session.Scopes = []string{"repo"}
			case "closed":
				service.closed = true
			}
			got, err := service.AuthorizeOrganizationSecret("caller", "id")
			if mode == "active" {
				if err != nil || got.Token != "synthetic" || got.APIBaseURL != session.profile.APIBaseURL {
					t.Fatalf("authority=%#v err=%v", got, err)
				}
			} else if err == nil {
				t.Fatal("unavailable session granted GitHub authority")
			}
		})
	}
}
