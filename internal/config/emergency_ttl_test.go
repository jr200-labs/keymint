package config

import (
	"testing"
	"time"
)

func TestValidateGitHubEmergencyProfileWithNinetyMinuteTTL(t *testing.T) {
	cfg := Config{
		Keys: map[string]Key{"routine": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/dev/null"}},
		EmergencyProfiles: map[string]EmergencyProfile{
			"github-personal": {
				Provider: "github_user", MaxTTL: "90m", ClientIDFile: "/run/github/client-id",
				ClientSecretFile: "/run/github/client-secret", AllowedUserIDsFile: "/run/github/user-id",
				Scopes: []string{"repo", "workflow", "admin:org"},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEmergencyProfileTTLLimits(t *testing.T) {
	for _, tt := range []struct {
		name, provider, maxTTL string
		want                   time.Duration
	}{
		{"github default", "github_user", "", 15 * time.Minute},
		{"github maximum", "github_user", "90m", 90 * time.Minute},
		{"github above maximum", "github_user", "91m", 0},
		{"kubernetes maximum", "kubernetes", "1h", time.Hour},
		{"kubernetes above maximum", "kubernetes", "90m", 0},
		{"approval default ceiling", "approval", "", time.Hour},
		{"approval minimum ceiling", "approval", "5m", 5 * time.Minute},
		{"approval below minimum", "approval", "4m", 0},
		{"approval above maximum", "approval", "90m", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (EmergencyProfile{Provider: tt.provider, MaxTTL: tt.maxTTL}).TTL()
			if (err != nil) != (tt.want == 0) || got != tt.want {
				t.Fatalf("TTL() = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}
