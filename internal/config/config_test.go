package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeYAML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoad_HappyPath(t *testing.T) {
	path := writeYAML(t, `
keys:
  whengas:
    app_id: 12345
    install_id: 67890
    private_key_sops: /home/me/.config/keymint/whengas.sops.pem
    github_owner: whengas
  org-b:
    app_id: 99999
    install_id: 11111
    private_key_file: /etc/keymint/keys/org-b
allowlist:
  - subject: system:serviceaccount:nclaw:nclaw-runner
    keys: [whengas, org-b]
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(cfg.Keys); got != 2 {
		t.Errorf("len(Keys) = %d, want 2", got)
	}
	if cfg.Keys["whengas"].AppID != 12345 {
		t.Errorf("whengas AppID = %d, want 12345", cfg.Keys["whengas"].AppID)
	}
	if len(cfg.Allowlist) != 1 {
		t.Errorf("len(Allowlist) = %d, want 1", len(cfg.Allowlist))
	}
}

func TestLoad_RejectsEmptyKeys(t *testing.T) {
	path := writeYAML(t, "keys: {}\n")
	if _, err := Load(path); err == nil {
		t.Errorf("expected error on empty keys")
	}
}

func TestLoad_RejectsMissingAppID(t *testing.T) {
	path := writeYAML(t, `
keys:
  whengas:
    install_id: 67890
    private_key_sops: /tmp/whengas.sops.pem
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "app_id") {
		t.Errorf("expected app_id error, got %v", err)
	}
}

func TestLoad_RejectsMissingInstallID(t *testing.T) {
	path := writeYAML(t, `
keys:
  whengas:
    app_id: 12345
    private_key_sops: /tmp/whengas.sops.pem
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "install_id") {
		t.Errorf("expected install_id error, got %v", err)
	}
}

func TestLoad_RejectsNoKeySource(t *testing.T) {
	path := writeYAML(t, `
keys:
  whengas:
    app_id: 12345
    install_id: 67890
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "private_key") {
		t.Errorf("expected private_key error, got %v", err)
	}
}

func TestLoad_RejectsAllowlistUnknownKey(t *testing.T) {
	path := writeYAML(t, `
keys:
  whengas:
    app_id: 12345
    install_id: 67890
    private_key_sops: /tmp/whengas.sops.pem
allowlist:
  - subject: system:serviceaccount:nclaw:nclaw-runner
    keys: [whengas, ghost]
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Errorf("expected unknown-key error, got %v", err)
	}
}

func TestFindByGitHubURL(t *testing.T) {
	cfg := &Config{
		Keys: map[string]Key{
			"whengas":    {GitHubOwner: "whengas"},
			"jr200-labs": {GitHubOwner: "jr200-labs"},
			"no-match":   {},
		},
	}
	cases := []struct {
		url      string
		wantName string
		wantHit  bool
	}{
		{"https://github.com/whengas/whengas-iac.git", "whengas", true},
		{"git@github.com:jr200-labs/keymint.git", "jr200-labs", true},
		{"ssh://git@github.com/whengas/whengas-api.git", "whengas", true},
		{"https://gitlab.com/whengas/whengas-iac.git", "", false},
		{"https://github.com/strangerorg/repo.git", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			name, _, ok := cfg.FindByGitHubURL(tc.url)
			if ok != tc.wantHit {
				t.Errorf("ok = %v, want %v", ok, tc.wantHit)
			}
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
		})
	}
}

func TestDefaultPath(t *testing.T) {
	got, err := DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath: %v", err)
	}
	if !strings.Contains(got, "keymint") {
		t.Errorf("path %q should contain 'keymint'", got)
	}
	if !strings.HasSuffix(got, "config.yaml") {
		t.Errorf("path %q should end with config.yaml", got)
	}
}
