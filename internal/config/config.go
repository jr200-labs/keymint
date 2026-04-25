// Package config loads keymint's YAML configuration from disk.
//
// The config schema is shared between CLI mode (laptop) and Service
// mode (in-cluster). Each Key entry describes one GitHub App: its
// numeric IDs, where to find the PEM (a SOPS-encrypted file on
// laptop, a Secret-mounted plaintext file in cluster), and an
// optional URL pattern used by the git credential helper to route
// `git push` requests to the right App.
//
// The Allowlist section only applies to Service mode and tells the
// HTTP server which Kubernetes ServiceAccounts may mint tokens for
// which keys. CLI mode ignores it.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

// gitURLOwnerPattern extracts the owner segment from any common git
// URL form on github.com:
//
//	https://github.com/owner/repo(.git)?
//	git@github.com:owner/repo(.git)?
//	ssh://git@github.com/owner/repo(.git)?
//
// All three put the owner directly after the host, separated by
// either `/` (HTTPS, ssh://) or `:` (SCP-style SSH).
var gitURLOwnerPattern = regexp.MustCompile(`github\.com[/:]([^/]+)/`)

// Config is the top-level configuration structure.
type Config struct {
	// Keys is the set of GitHub Apps keymint can mint tokens for,
	// indexed by a short user-chosen name (the "key" — used as the
	// positional arg to `keymint mint <key>` and as the lookup name
	// in the SA allowlist).
	Keys map[string]Key `yaml:"keys"`

	// Allowlist is consulted only in Service mode. Each entry maps a
	// Kubernetes ServiceAccount subject (`system:serviceaccount:NS:NAME`)
	// to the keys it is allowed to mint for.
	Allowlist []AllowEntry `yaml:"allowlist,omitempty"`
}

// Key describes one GitHub App.
type Key struct {
	// AppID is the numeric GitHub App ID (visible in the App
	// settings page on GitHub).
	AppID int64 `yaml:"app_id"`

	// InstallationID is the numeric installation ID for the org or
	// user the token will act on behalf of.
	InstallationID int64 `yaml:"install_id"`

	// PrivateKeyFile is the path to the App's PEM private key on
	// disk in plaintext. Used in Service mode where the PEM is
	// mounted from a Kubernetes Secret.
	PrivateKeyFile string `yaml:"private_key_file,omitempty"`

	// PrivateKeySOPS is the path to a SOPS-encrypted file containing
	// the App's PEM private key. Used in CLI mode; keymint shells out
	// to `sops -d` per call so the plaintext key never persists to
	// disk.
	PrivateKeySOPS string `yaml:"private_key_sops,omitempty"`

	// GitHubOwner is the GitHub user or organization this Key signs
	// tokens for. Used by the git credential helper to route a given
	// remote URL to the right Key by extracting the owner segment
	// from the URL and comparing exactly. Example: "whengas",
	// "jr200-labs".
	GitHubOwner string `yaml:"github_owner,omitempty"`

	// APIBaseURL overrides the GitHub REST API base URL for this Key.
	// Empty means use the public api.github.com. Set this to point at
	// GitHub Enterprise Server.
	APIBaseURL string `yaml:"api_base_url,omitempty"`
}

// AllowEntry maps a Kubernetes ServiceAccount subject to the set of
// Keys it is permitted to mint tokens for.
type AllowEntry struct {
	// Subject is the canonical k8s SA subject: system:serviceaccount:<ns>:<name>.
	Subject string `yaml:"subject"`

	// Keys is the set of Key names from the top-level Keys map that
	// this Subject is allowed to mint for.
	Keys []string `yaml:"keys"`
}

// Load reads and parses a config file from disk. If path is empty,
// looks at the default location ($XDG_CONFIG_HOME/keymint/config.yaml,
// falling back to ~/.config/keymint/config.yaml).
func Load(path string) (*Config, error) {
	if path == "" {
		var err error
		path, err = DefaultPath()
		if err != nil {
			return nil, err
		}
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(bytes, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: validate %s: %w", path, err)
	}

	return &cfg, nil
}

// DefaultPath returns the default config file path:
// $XDG_CONFIG_HOME/keymint/config.yaml, or ~/.config/keymint/config.yaml.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: determine user config dir: %w", err)
	}
	return filepath.Join(dir, "keymint", "config.yaml"), nil
}

// Validate checks that the config is internally consistent.
func (c *Config) Validate() error {
	if len(c.Keys) == 0 {
		return errors.New("no keys defined")
	}
	for name, k := range c.Keys {
		if name == "" {
			return errors.New("key name must be non-empty")
		}
		if k.AppID == 0 {
			return fmt.Errorf("key %q: app_id is required", name)
		}
		if k.InstallationID == 0 {
			return fmt.Errorf("key %q: install_id is required", name)
		}
		if k.PrivateKeyFile == "" && k.PrivateKeySOPS == "" {
			return fmt.Errorf("key %q: must set private_key_file or private_key_sops", name)
		}
	}
	for i, e := range c.Allowlist {
		if e.Subject == "" {
			return fmt.Errorf("allowlist[%d]: subject is required", i)
		}
		if len(e.Keys) == 0 {
			return fmt.Errorf("allowlist[%d]: keys is required", i)
		}
		for _, ref := range e.Keys {
			if _, ok := c.Keys[ref]; !ok {
				return fmt.Errorf("allowlist[%d]: unknown key %q (not in keys map)", i, ref)
			}
		}
	}
	return nil
}

// FindByGitHubURL returns the Key whose GitHubOwner matches the owner
// segment parsed from the given git remote URL. Returns the key name,
// the Key, and a hit flag.
//
// Used by the git credential helper to route remotes to the right
// App. Handles HTTPS and SCP-style / ssh:// URL forms.
func (c *Config) FindByGitHubURL(url string) (string, *Key, bool) {
	owner := parseGitHubOwner(url)
	if owner == "" {
		return "", nil, false
	}
	for name, k := range c.Keys {
		if k.GitHubOwner == owner {
			key := k
			return name, &key, true
		}
	}
	return "", nil, false
}

func parseGitHubOwner(url string) string {
	m := gitURLOwnerPattern.FindStringSubmatch(url)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}
