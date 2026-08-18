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
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

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

	// ExpectedAudiences is the list of audiences keymint will require
	// inbound projected ServiceAccount tokens to have been bound to.
	// Forwarded into TokenReview Spec.Audiences so a stolen token
	// scoped to a different audience (vault, another service, etc.)
	// cannot be replayed against keymint. Service mode only; CLI mode
	// ignores it.
	ExpectedAudiences []string `yaml:"expected_audiences,omitempty"`

	// TrustedProxies is the list of CIDR blocks (e.g. "10.0.0.0/8",
	// "192.168.1.5/32") whose direct connections are allowed to set
	// X-Forwarded-For / X-Real-IP. When the immediate peer address
	// is in one of these blocks, keymint walks the XFF chain to
	// recover the real client IP for per-IP rate limiting. Without
	// this, an Ingress controller / API gateway / mesh sidecar
	// fronting keymint causes every cluster client to share the
	// proxy's IP and trip the pre-auth limiter together.
	//
	// Empty (the default) disables proxy-header trust: r.RemoteAddr
	// is used as-is. Set this only to your real load-balancer
	// CIDRs; trusting too widely allows clients to spoof their IP.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`

	// EmergencyProfiles are short-lived, human-authenticated credentials.
	// They are separate from installation Keys because they represent an
	// explicitly activated operator identity, not routine workload identity.
	EmergencyProfiles map[string]EmergencyProfile `yaml:"emergency_profiles,omitempty"`
}

// EmergencyProfile describes one credential source activated by a human.
type EmergencyProfile struct {
	Provider string `yaml:"provider"`
	MaxTTL   string `yaml:"max_ttl,omitempty"`

	// GitHub OAuth App device flow.
	ClientID           string   `yaml:"client_id,omitempty"`
	ClientIDFile       string   `yaml:"client_id_file,omitempty"`
	ClientSecret       string   `yaml:"client_secret,omitempty"`
	ClientSecretFile   string   `yaml:"client_secret_file,omitempty"`
	AllowedUserIDs     []int64  `yaml:"allowed_user_ids,omitempty"`
	AllowedUserIDsFile string   `yaml:"allowed_user_ids_file,omitempty"`
	Scopes             []string `yaml:"scopes,omitempty"`
	APIBaseURL         string   `yaml:"api_base_url,omitempty"`

	// Kubernetes TokenRequest, protected by TOTP re-authentication.
	Namespace      string `yaml:"namespace,omitempty"`
	ServiceAccount string `yaml:"service_account,omitempty"`
	TOTPSecretFile string `yaml:"totp_secret_file,omitempty"`
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
	// from the URL and comparing exactly. Example: "example-org".
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

	// EmergencyProfiles are the human-authenticated profiles this workload may
	// activate. Empty means routine installation tokens only.
	EmergencyProfiles []string `yaml:"emergency_profiles,omitempty"`
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
		if len(e.Keys) == 0 && len(e.EmergencyProfiles) == 0 {
			return fmt.Errorf("allowlist[%d]: keys or emergency_profiles is required", i)
		}
		for _, ref := range e.Keys {
			if _, ok := c.Keys[ref]; !ok {
				return fmt.Errorf("allowlist[%d]: unknown key %q (not in keys map)", i, ref)
			}
		}
		for _, ref := range e.EmergencyProfiles {
			if _, ok := c.EmergencyProfiles[ref]; !ok {
				return fmt.Errorf("allowlist[%d]: unknown emergency profile %q", i, ref)
			}
		}
	}
	for name, profile := range c.EmergencyProfiles {
		if name == "" {
			return errors.New("emergency profile name must be non-empty")
		}
		if _, err := profile.TTL(); err != nil {
			return fmt.Errorf("emergency profile %q: %w", name, err)
		}
		switch profile.Provider {
		case "github_user":
			if (profile.ClientID == "" && profile.ClientIDFile == "") || (profile.ClientSecret == "" && profile.ClientSecretFile == "") || (len(profile.AllowedUserIDs) == 0 && profile.AllowedUserIDsFile == "") || len(profile.Scopes) == 0 {
				return fmt.Errorf("emergency profile %q: client ID, client secret, allowed user IDs, and scopes are required", name)
			}
		case "kubernetes":
			if profile.Namespace == "" || profile.ServiceAccount == "" || profile.TOTPSecretFile == "" {
				return fmt.Errorf("emergency profile %q: namespace, service_account, and totp_secret_file are required", name)
			}
		default:
			return fmt.Errorf("emergency profile %q: unsupported provider %q", name, profile.Provider)
		}
	}
	for i, cidr := range c.TrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("trusted_proxies[%d] %q: %w", i, cidr, err)
		}
	}
	return nil
}

// TTL returns the configured maximum session duration, defaulting to 15 minutes.
func (p EmergencyProfile) TTL() (time.Duration, error) {
	if p.MaxTTL == "" {
		return 15 * time.Minute, nil
	}
	ttl, err := time.ParseDuration(p.MaxTTL)
	if err != nil || ttl <= 0 || ttl > time.Hour {
		return 0, errors.New("max_ttl must be between 1ns and 1h")
	}
	return ttl, nil
}

// ParsedTrustedProxies returns the TrustedProxies field as parsed
// CIDR networks. Validate() guarantees they parse, so a non-nil
// error here would only occur if validation was bypassed.
func (c *Config) ParsedTrustedProxies() ([]*net.IPNet, error) {
	if len(c.TrustedProxies) == 0 {
		return nil, nil
	}
	out := make([]*net.IPNet, 0, len(c.TrustedProxies))
	for _, cidr := range c.TrustedProxies {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("config: parse trusted_proxies %q: %w", cidr, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// FindByGitHubURL returns the Key whose GitHubOwner matches the owner
// segment parsed from the given git remote URL. Returns the key name,
// the Key, and a hit flag.
//
// Used by the git credential helper to route remotes to the right
// App. Handles HTTPS and SCP-style / ssh:// URL forms.
func (c *Config) FindByGitHubURL(gitURL string) (string, *Key, bool) {
	if !strings.Contains(gitURL, "://") && strings.Contains(gitURL, ":") {
		gitURL = "ssh://" + strings.Replace(gitURL, ":", "/", 1)
	}
	u, err := url.Parse(gitURL)
	if err != nil {
		return "", nil, false
	}
	host := u.Host
	if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(host)
		if err == nil {
			host = h
		}
	}

	owner := parseGitHubOwner(gitURL)
	if owner == "" {
		return "", nil, false
	}
	for name, k := range c.Keys {
		isGitHub := strings.EqualFold(host, "github.com") || (k.APIBaseURL != "" && strings.Contains(k.APIBaseURL, host))
		if !isGitHub {
			continue
		}
		if strings.EqualFold(k.GitHubOwner, owner) {
			key := k
			return name, &key, true
		}
	}
	return "", nil, false
}

func parseGitHubOwner(gitURL string) string {
	// Convert SCP-style SSH URLs (git@host:owner/repo) to standard URI format
	if !strings.Contains(gitURL, "://") && strings.Contains(gitURL, ":") {
		gitURL = "ssh://" + strings.Replace(gitURL, ":", "/", 1)
	}

	u, err := url.Parse(gitURL)
	if err != nil {
		return ""
	}

	pathParts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(pathParts) > 0 && pathParts[0] != "" {
		return pathParts[0]
	}
	return ""
}
