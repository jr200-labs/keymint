package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type TelegramRelay struct {
	OwnerID         int64  `yaml:"owner_id"`
	OperatorSubject string `yaml:"operator_subject"`
	ApprovalProfile string `yaml:"approval_profile"`
	RelaySubject    string `yaml:"relay_subject"`
	URL             string `yaml:"url"`
	ControlKeyFile  string `yaml:"control_key_file"`
	WrappingKeyFile string `yaml:"wrapping_key_file"`
}

var relayNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// TelegramHTTPSOrigin validates and canonicalizes an HTTPS origin for Telegram
// enrollment. API paths are appended to the result.
func TelegramHTTPSOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return "", errors.New("must be a plain HTTPS origin")
	}
	host := strings.ToLower(u.Hostname())
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	port := u.Port()
	if port != "" {
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return "", errors.New("HTTPS origin port is invalid")
		}
		if number == 443 {
			port = ""
		} else {
			port = strconv.FormatUint(number, 10)
		}
	}
	switch {
	case port != "":
		u.Host = net.JoinHostPort(host, port)
	case strings.Contains(host, ":"):
		u.Host = "[" + host + "]"
	default:
		u.Host = host
	}
	return u.String(), nil
}

func (c *Config) validateTelegramRelays() error {
	seenURLs := make(map[string]bool)
	seenSubjects := make(map[string]bool)
	for name, relay := range c.TelegramRelays {
		if !relayNamePattern.MatchString(name) || relay.OwnerID <= 0 || relay.OperatorSubject == "" ||
			relay.RelaySubject == "" || relay.OperatorSubject == relay.RelaySubject ||
			relay.ControlKeyFile == "" || relay.WrappingKeyFile == "" || relay.ControlKeyFile == relay.WrappingKeyFile {
			return fmt.Errorf("telegram relay %q: invalid name, account, subjects, or key files", name)
		}
		if len(c.ExpectedAudiences) == 0 || c.EmergencyStateFile == "" || c.Passkeys == nil {
			return fmt.Errorf("telegram relay %q: enrollment requires audience-bound authentication and durable passkey approvals", name)
		}
		origin, err := TelegramHTTPSOrigin(relay.URL)
		if err != nil {
			return fmt.Errorf("telegram relay %q: url %w", name, err)
		}
		if seenURLs[origin] || seenSubjects[relay.RelaySubject] {
			return fmt.Errorf("telegram relay %q: each relay requires its own origin and workload identity", name)
		}
		seenURLs[origin], seenSubjects[relay.RelaySubject] = true, true

		profile, ok := c.EmergencyProfiles[relay.ApprovalProfile]
		if !ok || profile.Provider != "approval" || profile.AuthenticationMethod() != "webauthn" {
			return fmt.Errorf("telegram relay %q: approval_profile must be a passkey approval profile", name)
		}
		allowed := false
		for _, entry := range c.Allowlist {
			if entry.Subject == relay.OperatorSubject {
				for _, profile := range entry.EmergencyProfiles {
					allowed = allowed || profile == relay.ApprovalProfile
				}
			}
		}
		if !allowed {
			return fmt.Errorf("telegram relay %q: operator subject must be allowed to use the approval profile", name)
		}
	}
	return nil
}
