package config

import (
	"fmt"
	"net/url"
	"regexp"
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
		u, err := url.Parse(relay.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
			u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			return fmt.Errorf("telegram relay %q: url must be a plain HTTPS origin", name)
		}
		if seenURLs[u.Host] || seenSubjects[relay.RelaySubject] {
			return fmt.Errorf("telegram relay %q: each relay requires its own origin and workload identity", name)
		}
		seenURLs[u.Host], seenSubjects[relay.RelaySubject] = true, true
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
