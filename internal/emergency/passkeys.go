package emergency

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jr200-labs/keymint/internal/config"
)

type passkeyUser struct {
	ID          []byte                `json:"id"`
	Name        string                `json:"name"`
	DisplayName string                `json:"display_name"`
	Credentials []webauthn.Credential `json:"credentials"`
}

func (user *passkeyUser) WebAuthnID() []byte                         { return user.ID }
func (user *passkeyUser) WebAuthnName() string                       { return user.Name }
func (user *passkeyUser) WebAuthnDisplayName() string                { return user.DisplayName }
func (user *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return user.Credentials }

type passkeys struct {
	mu   sync.Mutex
	web  *webauthn.WebAuthn
	file string
	user passkeyUser
}

func newPasskeys(cfg *config.PasskeyConfig) (*passkeys, error) {
	if cfg == nil {
		return nil, nil
	}
	web, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("configure passkeys: %w", err)
	}
	manager := &passkeys{web: web, file: cfg.StateFile}
	if err := manager.loadOrCreate(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (manager *passkeys) loadOrCreate() error {
	encoded, err := os.ReadFile(manager.file)
	if errors.Is(err, os.ErrNotExist) {
		manager.user = passkeyUser{ID: make([]byte, 32), Name: "operator", DisplayName: "Emergency operator", Credentials: []webauthn.Credential{}}
		if _, err := rand.Read(manager.user.ID); err != nil {
			return fmt.Errorf("create passkey user ID: %w", err)
		}
		return manager.persist()
	}
	if err != nil {
		return fmt.Errorf("read passkey state: %w", err)
	}
	if err := json.Unmarshal(encoded, &manager.user); err != nil {
		return fmt.Errorf("decode passkey state: %w", err)
	}
	if len(manager.user.ID) == 0 || manager.user.Name == "" || manager.user.DisplayName == "" {
		return errors.New("passkey state is incomplete")
	}
	return nil
}

func (manager *passkeys) beginLogin() (any, *webauthn.SessionData, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.user.Credentials) == 0 {
		return nil, nil, errors.New("no passkeys are enrolled")
	}
	return manager.web.BeginLogin(&manager.user, webauthn.WithUserVerification(protocol.VerificationRequired))
}

func (manager *passkeys) finishLogin(session webauthn.SessionData, request *http.Request) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	credential, err := manager.web.FinishLogin(&manager.user, session, request)
	if err != nil {
		return err
	}
	for index := range manager.user.Credentials {
		if string(manager.user.Credentials[index].ID) == string(credential.ID) {
			manager.user.Credentials[index] = *credential
			return manager.persist()
		}
	}
	return errors.New("verified passkey is not enrolled")
}

func (manager *passkeys) beginRegistration() (any, *webauthn.SessionData, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.web.BeginRegistration(
		&manager.user,
		webauthn.WithExclusions(webauthn.Credentials(manager.user.Credentials).CredentialDescriptors()),
	)
}

func (manager *passkeys) finishRegistration(session webauthn.SessionData, request *http.Request) (*webauthn.Credential, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	credential, err := manager.web.FinishRegistration(&manager.user, session, request)
	if err != nil {
		return nil, err
	}
	manager.user.Credentials = append(manager.user.Credentials, *credential)
	if err := manager.persist(); err != nil {
		manager.user.Credentials = manager.user.Credentials[:len(manager.user.Credentials)-1]
		return nil, err
	}
	return credential, nil
}

func (manager *passkeys) persist() error {
	if err := os.MkdirAll(filepath.Dir(manager.file), 0o700); err != nil {
		return fmt.Errorf("create passkey state directory: %w", err)
	}
	encoded, err := json.Marshal(manager.user)
	if err != nil {
		return fmt.Errorf("encode passkey state: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(manager.file), ".passkeys-*")
	if err != nil {
		return fmt.Errorf("create passkey state: %w", err)
	}
	name := temporary.Name()
	defer func() { _ = os.Remove(name) }()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, manager.file); err != nil {
		return fmt.Errorf("replace passkey state: %w", err)
	}
	return nil
}
