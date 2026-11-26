package emergency

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
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
	Labels      map[string]string     `json:"credential_labels,omitempty"`
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
	user, err := readPasskeyUser(manager.file)
	if errors.Is(err, os.ErrNotExist) {
		manager.user = passkeyUser{ID: make([]byte, 32), Name: "operator", DisplayName: "Emergency operator", Credentials: []webauthn.Credential{}}
		if _, err := rand.Read(manager.user.ID); err != nil {
			return fmt.Errorf("create passkey user ID: %w", err)
		}
		return manager.persist()
	}
	if err != nil {
		return err
	}
	manager.user = user
	return nil
}

func readPasskeyUser(path string) (passkeyUser, error) {
	var user passkeyUser
	if path == "" {
		return user, errors.New("a passkey state file is required")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return user, fmt.Errorf("read passkey state: %w", err)
	}
	if err := json.Unmarshal(encoded, &user); err != nil {
		return user, fmt.Errorf("decode passkey state: %w", err)
	}
	if len(user.ID) == 0 || user.Name == "" || user.DisplayName == "" {
		return user, errors.New("passkey state is incomplete")
	}
	return user, nil
}

func passkeyCredentialID(id []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(id))
}

func (manager *passkeys) loginUser(allowed []string) passkeyUser {
	user := manager.user
	user.Credentials = nil
	for _, credential := range manager.user.Credentials {
		if !credential.Authenticator.CloneWarning && (allowed == nil || slices.Contains(allowed, passkeyCredentialID(credential.ID))) {
			user.Credentials = append(user.Credentials, credential)
		}
	}
	return user
}

type PasskeyInfo struct {
	ID           string `json:"id"`
	Label        string `json:"label,omitempty"`
	CloneWarning bool   `json:"clone_warning"`
}

func ListPasskeys(path string) ([]PasskeyInfo, error) {
	user, err := readPasskeyUser(path)
	if err != nil {
		return nil, err
	}
	items := make([]PasskeyInfo, 0, len(user.Credentials))
	for _, credential := range user.Credentials {
		id := passkeyCredentialID(credential.ID)
		items = append(items, PasskeyInfo{ID: id, Label: user.Labels[id], CloneWarning: credential.Authenticator.CloneWarning})
	}
	return items, nil
}

// RevokePasskey edits the offline state file. Stop Keymint before calling it.
func RevokePasskey(path, id string) error {
	user, err := readPasskeyUser(path)
	if err != nil {
		return err
	}
	for index, credential := range user.Credentials {
		if passkeyCredentialID(credential.ID) == id {
			user.Credentials = slices.Delete(user.Credentials, index, index+1)
			delete(user.Labels, id)
			return (&passkeys{file: path, user: user}).persist()
		}
	}
	return errors.New("passkey credential was not found")
}

func (manager *passkeys) beginLogin(allowed []string) (any, *webauthn.SessionData, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	user := manager.loginUser(allowed)
	if len(user.Credentials) == 0 {
		return nil, nil, errors.New("no passkeys are enrolled")
	}
	return manager.web.BeginLogin(&user, webauthn.WithUserVerification(protocol.VerificationRequired))
}

func (manager *passkeys) finishLogin(session webauthn.SessionData, request *http.Request, allowed []string) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	user := manager.loginUser(allowed)
	credential, err := manager.web.FinishLogin(&user, session, request)
	if err != nil {
		return err
	}
	if credential.Authenticator.CloneWarning {
		return errors.New("passkey signature counter did not advance or the credential was previously flagged")
	}
	for index := range manager.user.Credentials {
		if string(manager.user.Credentials[index].ID) == string(credential.ID) {
			previous := manager.user.Credentials[index]
			manager.user.Credentials[index] = *credential
			if err := manager.persist(); err != nil {
				manager.user.Credentials[index] = previous
				return err
			}
			return nil
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

func (manager *passkeys) finishRegistration(session webauthn.SessionData, request *http.Request, label string) (*webauthn.Credential, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	credential, err := manager.web.FinishRegistration(&manager.user, session, request)
	if err != nil {
		return nil, err
	}
	for _, enrolled := range manager.user.Credentials {
		if slices.Equal(enrolled.ID, credential.ID) {
			return nil, errors.New("passkey credential is already enrolled")
		}
	}
	manager.user.Credentials = append(manager.user.Credentials, *credential)
	id := passkeyCredentialID(credential.ID)
	if label != "" {
		if manager.user.Labels == nil {
			manager.user.Labels = make(map[string]string)
		}
		manager.user.Labels[id] = label
	}
	if err := manager.persist(); err != nil {
		delete(manager.user.Labels, id)
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
