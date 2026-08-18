// Package emergency owns short-lived, human-authenticated credential sessions.
package emergency

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // TOTP requires HMAC-SHA1 for authenticator compatibility.
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jr200-labs/keymint/internal/config"
)

type State string

const (
	AwaitingGitHub  State = "awaiting_github"
	AwaitingTOTP    State = "awaiting_totp"
	AwaitingPasskey State = "awaiting_passkey"
	Active          State = "active"
	Expired         State = "expired"
)

type Profile struct {
	Name           string `json:"name"`
	Provider       string `json:"provider"`
	Authentication string `json:"authentication"`
	MaxTTL         int64  `json:"max_ttl_seconds"`
}

type Session struct {
	ID              string    `json:"id"`
	Profile         string    `json:"profile"`
	Provider        string    `json:"provider"`
	Authentication  string    `json:"authentication"`
	State           State     `json:"state"`
	VerificationURI string    `json:"verification_uri,omitempty"`
	UserCode        string    `json:"user_code,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`

	subject        string
	deviceCode     string
	accessToken    string
	credentialAt   time.Time
	nextPoll       time.Time
	pollEvery      time.Duration
	boundSecret    string
	verifyAttempts int
}

type PasskeyEnrollment struct {
	ID              string    `json:"id"`
	State           string    `json:"state"`
	VerificationURI string    `json:"verification_uri"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type passkeyCeremony struct {
	subject   string
	sessionID string
	kind      string
	options   any
	data      webauthn.SessionData
	expiresAt time.Time
}

type Credential struct {
	Provider  string    `json:"provider"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type revokedCredential struct {
	profile config.EmergencyProfile
	token   string
	secret  string
}

type TokenIssuer interface {
	Issue(context.Context, string, string, time.Duration, string) (token, boundSecret string, expiresAt time.Time, err error)
	Revoke(context.Context, string, string) error
}

type Service struct {
	mu                     sync.Mutex
	profiles               map[string]config.EmergencyProfile
	allowed                map[string]map[string]bool
	sessions               map[string]*Session
	http                   *http.Client
	issuer                 TokenIssuer
	passkeys               *passkeys
	passkeyVerificationURL string
	ceremonies             map[string]passkeyCeremony
	now                    func() time.Time
}

const maxSessions = 1024

func New(cfg *config.Config, client *http.Client, issuer TokenIssuer) (*Service, error) {
	manager, err := newPasskeys(cfg.Passkeys)
	if err != nil {
		return nil, err
	}
	service := &Service{http: client, issuer: issuer, passkeys: manager, sessions: map[string]*Session{}, ceremonies: map[string]passkeyCeremony{}, now: time.Now}
	if cfg.Passkeys != nil {
		service.passkeyVerificationURL = strings.TrimRight(cfg.Passkeys.VerificationURL, "/")
	}
	service.Reload(cfg)
	return service, nil
}

func (service *Service) Reload(cfg *config.Config) {
	service.mu.Lock()
	oldProfiles := service.profiles
	service.profiles = make(map[string]config.EmergencyProfile, len(cfg.EmergencyProfiles))
	for name, profile := range cfg.EmergencyProfiles {
		service.profiles[name] = profile
	}
	service.allowed = map[string]map[string]bool{}
	for _, entry := range cfg.Allowlist {
		for _, name := range entry.EmergencyProfiles {
			if service.allowed[entry.Subject] == nil {
				service.allowed[entry.Subject] = map[string]bool{}
			}
			service.allowed[entry.Subject][name] = true
		}
	}
	var revoked []revokedCredential
	for id, session := range service.sessions {
		if _, exists := service.profiles[session.Profile]; exists && service.allowed[session.subject][session.Profile] {
			continue
		}
		if session.accessToken != "" || session.boundSecret != "" {
			revoked = append(revoked, revokedCredential{profile: oldProfiles[session.Profile], token: session.accessToken, secret: session.boundSecret})
		}
		delete(service.sessions, id)
	}
	service.mu.Unlock()
	for _, credential := range revoked {
		if err := service.revokeCredential(context.Background(), credential); err != nil {
			slog.Error("revoke credential removed by config reload", "provider", credential.profile.Provider, "error", err)
		}
	}
}

func (service *Service) Profiles(subject string) []Profile {
	service.mu.Lock()
	defer service.mu.Unlock()
	result := make([]Profile, 0, len(service.allowed[subject]))
	for name := range service.allowed[subject] {
		profile := service.profiles[name]
		ttl, _ := profile.TTL()
		result = append(result, Profile{Name: name, Provider: profile.Provider, Authentication: profile.AuthenticationMethod(), MaxTTL: int64(ttl.Seconds())})
	}
	slicesSortProfiles(result)
	return result
}

func (service *Service) Create(ctx context.Context, subject, profileName string, requestedTTL time.Duration) (Session, error) {
	service.mu.Lock()
	profile, exists := service.profiles[profileName]
	allowed := service.allowed[subject][profileName]
	service.mu.Unlock()
	if !exists || !allowed {
		return Session{}, errors.New("emergency profile is unavailable")
	}
	maxTTL, _ := profile.TTL()
	if requestedTTL <= 0 || requestedTTL > maxTTL {
		requestedTTL = maxTTL
	}
	now := service.now().UTC()
	id, err := randomID()
	if err != nil {
		return Session{}, fmt.Errorf("create emergency session ID: %w", err)
	}
	session := &Session{ID: id, Profile: profileName, Provider: profile.Provider, Authentication: profile.AuthenticationMethod(), subject: subject, ExpiresAt: now.Add(requestedTTL)}
	switch profile.AuthenticationMethod() {
	case "github_device":
		device, err := service.startGitHubDevice(ctx, profile)
		if err != nil {
			return Session{}, err
		}
		session.State, session.VerificationURI, session.UserCode = AwaitingGitHub, device.VerificationURI, device.UserCode
		session.deviceCode, session.pollEvery, session.nextPoll = device.DeviceCode, device.Interval, now
	case "totp":
		session.State = AwaitingTOTP
	case "webauthn":
		if service.passkeys == nil {
			return Session{}, errors.New("passkeys are unavailable")
		}
		options, data, err := service.passkeys.beginLogin()
		if err != nil {
			return Session{}, err
		}
		token, err := randomID()
		if err != nil {
			return Session{}, fmt.Errorf("create passkey ceremony token: %w", err)
		}
		session.State = AwaitingPasskey
		session.VerificationURI = service.passkeyVerificationURL + "/#" + token
		service.mu.Lock()
		service.ceremonies[token] = passkeyCeremony{subject: subject, sessionID: id, kind: "authentication", options: options, data: *data, expiresAt: now.Add(5 * time.Minute)}
		service.mu.Unlock()
	default:
		return Session{}, errors.New("unsupported emergency authentication")
	}
	if err := service.Prune(ctx); err != nil {
		slog.Error("prune expired emergency credentials", "error", err)
	}
	service.mu.Lock()
	if len(service.sessions) >= maxSessions {
		for token, ceremony := range service.ceremonies {
			if ceremony.sessionID == session.ID {
				delete(service.ceremonies, token)
			}
		}
		service.mu.Unlock()
		return Session{}, errors.New("too many active emergency sessions")
	}
	service.sessions[session.ID] = session
	service.mu.Unlock()
	return publicSession(session), nil
}

func (service *Service) BeginPasskeyEnrollment(subject, proofSessionID string) (PasskeyEnrollment, error) {
	if service.passkeys == nil {
		return PasskeyEnrollment{}, errors.New("passkeys are unavailable")
	}
	service.mu.Lock()
	proof, err := service.ownedSession(subject, proofSessionID)
	if err != nil || proof.State != Active || proof.Authentication != "totp" || !proof.ExpiresAt.After(service.now()) {
		service.mu.Unlock()
		return PasskeyEnrollment{}, errors.New("an active TOTP-authenticated session is required")
	}
	service.mu.Unlock()
	options, data, err := service.passkeys.beginRegistration()
	if err != nil {
		return PasskeyEnrollment{}, err
	}
	id, err := randomID()
	if err != nil {
		return PasskeyEnrollment{}, err
	}
	token, err := randomID()
	if err != nil {
		return PasskeyEnrollment{}, err
	}
	now := service.now().UTC()
	enrollment := PasskeyEnrollment{ID: id, State: "awaiting_passkey", VerificationURI: service.passkeyVerificationURL + "/#" + token, ExpiresAt: now.Add(5 * time.Minute)}
	service.mu.Lock()
	service.ceremonies[token] = passkeyCeremony{subject: subject, kind: "registration", options: options, data: *data, expiresAt: enrollment.ExpiresAt}
	service.mu.Unlock()
	return enrollment, nil
}

func (service *Service) PasskeyOptions(subject, token string) (map[string]any, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	ceremony, ok := service.ceremonies[token]
	if !ok || ceremony.subject != subject || !ceremony.expiresAt.After(service.now()) {
		return nil, errors.New("passkey ceremony not found or expired")
	}
	return map[string]any{"kind": ceremony.kind, "public_key": ceremony.options}, nil
}

func (service *Service) VerifyPasskey(subject, token string, request *http.Request) error {
	service.mu.Lock()
	ceremony, ok := service.ceremonies[token]
	if !ok || ceremony.subject != subject || !ceremony.expiresAt.After(service.now()) {
		service.mu.Unlock()
		return errors.New("passkey ceremony not found or expired")
	}
	delete(service.ceremonies, token)
	service.mu.Unlock()
	if ceremony.sessionID != "" {
		if err := service.passkeys.finishLogin(ceremony.data, request); err != nil {
			return fmt.Errorf("verify passkey: %w", err)
		}
		service.mu.Lock()
		defer service.mu.Unlock()
		session := service.sessions[ceremony.sessionID]
		if session == nil || session.subject != subject || session.State != AwaitingPasskey {
			return errors.New("emergency session is unavailable")
		}
		session.State = Active
		return nil
	}
	_, err := service.passkeys.finishRegistration(ceremony.data, request)
	if err != nil {
		return fmt.Errorf("register passkey: %w", err)
	}
	return nil
}

func (service *Service) Prune(ctx context.Context) error {
	type expiredSession struct {
		id         string
		session    *Session
		credential revokedCredential
	}
	now := service.now()
	service.mu.Lock()
	var expired []expiredSession
	for id, current := range service.sessions {
		if current.ExpiresAt.After(now) {
			continue
		}
		current.State = Expired
		profile := service.profiles[current.Profile]
		expired = append(expired, expiredSession{id: id, session: current, credential: revokedCredential{profile: profile, token: current.accessToken, secret: current.boundSecret}})
		delete(service.sessions, id)
	}
	for token, ceremony := range service.ceremonies {
		if !ceremony.expiresAt.After(now) {
			delete(service.ceremonies, token)
		}
	}
	service.mu.Unlock()
	var result error
	for _, item := range expired {
		if err := service.revokeCredential(ctx, item.credential); err != nil {
			service.mu.Lock()
			if service.sessions[item.id] == nil {
				service.sessions[item.id] = item.session
			}
			service.mu.Unlock()
			result = errors.Join(result, err)
		}
	}
	return result
}

func (service *Service) Get(ctx context.Context, subject, id string) (Session, error) {
	service.mu.Lock()
	session, err := service.ownedSession(subject, id)
	if err != nil {
		service.mu.Unlock()
		return Session{}, err
	}
	if !session.ExpiresAt.After(service.now()) {
		session.State = Expired
	}
	copy := *session
	profile := service.profiles[session.Profile]
	revoked := revokedCredential{profile: profile, token: session.accessToken, secret: session.boundSecret}
	service.mu.Unlock()
	if copy.State == Expired {
		if err := service.revokeCredential(ctx, revoked); err != nil {
			return Session{}, err
		}
		service.mu.Lock()
		if current := service.sessions[id]; current == session {
			current.accessToken, current.boundSecret = "", ""
		}
		service.mu.Unlock()
	}
	if copy.State == AwaitingGitHub && !copy.nextPoll.After(service.now()) {
		if err := service.pollGitHub(ctx, &copy, profile); err != nil {
			return Session{}, err
		}
		service.mu.Lock()
		if current := service.sessions[id]; current != nil && current.subject == subject {
			*current = copy
		}
		service.mu.Unlock()
	}
	return publicSession(&copy), nil
}

func (service *Service) VerifyTOTP(subject, id, code string) (Session, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	session, err := service.ownedSession(subject, id)
	if err != nil {
		return Session{}, err
	}
	if session.State != AwaitingTOTP || !session.ExpiresAt.After(service.now()) {
		return Session{}, errors.New("session is not awaiting TOTP")
	}
	profile := service.profiles[session.Profile]
	if session.verifyAttempts >= 5 {
		session.State = Expired
		return Session{}, errors.New("too many invalid TOTP attempts")
	}
	secret, err := os.ReadFile(profile.TOTPSecretFile)
	if err != nil {
		return Session{}, fmt.Errorf("read TOTP secret: %w", err)
	}
	if !validTOTP(strings.TrimSpace(string(secret)), code, service.now()) {
		session.verifyAttempts++
		return Session{}, errors.New("invalid TOTP code")
	}
	session.State = Active
	return publicSession(session), nil
}

func (service *Service) Credential(ctx context.Context, subject, id string) (Credential, error) {
	service.mu.Lock()
	session, err := service.ownedSession(subject, id)
	if err != nil {
		service.mu.Unlock()
		return Credential{}, err
	}
	if session.State != Active || !session.ExpiresAt.After(service.now()) {
		service.mu.Unlock()
		return Credential{}, errors.New("emergency session is not active")
	}
	profile := service.profiles[session.Profile]
	if profile.Provider == "github_user" {
		credential := Credential{Provider: profile.Provider, Token: session.accessToken, ExpiresAt: session.ExpiresAt}
		service.mu.Unlock()
		return credential, nil
	}
	boundSecret := session.boundSecret
	ttl := session.ExpiresAt.Sub(service.now())
	if service.issuer == nil {
		service.mu.Unlock()
		return Credential{}, errors.New("Kubernetes emergency issuer is unavailable")
	}
	// ponytail: emergency issuance holds the global session lock; use per-session
	// locks only if emergency-session concurrency becomes operationally relevant.
	token, secret, expiresAt, err := service.issuer.Issue(ctx, profile.Namespace, profile.ServiceAccount, ttl, boundSecret)
	if err != nil {
		service.mu.Unlock()
		return Credential{}, err
	}
	session.boundSecret = secret
	service.mu.Unlock()
	return Credential{Provider: profile.Provider, Token: token, ExpiresAt: expiresAt}, nil
}

func (service *Service) Revoke(ctx context.Context, subject, id string) error {
	service.mu.Lock()
	session, err := service.ownedSession(subject, id)
	if err != nil {
		service.mu.Unlock()
		return err
	}
	revoked := revokedCredential{profile: service.profiles[session.Profile], token: session.accessToken, secret: session.boundSecret}
	// ponytail: emergency revocation holds the global session lock so no
	// credential can be issued concurrently; use per-session locks at scale.
	if err := service.revokeCredential(ctx, revoked); err != nil {
		service.mu.Unlock()
		return err
	}
	delete(service.sessions, id)
	service.mu.Unlock()
	return nil
}

func (service *Service) ownedSession(subject, id string) (*Session, error) {
	session := service.sessions[id]
	if session == nil || session.subject != subject {
		return nil, errors.New("emergency session not found")
	}
	return session, nil
}

type deviceResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int64  `json:"expires_in"`
	Interval        int64  `json:"interval"`
}

type device struct {
	DeviceCode, UserCode, VerificationURI string
	Interval                              time.Duration
}

func (service *Service) startGitHubDevice(ctx context.Context, profile config.EmergencyProfile) (device, error) {
	clientID, _, _, err := githubIdentity(profile)
	if err != nil {
		return device{}, err
	}
	values := url.Values{"client_id": {clientID}, "scope": {strings.Join(profile.Scopes, " ")}}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/device/code", strings.NewReader(values.Encode()))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response deviceResponse
	if err := service.doJSON(request, &response); err != nil {
		return device{}, fmt.Errorf("start GitHub device flow: %w", err)
	}
	return device{response.DeviceCode, response.UserCode, response.VerificationURI, time.Duration(max(response.Interval, 5)) * time.Second}, nil
}

func (service *Service) pollGitHub(ctx context.Context, session *Session, profile config.EmergencyProfile) error {
	clientID, _, allowedUserIDs, err := githubIdentity(profile)
	if err != nil {
		return err
	}
	values := url.Values{"client_id": {clientID}, "device_code": {session.deviceCode}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(values.Encode()))
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var token struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := service.doJSON(request, &token); err != nil {
		return fmt.Errorf("poll GitHub device flow: %w", err)
	}
	if token.AccessToken == "" {
		if token.Error != "" && token.Error != "authorization_pending" && token.Error != "slow_down" {
			return fmt.Errorf("GitHub device flow: %s", token.Error)
		}
		if token.Error == "slow_down" {
			session.pollEvery += 5 * time.Second
		}
		session.nextPoll = service.now().Add(session.pollEvery)
		return nil
	}
	userID, err := service.githubUserID(ctx, profile, token.AccessToken)
	if err != nil {
		_ = service.revokeCredential(ctx, revokedCredential{profile: profile, token: token.AccessToken})
		return err
	}
	if !containsID(allowedUserIDs, userID) {
		_ = service.revokeCredential(ctx, revokedCredential{profile: profile, token: token.AccessToken})
		return errors.New("authenticated GitHub user is not allowed for this profile")
	}
	session.accessToken, session.State = token.AccessToken, Active
	return nil
}

func githubIdentity(profile config.EmergencyProfile) (string, string, []int64, error) {
	clientID := profile.ClientID
	if profile.ClientIDFile != "" {
		value, err := os.ReadFile(profile.ClientIDFile)
		if err != nil {
			return "", "", nil, fmt.Errorf("read GitHub client ID: %w", err)
		}
		clientID = strings.TrimSpace(string(value))
	}
	clientSecret := profile.ClientSecret
	if profile.ClientSecretFile != "" {
		value, err := os.ReadFile(profile.ClientSecretFile)
		if err != nil {
			return "", "", nil, fmt.Errorf("read GitHub client secret: %w", err)
		}
		clientSecret = strings.TrimSpace(string(value))
	}
	allowed := append([]int64(nil), profile.AllowedUserIDs...)
	if profile.AllowedUserIDsFile != "" {
		value, err := os.ReadFile(profile.AllowedUserIDsFile)
		if err != nil {
			return "", "", nil, fmt.Errorf("read allowed GitHub user IDs: %w", err)
		}
		allowed = nil
		for _, field := range strings.FieldsFunc(string(value), func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
			id, err := strconv.ParseInt(field, 10, 64)
			if err != nil {
				return "", "", nil, errors.New("allowed GitHub user IDs file contains a non-numeric value")
			}
			allowed = append(allowed, id)
		}
	}
	if clientID == "" || clientSecret == "" || len(allowed) == 0 {
		return "", "", nil, errors.New("GitHub emergency identity is empty")
	}
	return clientID, clientSecret, allowed, nil
}

func (service *Service) revokeCredential(ctx context.Context, credential revokedCredential) error {
	var result error
	if credential.token != "" {
		clientID, clientSecret, _, err := githubIdentity(credential.profile)
		if err != nil {
			result = err
		} else {
			base := strings.TrimRight(credential.profile.APIBaseURL, "/")
			if base == "" {
				base = "https://api.github.com"
			}
			body, _ := json.Marshal(map[string]string{"access_token": credential.token})
			request, _ := http.NewRequestWithContext(ctx, http.MethodDelete, base+"/applications/"+url.PathEscape(clientID)+"/token", strings.NewReader(string(body)))
			request.SetBasicAuth(clientID, clientSecret)
			request.Header.Set("Accept", "application/vnd.github+json")
			request.Header.Set("Content-Type", "application/json")
			response, err := service.http.Do(request)
			if err != nil {
				result = errors.Join(result, err)
			} else {
				defer func() { _ = response.Body.Close() }()
				if response.StatusCode < 200 || response.StatusCode >= 300 {
					message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
					result = errors.Join(result, fmt.Errorf("revoke GitHub token: %s: %s", response.Status, strings.TrimSpace(string(message))))
				}
			}
		}
	}
	if credential.secret != "" && service.issuer != nil {
		result = errors.Join(result, service.issuer.Revoke(ctx, credential.profile.Namespace, credential.secret))
	}
	return result
}

func (service *Service) githubUserID(ctx context.Context, profile config.EmergencyProfile, token string) (int64, error) {
	base := strings.TrimRight(profile.APIBaseURL, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/user", nil)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+token)
	var user struct {
		ID int64 `json:"id"`
	}
	if err := service.doJSON(request, &user); err != nil {
		return 0, fmt.Errorf("validate GitHub user: %w", err)
	}
	return user.ID, nil
}

func (service *Service) doJSON(request *http.Request, target any) error {
	response, err := service.http.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("%s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	return json.NewDecoder(response.Body).Decode(target)
}

func validTOTP(secret, code string, now time.Time) bool {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil || len(code) != 6 {
		return false
	}
	for offset := int64(-1); offset <= 1; offset++ {
		counter := uint64(now.Unix()/30 + offset)
		buffer := make([]byte, 8)
		binary.BigEndian.PutUint64(buffer, counter)
		mac := hmac.New(sha1.New, decoded)
		_, _ = mac.Write(buffer)
		sum := mac.Sum(nil)
		index := sum[len(sum)-1] & 0x0f
		value := (uint32(sum[index])&0x7f)<<24 | uint32(sum[index+1])<<16 | uint32(sum[index+2])<<8 | uint32(sum[index+3])
		want := fmt.Sprintf("%06d", value%1_000_000)
		if hmac.Equal([]byte(want), []byte(code)) {
			return true
		}
	}
	return false
}

func randomID() (string, error) {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "E-" + base64.RawURLEncoding.EncodeToString(value), nil
}

func publicSession(session *Session) Session {
	copy := *session
	copy.subject, copy.deviceCode, copy.accessToken, copy.boundSecret = "", "", "", ""
	copy.credentialAt, copy.nextPoll, copy.pollEvery, copy.verifyAttempts = time.Time{}, time.Time{}, 0, 0
	return copy
}

func containsID(values []int64, wanted int64) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func slicesSortProfiles(values []Profile) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j].Name < values[j-1].Name; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
