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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jr200-labs/keymint/internal/tracing"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/logging"
	"github.com/jr200-labs/keymint/internal/metrics"
	"go.uber.org/zap"
)

var errScopeMismatch = errors.New("GitHub granted scopes do not match the restricted request; token rejected")

type State string

const (
	AwaitingGitHub  State = "awaiting_github"
	AwaitingTOTP    State = "awaiting_totp"
	AwaitingPasskey State = "awaiting_passkey"
	Active          State = "active"
	Expired         State = "expired"
	Invalidated     State = "invalidated"
	Revoked         State = "revoked"
)

type Profile struct {
	Name           string `json:"name"`
	Provider       string `json:"provider"`
	Authentication string `json:"authentication"`
	MaxTTL         int64  `json:"max_ttl_seconds"`
}

type Session struct {
	ApprovalLabel   string    `json:"approval_label,omitempty"`
	ApprovalDigest  string    `json:"approval_digest,omitempty"`
	ApprovalUsed    bool      `json:"approval_used,omitempty"`
	Scopes          []string  `json:"scopes,omitempty"`
	ID              string    `json:"id"`
	Profile         string    `json:"profile"`
	Provider        string    `json:"provider"`
	Authentication  string    `json:"authentication"`
	State           State     `json:"state"`
	VerificationURI string    `json:"verification_uri,omitempty"`
	UserCode        string    `json:"user_code,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`

	approvalTTL            time.Duration
	profile                config.EmergencyProfile
	subject                string
	deviceCode             string
	accessToken            string
	nextPoll               time.Time
	pollEvery              time.Duration
	boundSecret            string
	operation              operation
	gate                   chan struct{}
	withdrawalEventPending bool
}

type PasskeyEnrollment struct {
	ID              string    `json:"id"`
	State           string    `json:"state"`
	VerificationURI string    `json:"verification_uri"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type passkeyCeremony struct {
	label          string
	credentials    []string
	proofSessionID string
	subject        string
	sessionID      string
	kind           string
	options        any
	data           webauthn.SessionData
	expiresAt      time.Time
}

type Credential struct {
	Provider  string    `json:"provider"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type revokedCredential struct {
	id      string
	profile config.EmergencyProfile
	token   string
	secret  string
}

type TokenIssuer interface {
	Issue(context.Context, string, string, time.Duration, string) (token, boundSecret string, expiresAt time.Time, err error)
	Revoke(context.Context, string, string) error
}

type Service struct {
	metrics                *metrics.Metrics
	mu                     sync.Mutex
	revision               uint64
	closed                 bool
	profiles               map[string]config.EmergencyProfile
	allowed                map[string]map[string]bool
	sessions               map[string]*Session
	creating               map[string]string
	http                   *http.Client
	issuer                 TokenIssuer
	passkeys               *passkeys
	passkeyVerificationURL string
	ceremonies             map[string]passkeyCeremony
	events                 *eventStore
	cleanup                *cleanupStore
	now                    func() time.Time
	journalRetention       time.Duration
}

const (
	maxSessions           = 1024
	maxSessionsPerSubject = 16
)

func New(cfg *config.Config, client *http.Client, issuer TokenIssuer, instruments ...*metrics.Metrics) (*Service, error) {
	manager, err := newPasskeys(cfg.Passkeys)
	if err != nil {
		return nil, err
	}
	events, err := openEventStore(cfg.EmergencyStateFile)
	if err != nil {
		return nil, err
	}
	cleanup, err := openCleanupStore(events.db, cfg.EmergencyStateFile)
	if err != nil {
		_ = events.close()
		return nil, err
	}
	service := &Service{cleanup: cleanup, http: tracing.HTTPClient(client), issuer: issuer, passkeys: manager, sessions: map[string]*Session{}, creating: map[string]string{}, ceremonies: map[string]passkeyCeremony{}, events: events, now: time.Now}
	if len(instruments) > 0 {
		service.metrics = instruments[0]
		events.metrics = instruments[0]
	}
	if cfg.Passkeys != nil {
		service.passkeyVerificationURL = strings.TrimRight(cfg.Passkeys.VerificationURL, "/")
	}
	service.Reload(cfg)
	restored, err := cleanup.list(context.Background())
	if err != nil {
		_ = events.close()
		return nil, err
	}
	for _, record := range restored {
		record.Due = service.now()
		if err = cleanup.put(context.Background(), record); err != nil {
			_ = events.close()
			return nil, err
		}
	}
	// Every restored cleanup belongs to a previous process, never a live session.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := service.drainCleanup(ctx, true); err != nil {
		logging.FromContext(ctx).Error("recover emergency credential cleanup", zap.Error(err))
	}
	return service, nil
}

func (service *Service) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	service.mu.Lock()
	service.closed = true
	service.revision++
	var gates []chan struct{}
	for _, session := range service.sessions {
		if !terminal(session.State) {
			_ = service.transitionLocked(ctx, session, Invalidated, eventFor(Invalidated))
		}
		if session.gate != nil {
			gates = append(gates, session.gate)
		}
	}
	service.mu.Unlock()
	for _, gate := range gates {
		select {
		case gate <- struct{}{}:
			<-gate
		case <-ctx.Done():
			return errors.Join(ctx.Err(), service.events.close())
		}
	}
	return errors.Join(service.drainCleanup(ctx, true), service.events.close())
}

func (service *Service) Reload(cfg *config.Config) {
	service.mu.Lock()
	service.revision++
	service.journalRetention, _ = cfg.JournalRetention()
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
	var invalidated []*Session
	for id, session := range service.sessions {
		if terminal(session.State) {
			continue
		}
		if current, exists := service.profiles[session.Profile]; exists && service.allowed[session.subject][session.Profile] && reflect.DeepEqual(current, session.profile) {
			continue
		}

		if err := service.transitionLocked(context.Background(), session, Invalidated, eventFor(Invalidated)); err != nil {
			zap.L().Error("record emergency invalidation", zap.Error(err))
			continue
		}
		copy := *session
		invalidated = append(invalidated, &copy)
		if session.operation == idle {
			delete(service.sessions, id)
		}
	}
	service.mu.Unlock()
	reloadCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if len(invalidated) > 0 {
		if err := service.drainCleanup(reloadCtx, false); err != nil {
			zap.L().Error("retry credential cleanup after config reload", zap.Error(err))
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
	return service.CreateWithScopes(ctx, subject, profileName, requestedTTL, nil)
}

// CreateWithScopes only permits a subset of the configured OAuth profile.
func (service *Service) CreateWithScopes(ctx context.Context, subject, profileName string, requestedTTL time.Duration, scopes []string) (Session, error) {
	return service.create(ctx, subject, profileName, requestedTTL, scopes, "", "")
}

func (service *Service) CreateApproval(ctx context.Context, subject, profileName string, ttl time.Duration, digest, label string) (Session, error) {
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != 32 || strings.TrimSpace(label) == "" || len(label) > 3000 || strings.ContainsAny(label, "\r\n") {
		return Session{}, errors.New("approval requires a SHA-256 digest and a review label")
	}
	if ttl == 0 {
		ttl = config.MinApprovalTTL
	}
	if ttl < config.MinApprovalTTL || ttl > config.MaxApprovalTTL {
		return Session{}, errors.New("approval TTL must be between five minutes and one hour")
	}
	return service.create(ctx, subject, profileName, ttl, nil, digest, label)
}

func (service *Service) create(ctx context.Context, subject, profileName string, requestedTTL time.Duration, scopes []string, digest, label string) (Session, error) {
	service.mu.Lock()
	profile, exists := service.profiles[profileName]
	allowed := service.allowed[subject][profileName]
	revision := service.revision
	originalProfile := profile
	service.mu.Unlock()
	if !exists || !allowed {
		return Session{}, errors.New("emergency profile is unavailable")
	}
	if (profile.Provider == "approval") != (digest != "") {
		return Session{}, errors.New("approval profile and bound request are required together")
	}
	if len(scopes) > 0 {
		if profile.Provider != "github_user" {
			return Session{}, errors.New("scope restrictions require a GitHub user profile")
		}
		for _, scope := range scopes {
			if scope == "" || !slices.Contains(profile.Scopes, scope) {
				return Session{}, errors.New("requested scope is not allowed by the emergency profile")
			}
		}
		scopes = append([]string(nil), scopes...)
		slices.Sort(scopes)
		scopes = slices.Compact(scopes)
		profile.Scopes = scopes
	}
	maxTTL, err := profile.TTL()
	if err != nil {
		return Session{}, err
	}
	if digest != "" && requestedTTL > maxTTL {
		return Session{}, errors.New("approval TTL exceeds the profile maximum")
	}
	if requestedTTL <= 0 || requestedTTL > maxTTL {
		requestedTTL = maxTTL
	}
	now := service.now().UTC()
	id, err := randomID()
	if err != nil {
		return Session{}, fmt.Errorf("create emergency session ID: %w", err)
	}
	if err := service.Prune(ctx); err != nil {
		logging.FromContext(ctx).Error("prune expired emergency credentials", zap.Error(err))
	}
	service.mu.Lock()
	if service.closed || service.revision != revision || !service.allowed[subject][profileName] {
		service.mu.Unlock()
		return Session{}, errors.New("session authorization changed during creation")
	}
	count := 0
	for _, session := range service.sessions {
		if session.subject == subject {
			count++
		}
	}
	for _, owner := range service.creating {
		if owner == subject {
			count++
		}
	}
	if count >= maxSessionsPerSubject || len(service.sessions)+len(service.creating) >= maxSessions {
		service.mu.Unlock()
		return Session{}, errors.New("emergency session capacity reached")
	}
	service.creating[id] = subject
	service.mu.Unlock()
	defer func() {
		service.mu.Lock()
		delete(service.creating, id)
		service.mu.Unlock()
	}()
	var ceremonyToken string
	var ceremony passkeyCeremony
	session := &Session{approvalTTL: requestedTTL, profile: originalProfile, ApprovalDigest: digest, ApprovalLabel: label, Scopes: scopes, ID: id, Profile: profileName, Provider: profile.Provider, Authentication: profile.AuthenticationMethod(), subject: subject, ExpiresAt: now.Add(requestedTTL)}
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
		options, data, err := service.passkeys.beginLogin(profile.PasskeyCredentials)
		if err != nil {
			return Session{}, err
		}
		token, err := randomID()
		if err != nil {
			return Session{}, fmt.Errorf("create passkey ceremony token: %w", err)
		}
		session.State = AwaitingPasskey
		session.VerificationURI = service.passkeyVerificationURL + "/#" + token
		ceremonyExpiry := now.Add(5 * time.Minute)
		if digest != "" {
			ceremonyExpiry = session.ExpiresAt
		}
		ceremonyToken = token
		ceremony = passkeyCeremony{subject: subject, sessionID: id, kind: "authentication", credentials: profile.PasskeyCredentials, options: options, data: *data, expiresAt: ceremonyExpiry}
	default:
		return Session{}, errors.New("unsupported emergency authentication")
	}
	service.mu.Lock()
	if service.closed || service.revision != revision || !service.allowed[subject][profileName] || !session.ExpiresAt.After(service.now()) {
		service.mu.Unlock()
		return Session{}, errors.New("session expired or authorization changed during creation")
	}
	if err := service.record(ctx, "session.created", session); err != nil {
		service.mu.Unlock()
		return Session{}, fmt.Errorf("record emergency session creation: %w", err)
	}
	if ceremonyToken != "" {
		service.ceremonies[ceremonyToken] = ceremony
	}
	delete(service.creating, id)
	service.sessions[id] = session
	result := publicSession(session)
	service.mu.Unlock()
	return result, nil
}

func (service *Service) BeginPasskeyEnrollment(subject, proofSessionID string) (PasskeyEnrollment, error) {
	return service.BeginLabeledPasskeyEnrollment(subject, proofSessionID, "")
}

func (service *Service) BeginLabeledPasskeyEnrollment(subject, proofSessionID, label string) (PasskeyEnrollment, error) {
	label = strings.TrimSpace(label)
	if len(label) > 128 || strings.IndexFunc(label, unicode.IsControl) >= 0 {
		return PasskeyEnrollment{}, errors.New("passkey label must be at most 128 bytes without control characters")
	}
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
	service.ceremonies[token] = passkeyCeremony{proofSessionID: proofSessionID, subject: subject, kind: "registration", label: label, options: options, data: *data, expiresAt: enrollment.ExpiresAt}
	service.mu.Unlock()
	return enrollment, nil
}

// ApprovalDurationHeader carries the owner's selection on the passkey submission.
const ApprovalDurationHeader = "X-Padd-Approval-Duration"

func approvalDurations(profile config.EmergencyProfile) []int {
	maxTTL, err := profile.TTL()
	if err != nil {
		return nil
	}
	var choices []int
	for _, minutes := range []int{5, 15, 30, 60} {
		if time.Duration(minutes)*time.Minute <= maxTTL {
			choices = append(choices, minutes)
		}
	}
	return choices
}

func (service *Service) PasskeyOptions(subject, token string) (map[string]any, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	ceremony, ok := service.ceremonies[token]
	if !ok || ceremony.subject != subject || !ceremony.expiresAt.After(service.now()) {
		return nil, errors.New("passkey ceremony not found or expired")
	}
	options := map[string]any{"kind": ceremony.kind, "public_key": ceremony.options}
	if session := service.sessions[ceremony.sessionID]; session != nil && session.Provider == "approval" {
		if session.State != AwaitingPasskey || !session.ExpiresAt.After(service.now()) {
			return nil, errors.New("approval is unavailable")
		}
		options["approval_label"] = session.ApprovalLabel
		options["expires_at"] = session.ExpiresAt
		choices := approvalDurations(session.profile)
		if len(choices) > 0 {
			options["approval_duration_minutes"] = choices
			preferred := int(session.approvalTTL / time.Minute)
			if !slices.Contains(choices, preferred) {
				preferred = choices[0]
			}
			options["default_approval_duration_minutes"] = preferred
		}
	}
	return options, nil
}

func (service *Service) VerifyPasskey(subject, token string, request *http.Request) error {
	service.mu.Lock()
	ceremony, ok := service.ceremonies[token]
	if !ok || ceremony.subject != subject || !ceremony.expiresAt.After(service.now()) {
		service.mu.Unlock()
		return errors.New("passkey ceremony not found or expired")
	}
	var duration time.Duration
	if values := request.Header.Values(ApprovalDurationHeader); len(values) > 0 {
		session := service.sessions[ceremony.sessionID]
		minutes, err := strconv.Atoi(values[0])
		if len(values) != 1 || err != nil || session == nil || session.Provider != "approval" ||
			session.State != AwaitingPasskey || !session.ExpiresAt.After(service.now()) ||
			!slices.Contains(approvalDurations(session.profile), minutes) {
			service.mu.Unlock()
			return errors.New("invalid REST approval duration")
		}
		duration = time.Duration(minutes) * time.Minute
	}
	delete(service.ceremonies, token)
	service.mu.Unlock()
	if ceremony.sessionID != "" {
		if err := service.passkeys.finishLogin(ceremony.data, request, ceremony.credentials); err != nil {
			return fmt.Errorf("verify passkey: %w", err)
		}
		service.mu.Lock()
		session := service.sessions[ceremony.sessionID]
		if session == nil || session.subject != subject || session.State != AwaitingPasskey {
			service.mu.Unlock()
			return errors.New("emergency session is unavailable")
		}
		if !session.ExpiresAt.After(service.now()) {
			service.mu.Unlock()
			return errors.New("session expired during passkey verification")
		}
		previousExpiry := session.ExpiresAt
		if duration > 0 {
			session.ExpiresAt = service.now().UTC().Add(duration)
		}
		err := service.transitionLocked(request.Context(), session, Active, "session.activated")
		if err != nil {
			session.ExpiresAt = previousExpiry
		}
		service.mu.Unlock()
		return err
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	proof, err := service.ownedSession(subject, ceremony.proofSessionID)
	if err != nil || proof.State != Active || proof.Authentication != "totp" || !proof.ExpiresAt.After(service.now()) || service.closed {
		return errors.New("passkey enrollment proof is no longer active")
	}
	_, err = service.passkeys.finishRegistration(ceremony.data, request, ceremony.label)
	if err != nil {
		return fmt.Errorf("register passkey: %w", err)
	}
	return nil
}

func (service *Service) PruneJournal(ctx context.Context) error {
	service.mu.Lock()
	retention := service.journalRetention
	service.mu.Unlock()
	if retention == 0 {
		return nil
	}
	return service.events.prune(ctx, service.now().Add(-retention))
}

func (service *Service) Prune(ctx context.Context) error {
	now := service.now()
	var result error
	service.mu.Lock()
	var expired []revokedCredential
	var pending []struct{ subject, id string }
	attempted := make(map[string]bool)
	for id, current := range service.sessions {
		if current.operation != idle {
			continue
		}
		if current.State == RevocationPending {
			pending = append(pending, struct{ subject, id string }{current.subject, id})
			attempted[id] = true
			continue
		}
		if current.ExpiresAt.After(now) && !terminal(current.State) {
			continue
		}
		target, event := Expired, "session.expired"
		if terminal(current.State) {
			target, event = current.State, eventFor(current.State)
		}
		if !terminal(current.State) || current.withdrawalEventPending {
			if err := service.transitionLocked(ctx, current, target, event); err != nil {
				result = errors.Join(result, err)
				continue
			}
		}
		if current.accessToken != "" || current.boundSecret != "" {
			attempted[id] = true
			expired = append(expired, revokedCredential{id: current.ID, profile: current.profile, token: current.accessToken, secret: current.boundSecret})
		}
		delete(service.sessions, id)
	}
	for token, ceremony := range service.ceremonies {
		if !ceremony.expiresAt.After(now) {
			delete(service.ceremonies, token)
		}
	}
	service.mu.Unlock()
	for _, credential := range expired {
		result = errors.Join(result, service.revokeTrackedCredential(ctx, credential))
	}
	for _, session := range pending {
		if err := service.Revoke(ctx, session.subject, session.id); err != nil && !errors.Is(err, ErrSessionUnavailable) {
			result = errors.Join(result, fmt.Errorf("cleanup session %q: %w", session.id, err))
		}
	}
	return errors.Join(result, service.drainCleanupExcept(ctx, false, attempted))
}

func (service *Service) Get(ctx context.Context, subject, id string) (Session, error) {
	session, release, err := service.beginOperation(ctx, subject, id, polling)
	if err != nil {
		return Session{}, err
	}
	defer release()

	if !session.ExpiresAt.After(service.now()) && !terminal(session.State) && session.State != RevocationPending {
		if err = service.transitionLocked(ctx, session, Expired, eventFor(Expired)); err != nil {
			service.mu.Unlock()
			return Session{}, err
		}
	}
	copy := *session
	profile := session.profile
	if copy.State == Expired {
		service.mu.Unlock()
		err = service.revokeCredential(ctx, revokedCredential{id: id, profile: profile, token: copy.accessToken, secret: copy.boundSecret})
		if err == nil {
			service.mu.Lock()
			session.accessToken, session.boundSecret = "", ""
			service.mu.Unlock()
		}
		return publicSession(&copy), err
	}
	if session.State != AwaitingGitHub || session.nextPoll.After(service.now()) {
		service.mu.Unlock()
		return publicSession(&copy), nil
	}
	// Reserve exactly one exchange for this session. No other poll can overwrite
	// it; removal and expiry remain possible while network I/O is in progress.
	service.mu.Unlock()
	err = service.pollGitHub(ctx, &copy, profile)
	service.mu.Lock()
	current := service.sessions[id]
	valid := current == session && current.State == AwaitingGitHub && current.ExpiresAt.After(service.now())
	if err != nil {
		if valid && errors.Is(err, errScopeMismatch) {
			journalErr := service.transitionLocked(ctx, current, Invalidated, eventFor(Invalidated))
			if journalErr == nil {
				delete(service.sessions, id)
			}
			err = errors.Join(err, journalErr)
		}
		service.mu.Unlock()
		return Session{}, err
	}
	if !valid {
		service.mu.Unlock()
		cleanupErr := service.revokeCredential(context.WithoutCancel(ctx), revokedCredential{id: id, profile: profile, token: copy.accessToken, secret: copy.boundSecret})
		return Session{}, errors.Join(errors.New("session changed during authentication"), cleanupErr)
	}
	if copy.State == Active {
		if err = service.transitionLocked(ctx, current, Active, eventFor(Active)); err != nil {
			service.mu.Unlock()
			_ = service.revokeCredential(context.WithoutCancel(ctx), revokedCredential{id: id, profile: profile, token: copy.accessToken})
			return Session{}, err
		}
	}
	*current = copy
	service.mu.Unlock()
	return publicSession(&copy), nil
}

func (service *Service) VerifyTOTP(subject, id, code string) (Session, error) {
	service.mu.Lock()
	session, err := service.ownedSession(subject, id)
	if err != nil {
		service.mu.Unlock()
		return Session{}, err
	}
	if session.State != AwaitingTOTP || !session.ExpiresAt.After(service.now()) {
		service.mu.Unlock()
		return Session{}, errors.New("session is not awaiting TOTP")
	}
	profile := session.profile
	secret, err := os.ReadFile(profile.TOTPSecretFile)
	if err != nil {
		service.mu.Unlock()
		return Session{}, fmt.Errorf("read TOTP secret: %w", err)
	}
	if err := service.verifyTOTPCode(strings.TrimSpace(string(secret)), code); err != nil {
		service.mu.Unlock()
		return Session{}, err
	}

	err = service.transitionLocked(context.Background(), session, Active, "session.activated")
	result := publicSession(session)
	service.mu.Unlock()
	return result, err
}

// RedeemApproval consumes an exact, active approval before the caller dispatches.
func (service *Service) RedeemApproval(ctx context.Context, subject, id, digest string) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	session, err := service.ownedSession(subject, id)
	if err != nil || service.closed || session.Provider != "approval" || session.State != Active ||
		!session.ExpiresAt.After(service.now()) || session.ApprovalDigest != digest || session.ApprovalUsed {
		return errors.New("approval is unavailable")
	}
	if err := service.record(ctx, "approval.redeemed", session); err != nil {
		return err
	}
	session.ApprovalUsed = true
	return nil
}

func (service *Service) Credential(ctx context.Context, subject, id string) (Credential, error) {
	session, release, err := service.beginOperation(ctx, subject, id, issuing)
	if err != nil {
		return Credential{}, err
	}
	defer release()

	if session.State != Active || !session.ExpiresAt.After(service.now()) {
		service.mu.Unlock()
		return Credential{}, errors.New("emergency session is not active")
	}
	profile := session.profile
	if profile.Provider == "github_user" {
		credential := Credential{Provider: profile.Provider, Token: session.accessToken, ExpiresAt: session.ExpiresAt}
		service.mu.Unlock()
		return credential, nil
	}
	if profile.Provider != "kubernetes" {
		service.mu.Unlock()
		return Credential{}, errors.New("session cannot issue credentials")
	}
	boundSecret := session.boundSecret
	ttl := session.ExpiresAt.Sub(service.now())
	if service.issuer == nil {
		service.mu.Unlock()
		return Credential{}, errors.New("Kubernetes emergency issuer is unavailable")
	}
	// Reserve cleanup before releasing the registry lock for external issuance.
	if boundSecret == "" {
		name, err := randomKubernetesName()
		if err != nil {
			service.mu.Unlock()
			return Credential{}, err
		}
		boundSecret = "keymint-emergency-" + name
		if err = service.rememberCredential(ctx, session.ID, profile, session.accessToken, boundSecret, session.ExpiresAt); err != nil {
			service.mu.Unlock()
			return Credential{}, err
		}
		session.boundSecret = boundSecret
	}
	service.mu.Unlock()
	token, secret, expiresAt, err := service.issuer.Issue(ctx, profile.Namespace, profile.ServiceAccount, ttl, boundSecret)
	service.mu.Lock()
	if service.sessions[id] != session || session.State != Active || !session.ExpiresAt.After(service.now()) || service.closed {
		service.mu.Unlock()
		cleanupErr := service.revokeCredential(context.WithoutCancel(ctx), revokedCredential{id: id, profile: profile, token: session.accessToken, secret: boundSecret})
		return Credential{}, errors.Join(errors.New("session changed during credential issuance"), cleanupErr)
	}
	if err != nil {
		service.mu.Unlock()
		return Credential{}, err
	}
	if err := service.rememberCredential(ctx, session.ID, profile, session.accessToken, secret, session.ExpiresAt); err != nil {
		_ = service.issuer.Revoke(context.WithoutCancel(ctx), profile.Namespace, secret)
		service.mu.Unlock()
		return Credential{}, err
	}
	session.boundSecret = secret
	if session.ExpiresAt.Before(expiresAt) {
		expiresAt = session.ExpiresAt
	}
	service.mu.Unlock()
	return Credential{Provider: profile.Provider, Token: token, ExpiresAt: expiresAt}, nil
}

// Authorize verifies that a session belongs to the caller and still represents
// completed human authentication without issuing or exposing its credential.
func (service *Service) Authorize(subject, id string) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	session, err := service.ownedSession(subject, id)
	if err != nil {
		return err
	}
	if service.closed || session.Provider == "approval" || session.State != Active || !session.ExpiresAt.After(service.now()) {
		return errors.New("emergency session is not active")
	}
	return nil
}

// GitHubAuthorization keeps an OAuth credential bound to its original API.
// It is internal broker authority, never serialized in a sealing response.
type GitHubAuthorization struct {
	Token      string
	APIBaseURL string
}

// AuthorizeOrganizationSecret requires an active GitHub user session whose
// effective requested scopes permit organization secrets. It never issues a
// Kubernetes credential or broadens a restricted emergency session.
func (service *Service) AuthorizeOrganizationSecret(subject, id string) (GitHubAuthorization, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	session, err := service.ownedSession(subject, id)
	if err != nil || service.closed || session.State != Active || !session.ExpiresAt.After(service.now()) || session.profile.Provider != "github_user" || session.accessToken == "" {
		return GitHubAuthorization{}, errors.New("an active GitHub user session is required for organization secrets")
	}
	scopes := session.Scopes
	if len(scopes) == 0 {
		scopes = session.profile.Scopes
	}
	if !slices.Contains(scopes, "admin:org") {
		return GitHubAuthorization{}, errors.New("GitHub session must allow admin:org for organization secrets")
	}
	return GitHubAuthorization{Token: session.accessToken, APIBaseURL: session.profile.APIBaseURL}, nil
}

func (service *Service) Revoke(ctx context.Context, subject, id string) error {
	session, release, err := service.beginOperation(ctx, subject, id, revoking)
	if err != nil {
		return err
	}
	defer release()
	if terminal(session.State) {
		defer service.mu.Unlock()
		if session.State == Revoked && session.withdrawalEventPending {
			if err := service.transitionLocked(ctx, session, Revoked, eventFor(Revoked)); err != nil {
				return err
			}
			delete(service.sessions, id)
		}
		return nil
	}
	if session.State != RevocationPending || session.withdrawalEventPending {
		err = service.transitionLocked(ctx, session, RevocationPending, eventFor(RevocationPending))
		if err != nil {
			service.mu.Unlock()
			return err
		}
	}
	credential := revokedCredential{id: id, profile: session.profile, token: session.accessToken, secret: session.boundSecret}
	service.mu.Unlock()
	err = service.revokeTrackedCredential(ctx, credential)
	service.mu.Lock()
	defer service.mu.Unlock()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRevocationPending, err)
	}
	session.accessToken, session.boundSecret = "", ""
	if terminal(session.State) {
		if !session.withdrawalEventPending {
			delete(service.sessions, id)
		}
		return nil
	}
	if err = service.transitionLocked(ctx, session, Revoked, eventFor(Revoked)); err != nil {
		return err
	}
	delete(service.sessions, id)
	return nil
}

func (service *Service) Events(ctx context.Context, subject, after string, wait time.Duration) (EventPage, error) {
	return service.events.watch(ctx, subject, after, wait)
}

func (service *Service) record(ctx context.Context, eventType string, session *Session) error {
	return service.events.append(ctx, Event{
		Type: eventType, SessionID: session.ID, Subject: session.subject,
		Profile: session.Profile, Provider: session.Provider, State: session.State,
		ApprovalDigest: session.ApprovalDigest, ExpiresAt: session.ExpiresAt, OccurredAt: service.now().UTC(),
	})
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
		Scope       string `json:"scope"`
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
	// Stage cleanup immediately after exchange, before identity/scope validation.
	if err := service.rememberCredential(ctx, session.ID, profile, token.AccessToken, "", service.now()); err != nil {
		_ = service.revokeCredential(context.WithoutCancel(ctx), revokedCredential{profile: profile, token: token.AccessToken})
		return fmt.Errorf("persist credential cleanup: %w", err)
	}
	if len(session.Scopes) > 0 {
		granted := strings.FieldsFunc(token.Scope, func(r rune) bool { return r == ',' || r == ' ' })
		slices.Sort(granted)
		granted = slices.Compact(granted)
		if !slices.Equal(granted, session.Scopes) {
			_ = service.revokeCredential(ctx, revokedCredential{id: session.ID, profile: profile, token: token.AccessToken})
			return errScopeMismatch
		}
	}
	userID, err := service.githubUserID(ctx, profile, token.AccessToken)
	if err != nil {
		_ = service.revokeCredential(ctx, revokedCredential{id: session.ID, profile: profile, token: token.AccessToken})
		return err
	}
	if !containsID(allowedUserIDs, userID) {
		_ = service.revokeCredential(ctx, revokedCredential{id: session.ID, profile: profile, token: token.AccessToken})
		return errors.New("authenticated GitHub user is not allowed for this profile")
	}
	if err := service.rememberCredential(ctx, session.ID, profile, token.AccessToken, "", session.ExpiresAt); err != nil {
		return err
	}
	session.accessToken, session.State = token.AccessToken, Active
	return nil
}

// ValidateProfileFiles checks file-backed authentication inputs without activating a session.
func ValidateProfileFiles(profile config.EmergencyProfile) error {
	switch profile.AuthenticationMethod() {
	case "github_device":
		_, _, _, err := githubIdentity(profile)
		return err
	case "totp":
		value, err := os.ReadFile(profile.TOTPSecretFile)
		if err != nil {
			return err
		}
		defer clear(value)
		secret := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(string(value)), " ", ""))
		decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
		defer clear(decoded)
		if err != nil || len(decoded) < 16 {
			return errors.New("TOTP secret must contain at least 16 base32-encoded bytes")
		}
	}
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

func (service *Service) revokeCredential(ctx context.Context, credential revokedCredential) (result error) {
	started := time.Now()
	defer func() { service.metrics.ObserveOperation("credential_revoke", started, result) }()
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
					result = errors.Join(result, fmt.Errorf("revoke GitHub token: HTTP %d", response.StatusCode))
				}
			}
		}
	}
	if credential.secret != "" && service.issuer != nil {
		result = errors.Join(result, service.issuer.Revoke(ctx, credential.profile.Namespace, credential.secret))
	}
	if result == nil && credential.id != "" {
		result = service.cleanup.remove(ctx, credential.id)
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
		return fmt.Errorf("upstream returned HTTP %d", response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target)
}

func validTOTP(secret, code string, now time.Time) bool {
	_, ok := totpStep(secret, code, now)
	return ok
}

func totpStep(secret, code string, now time.Time) (int64, bool) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil || len(decoded) < 16 || len(code) != 6 {
		return 0, false
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
			return int64(counter), true
		}
	}
	return 0, false
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
	copy.Scopes = slices.Clone(session.Scopes)
	copy.subject, copy.deviceCode, copy.accessToken, copy.boundSecret = "", "", "", ""
	copy.nextPoll, copy.pollEvery = time.Time{}, 0
	copy.profile = config.EmergencyProfile{}
	copy.gate = nil
	copy.operation = idle
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
