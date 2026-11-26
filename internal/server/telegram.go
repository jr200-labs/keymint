package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/emergency"
	"github.com/jr200-labs/keymint/internal/logging"
	"github.com/skip2/go-qrcode"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

type telegramAction struct {
	Action    string    `json:"action"`
	ID        string    `json:"id"`
	OwnerID   int64     `json:"owner_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Password  string    `json:"password,omitempty"`
}

type telegramStatus struct {
	State     string    `json:"state"`
	LoginURL  string    `json:"login_url,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

var defaultTelegramRelayClient = &http.Client{
	Timeout: 8 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type telegramObservation struct {
	action, outcome, enrollmentID, state string
}

func (s *Server) observeTelegram(r *http.Request, observation *telegramObservation, started time.Time) {
	duration := time.Since(started)
	action, outcome := observation.action, observation.outcome
	if s.metrics != nil {
		s.metrics.TelegramRequests.WithLabelValues(action, outcome).Inc()
		s.metrics.TelegramDuration.WithLabelValues(action).Observe(duration.Seconds())
	}
	span := trace.SpanFromContext(r.Context())
	span.SetAttributes(attribute.String("keymint.telegram.action", action), attribute.String("keymint.telegram.outcome", outcome))
	if observation.state != "" {
		span.SetAttributes(attribute.String("keymint.telegram.state", observation.state))
	}

	logger := logging.FromContext(r.Context())
	fields := []zap.Field{zap.String("action", action), zap.String("outcome", outcome), zap.Duration("duration", duration)}
	if observation.enrollmentID != "" {
		fields = append(fields, zap.String("enrollment_id", observation.enrollmentID))
	}
	if observation.state != "" {
		fields = append(fields, zap.String("state", observation.state))
	}
	switch outcome {
	case "control_key_unavailable", "wrapping_key_unavailable", "relay_url_invalid", "relay_timeout",
		"relay_unreachable", "relay_http_error", "relay_invalid_response", "qr_invalid_token", "qr_render_error", "internal_error":
		logger.Warn("Telegram request failed", fields...)
	case "success":
		switch action {
		case "approval", "start", "password", "commit", "cancel", "wrapping_key":
			logger.Info("Telegram request completed", fields...)
		case "status":
			switch observation.state {
			case "enrolled", "expired", "failed", "canceled", "cancelled":
				logger.Info("Telegram enrollment state observed", fields...)
			}
		}
	default:
		logger.Debug("Telegram request rejected", fields...)
	}
}

func telegramEnrollmentAction(method, action string) string {
	switch method {
	case http.MethodGet:
		switch action {
		case "status", "qr":
			return action
		}
	case http.MethodPost:
		switch action {
		case "start", "commit", "cancel", "password":
			return action
		}
	}
	return "unknown"
}

func telegramObservedState(state string) string {
	switch state {
	case "starting", "qr", "password_required", "verifying", "verified", "committing",
		"enrolled", "expired", "failed", "canceled", "cancelled":
		return state
	default:
		return "unknown"
	}
}

func telegramApproval(name string, relay config.TelegramRelay) (string, string) {
	label := fmt.Sprintf("Enroll Telegram account %d for relay %s", relay.OwnerID, name)
	digest := sha256.Sum256(fmt.Appendf(nil, "keymint.telegram-enrollment.v1\x00%s\x00%d\x00%s\x00%s", name, relay.OwnerID, relay.URL, relay.RelaySubject))
	return fmt.Sprintf("%x", digest), label
}

func (s *Server) handleTelegramApproval(w http.ResponseWriter, r *http.Request) {
	observation := telegramObservation{action: "approval", outcome: "internal_error"}
	defer s.observeTelegram(r, &observation, time.Now())
	w.Header().Set("Cache-Control", "no-store")
	relay, ok := s.telegramOperator(w, r)
	if !ok {
		observation.outcome = "access_denied"
		return
	}
	digest, label := telegramApproval(r.PathValue("relay"), relay.config)
	session, err := s.emergency.CreateApproval(r.Context(), relay.subject, relay.config.ApprovalProfile, config.MinApprovalTTL, digest, label)
	if err != nil {
		observation.outcome = "approval_unavailable"
		writeJSONError(w, http.StatusForbidden, "Telegram enrollment approval is unavailable")
		return
	}
	observation.outcome, observation.enrollmentID, observation.state = "success", session.ID, string(emergency.AwaitingPasskey)
	writeJSON(w, session)
}

type telegramOperator struct {
	subject string
	config  config.TelegramRelay
}

func (s *Server) telegramOperator(w http.ResponseWriter, r *http.Request) (telegramOperator, bool) {
	subject, ok := s.emergencySubject(w, r)
	if !ok {
		return telegramOperator{}, false
	}
	relay, ok := s.currentConfig().TelegramRelays[r.PathValue("relay")]
	if !ok || relay.OperatorSubject != subject {
		writeJSONError(w, http.StatusForbidden, "Telegram enrollment is unavailable")
		return telegramOperator{}, false
	}
	return telegramOperator{subject: subject, config: relay}, true
}

func (s *Server) handleTelegramEnrollment(w http.ResponseWriter, r *http.Request) {
	name, id := r.PathValue("relay"), r.PathValue("id")
	action := telegramEnrollmentAction(r.Method, r.PathValue("action"))
	observation := telegramObservation{action: action, outcome: "internal_error"}
	defer s.observeTelegram(r, &observation, time.Now())
	w.Header().Set("Cache-Control", "no-store")
	operator, ok := s.telegramOperator(w, r)
	if !ok {
		observation.outcome = "access_denied"
		return
	}
	if action == "unknown" {
		observation.outcome = "unknown_action"
		http.NotFound(w, r)
		return
	}
	digest, label := telegramApproval(name, operator.config)
	relayAction := telegramAction{Action: action, ID: id, OwnerID: operator.config.OwnerID}
	switch action {
	case "qr":
		relayAction.Action = "status"
	case "password":
		var input struct {
			Password string `json:"password"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.Password == "" || len(input.Password) > 1024 {
			observation.outcome = "invalid_password_request"
			writeJSONError(w, http.StatusBadRequest, "Telegram password is required")
			return
		}
		relayAction.Password = input.Password
	}
	session, err := s.emergency.Get(r.Context(), operator.subject, id)
	if err != nil || session.State != emergency.Active || session.Profile != operator.config.ApprovalProfile ||
		session.ApprovalDigest != digest || session.ApprovalLabel != label ||
		!session.ExpiresAt.After(time.Now()) || s.currentConfig().TelegramRelays[name] != operator.config {
		observation.outcome = "approval_required"
		writeJSONError(w, http.StatusForbidden, "active passkey approval for this Telegram relay is required")
		return
	}
	observation.enrollmentID = session.ID
	relayAction.ExpiresAt = session.ExpiresAt
	if !session.ApprovalUsed {
		if action != "start" || s.emergency.RedeemApproval(r.Context(), operator.subject, id, digest) != nil {
			observation.outcome = "approval_not_redeemed"
			writeJSONError(w, http.StatusConflict, "start the approved Telegram enrollment first")
			return
		}
	}
	status, failure := s.callTelegramRelay(r, operator.config, relayAction)
	if failure != nil {
		observation.outcome = failure.outcome
		writeJSONError(w, failure.status, failure.message)
		return
	}
	observation.state = telegramObservedState(status.State)
	if action == "qr" {
		observation.outcome = writeTelegramQR(w, status, r.Header.Get("Accept") == "text/plain")
		return
	}
	observation.outcome = "success"
	status.LoginURL = ""
	writeJSON(w, status)
}

type telegramRelayFailure struct {
	status  int
	outcome string
	message string
}

func (s *Server) callTelegramRelay(r *http.Request, relay config.TelegramRelay, action telegramAction) (telegramStatus, *telegramRelayFailure) {
	var status telegramStatus
	key, err := readTelegramKey(relay.ControlKeyFile)
	if err != nil {
		return status, &telegramRelayFailure{http.StatusServiceUnavailable, "control_key_unavailable", "Telegram relay control key is unavailable"}
	}
	defer clear(key)
	body, err := json.Marshal(action)
	if err != nil {
		return status, &telegramRelayFailure{http.StatusBadRequest, "internal_error", "invalid Telegram enrollment request"}
	}
	defer clear(body)
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, relay.URL+"/v1/enrollment", bytes.NewReader(body))
	if err != nil {
		return status, &telegramRelayFailure{http.StatusServiceUnavailable, "relay_url_invalid", "Telegram relay URL is invalid"}
	}
	request.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(key))
	request.Header.Set("Content-Type", "application/json")
	response, err := s.telegramRelayClient.Do(request)
	if err != nil {
		outcome := "relay_unreachable"
		if timeout, ok := err.(*url.Error); ok && timeout.Timeout() {
			outcome = "relay_timeout"
		}
		return status, &telegramRelayFailure{http.StatusBadGateway, outcome, "Telegram relay is unreachable"}
	}
	defer func() { _ = response.Body.Close() }()
	switch response.StatusCode {
	case http.StatusOK:
		if json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&status) == nil && status.State != "" {
			return status, nil
		}
		return status, &telegramRelayFailure{http.StatusBadGateway, "relay_invalid_response", "Telegram relay could not process enrollment"}
	case http.StatusConflict:
		return status, &telegramRelayFailure{http.StatusConflict, "relay_conflict", "Telegram relay rejected this enrollment state"}
	}
	return status, &telegramRelayFailure{http.StatusBadGateway, "relay_http_error", "Telegram relay could not process enrollment"}
}

func writeTelegramQR(w http.ResponseWriter, status telegramStatus, terminal bool) string {
	login, err := url.Parse(status.LoginURL)
	if err != nil || status.State != "qr" || !status.ExpiresAt.After(time.Now()) ||
		login.Scheme != "tg" || login.Host != "login" || login.Path != "" || login.User != nil || login.Fragment != "" ||
		len(login.Query()) != 1 || len(login.Query()["token"]) != 1 {
		writeJSONError(w, http.StatusConflict, "Telegram QR is not ready")
		return "qr_not_ready"
	}
	encodedToken := login.Query().Get("token")
	token, err := base64.RawURLEncoding.DecodeString(encodedToken)
	if err != nil {
		// Some Telegram client libraries include base64url padding.
		token, err = base64.URLEncoding.DecodeString(encodedToken)
	}
	if err != nil || len(token) == 0 {
		writeJSONError(w, http.StatusBadGateway, "Telegram relay returned an invalid QR token")
		return "qr_invalid_token"
	}
	qr, err := qrcode.New(login.String(), qrcode.Medium)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "Telegram QR could not be rendered")
		return "qr_render_error"
	}
	if terminal {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, qr.ToSmallString(true))
		return "success"
	}
	png, err := qr.PNG(320)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "Telegram QR could not be rendered")
		return "qr_render_error"
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(png)))
	_, _ = w.Write(png)
	return "success"
}

func (s *Server) handleTelegramWrappingKey(w http.ResponseWriter, r *http.Request) {
	observation := telegramObservation{action: "wrapping_key", outcome: "internal_error"}
	defer s.observeTelegram(r, &observation, time.Now())
	w.Header().Set("Cache-Control", "no-store")
	snapshot := s.snapshot.Load()
	subject, failure := s.auth.authenticate(r.Context(), r, snapshot.trustedProxies)
	if failure != nil {
		observation.outcome = "access_denied"
		writeJSONError(w, failure.status, failure.message)
		return
	}
	relay, ok := snapshot.cfg.TelegramRelays[r.PathValue("relay")]
	if !ok || subject != relay.RelaySubject {
		observation.outcome = "access_denied"
		writeJSONError(w, http.StatusForbidden, "Telegram wrapping key is unavailable")
		return
	}
	key, err := readTelegramKey(relay.WrappingKeyFile)
	if err != nil {
		observation.outcome = "wrapping_key_unavailable"
		writeJSONError(w, http.StatusServiceUnavailable, "Telegram wrapping key is unavailable")
		return
	}
	defer clear(key)
	if s.snapshot.Load() != snapshot {
		observation.outcome = "policy_changed"
		writeJSONError(w, http.StatusConflict, "Telegram relay policy changed")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(key)))
	observation.outcome = "success"
	_, _ = w.Write(key)
}

// ValidateTelegramRelayFiles checks the mounted relay key pair without exposing it.
func ValidateTelegramRelayFiles(relay config.TelegramRelay) error {
	control, err := readTelegramKey(relay.ControlKeyFile)
	if err != nil {
		return fmt.Errorf("control key: %w", err)
	}
	defer clear(control)
	wrapping, err := readTelegramKey(relay.WrappingKeyFile)
	if err != nil {
		return fmt.Errorf("wrapping key: %w", err)
	}
	defer clear(wrapping)
	if bytes.Equal(control, wrapping) {
		return errors.New("control and wrapping keys must be distinct")
	}
	return nil
}

func readTelegramKey(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	encoded, err := io.ReadAll(io.LimitReader(file, 129))
	defer clear(encoded)
	if err != nil || len(encoded) > 128 {
		return nil, errors.New("invalid Telegram key file")
	}
	encodedTrimmed := bytes.TrimSpace(encoded)
	key := make([]byte, base64.StdEncoding.DecodedLen(len(encodedTrimmed)))
	n, err := base64.StdEncoding.Decode(key, encodedTrimmed)
	if err != nil || n != 32 {
		clear(key)
		return nil, errors.New("invalid Telegram key")
	}
	return key[:n], nil
}
