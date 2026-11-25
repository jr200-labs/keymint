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
	"github.com/skip2/go-qrcode"
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

func telegramApproval(name string, relay config.TelegramRelay) (string, string) {
	label := fmt.Sprintf("Enroll Telegram account %d for relay %s", relay.OwnerID, name)
	digest := sha256.Sum256(fmt.Appendf(nil, "keymint.telegram-enrollment.v1\x00%s\x00%d\x00%s\x00%s", name, relay.OwnerID, relay.URL, relay.RelaySubject))
	return fmt.Sprintf("%x", digest), label
}

func (s *Server) handleTelegramApproval(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	relay, ok := s.telegramOperator(w, r)
	if !ok {
		return
	}
	digest, label := telegramApproval(r.PathValue("relay"), relay.config)
	session, err := s.emergency.CreateApproval(r.Context(), relay.subject, relay.config.ApprovalProfile, config.MinApprovalTTL, digest, label)
	if err != nil {
		writeJSONError(w, http.StatusForbidden, "Telegram enrollment approval is unavailable")
		return
	}
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
	w.Header().Set("Cache-Control", "no-store")
	operator, ok := s.telegramOperator(w, r)
	if !ok {
		return
	}
	name, id, action := r.PathValue("relay"), r.PathValue("id"), r.PathValue("action")
	digest, label := telegramApproval(name, operator.config)
	relayAction := telegramAction{Action: action, ID: id, OwnerID: operator.config.OwnerID}
	if r.Method == http.MethodGet {
		if action != "status" && action != "qr" {
			http.NotFound(w, r)
			return
		}
		relayAction.Action = "status"
	} else {
		switch action {
		case "start", "commit", "cancel":
		case "password":
			var input struct {
				Password string `json:"password"`
			}
			decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.Password == "" || len(input.Password) > 1024 {
				writeJSONError(w, http.StatusBadRequest, "Telegram password is required")
				return
			}
			relayAction.Password = input.Password
		default:
			http.NotFound(w, r)
			return
		}
	}
	session, err := s.emergency.Get(r.Context(), operator.subject, id)
	if err != nil || session.State != emergency.Active || session.Profile != operator.config.ApprovalProfile ||
		session.ApprovalDigest != digest || session.ApprovalLabel != label ||
		!session.ExpiresAt.After(time.Now()) || s.currentConfig().TelegramRelays[name] != operator.config {
		writeJSONError(w, http.StatusForbidden, "active passkey approval for this Telegram relay is required")
		return
	}
	relayAction.ExpiresAt = session.ExpiresAt
	if !session.ApprovalUsed {
		if action != "start" || s.emergency.RedeemApproval(r.Context(), operator.subject, id, digest) != nil {
			writeJSONError(w, http.StatusConflict, "start the approved Telegram enrollment first")
			return
		}
	}
	status, code, err := s.callTelegramRelay(r, operator.config, relayAction)
	if err != nil {
		writeJSONError(w, code, err.Error())
		return
	}
	if action == "qr" {
		writeTelegramQR(w, status, r.Header.Get("Accept") == "text/plain")
		return
	}
	status.LoginURL = ""
	writeJSON(w, status)
}

func (s *Server) callTelegramRelay(r *http.Request, relay config.TelegramRelay, action telegramAction) (telegramStatus, int, error) {
	var status telegramStatus
	key, err := readTelegramKey(relay.ControlKeyFile)
	if err != nil {
		return status, http.StatusServiceUnavailable, errors.New("Telegram relay control key is unavailable")
	}
	defer clear(key)
	body, err := json.Marshal(action)
	if err != nil {
		return status, http.StatusBadRequest, errors.New("invalid Telegram enrollment request")
	}
	defer clear(body)
	request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, relay.URL+"/v1/enrollment", bytes.NewReader(body))
	if err != nil {
		return status, http.StatusServiceUnavailable, errors.New("Telegram relay URL is invalid")
	}
	request.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(key))
	request.Header.Set("Content-Type", "application/json")
	response, err := s.telegramRelayClient.Do(request)
	if err != nil {
		return status, http.StatusBadGateway, errors.New("Telegram relay is unreachable")
	}
	defer func() { _ = response.Body.Close() }()
	switch response.StatusCode {
	case http.StatusOK:
		if json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&status) == nil && status.State != "" {
			return status, http.StatusOK, nil
		}
	case http.StatusConflict:
		return status, http.StatusConflict, errors.New("Telegram relay rejected this enrollment state")
	}
	return status, http.StatusBadGateway, errors.New("Telegram relay could not process enrollment")
}

func writeTelegramQR(w http.ResponseWriter, status telegramStatus, terminal bool) {
	login, err := url.Parse(status.LoginURL)
	if err != nil || status.State != "qr" || !status.ExpiresAt.After(time.Now()) ||
		login.Scheme != "tg" || login.Host != "login" || login.Path != "" || login.User != nil || login.Fragment != "" ||
		len(login.Query()) != 1 || len(login.Query()["token"]) != 1 {
		writeJSONError(w, http.StatusConflict, "Telegram QR is not ready")
		return
	}
	token, err := base64.RawURLEncoding.DecodeString(login.Query().Get("token"))
	if err != nil || len(token) == 0 {
		writeJSONError(w, http.StatusBadGateway, "Telegram relay returned an invalid QR token")
		return
	}
	qr, err := qrcode.New(login.String(), qrcode.Medium)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "Telegram QR could not be rendered")
		return
	}
	if terminal {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, qr.ToSmallString(true))
		return
	}
	png, err := qr.PNG(320)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "Telegram QR could not be rendered")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(png)))
	_, _ = w.Write(png)
}

func (s *Server) handleTelegramWrappingKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	snapshot := s.snapshot.Load()
	subject, failure := s.auth.authenticate(r.Context(), r, snapshot.trustedProxies)
	if failure != nil {
		writeJSONError(w, failure.status, failure.message)
		return
	}
	relay, ok := snapshot.cfg.TelegramRelays[r.PathValue("relay")]
	if !ok || subject != relay.RelaySubject {
		writeJSONError(w, http.StatusForbidden, "Telegram wrapping key is unavailable")
		return
	}
	key, err := readTelegramKey(relay.WrappingKeyFile)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "Telegram wrapping key is unavailable")
		return
	}
	defer clear(key)
	if s.snapshot.Load() != snapshot {
		writeJSONError(w, http.StatusConflict, "Telegram relay policy changed")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(key)))
	_, _ = w.Write(key)
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
