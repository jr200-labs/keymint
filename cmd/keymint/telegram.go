package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var telegramRelayName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func newTelegramEnrollCmd() *cobra.Command {
	var origin, tokenFile string
	cmd := &cobra.Command{
		Use:   "telegram-enroll <relay>",
		Short: "Approve and enroll a Telegram account through Keymint",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			origin = strings.TrimSuffix(origin, "/")
			u, err := url.Parse(origin)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Path != "" ||
				u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !telegramRelayName.MatchString(args[0]) || tokenFile == "" {
				return errors.New("a Keymint HTTPS origin, relay name and operator token file are required")
			}
			if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
				return errors.New("Telegram enrollment requires a private interactive terminal")
			}
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer cancel()
			client := telegramEnrollmentClient{
				origin: origin, tokenFile: tokenFile,
				http: &http.Client{
					Timeout:       10 * time.Second,
					CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
				},
			}
			return client.enroll(ctx, args[0], cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&origin, "url", "", "Keymint HTTPS origin")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "audience-bound operator ServiceAccount token file")
	return cmd
}

type telegramEnrollmentClient struct {
	origin, tokenFile string
	http              *http.Client
}

type telegramEnrollmentState struct {
	ID              string    `json:"id"`
	State           string    `json:"state"`
	VerificationURI string    `json:"verification_uri"`
	ApprovalLabel   string    `json:"approval_label"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func (c telegramEnrollmentClient) enroll(ctx context.Context, relay string, out io.Writer) (err error) {
	path := "/telegram-enrollments/" + relay
	var state telegramEnrollmentState
	if err := c.getState(ctx, http.MethodPost, path, nil, &state); err != nil {
		return err
	}
	verification, err := url.Parse(state.VerificationURI)
	if err != nil || verification.Scheme != "https" || verification.Hostname() == "" || verification.User != nil ||
		!telegramRelayName.MatchString(state.ID) || state.State != "awaiting_passkey" {
		return errors.New("Keymint did not return a valid passkey ceremony")
	}
	path += "/" + state.ID
	_, _ = fmt.Fprintf(out, "%s\nApprove with your passkey at %s\n", state.ApprovalLabel, verification)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for state.State == "awaiting_passkey" {
		if err := waitForTelegramState(ctx, tick.C); err != nil {
			return err
		}
		if err := c.getState(ctx, http.MethodGet, "/emergency/sessions/"+state.ID, nil, &state); err != nil {
			return err
		}
	}
	if state.State != "active" {
		return fmt.Errorf("passkey approval ended in state %q", state.State)
	}
	defer func() {
		if err == nil {
			return
		}
		cancelCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, _, _ = c.request(cancelCtx, http.MethodPost, path+"/cancel", "application/json", nil)
	}()
	if err := c.getState(ctx, http.MethodPost, path+"/start", nil, &state); err != nil {
		return err
	}
	var shown time.Time
	for {
		switch state.State {
		case "qr":
			if !state.ExpiresAt.Equal(shown) && state.ExpiresAt.After(time.Now()) {
				qr, code, err := c.request(ctx, http.MethodGet, path+"/qr", "text/plain", nil)
				if err != nil {
					return err
				}
				if code == http.StatusOK {
					_, _ = fmt.Fprintf(out, "Scan with your already signed-in Telegram app.\n\x1b[30;47m%s\x1b[0m\n", bytes.ReplaceAll(qr, []byte("\n"), []byte("\x1b[0m\n\x1b[30;47m")))
					shown = state.ExpiresAt
				} else if code != http.StatusConflict {
					return fmt.Errorf("Keymint QR request returned HTTP %d", code)
				}
			}
		case "password_required":
			_, _ = fmt.Fprint(out, "Telegram two-step verification password: ")
			password, err := term.ReadPassword(int(os.Stdin.Fd()))
			_, _ = fmt.Fprintln(out)
			if err != nil {
				clear(password)
				return err
			}
			body, err := json.Marshal(map[string]string{"password": string(password)})
			clear(password)
			if err != nil {
				return err
			}
			err = c.getState(ctx, http.MethodPost, path+"/password", body, &state)
			clear(body)
			if err != nil {
				return err
			}
		case "verified":
			if err := c.getState(ctx, http.MethodPost, path+"/commit", nil, &state); err != nil {
				return err
			}
			if state.State == "enrolled" {
				continue
			}
		case "starting", "verifying", "committing":
		case "enrolled":
			_, _ = fmt.Fprintln(out, "Telegram account enrolled.")
			return nil
		default:
			return fmt.Errorf("Telegram enrollment ended in state %q", state.State)
		}
		if err := waitForTelegramState(ctx, tick.C); err != nil {
			return err
		}
		if err := c.getState(ctx, http.MethodGet, path+"/status", nil, &state); err != nil {
			return err
		}
	}
}

func (c telegramEnrollmentClient) getState(ctx context.Context, method, path string, body []byte, state *telegramEnrollmentState) error {
	response, status, err := c.request(ctx, method, path, "application/json", body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("Keymint enrollment request returned HTTP %d", status)
	}
	*state = telegramEnrollmentState{}
	if err := json.Unmarshal(response, state); err != nil || state.State == "" {
		return errors.New("Keymint returned an invalid enrollment state")
	}
	return nil
}

func (c telegramEnrollmentClient) request(ctx context.Context, method, path, accept string, body []byte) ([]byte, int, error) {
	file, err := os.Open(c.tokenFile)
	if err != nil {
		return nil, 0, err
	}
	token, err := io.ReadAll(io.LimitReader(file, 8193))
	_ = file.Close()
	defer clear(token)
	if err != nil || len(token) > 8192 || len(bytes.TrimSpace(token)) == 0 {
		return nil, 0, errors.New("invalid operator token file")
	}
	request, err := http.NewRequestWithContext(ctx, method, c.origin+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Authorization", "Bearer "+string(bytes.TrimSpace(token)))
	request.Header.Set("Accept", accept)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, 0, errors.New("Keymint enrollment endpoint is unreachable")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, response.StatusCode, nil
	}
	result, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	if err != nil || len(result) > 32768 {
		return nil, 0, errors.New("invalid Keymint enrollment response")
	}
	return result, response.StatusCode, nil
}

func waitForTelegramState(ctx context.Context, tick <-chan time.Time) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tick:
		return nil
	}
}
