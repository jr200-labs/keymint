package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTelegramEnrollmentClientCompletesApprovalQRAndCommit(t *testing.T) {
	const base = "/telegram-enrollments/owner/E-test"
	tokenFile := filepath.Join(t.TempDir(), "operator-token")
	if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var requestsMu sync.Mutex
	var requests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestsMu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		requestsMu.Unlock()
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("operator token missing")
		}
		state := telegramEnrollmentState{ID: "E-test"}
		switch r.URL.Path {
		case "/telegram-enrollments/owner":
			state.State, state.VerificationURI, state.ApprovalLabel = "awaiting_passkey", "https://keymint.example/verify#test", "Approve test account"
		case "/emergency/sessions/E-test":
			state.State = "active"
		case base + "/start":
			state.State, state.ExpiresAt = "qr", time.Now().Add(time.Minute)
		case base + "/qr":
			if r.Header.Get("Accept") != "text/plain" {
				t.Error("terminal QR was not requested")
			}
			_, _ = w.Write([]byte("test QR"))
			return
		case base + "/status":
			state.State = "verified"
		case base + "/commit":
			state.State = "enrolled"
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(state)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := telegramEnrollmentClient{origin: server.URL, tokenFile: tokenFile, http: server.Client()}
	var output bytes.Buffer
	if err := client.enroll(ctx, "owner", &output); err != nil {
		t.Fatal(err)
	}
	want := []string{"POST /telegram-enrollments/owner", "GET /emergency/sessions/E-test", "POST " + base + "/start",
		"GET " + base + "/qr", "GET " + base + "/status", "POST " + base + "/commit"}
	requestsMu.Lock()
	defer requestsMu.Unlock()
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("enrollment requests = %v, want %v", requests, want)
	}
	for _, text := range []string{"Approve test account", "test QR", "Telegram account enrolled."} {
		if !strings.Contains(output.String(), text) {
			t.Errorf("enrollment output missing %q", text)
		}
	}
}
