package emergency

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestKubernetesIssuerReadsRotatedServiceAccountTokenForEveryRequest(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("first-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	wantToken := "first-token"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer "+wantToken {
			t.Errorf("Authorization = %q, want bearer for current token", got)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	issuer := &KubernetesIssuer{apiServer: server.URL, tokenPath: tokenPath, http: server.Client()}
	if err := issuer.request(context.Background(), http.MethodDelete, "/api/v1/first", nil, nil); err != nil {
		t.Fatal(err)
	}

	wantToken = "rotated-token"
	if err := os.WriteFile(tokenPath, []byte(wantToken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := issuer.request(context.Background(), http.MethodDelete, "/api/v1/second", nil, nil); err != nil {
		t.Fatal(err)
	}
}

func TestKubernetesIssuerUsesAPIServerDefaultAudience(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("issuer-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/namespaces/operators/secrets":
			writer.WriteHeader(http.StatusCreated)
		case request.Method == http.MethodGet && request.URL.Path != "":
			_, _ = writer.Write([]byte(`{"metadata":{"uid":"secret-uid"}}`))
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/namespaces/operators/serviceaccounts/breakglass/token":
			var body struct {
				Spec map[string]any `json:"spec"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if _, exists := body.Spec["audiences"]; exists {
				t.Fatalf("TokenRequest hard-codes audiences: %#v", body.Spec["audiences"])
			}
			_, _ = writer.Write([]byte(`{"status":{"token":"cluster-token","expirationTimestamp":"2030-01-01T00:00:00Z"}}`))
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()

	issuer := &KubernetesIssuer{apiServer: server.URL, tokenPath: tokenPath, http: server.Client()}
	token, _, expiresAt, err := issuer.Issue(context.Background(), "operators", "breakglass", time.Minute, "")
	if err != nil || token != "cluster-token" || expiresAt.IsZero() {
		t.Fatalf("Issue() = token %q expires %v error %v", token, expiresAt, err)
	}
}
