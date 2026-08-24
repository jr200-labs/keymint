package emergency

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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
