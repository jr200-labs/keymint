package emergency

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestRandomKubernetesNameIsDNSLabelSafe(t *testing.T) {
	valid := regexp.MustCompile(`^[a-f0-9]{18}$`)
	for range 256 {
		name, err := randomKubernetesName()
		if err != nil {
			t.Fatal(err)
		}
		if !valid.MatchString(name) {
			t.Fatalf("random Kubernetes name %q is not a lowercase DNS-label-safe hexadecimal value", name)
		}
	}
}

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
		_, _ = writer.Write([]byte(`{"kind":"Status"}`))
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
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if !info.Reused {
				t.Error("issuer did not reuse connection after deleting without decoding a body")
			}
		},
	})
	if err := issuer.request(ctx, http.MethodDelete, "/api/v1/second", nil, nil); err != nil {
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

func TestKubernetesIssuerUsesIPv6HostAndBoundedTransport(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, certificate, 0600); err != nil {
		t.Fatal(err)
	}
	issuer, err := newKubernetesIssuer("fd00::1", "6443", caPath)
	if err != nil {
		t.Fatal(err)
	}
	if issuer.apiServer != "https://[fd00::1]:6443" {
		t.Errorf("unexpected API URL: %q", issuer.apiServer)
	}
	transport := issuer.http.Transport.(*http.Transport)
	if transport.TLSHandshakeTimeout <= 0 || transport.ResponseHeaderTimeout <= 0 ||
		transport.IdleConnTimeout <= 0 || transport.MaxIdleConnsPerHost <= 0 {
		t.Error("missing Kubernetes transport bounds")
	}
}
