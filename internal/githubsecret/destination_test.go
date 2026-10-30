package githubsecret

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveBindsScopeToTrustedEndpoint(t *testing.T) {
	for _, scope := range []Scope{Repository, Organization} {
		t.Run(string(scope), func(t *testing.T) {
			target := Target{Owner: "example-org", Repository: "example-app", Scope: scope}
			expected := "/api/v3/repos/example-org/example-app/actions/secrets/public-key"
			if scope == Organization {
				expected = "/api/v3/orgs/example-org/actions/secrets/public-key"
			}
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != expected || r.Header.Get("Authorization") != "Bearer synthetic" {
					t.Errorf("unexpected lookup: %s", r.URL.Path)
				}
				_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "trusted", "key": base64.StdEncoding.EncodeToString(make([]byte, 32))})
			}))
			defer upstream.Close()
			got, err := Resolve(context.Background(), upstream.Client(), upstream.URL+"/api/v3/", "synthetic", target)
			if err != nil || got.Target != target || got.KeyID != "trusted" {
				t.Fatalf("destination=%#v err=%v", got, err)
			}
		})
	}
}

func TestResolveRejectsRedirectsAndInvalidMetadata(t *testing.T) {
	for _, mode := range []string{"redirect", "missing_id", "bad_key", "forbidden"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				switch mode {
				case "redirect":
					http.Redirect(w, r, "/elsewhere", http.StatusFound)
				case "forbidden":
					w.WriteHeader(http.StatusForbidden)
				case "missing_id":
					_ = json.NewEncoder(w).Encode(map[string]string{"key": base64.StdEncoding.EncodeToString(make([]byte, 32))})
				default:
					_ = json.NewEncoder(w).Encode(map[string]string{"key_id": "id", "key": "invalid"})
				}
			}))
			defer upstream.Close()
			if _, err := Resolve(context.Background(), upstream.Client(), upstream.URL, "synthetic", Target{"example-org", "example-app", Organization}); err == nil {
				t.Fatal("unsafe lookup accepted")
			}
			if calls != 1 {
				t.Fatalf("redirect followed: calls=%d", calls)
			}
		})
	}
	for _, target := range []Target{{"owner", "repo", "environment"}, {"..", "repo", Repository}, {"owner", "../repo", Organization}} {
		if _, err := Resolve(context.Background(), nil, "https://api.github.com", "synthetic", target); err == nil {
			t.Fatalf("invalid target accepted: %#v", target)
		}
	}
	for _, base := range []string{"http://example.test", "https://user:secret@example.test", "https://example.test?url=other"} {
		if _, err := APIBase(base); err == nil {
			t.Fatalf("unsafe authority accepted: %s", base)
		}
	}
}
