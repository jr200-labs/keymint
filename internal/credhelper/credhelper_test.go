package credhelper

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jr200-labs/keymint/internal/config"
)

func TestGet_HappyPath(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{
			"whengas": {
				AppID:          1,
				InstallationID: 1,
				PrivateKeyFile: "/tmp/whengas.pem",
				GitHubOwner:    "whengas",
			},
		},
	}

	called := 0
	mintFn := func(_ context.Context, k config.Key) (string, error) {
		called++
		if k.GitHubOwner != "whengas" {
			t.Errorf("mint called with wrong key: %v", k)
		}
		return "ghs_synthetic", nil
	}

	in := strings.NewReader(strings.Join([]string{
		"protocol=https",
		"host=github.com",
		"path=whengas/whengas-iac.git",
		"",
	}, "\n"))
	out := &bytes.Buffer{}

	if err := Get(context.Background(), in, out, cfg, mintFn); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if called != 1 {
		t.Errorf("mint called %d times, want 1", called)
	}
	got := out.String()
	if !strings.Contains(got, "username=x-access-token") {
		t.Errorf("output missing username line: %q", got)
	}
	if !strings.Contains(got, "password=ghs_synthetic") {
		t.Errorf("output missing password line: %q", got)
	}
}

func TestGet_NoMatchingKey(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{
			"whengas": {GitHubOwner: "whengas"},
		},
	}

	called := false
	mintFn := func(_ context.Context, _ config.Key) (string, error) {
		called = true
		return "", nil
	}

	in := strings.NewReader("protocol=https\nhost=github.com\npath=stranger/repo.git\n\n")
	out := &bytes.Buffer{}

	if err := Get(context.Background(), in, out, cfg, mintFn); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if called {
		t.Errorf("mint should not be called for unmatched key")
	}
	if got := out.String(); got != "" {
		t.Errorf("output should be empty when no key matches, got %q", got)
	}
}

func TestGet_MissingPath(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"whengas": {GitHubOwner: "whengas"}},
	}
	in := strings.NewReader("protocol=https\nhost=github.com\n\n")
	out := &bytes.Buffer{}

	err := Get(context.Background(), in, out, cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "useHttpPath") {
		t.Errorf("expected useHttpPath error, got %v", err)
	}
}

func TestGet_MissingHost(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"whengas": {GitHubOwner: "whengas"}},
	}
	in := strings.NewReader("protocol=https\n\n")
	out := &bytes.Buffer{}

	err := Get(context.Background(), in, out, cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "host") {
		t.Errorf("expected host error, got %v", err)
	}
}

func TestGet_MintError(t *testing.T) {
	cfg := &config.Config{
		Keys: map[string]config.Key{"whengas": {GitHubOwner: "whengas"}},
	}
	mintFn := func(_ context.Context, _ config.Key) (string, error) {
		return "", errors.New("synthetic mint failure")
	}
	in := strings.NewReader("protocol=https\nhost=github.com\npath=whengas/repo.git\n\n")
	out := &bytes.Buffer{}

	err := Get(context.Background(), in, out, cfg, mintFn)
	if err == nil || !strings.Contains(err.Error(), "synthetic") {
		t.Errorf("expected mint error to propagate, got %v", err)
	}
}

func TestGet_MalformedLine(t *testing.T) {
	// Lines without `=` are silently skipped per the protocol's
	// "be liberal in what you accept" guidance.
	cfg := &config.Config{
		Keys: map[string]config.Key{
			"whengas": {AppID: 1, InstallationID: 1, PrivateKeyFile: "/x", GitHubOwner: "whengas"},
		},
	}
	mintFn := func(_ context.Context, _ config.Key) (string, error) {
		return "ghs_x", nil
	}
	in := strings.NewReader(strings.Join([]string{
		"garbage line with no equals",
		"protocol=https",
		"host=github.com",
		"path=whengas/repo.git",
		"",
	}, "\n"))
	out := &bytes.Buffer{}

	if err := Get(context.Background(), in, out, cfg, mintFn); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !strings.Contains(out.String(), "ghs_x") {
		t.Errorf("expected token in output: %q", out.String())
	}
}

func TestNoOp(t *testing.T) {
	in := strings.NewReader("anything\n")
	out := &bytes.Buffer{}
	if err := NoOp(in, out); err != nil {
		t.Errorf("NoOp returned error: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("NoOp wrote output: %q", out.String())
	}
}

func TestReconstructURL(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]string
		want  string
	}{
		{"full", map[string]string{"protocol": "https", "host": "github.com", "path": "whengas/repo.git"}, "https://github.com/whengas/repo.git"},
		{"default protocol", map[string]string{"host": "github.com", "path": "whengas/repo.git"}, "https://github.com/whengas/repo.git"},
		{"no path", map[string]string{"protocol": "https", "host": "github.com"}, "https://github.com"},
		{"no host", map[string]string{"protocol": "https"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reconstructURL(tc.attrs); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
