package sops

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// withRunner swaps the package-level runner for the duration of t.
func withRunner(t *testing.T, fn func(ctx context.Context, args ...string) ([]byte, error)) {
	t.Helper()
	saved := runner
	runner = fn
	t.Cleanup(func() { runner = saved })
}

func TestDecrypt_ShellsOutWithCorrectArgs(t *testing.T) {
	var capturedArgs []string
	withRunner(t, func(_ context.Context, args ...string) ([]byte, error) {
		capturedArgs = args
		return []byte("plaintext-pem"), nil
	})

	got, err := Decrypt(context.Background(), "/path/to/key.sops.pem")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "plaintext-pem" {
		t.Errorf("got %q, want plaintext-pem", got)
	}
	wantArgs := []string{"-d", "--", "/path/to/key.sops.pem"}
	if !equal(capturedArgs, wantArgs) {
		t.Errorf("args = %v, want %v", capturedArgs, wantArgs)
	}
}

func TestDecrypt_PropagatesError(t *testing.T) {
	withRunner(t, func(_ context.Context, _ ...string) ([]byte, error) {
		return nil, errors.New("synthetic decrypt failure")
	})

	_, err := Decrypt(context.Background(), "/whatever.sops.pem")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "synthetic") {
		t.Errorf("error should propagate runner failure: %v", err)
	}
}

func TestDecrypt_RejectsEmptyPath(t *testing.T) {
	if _, err := Decrypt(context.Background(), ""); err == nil {
		t.Errorf("expected error on empty path")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
