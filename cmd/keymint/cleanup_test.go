package main

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestCleanupQuarantineRequiresExplicitSelection(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "missing.db")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--all"}, `"state-file" not set`},
		{[]string{"--state-file", dbPath}, "specify either"},
		{[]string{"--state-file", dbPath, "--session-id", " "}, "specify either"},
		{[]string{"--state-file", dbPath, "--session-id", "E-test", "--all"}, "specify either"},
	} {
		cmd := newCleanupQuarantineCmd()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(tc.args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("args %v returned %v, want %q", tc.args, err, tc.want)
		}
	}
}
