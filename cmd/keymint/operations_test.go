package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateServiceChecksFilesAndReloadInvariants(t *testing.T) {
	dir := t.TempDir()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "app.pem")
	content := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)})
	if err := os.WriteFile(keyFile, content, 0600); err != nil {
		t.Fatal(err)
	}
	writeConfig := func(name, audience, keyPath string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		yaml := fmt.Sprintf("expected_audiences: [%s]\nkeys:\n  app:\n    app_id: 1\n    install_id: 2\n    private_key_file: %q\n", audience, keyPath)
		if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	current := writeConfig("current.yaml", "keymint", keyFile)
	candidate := writeConfig("candidate.yaml", "changed", keyFile)
	missing := writeConfig("missing.yaml", "keymint", filepath.Join(dir, "missing.pem"))
	for _, tc := range []struct {
		path, against, want string
	}{
		{current, "", ""},
		{current, current, ""},
		{candidate, current, "require restart"},
		{missing, "", "read private_key_file"},
	} {
		cmd := newRootCmd()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		args := []string{"validate", "--service", "--config", tc.path}
		if tc.against != "" {
			args = append(args, "--against", tc.against)
		}
		cmd.SetArgs(args)
		err := cmd.Execute()
		if (tc.want == "" && err != nil) || (tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want))) {
			t.Errorf("args %v returned %v, want %q", args, err, tc.want)
		}
	}
}
