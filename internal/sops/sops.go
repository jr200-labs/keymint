// Package sops decrypts SOPS-encrypted files by shelling out to the
// system `sops` binary.
//
// keymint deliberately shells out rather than embedding the SOPS Go
// library: SOPS users typically already have age keys configured in
// the canonical place (~/.config/sops/age/keys.txt or whatever the
// SOPS_AGE_KEY_FILE env var points at), and shelling out picks up
// that configuration for free. Embedding the library would mean
// reimplementing key discovery and risks divergence from the user's
// existing SOPS workflow.
//
// The plaintext key is returned in memory and is the caller's
// responsibility to use briefly and let GC reclaim. We never write
// plaintext to disk.
package sops

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

// runner is the function used to execute `sops`. Real usage hits
// exec.CommandContext; tests override this to return canned output
// without requiring sops to be installed.
var runner = realRunner

func realRunner(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "sops", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sops: %w (stderr: %s)", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// Decrypt runs `sops -d <path>` and returns the decrypted bytes.
//
// SOPS resolves keys via its own configuration: SOPS_AGE_KEY_FILE,
// SOPS_AGE_RECIPIENTS, ~/.config/sops/age/keys.txt, etc. keymint does
// not interpose; whatever the user has configured for `sops -d` works
// here too.
func Decrypt(ctx context.Context, path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("sops: empty path")
	}
	return runner(ctx, "-d", path)
}
