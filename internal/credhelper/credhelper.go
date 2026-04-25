// Package credhelper implements the git credential helper protocol so
// that `git config credential.helper "keymint helper"` can transparently
// supply short-lived GitHub App tokens for `git push` / `git fetch` /
// `gh` invocations against the right org.
//
// Protocol reference:
//
//	https://git-scm.com/docs/gitcredentials
//	https://git-scm.com/docs/git-credential
//
// Git invokes the helper with an action ("get", "store", "erase").
// For each action git writes attribute=value lines to the helper's
// stdin, terminated by a blank line, and reads the helper's response
// from stdout in the same format.
//
// We only meaningfully implement "get". "store" and "erase" no-op
// because keymint mints fresh tokens on demand and never persists
// them.
//
// Important: by default git only sends `host` (not `path`) to
// credential helpers. To route requests to the right App when the
// host is `github.com` for both, the user MUST enable path-aware
// credentials:
//
//	git config --global credential.https://github.com.useHttpPath true
//
// Without that, every github.com remote looks identical to the
// helper and we cannot tell which App's token to mint.
package credhelper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/jr200-labs/keymint/internal/config"
)

// MintFunc takes a Config Key entry and returns a fresh installation
// token string. It is injected so this package does not depend on
// internal/mint or internal/sops directly — keeping the seams clean
// for testing and avoiding a circular import if the mint pipeline
// ever grows.
type MintFunc func(ctx context.Context, key config.Key) (token string, err error)

// Get implements the "get" action. It reads attribute=value lines
// from input until a blank line, looks up the matching Key in cfg by
// the reconstructed remote URL, mints a token, and writes the
// resulting credentials to output.
func Get(ctx context.Context, in io.Reader, out io.Writer, cfg *config.Config, mint MintFunc) error {
	attrs, err := parseAttributes(in)
	if err != nil {
		return err
	}

	url := reconstructURL(attrs)
	if url == "" {
		return errors.New("credhelper: missing host attribute from git")
	}

	if attrs["path"] == "" {
		return fmt.Errorf("credhelper: git did not send `path` for %s — set credential.useHttpPath=true; see README", attrs["host"])
	}

	_, key, ok := cfg.FindByGitHubURL(url)
	if !ok {
		// No matching key configured. Per the protocol we exit cleanly
		// without writing anything; git will then fall through to the
		// next configured helper or prompt the user.
		return nil
	}

	tok, err := mint(ctx, *key)
	if err != nil {
		return fmt.Errorf("credhelper: mint: %w", err)
	}

	return writeCredentials(out, tok)
}

// NoOp implements the "store" and "erase" actions. keymint does not
// persist tokens, so both are silent successes.
func NoOp(_ io.Reader, _ io.Writer) error {
	return nil
}

// parseAttributes reads attribute=value lines from r until a blank
// line or EOF.
func parseAttributes(r io.Reader) (map[string]string, error) {
	attrs := make(map[string]string)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			// Per the protocol, malformed lines are tolerated; skip.
			continue
		}
		attrs[line[:idx]] = line[idx+1:]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("credhelper: read input: %w", err)
	}
	return attrs, nil
}

// reconstructURL builds an HTTPS-style URL from the credential
// attributes git sent. Returns empty string if host is missing.
func reconstructURL(attrs map[string]string) string {
	host := attrs["host"]
	if host == "" {
		return ""
	}
	protocol := attrs["protocol"]
	if protocol == "" {
		protocol = "https"
	}
	path := attrs["path"]
	if path == "" {
		return fmt.Sprintf("%s://%s", protocol, host)
	}
	return fmt.Sprintf("%s://%s/%s", protocol, host, path)
}

// writeCredentials emits the username + password lines git expects.
// GitHub installation tokens use a fixed username "x-access-token".
func writeCredentials(w io.Writer, token string) error {
	if _, err := fmt.Fprintf(w, "username=x-access-token\npassword=%s\n", token); err != nil {
		return fmt.Errorf("credhelper: write output: %w", err)
	}
	return nil
}
