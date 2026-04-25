package main

import (
	"context"
	"os"

	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/mint"
	"github.com/jr200-labs/keymint/internal/sops"
)

// mintForKey is the shared pipeline used by `keymint mint <key>` and
// `keymint helper`: read the PEM (via SOPS or plaintext file), parse
// it, and call mint.Mint with the Key's IDs and API base URL.
//
// Splitting it out here keeps the cobra subcommands focused on flag
// handling and lets the credential helper subcommand re-use the same
// flow without depending on internal/mint or internal/sops.
func mintForKey(ctx context.Context, k config.Key) (mint.Token, error) {
	pemBytes, err := readPEM(ctx, k)
	if err != nil {
		return mint.Token{}, err
	}

	privateKey, err := mint.ParsePrivateKey(pemBytes)
	if err != nil {
		return mint.Token{}, err
	}

	return mint.Mint(ctx, mint.Request{
		AppID:          k.AppID,
		InstallationID: k.InstallationID,
		PrivateKey:     privateKey,
		APIBaseURL:     k.APIBaseURL,
	})
}

// readPEM resolves the PEM bytes for a key entry. Precedence:
// private_key_sops over private_key_file. Validation in config.Load
// guarantees at least one is set.
func readPEM(ctx context.Context, k config.Key) ([]byte, error) {
	if k.PrivateKeySOPS != "" {
		return sops.Decrypt(ctx, k.PrivateKeySOPS)
	}
	return os.ReadFile(k.PrivateKeyFile)
}
