package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jr200-labs/keymint/internal/mint"
	"github.com/spf13/cobra"
)

// newMintCmd implements `keymint mint` — the CLI entrypoint that signs
// a fresh GitHub App JWT, exchanges it for an installation token, and
// prints the token to stdout.
//
// At this stage of the rollout there is no config-file loader yet
// (config + SOPS lands in a follow-up PR), so the user passes app-id
// / install-id / key-file as flags. The positional <key> argument is
// reserved for forward compatibility with the eventual config-driven
// flow.
func newMintCmd() *cobra.Command {
	var (
		appID      int64
		installID  int64
		keyFile    string
		apiBaseURL string
		timeout    time.Duration
	)

	cmd := &cobra.Command{
		Use:   "mint <key>",
		Short: "Mint an installation token (CLI mode)",
		Long: `Mint a short-lived GitHub App installation token and print it
to stdout.

The positional <key> argument is the name of a key entry in the
keymint config (config-file support lands in a follow-up PR — for
now, pass --app-id / --install-id / --key-file directly).

Example:

    keymint mint whengas \
      --app-id      3495091 \
      --install-id  126859631 \
      --key-file    ~/.config/github-app/whengas.pem
`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			if appID == 0 || installID == 0 || keyFile == "" {
				return errors.New("--app-id, --install-id, and --key-file are required (config-file support lands in a follow-up PR)")
			}

			pemBytes, err := os.ReadFile(keyFile)
			if err != nil {
				return fmt.Errorf("read key file: %w", err)
			}
			privateKey, err := mint.ParsePrivateKey(pemBytes)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			tok, err := mint.Mint(ctx, mint.Request{
				AppID:          appID,
				InstallationID: installID,
				PrivateKey:     privateKey,
				APIBaseURL:     apiBaseURL,
			})
			if err != nil {
				return err
			}

			fmt.Println(tok.Token)
			return nil
		},
	}

	cmd.Flags().Int64Var(&appID, "app-id", 0, "GitHub App ID (required)")
	cmd.Flags().Int64Var(&installID, "install-id", 0, "GitHub App installation ID (required)")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "path to the App's PEM private key (required)")
	cmd.Flags().StringVar(&apiBaseURL, "api-base-url", "", "GitHub API base URL (default: https://api.github.com)")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")

	return cmd
}
