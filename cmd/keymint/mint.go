package main

import (
	"context"
	"fmt"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
	"github.com/spf13/cobra"
)

// newMintCmd implements `keymint mint <key>` — the CLI entrypoint
// that loads the keymint config, finds the named key, decrypts its
// PEM (via SOPS or plaintext file), and prints a fresh installation
// token to stdout.
func newMintCmd() *cobra.Command {
	var (
		configPath string
		timeout    time.Duration
	)

	cmd := &cobra.Command{
		Use:   "mint <key>",
		Short: "Mint an installation token (CLI mode)",
		Long: `Mint a short-lived GitHub App installation token for the named key
in the keymint config and print it to stdout.

The PEM private key is read on demand. If the key entry has
private_key_sops set, keymint shells out to ` + "`sops -d`" + ` to decrypt
it; if private_key_file is set, the PEM is read from disk in
plaintext. The plaintext key is held in memory for the duration of
the mint call only.

Example config (~/.config/keymint/config.yaml):

    keys:
      whengas:
        app_id:           3495091
        install_id:       126859631
        private_key_sops: ~/.config/keymint/whengas.sops.pem
        github_owner:     whengas

Then:

    keymint mint whengas
`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			keyName := args[0]

			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}

			entry, ok := cfg.Keys[keyName]
			if !ok {
				return fmt.Errorf("mint: key %q not found in config", keyName)
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			tok, err := mintForKey(ctx, entry)
			if err != nil {
				return err
			}

			fmt.Println(tok.Token)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to keymint config (default: $XDG_CONFIG_HOME/keymint/config.yaml)")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "overall mint timeout (decrypt + JWT + GitHub round-trip)")

	return cmd
}
