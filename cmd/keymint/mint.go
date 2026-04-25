package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newMintCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mint <key>",
		Short: "Mint an installation token (CLI mode)",
		Long: `Mint a short-lived GitHub App installation token for the named key
in the keymint config and print it to stdout.

Reads the App private key on demand from the SOPS-encrypted file
referenced by the key's config entry. The plaintext key never persists
to disk; it lives in memory only for the duration of the mint call.`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return fmt.Errorf("mint: not implemented yet (key=%q) — see PR series in WG-119", args[0])
		},
	}
	cmd.Flags().StringP("config", "c", "", "path to keymint config (default: $HOME/.config/keymint/config.yaml)")
	return cmd
}
