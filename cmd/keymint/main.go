package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "keymint",
		Short: "Mint short-lived GitHub App installation tokens",
		Long: `keymint is a small broker for GitHub App installation tokens.

It runs in two modes:

  CLI mode (laptop):
      keymint mint <key>            # print a fresh installation token to stdout
      keymint helper                # git credential helper protocol

  Service mode (in-cluster):
      keymint serve --listen :9999  # HTTP server, validates k8s SA via TokenReview

Both modes share the same config schema and signing logic. Source of truth
for App private keys is operator-supplied (SOPS-encrypted file on laptop,
mounted Secret in-cluster).`,
		SilenceUsage: true,
	}

	root.AddCommand(newMintCmd())
	root.AddCommand(newServeCmd())
	root.AddCommand(newHelperCmd())
	root.AddCommand(newVersionCmd())

	return root
}
