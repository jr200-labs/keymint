package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newHelperCmd implements the git credential helper protocol so that
// `git config credential.helper "keymint helper"` routes credentials
// for github.com remotes through keymint mint.
//
// The protocol is documented at
// https://git-scm.com/docs/gitcredentials#_custom_helpers — keymint
// reads `protocol`, `host`, `path` from stdin, looks up the matching
// key entry, mints a token, and writes `username=x-access-token` +
// `password=<token>` back to stdout.
func newHelperCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "helper",
		Short: "Git credential helper entrypoint",
		Long: `Implements git's credential helper protocol. When git invokes
keymint as a credential helper for a github.com remote, keymint matches
the remote URL against configured keys and mints a fresh installation
token, returning it as the password.

Wire it up with:

    git config --global credential.https://github.com.helper "!keymint helper"

The helper subcommand is also exposed as a standalone binary
"git-credential-keymint" so git can find it via PATH.`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("helper: not implemented yet — see PR series in WG-119")
		},
	}
	cmd.Flags().StringP("config", "c", "", "path to keymint config (default: $HOME/.config/keymint/config.yaml)")
	return cmd
}
