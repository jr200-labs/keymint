package main

import (
	"context"
	"os"
	"time"

	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/credhelper"
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
	var (
		configPath string
		timeout    time.Duration
	)

	cmd := &cobra.Command{
		Use:   "helper [get|store|erase]",
		Short: "Git credential helper entrypoint",
		Long: `Implements git's credential helper protocol. When git invokes
keymint as a credential helper for a github.com remote, keymint
matches the remote URL against configured keys (by github_owner) and
mints a fresh installation token, returning it as the password.

Wire it up with:

    git config --global credential.https://github.com.helper "keymint helper"
    git config --global credential.https://github.com.useHttpPath true

The useHttpPath setting is required so git includes the repo path
when calling the helper — without it every github.com remote looks
identical and keymint cannot tell which org's App should sign the
token.

Only the "get" action mints. "store" and "erase" no-op because
keymint mints fresh tokens on demand and does not persist them.
`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			action := "get"
			if len(args) == 1 {
				action = args[0]
			}

			switch action {
			case "store", "erase":
				return credhelper.NoOp(os.Stdin, os.Stdout)
			case "get":
				cfg, err := config.Load(configPath)
				if err != nil {
					return err
				}

				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				defer cancel()

				return credhelper.Get(ctx, os.Stdin, os.Stdout, cfg, func(ctx context.Context, k config.Key) (string, error) {
					tok, err := mintForKey(ctx, k)
					if err != nil {
						return "", err
					}
					return tok.Token, nil
				})
			default:
				// Unknown actions: per the protocol, exit cleanly so git
				// can fall through to the next helper.
				return credhelper.NoOp(os.Stdin, os.Stdout)
			}
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to keymint config (default: $XDG_CONFIG_HOME/keymint/config.yaml)")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "overall mint timeout for the get action")

	return cmd
}
