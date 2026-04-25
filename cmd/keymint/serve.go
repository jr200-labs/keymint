package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run keymint as an HTTP service (in-cluster mode)",
		Long: `Run keymint as an HTTP server. Validates inbound requests by
calling the Kubernetes TokenReview API with the caller's bearer token
and checking the resolved ServiceAccount against the allowlist in the
keymint config. Mints an installation token and returns it as JSON.

This mode is intended to run inside a Kubernetes cluster with the
"tokenreviews.authentication.k8s.io: create" RBAC permission. App
private keys are read from filesystem paths (mounted Secret), not from
SOPS files.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			return fmt.Errorf("serve: not implemented yet — see PR series in WG-119")
		},
	}
	cmd.Flags().String("listen", ":9999", "HTTP listen address")
	cmd.Flags().String("config", "/etc/keymint/config.yaml", "path to keymint config")
	cmd.Flags().String("log-level", "info", "log level: disabled|panic|fatal|error|warn|info|debug|trace")
	cmd.Flags().Bool("log-human", false, "human-readable log format (default: JSON)")
	return cmd
}
