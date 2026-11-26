package main

import (
	"errors"
	"strings"

	"github.com/jr200-labs/keymint/internal/emergency"
	"github.com/spf13/cobra"
)

func newCleanupQuarantineCmd() *cobra.Command {
	var stateFile, sessionID string
	var all bool
	cmd := &cobra.Command{
		Use:   "cleanup-quarantine",
		Short: "Move emergency cleanup records out of the retry queue",
		Long: "Move encrypted emergency cleanup records out of the retry queue while Keymint is stopped. " +
			"Quarantine does not revoke credentials. Revoke them separately before quarantining their records.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if all == (strings.TrimSpace(sessionID) != "") || (all && cmd.Flags().Changed("session-id")) {
				return errors.New("specify either --session-id or --all")
			}
			count, err := emergency.QuarantineCleanup(cmd.Context(), stateFile, sessionID)
			if err != nil {
				return err
			}
			cmd.Printf("Quarantined %d cleanup record(s)\n", count)
			return nil
		},
	}
	cmd.Flags().StringVar(&stateFile, "state-file", "", "Path to the existing emergency state database")
	cmd.Flags().StringVar(&sessionID, "session-id", "", "Session ID to quarantine")
	cmd.Flags().BoolVar(&all, "all", false, "Quarantine all pending cleanup records")
	_ = cmd.MarkFlagRequired("state-file")
	return cmd
}
