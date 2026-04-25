package main

import (
	"github.com/jr200-labs/keymint/internal/version"
	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the keymint version",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Println(version.Version)
		},
	}
}
