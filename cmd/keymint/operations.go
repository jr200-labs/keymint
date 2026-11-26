package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/emergency"
	"github.com/jr200-labs/keymint/internal/mint"
	"github.com/jr200-labs/keymint/internal/releasekey"
	"github.com/jr200-labs/keymint/internal/server"
	"github.com/spf13/cobra"
)

func newValidateCmd() *cobra.Command {
	var path, against string
	var service bool
	cmd := &cobra.Command{
		Use: "validate", Short: "Validate configuration and optionally check service deployment files",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(path)
			if err != nil {
				return err
			}
			if against != "" && !service {
				return errors.New("--against requires --service")
			}
			if service {
				if err := cfg.ValidateService(); err != nil {
					return err
				}
				if against != "" {
					current, err := loadServiceConfig(against)
					if err != nil {
						return err
					}
					if err := cfg.ValidateReloadFrom(current); err != nil {
						return err
					}
				}
				if err := validateServiceFiles(cfg); err != nil {
					return err
				}
			}
			cmd.Println("Configuration is valid")
			return nil
		},
	}
	cmd.Flags().StringVarP(&path, "config", "c", "", "Path to config.yaml")
	cmd.Flags().BoolVar(&service, "service", false, "Check service invariants and mounted files")
	cmd.Flags().StringVar(&against, "against", "", "Check whether the candidate can hot-reload over this service configuration")
	return cmd
}

func validateServiceFiles(cfg *config.Config) error {
	for name, key := range cfg.Keys {
		data, err := os.ReadFile(key.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("key %q: read private_key_file: %w", name, err)
		}
		parsed, err := mint.ParsePrivateKey(data)
		clear(data)
		if _, ok := parsed.(*rsa.PrivateKey); err != nil || !ok {
			return fmt.Errorf("key %q: private_key_file must contain an RSA private key", name)
		}
	}
	for name, key := range cfg.ReleaseKeys {
		if err := releasekey.ValidateFile(key); err != nil {
			return fmt.Errorf("release key %q: %w", name, err)
		}
	}
	for name, profile := range cfg.EmergencyProfiles {
		if err := emergency.ValidateProfileFiles(profile); err != nil {
			return fmt.Errorf("emergency profile %q: %w", name, err)
		}
	}
	for name, relay := range cfg.TelegramRelays {
		if err := server.ValidateTelegramRelayFiles(relay); err != nil {
			return fmt.Errorf("telegram relay %q: %w", name, err)
		}
	}
	if cfg.Passkeys != nil {
		keys, err := emergency.ListPasskeys(cfg.Passkeys.StateFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		ids := make(map[string]bool, len(keys))
		for _, key := range keys {
			ids[key.ID] = !key.CloneWarning
		}
		for name, profile := range cfg.EmergencyProfiles {
			for _, id := range profile.PasskeyCredentials {
				if !ids[id] {
					return fmt.Errorf("emergency profile %q: passkey credential %s is missing or flagged", name, id)
				}
			}
		}
	}
	return nil
}

func newCleanupStatusCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use: "cleanup-status", Short: "List pending and quarantined emergency cleanup records",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			status, err := emergency.InspectCleanup(cmd.Context(), path)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(status)
		},
	}
	cmd.Flags().StringVar(&path, "state-file", "", "Path to the existing emergency state database")
	_ = cmd.MarkFlagRequired("state-file")
	return cmd
}

func newPasskeysCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{Use: "passkeys", Short: "Inspect or update the passkey state file"}
	cmd.PersistentFlags().StringVar(&path, "state-file", "", "Path to the existing passkey state file")
	list := &cobra.Command{
		Use: "list", Short: "List passkey IDs and labels", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			keys, err := emergency.ListPasskeys(path)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(keys)
		},
	}
	revoke := &cobra.Command{
		Use: "revoke <credential-id>", Short: "Remove a passkey while the Keymint service is stopped", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := emergency.RevokePasskey(path, args[0]); err != nil {
				return err
			}
			cmd.Println("Passkey revoked")
			return nil
		},
	}
	cmd.AddCommand(list, revoke)
	return cmd
}
