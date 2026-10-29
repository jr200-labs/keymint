package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServiceConfigRequiresRecoverableEmergencyStorage(t *testing.T) {
	base := "keys:\n  app:\n    app_id: 1\n    install_id: 2\n    private_key_file: /run/key.pem\n"
	emergency := "emergency_profiles:\n  ops:\n    provider: kubernetes\n    namespace: ops\n    service_account: admin\n    totp_secret_file: /run/totp\n"
	for _, tc := range []struct {
		name, yaml string
		valid      bool
	}{{"routine", base, true}, {"missing cleanup", base + emergency, false}, {"durable", base + emergency + "emergency_state_file: /data/events.db\n", true}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := loadServiceConfig(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v error=%v", tc.valid, err)
			}
		})
	}
}
