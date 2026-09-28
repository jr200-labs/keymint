package releasekey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/jr200-labs/keymint/internal/config"
	"golang.org/x/crypto/nacl/box"
)

func TestSealReturnsDestinationBoundCiphertextWithoutPlaintext(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateText := base64.StdEncoding.EncodeToString(private.Seed())
	path := filepath.Join(t.TempDir(), "sparkle-seed")
	if err := os.WriteFile(path, []byte(privateText+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recipientPublic, recipientPrivate, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(config.ReleaseKey{
		PrivateKeyFile: path,
		SecretName:     "SPARKLE_EDDSA_PRIVATE_KEY",
	}, Destination{KeyID: "github-key-1", PublicKey: base64.StdEncoding.EncodeToString(recipientPublic[:])})
	if err != nil {
		t.Fatal(err)
	}
	if sealed.EncryptedValue == privateText || sealed.DestinationKey != "github-key-1" {
		t.Fatalf("invalid sealed metadata: %#v", sealed)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(sealed.EncryptedValue)
	if err != nil {
		t.Fatal(err)
	}
	opened, ok := box.OpenAnonymous(nil, ciphertext, recipientPublic, recipientPrivate)
	if !ok || string(opened) != privateText {
		t.Fatal("destination could not recover the exact Sparkle seed")
	}
	if sealed.PublicKey != base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)) {
		t.Fatal("derived public key does not match the seed")
	}
}

func TestSealRejectsNonSeedPrivateMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sparkle-seed")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(make([]byte, 64))), 0o600); err != nil {
		t.Fatal(err)
	}
	public, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Seal(config.ReleaseKey{PrivateKeyFile: path}, Destination{
		KeyID: "key", PublicKey: base64.StdEncoding.EncodeToString(public[:]),
	})
	if err == nil {
		t.Fatal("accepted a non-seed private key")
	}
}
