// Package releasekey seals recoverable release-signing material directly to
// a destination public key without exposing plaintext through Keymint's API.
package releasekey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jr200-labs/keymint/internal/config"
	"golang.org/x/crypto/nacl/box"
)

const maxPrivateKeyFile = 4096

type Destination struct {
	KeyID     string
	PublicKey string
}

type Sealed struct {
	PublicKey      string `json:"public_key"`
	SecretName     string `json:"secret_name"`
	DestinationKey string `json:"destination_key_id"`
	EncryptedValue string `json:"encrypted_value"`
}

// Seal reads a Sparkle Ed25519 seed, derives its public half, and encrypts the
// original base64 seed using the anonymous NaCl box format required by GitHub
// Actions secrets.
func Seal(key config.ReleaseKey, destination Destination) (Sealed, error) {
	if destination.KeyID == "" || len(destination.KeyID) > 128 {
		return Sealed{}, errors.New("destination key identifier is invalid")
	}
	destinationBytes, err := base64.StdEncoding.DecodeString(destination.PublicKey)
	if err != nil || len(destinationBytes) != 32 {
		return Sealed{}, errors.New("destination public key is invalid")
	}
	info, err := os.Stat(key.PrivateKeyFile)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPrivateKeyFile {
		return Sealed{}, errors.New("release signing key is unavailable")
	}
	encoded, err := os.ReadFile(key.PrivateKeyFile)
	if err != nil {
		return Sealed{}, errors.New("release signing key is unavailable")
	}
	privateText := strings.TrimSpace(string(encoded))
	seed, err := base64.StdEncoding.DecodeString(privateText)
	if err != nil || len(seed) != ed25519.SeedSize {
		return Sealed{}, errors.New("release signing key has an invalid Sparkle Ed25519 seed")
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	var recipient [32]byte
	copy(recipient[:], destinationBytes)
	ciphertext, err := box.SealAnonymous(nil, []byte(privateText), &recipient, rand.Reader)
	if err != nil {
		return Sealed{}, fmt.Errorf("seal release signing key: %w", err)
	}
	return Sealed{
		PublicKey:      base64.StdEncoding.EncodeToString(public),
		SecretName:     key.SecretName,
		DestinationKey: destination.KeyID,
		EncryptedValue: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}
