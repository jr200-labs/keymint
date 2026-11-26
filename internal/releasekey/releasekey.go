// Package releasekey seals recoverable release-signing material directly to
// a destination public key without exposing plaintext through Keymint's API.
package releasekey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/jr200-labs/keymint/internal/config"
	"github.com/jr200-labs/keymint/internal/githubsecret"
	"golang.org/x/crypto/nacl/box"
)

const maxPrivateKeyFile = 4096

type Destination = githubsecret.Destination

type Sealed struct {
	githubsecret.Target
	PublicKey      string `json:"public_key"`
	SecretName     string `json:"secret_name"`
	DestinationKey string `json:"destination_key_id"`
	EncryptedValue string `json:"encrypted_value"`
}

// Seal reads a Sparkle Ed25519 private-key export, validates and derives its
// public half, and encrypts the original base64 export using the anonymous
// NaCl box format required by GitHub Actions secrets. Sparkle exports 96 bytes:
// a 64-byte Ed25519 private key followed by its 32-byte public key.
func Seal(key config.ReleaseKey, destination Destination) (Sealed, error) {
	if destination.KeyID == "" || len(destination.KeyID) > 128 {
		return Sealed{}, errors.New("destination key identifier is invalid")
	}
	destinationBytes, err := base64.StdEncoding.DecodeString(destination.PublicKey)
	if err != nil || len(destinationBytes) != 32 {
		return Sealed{}, errors.New("destination public key is invalid")
	}
	privateText, public, err := readPrivateKey(key)
	if err != nil {
		return Sealed{}, err
	}
	defer clear(privateText)
	var recipient [32]byte
	copy(recipient[:], destinationBytes)
	ciphertext, err := box.SealAnonymous(nil, privateText, &recipient, rand.Reader)
	if err != nil {
		return Sealed{}, fmt.Errorf("seal release signing key: %w", err)
	}
	return Sealed{
		Target:         destination.Target,
		PublicKey:      base64.StdEncoding.EncodeToString(public),
		SecretName:     key.SecretName,
		DestinationKey: destination.KeyID,
		EncryptedValue: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// ValidateFile checks the signing key format without sealing or returning it.
func ValidateFile(key config.ReleaseKey) error {
	text, _, err := readPrivateKey(key)
	clear(text)
	return err
}

func readPrivateKey(key config.ReleaseKey) ([]byte, ed25519.PublicKey, error) {
	info, err := os.Stat(key.PrivateKeyFile)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPrivateKeyFile {
		return nil, nil, errors.New("release signing key is unavailable")
	}
	encoded, err := os.ReadFile(key.PrivateKeyFile)
	if err != nil {
		return nil, nil, errors.New("release signing key is unavailable")
	}
	defer clear(encoded)
	text := bytes.TrimSpace(encoded)
	bundle := make([]byte, base64.StdEncoding.DecodedLen(len(text)))
	defer clear(bundle)
	n, err := base64.StdEncoding.Decode(bundle, text)
	if err != nil || n != ed25519.PrivateKeySize+ed25519.PublicKeySize {
		return nil, nil, errors.New("release signing key has an invalid Sparkle Ed25519 export")
	}
	private := ed25519.NewKeyFromSeed(bundle[:ed25519.SeedSize])
	defer clear(private)
	public := private.Public().(ed25519.PublicKey)
	if !bytes.Equal(bundle[:ed25519.PrivateKeySize], private) ||
		!bytes.Equal(bundle[ed25519.PrivateKeySize:n], public) {
		return nil, nil, errors.New("release signing key has an inconsistent Sparkle Ed25519 export")
	}
	return bytes.Clone(text), public, nil
}
