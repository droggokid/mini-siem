package auth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
)

func ReadJobPublicKey(path string) (ed25519.PublicKey, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read job public key")
	}

	// Reject malformed key-file contents before using them to verify delegated authority.
	public, err := hex.DecodeString(string(bytes.TrimSpace(encoded)))
	if err != nil || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("invalid job public key")
	}

	return ed25519.PublicKey(public), nil
}
