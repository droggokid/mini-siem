package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

func readOrCreateJobKey(seedPath, publicPath string) (ed25519.PrivateKey, error) {
	encoded, err := readOrCreateJWTSecret(seedPath)
	if err != nil {
		return nil, err
	}

	// Validate the encoded seed and exact key size before constructing a signing key.
	seed, err := hex.DecodeString(string(bytes.TrimSpace(encoded)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid job signing seed")
	}

	key := ed25519.NewKeyFromSeed(seed)
	public := []byte(hex.EncodeToString(key.Public().(ed25519.PublicKey)))

	existing, err := os.ReadFile(publicPath)
	if err == nil {
		// Fail on mismatched key material instead of silently replacing a verifier's key.
		if !bytes.Equal(bytes.TrimSpace(existing), public) {
			return nil, errors.New("job public key does not match signing seed")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err = os.MkdirAll(filepath.Dir(publicPath), 0700); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(publicPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return nil, err
	}

	_, writeErr := file.Write(public)
	if err = errors.Join(writeErr, file.Close()); err != nil {
		return nil, err
	}

	return key, nil
}
