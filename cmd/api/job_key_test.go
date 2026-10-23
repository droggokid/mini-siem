package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestJobKeyCreatedAndReused(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "private", "job-seed")
	publicPath := filepath.Join(dir, "public", "job-public")
	key, err := readOrCreateJobKey(seedPath, publicPath)
	if err != nil {
		t.Fatal(err)
	}

	public, err := os.ReadFile(publicPath)
	if err != nil || string(public) != hex.EncodeToString(key.Public().(ed25519.PublicKey)) {
		t.Fatal("published key does not match private key")
	}
	info, err := os.Stat(seedPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private seed must have mode 0600")
	}

	if err := os.Chmod(seedPath, 0400); err != nil {
		t.Fatal(err)
	}
	reused, err := readOrCreateJobKey(seedPath, publicPath)
	if err != nil || !bytes.Equal(key, reused) {
		t.Fatal("startup replaced private key")
	}

	if err := os.WriteFile(publicPath, []byte("mismatched"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readOrCreateJobKey(seedPath, publicPath); err == nil {
		t.Fatal("accepted mismatched public key")
	}
	unchanged, err := os.ReadFile(publicPath)
	if err != nil || string(unchanged) != "mismatched" {
		t.Fatal("overwrote mismatched public key")
	}
}

func TestJobKeyRejectsInvalidSeed(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed")
	publicPath := filepath.Join(dir, "public")
	for _, value := range []string{"short", "not hexadecimal secret material"} {
		if err := os.WriteFile(seedPath, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readOrCreateJobKey(seedPath, publicPath); err == nil {
			t.Fatal("accepted invalid seed")
		}
		if _, err := os.Stat(publicPath); !os.IsNotExist(err) {
			t.Fatal("published a key for invalid seed")
		}
	}
}
