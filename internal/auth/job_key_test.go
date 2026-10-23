package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestReadJobPublicKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public")
	if _, err := ReadJobPublicKey(path); err == nil {
		t.Fatal("accepted missing key")
	}
	for _, value := range []string{"", "bad", hex.EncodeToString(make([]byte, 31))} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadJobPublicKey(path); err == nil {
			t.Fatal("accepted malformed public key")
		}
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(public)), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadJobPublicKey(path)
	if err != nil || !public.Equal(got) {
		t.Fatal("could not read public key")
	}
}
