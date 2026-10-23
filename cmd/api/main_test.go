package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsInvalidSigningSecret(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	weak := filepath.Join(dir, "weak-secret")
	if err := os.WriteFile(weak, []byte("weak-secret-material"), 0600); err != nil {
		t.Fatal(err)
	}
	invalid := filepath.Join(dir, "whitespace-secret")
	if err := os.WriteFile(invalid, []byte(strings.Repeat(" ", 32)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ name, path string }{
		{"unreadable", dir},
		{"weak", weak},
		{"invalid", invalid},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before, _ := os.ReadFile(tt.path)
			t.Setenv("JWT_SECRET_FILE", tt.path)
			db := filepath.Join(dir, tt.name+".db")
			t.Setenv("USERS_DB_PATH", db)
			err := run()
			if err == nil || strings.Contains(err.Error(), "weak-secret-material") {
				t.Fatal("startup must reject invalid configuration without exposing secret material")
			}
			if _, err := os.Stat(db); !os.IsNotExist(err) {
				t.Fatal("startup opened a database before checking the signing secret")
			}
			after, _ := os.ReadFile(tt.path)
			if !bytes.Equal(before, after) {
				t.Fatal("startup changed an existing invalid secret")
			}
		})
	}
}

func TestRunCreatesAndReusesSigningSecret(t *testing.T) {
	for _, configured := range []bool{false, true} {
		name := "default"
		if configured {
			name = "configured"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			path := filepath.Join(".secrets", "jwt-secret")
			t.Setenv("JWT_SECRET_FILE", "")
			if configured {
				path = filepath.Join(dir, "data", "jwt-secret")
				t.Setenv("JWT_SECRET_FILE", path)
			}
			t.Setenv("USERS_DB_PATH", filepath.Join(dir, "missing", "users.db"))
			if err := run(); err == nil || !strings.Contains(err.Error(), "users") {
				t.Fatalf("startup did not create a signing secret before opening the users database: %v", err)
			}
			secret, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := hex.DecodeString(string(secret))
			if err != nil || len(decoded) != 32 {
				t.Fatal("generated secret must encode 32 random bytes as hex")
			}
			for file, mode := range map[string]os.FileMode{path: 0600, filepath.Dir(path): 0700} {
				info, err := os.Stat(file)
				if err != nil || info.Mode().Perm() != mode {
					t.Fatalf("%s must have mode %o: %v", file, mode, err)
				}
			}
			if err := os.Chmod(path, 0400); err != nil {
				t.Fatal(err)
			}
			if err := run(); err == nil || !strings.Contains(err.Error(), "users") {
				t.Fatalf("startup did not reuse the read-only signing secret: %v", err)
			}
			reused, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(secret, reused) {
				t.Fatal("startup changed the signing secret")
			}
		})
	}
}

func TestRunRejectsUncreatableSigningSecret(t *testing.T) {
	dir := t.TempDir()
	parent := filepath.Join(dir, "file")
	if err := os.WriteFile(parent, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_SECRET_FILE", filepath.Join(parent, "jwt-secret"))
	db := filepath.Join(dir, "users.db")
	t.Setenv("USERS_DB_PATH", db)
	if err := run(); err == nil {
		t.Fatal("startup must reject an uncreatable signing secret")
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Fatal("startup opened a database without a signing secret")
	}
}

func TestRunUsesDefaultSigningSecret(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("JWT_SECRET_FILE", "")
	t.Setenv("USERS_DB_PATH", filepath.Join(dir, "missing", "users.db"))
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(".secrets", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(".secrets", "jwt-secret"), []byte(" \n"+hex.EncodeToString(secret)+"\n "), 0444); err != nil {
		t.Fatal(err)
	}
	// An unwritable database path stops startup after the default secret is loaded.
	if err := run(); err == nil || !strings.Contains(err.Error(), "users") {
		t.Fatal("startup did not load the default signing secret before opening the users database")
	}
}

func TestRunUsesConfiguredSigningSecret(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	path := filepath.Join(dir, "configured-secret")
	if err := os.WriteFile(path, []byte(strings.Repeat("s", 32)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_SECRET_FILE", path)
	t.Setenv("USERS_DB_PATH", filepath.Join(dir, "missing", "users.db"))
	if err := run(); err == nil || !strings.Contains(err.Error(), "users") {
		t.Fatal("startup did not load the configured signing secret before opening the users database")
	}
}
