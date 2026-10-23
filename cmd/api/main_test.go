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

func TestRunCreatesSeparateEventSecret(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("JWT_SECRET_FILE", "")
	t.Setenv("EVENT_SECRET_FILE", "")
	t.Setenv("EVENT_URL", "")
	t.Setenv("USERS_DB_PATH", filepath.Join(dir, "missing", "users.db"))
	if err := run(); err == nil || !strings.Contains(err.Error(), "users") {
		t.Fatalf("startup did not initialize secrets before storage: %v", err)
	}
	userSecret, err := os.ReadFile(filepath.Join(".secrets", "jwt-secret"))
	if err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(".secrets", "event-secret")
	eventSecret, err := os.ReadFile(eventPath)
	if err != nil || bytes.Equal(userSecret, eventSecret) {
		t.Fatal("service and user secrets must be independently generated")
	}
	decoded, err := hex.DecodeString(string(eventSecret))
	if err != nil || len(decoded) != 32 {
		t.Fatal("Event secret must encode 32 random bytes")
	}
	info, err := os.Stat(eventPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("Event secret must have mode 0600")
	}
	if err := os.Chmod(eventPath, 0400); err != nil {
		t.Fatal(err)
	}
	if err := run(); err == nil || !strings.Contains(err.Error(), "users") {
		t.Fatalf("startup did not reuse Event secret: %v", err)
	}
	reused, err := os.ReadFile(eventPath)
	if err != nil || !bytes.Equal(eventSecret, reused) {
		t.Fatal("startup replaced Event secret")
	}
}

func TestRunRejectsInvalidEventConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name, secret, eventURL string
	}{
		{"weak secret", "short", "http://event:8080"},
		{"same secret", strings.Repeat("u", 32), "http://event:8080"},
		{"invalid URL", strings.Repeat("e", 32), "://bad"},
		{"URL credentials", strings.Repeat("e", 32), "http://user:password@event:8080"},
		{"URL query", strings.Repeat("e", 32), "http://event:8080?owner_id=1"},
		{"URL path", strings.Repeat("e", 32), "http://event:8080/other"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			userPath, eventPath := filepath.Join(dir, "user-secret"), filepath.Join(dir, "event-secret")
			if err := os.WriteFile(userPath, []byte(strings.Repeat("u", 32)), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(eventPath, []byte(tt.secret), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("JWT_SECRET_FILE", userPath)
			t.Setenv("EVENT_SECRET_FILE", eventPath)
			t.Setenv("EVENT_URL", tt.eventURL)
			dbPath := filepath.Join(dir, "users.db")
			t.Setenv("USERS_DB_PATH", dbPath)
			if err := run(); err == nil {
				t.Fatal("startup accepted invalid Event configuration")
			}
			if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
				t.Fatal("opened database before validating service configuration")
			}
			unchanged, err := os.ReadFile(eventPath)
			if err != nil || string(unchanged) != tt.secret {
				t.Fatal("startup replaced invalid Event secret")
			}
		})
	}
}
