package users

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func storedPasswordHash(t *testing.T, store *Store, username string) []byte {
	t.Helper()
	var hash []byte
	if err := store.db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestOpenSeedsUsers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.db")
	store := openTestStore(t, path)
	for _, tt := range []struct{ username, password, role string }{
		{"Alice", "alice-password", "user"},
		{"Bob", "bob-password", "user"},
		{"Admin", "admin-password", "admin"},
	} {
		t.Run(tt.username, func(t *testing.T) {
			user, err := store.LookupByUsername(context.Background(), tt.username)
			if err != nil {
				t.Fatal(err)
			}
			if user.ID <= 0 || user.Username != tt.username || user.Role != tt.role {
				t.Fatalf("unexpected identity: id=%d username=%q role=%q", user.ID, user.Username, user.Role)
			}
			hash := storedPasswordHash(t, store, tt.username)
			if err := bcrypt.CompareHashAndPassword(hash, []byte(tt.password)); err != nil {
				t.Fatalf("seed password does not match bcrypt hash: %v", err)
			}
			cost, err := bcrypt.Cost(hash)
			if err != nil || cost < bcrypt.DefaultCost {
				t.Fatalf("insufficient bcrypt cost: %d, %v", cost, err)
			}
			encoded, err := json.Marshal(user)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte("PasswordHash")) || bytes.Contains(encoded, []byte("password_hash")) {
				t.Fatal("password hash exposed in JSON")
			}
			if strings.Contains(fmt.Sprintf("%+v", user), fmt.Sprint(hash)) {
				t.Fatal("domain user exposes the stored password hash when formatted")
			}
		})
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"alice-password", "bob-password", "admin-password"} {
		if bytes.Contains(data, []byte(password)) {
			t.Fatal("database contains a plaintext seed password")
		}
	}
}

func TestReopenPreservesUsers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.db")
	store := openTestStore(t, path)
	before, err := store.LookupByUsername(context.Background(), "Alice")
	if err != nil {
		t.Fatal(err)
	}
	beforeHash := storedPasswordHash(t, store, "Alice")
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openTestStore(t, path)
	after, err := store.LookupByUsername(context.Background(), "Alice")
	if err != nil {
		t.Fatal(err)
	}
	afterHash := storedPasswordHash(t, store, "Alice")
	if before != after || !bytes.Equal(beforeHash, afterHash) {
		t.Fatal("reinitialization replaced an existing user")
	}
	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("got %d users after restart, want 3", count)
	}
}

func TestLookupByUsernameNotFound(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "users.db"))
	for _, username := range []string{"unknown", "", "' OR 1=1 --", "Alice' --", "'; DROP TABLE users; --"} {
		t.Run(username, func(t *testing.T) {
			user, err := store.LookupByUsername(context.Background(), username)
			if !errors.Is(err, sql.ErrNoRows) || user.ID != 0 {
				t.Fatalf("got id=%d error=%v, want sql.ErrNoRows and no identity", user.ID, err)
			}
		})
	}
	if _, err := store.LookupByUsername(context.Background(), "Admin"); err != nil {
		t.Fatalf("lookup after SQL injection attempts: %v", err)
	}
}

func TestOpenFailsForMissingDirectory(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "missing", "users.db"))
	if err == nil {
		store.Close()
		t.Fatal("opened database in a missing directory")
	}
}

func TestLookupReportsStorageFailure(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "users.db"))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupByUsername(context.Background(), "Alice"); err == nil || errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("got %v, want a storage error", err)
	}
}
