package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsInvalidAuthoritySecret(t *testing.T) {
	dir := t.TempDir()
	weak := filepath.Join(dir, "weak")
	if err := os.WriteFile(weak, []byte("weak-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(dir, "missing"), dir, weak} {
		t.Setenv("EVENT_SECRET_FILE", path)
		if err := run(); err == nil || strings.Contains(err.Error(), "weak-secret") {
			t.Fatalf("startup accepted invalid secret or leaked it: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Fatal("Event created its own authority secret")
	}
}
