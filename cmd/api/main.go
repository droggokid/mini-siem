package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/droggokid/mini-siem/cmd/api/internal/auth"
	"github.com/droggokid/mini-siem/cmd/api/internal/users"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	secretPath := os.Getenv("JWT_SECRET_FILE")
	if secretPath == "" {
		secretPath = ".secrets/jwt-secret"
	}

	secret, err := readOrCreateJWTSecret(secretPath)
	if err != nil {
		return fmt.Errorf("cannot load JWT secret file: %w", err)
	}

	tokens, err := auth.New(bytes.TrimSpace(secret))
	if err != nil {
		return err
	}

	path := os.Getenv("USERS_DB_PATH")
	if path == "" {
		path = "users.db"
	}

	store, err := users.Open(path)
	if err != nil {
		return err
	}

	defer store.Close()

	server := &http.Server{
		Addr:              ":8080",
		Handler:           newRouter(store, tokens),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Print("listening on :8080")
	return server.ListenAndServe()
}

func readOrCreateJWTSecret(path string) ([]byte, error) {
	secret, err := os.ReadFile(path)
	if !errors.Is(err, os.ErrNotExist) {
		return secret, err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return nil, err
	}

	secret = []byte(hex.EncodeToString(random))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}

	_, writeErr := file.Write(secret)
	if err = errors.Join(writeErr, file.Close()); err != nil {
		return nil, err
	}

	return secret, nil
}
