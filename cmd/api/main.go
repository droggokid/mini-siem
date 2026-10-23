package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/droggokid/mini-siem/cmd/api/internal/users"
	"github.com/droggokid/mini-siem/internal/auth"
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

	eventSecretPath := os.Getenv("EVENT_SECRET_FILE")
	if eventSecretPath == "" {
		eventSecretPath = ".secrets/event-secret"
	}
	eventSecret, err := readOrCreateJWTSecret(eventSecretPath)
	if err != nil {
		return fmt.Errorf("cannot load Event authorization secret file: %w", err)
	}
	// Reject configuration that collapses user-token and Event-authority trust domains.
	if bytes.Equal(bytes.TrimSpace(secret), bytes.TrimSpace(eventSecret)) {
		return errors.New("Event authorization secret must differ from the user JWT secret")
	}
	eventTokens, err := auth.New(bytes.TrimSpace(eventSecret))
	if err != nil {
		return fmt.Errorf("invalid Event authorization secret: %w", err)
	}
	eventURL := os.Getenv("EVENT_URL")
	if eventURL == "" {
		eventURL = "http://event:8080"
	}
	// Require a service base URL; do not let configuration inject credentials or request selectors.
	endpoint, err := url.Parse(eventURL)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return errors.New("EVENT_URL must be an HTTP service URL without credentials, query, fragment or path")
	}
	detectionURL := os.Getenv("DETECTION_URL")
	if detectionURL == "" {
		detectionURL = "http://detection:8080"
	}
	endpoint, err = url.Parse(detectionURL)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return errors.New("DETECTION_URL must be an HTTP service URL without credentials, query, fragment or path")
	}

	seedPath := os.Getenv("JOB_SEED_FILE")
	if seedPath == "" {
		seedPath = ".secrets/job-seed"
	}
	publicPath := os.Getenv("JOB_PUBLIC_KEY_FILE")
	if publicPath == "" {
		publicPath = ".secrets/job-public"
	}
	jobKey, err := readOrCreateJobKey(seedPath, publicPath)
	if err != nil {
		return fmt.Errorf("cannot initialize job authorization: %w", err)
	}
	if bytes.Equal(jobKey.Seed(), bytes.TrimSpace(secret)) || bytes.Equal(jobKey.Seed(), bytes.TrimSpace(eventSecret)) ||
		bytes.Equal([]byte(hex.EncodeToString(jobKey.Seed())), bytes.TrimSpace(secret)) ||
		bytes.Equal([]byte(hex.EncodeToString(jobKey.Seed())), bytes.TrimSpace(eventSecret)) {
		return errors.New("job signing seed must differ from existing authorization secrets")
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

	addr := os.Getenv("API_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           newRouter(store, tokens, eventURL, eventTokens, detectionURL, jobKey),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("listening on %s", addr)
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
