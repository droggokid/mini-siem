package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/droggokid/mini-siem/cmd/event/internal/events"
	"github.com/droggokid/mini-siem/internal/auth"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	secretPath := os.Getenv("EVENT_SECRET_FILE")
	if secretPath == "" {
		secretPath = ".secrets/event-secret"
	}

	secret, err := os.ReadFile(secretPath)
	if err != nil {
		return fmt.Errorf("cannot load Event authorization secret: %w", err)
	}

	tokens, err := auth.New(bytes.TrimSpace(secret))
	if err != nil {
		return fmt.Errorf("invalid Event authorization secret: %w", err)
	}

	publicPath := os.Getenv("JOB_PUBLIC_KEY_FILE")
	if publicPath == "" {
		publicPath = ".secrets/job-public"
	}
	jobKey, err := auth.ReadJobPublicKey(publicPath)
	if err != nil {
		return err
	}

	addr := os.Getenv("EVENT_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	var store events.Store

	server := &http.Server{
		Addr:              addr,
		Handler:           newRouter(&store, tokens, jobKey),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("listening on %s", addr)
	return server.ListenAndServe()
}
