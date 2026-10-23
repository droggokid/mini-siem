package main

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/droggokid/mini-siem/internal/auth"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	publicPath := os.Getenv("JOB_PUBLIC_KEY_FILE")
	if publicPath == "" {
		publicPath = ".secrets/job-public"
	}
	jobKey, err := auth.ReadJobPublicKey(publicPath)
	if err != nil {
		return err
	}

	eventURL := os.Getenv("EVENT_URL")
	if eventURL == "" {
		eventURL = "http://event:8080"
	}
	// Reject malformed service configuration before any delegated request is sent.
	endpoint, err := url.Parse(eventURL)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return errors.New("EVENT_URL must be an HTTP service URL without credentials, query, fragment or path")
	}

	addr := os.Getenv("DETECTION_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           newRouter(eventURL, jobKey),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("listening on %s", addr)
	return server.ListenAndServe()
}
