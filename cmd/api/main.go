package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/droggokid/mini-siem/cmd/api/internal/users"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	path := os.Getenv("USERS_DB_PATH")
	if path == "" {
		path = "users.db"
	}
	store, err := users.Open(path)
	if err != nil {
		return err
	}
	defer store.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Print("listening on :8080")
	return server.ListenAndServe()
}
