package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/droggokid/mini-siem/cmd/api/internal/users"
	"github.com/droggokid/mini-siem/internal/auth"
	"github.com/gin-gonic/gin"
)

func newRouter(store *users.Store, tokens *auth.Tokens, eventURL string, eventTokens *auth.Tokens, detectionURL string, jobKey ed25519.PrivateKey) http.Handler {
	router := gin.New()
	router.HandleMethodNotAllowed = true

	router.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "ok\n")
	})

	router.POST("/login", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")

		// Accept JSON credentials only, with a bounded body before decoding.
		mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
		if err != nil || mediaType != "application/json" {
			c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "expected application/json"})
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, 64*1024))
		if err != nil {
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			}
			return
		}

		var credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		// Validate request shape; the user store's SQL parameters prevent injection.
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()

		// Check the whole document and required fields; Decode alone can accept trailing JSON.
		if !json.Valid(body) || decoder.Decode(&credentials) != nil ||
			credentials.Username == "" || credentials.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid login request"})
			return
		}

		user, err := store.Authenticate(c.Request.Context(), credentials.Username, credentials.Password)
		if errors.Is(err, users.ErrAuthentication) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
			return
		}

		if err != nil {
			// Keep database error details out of the public login response.
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		// Bind identity and role to the account store, never to client-supplied claims.
		token, err := tokens.Sign(auth.Identity{ID: user.ID, Role: user.Role})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token": token,
			"token_type":   "Bearer",
			"expires_in":   int(auth.Lifetime / time.Second),
		})
	})

	router.GET("/me", tokens.Middleware(), func(c *gin.Context) {
		identity, ok := auth.FromContext(c.Request.Context())
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.JSON(http.StatusOK, identity)
	})

	events := eventHandler(eventURL, eventTokens)
	// Authenticate public requests; Event enforces the delegated owner's data scope.
	router.POST("/events", tokens.Middleware(), events)
	router.GET("/events", tokens.Middleware(), events)
	router.GET("/admin/events", tokens.Middleware(), func(c *gin.Context) {
		identity, _ := auth.FromContext(c.Request.Context())
		// Authorize cross-owner access before the proxy can sign privileged authority.
		if identity.Role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
	}, events)
	router.GET("/alerts", tokens.Middleware(), events)
	router.POST("/detections/run", tokens.Middleware(), detectionHandler(detectionURL, jobKey))

	return router
}
