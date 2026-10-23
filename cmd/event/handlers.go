package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/droggokid/mini-siem/cmd/event/internal/events"
	"github.com/droggokid/mini-siem/internal/auth"
	"github.com/gin-gonic/gin"
)

func newRouter(store *events.Store, tokens *auth.Tokens) http.Handler {
	router := gin.New()
	router.HandleMethodNotAllowed = true

	router.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "ok\n")
	})

	router.POST("/events", tokens.EventMiddleware(auth.AddEvent), func(c *gin.Context) {
		identity, ok := auth.FromContext(c.Request.Context())
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if c.Request.URL.RawQuery != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "query parameters are not supported"})
			return
		}

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

		var input struct {
			Type     string `json:"type"`
			SourceIP string `json:"source_ip"`
		}

		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if !json.Valid(body) || decoder.Decode(&input) != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event request"})
			return
		}

		event, err := store.Add(identity.ID, input.Type, input.SourceIP)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event type or source IP"})
			return
		}

		c.JSON(http.StatusCreated, event)
	})

	router.GET("/events", tokens.EventMiddleware(auth.ListEvents), func(c *gin.Context) {
		identity, ok := auth.FromContext(c.Request.Context())
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		if c.Request.URL.RawQuery != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "query parameters are not supported"})
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, 64*1024))
		if err != nil {
			if _, ok = errors.AsType[*http.MaxBytesError](err); ok {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			}

			return
		}

		if len(body) != 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "GET must not have a body"})
			return
		}

		owned := store.ListByOwner(identity.ID)
		if owned == nil {
			owned = []events.Event{}
		}

		c.JSON(http.StatusOK, owned)
	})

	return router
}
