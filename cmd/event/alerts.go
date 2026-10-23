package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/droggokid/mini-siem/cmd/event/internal/events"
	"github.com/droggokid/mini-siem/internal/auth"
	"github.com/gin-gonic/gin"
)

func registerAlerts(router *gin.Engine, store *events.Store, tokens *auth.Tokens, jobKey ed25519.PublicKey) {
	router.GET("/alerts", tokens.EventMiddleware(auth.ListAlerts), func(c *gin.Context) {
		if _, ok := readRequest(c); !ok {
			return
		}

		identity, _ := auth.FromContext(c.Request.Context())
		alerts := store.ListAlerts(identity.ID)
		if alerts == nil {
			alerts = []events.Alert{}
		}
		c.JSON(http.StatusOK, alerts)
	})

	router.POST("/jobs/alerts", auth.JobMiddleware(jobKey, auth.EventService, auth.AddAlerts), func(c *gin.Context) {
		body, ok := readRequest(c)
		if !ok {
			return
		}

		var inputs []events.AlertInput
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if !json.Valid(body) || decoder.Decode(&inputs) != nil || inputs == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid alert request"})
			return
		}

		scope := auth.JobFromContext(c.Request.Context())
		alerts, err := store.AddAlerts(scope.OwnerID, inputs)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid alert request"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"alerts_created": len(alerts)})
	})
}

func readRequest(c *gin.Context) ([]byte, bool) {
	if c.Request.URL.RawQuery != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "query parameters are not supported"})
		return nil, false
	}

	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, 64*1024))
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		}
		return nil, false
	}

	if c.Request.Method == http.MethodGet {
		if len(body) != 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "GET must not have a body"})
			return nil, false
		}
	} else {
		mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
		if err != nil || mediaType != "application/json" {
			c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "expected application/json"})
			return nil, false
		}
	}
	return body, true
}
