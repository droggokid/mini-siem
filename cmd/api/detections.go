package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/droggokid/mini-siem/internal/auth"
	"github.com/gin-gonic/gin"
)

func detectionHandler(detectionURL string, jobKey ed25519.PrivateKey) gin.HandlerFunc {
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return func(c *gin.Context) {
		identity, ok := auth.FromContext(c.Request.Context())
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		if c.Request.URL.RawQuery != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "query parameters are not supported"})
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
		if len(body) > 0 {
			mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
			if err != nil || mediaType != "application/json" {
				c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "expected application/json"})
				return
			}
			var input *struct{}
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if !json.Valid(body) || decoder.Decode(&input) != nil || input == nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "detection accepts no parameters"})
				return
			}
		}

		jobID := rand.Text()
		run, runErr := auth.SignJob(jobKey, identity.ID, jobID, auth.DetectionService, auth.RunDetection)
		read, readErr := auth.SignJob(jobKey, identity.ID, jobID, auth.EventService, auth.ListEvents)
		write, writeErr := auth.SignJob(jobKey, identity.ID, jobID, auth.EventService, auth.AddAlerts)
		if runErr != nil || readErr != nil || writeErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		body, err = json.Marshal(struct {
			ReadToken  string `json:"read_token"`
			WriteToken string `json:"write_token"`
		}{ReadToken: read, WriteToken: write})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		r, err := http.NewRequestWithContext(c.Request.Context(), http.MethodPost,
			strings.TrimRight(detectionURL, "/")+"/detections/run", bytes.NewReader(body))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		r.Header.Set("Authorization", "Bearer "+run)
		r.Header.Set(auth.JobHeader, jobID)
		r.Header.Set("Content-Type", "application/json")

		response, err := client.Do(r)
		if err != nil {
			status := http.StatusBadGateway
			if timeout, ok := errors.AsType[*url.Error](err); ok && timeout.Timeout() {
				status = http.StatusGatewayTimeout
			}
			c.JSON(status, gin.H{"error": "Detection service unavailable"})
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			c.JSON(http.StatusBadGateway, gin.H{"error": "Detection service unavailable"})
			return
		}

		data, err := io.ReadAll(response.Body)
		if err != nil || !json.Valid(data) {
			c.JSON(http.StatusBadGateway, gin.H{"error": "invalid Detection service response"})
			return
		}
		c.Data(http.StatusOK, "application/json", data)
	}
}
