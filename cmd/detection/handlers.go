package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/droggokid/mini-siem/eventkit"
	"github.com/droggokid/mini-siem/internal/auth"
	"github.com/gin-gonic/gin"
)

func newRouter(eventURL string, jobKey ed25519.PublicKey) http.Handler {
	router := gin.New()
	router.HandleMethodNotAllowed = true
	router.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "ok\n")
	})

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	router.POST("/detections/run", auth.JobMiddleware(jobKey, auth.DetectionService, auth.RunDetection), func(c *gin.Context) {
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

		var input *struct {
			ReadToken  string `json:"read_token"`
			WriteToken string `json:"write_token"`
		}

		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()

		if !json.Valid(body) || decoder.Decode(&input) != nil || input == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid detection request"})
			return
		}

		scope := auth.JobFromContext(c.Request.Context())
		readScope, readErr := auth.VerifyJob(jobKey, input.ReadToken, auth.EventService, auth.ListEvents)
		writeScope, writeErr := auth.VerifyJob(jobKey, input.WriteToken, auth.EventService, auth.AddAlerts)
		if readErr != nil || writeErr != nil || readScope != scope || writeScope != scope {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid job permissions"})
			return
		}

		data, err := eventRequest(c, client, eventURL, http.MethodGet, "/jobs/events", input.ReadToken, scope.JobID, nil, http.StatusOK)
		var events []struct {
			OwnerID int64 `json:"owner_id"`
			eventkit.Event
		}
		if err != nil || json.Unmarshal(data, &events) != nil || events == nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": "Event service unavailable"})
			return
		}

		ruleEvents := make([]eventkit.Event, len(events))
		for index, event := range events {
			_, ipErr := netip.ParseAddr(event.SourceIP)
			if event.OwnerID != scope.OwnerID || event.IngestedAt.IsZero() || ipErr != nil {
				c.JSON(http.StatusBadGateway, gin.H{"error": "invalid Event service response"})
				return
			}
			ruleEvents[index] = event.Event
		}

		findings := eventkit.Detect(ruleEvents)
		if len(findings) > 0 {
			body, err = json.Marshal(findings)
			if err != nil || len(body) > 64*1024 {
				c.JSON(http.StatusBadGateway, gin.H{"error": "alert batch exceeds Event request limit"})
				return
			}

			data, err = eventRequest(c, client, eventURL, http.MethodPost, "/jobs/alerts", input.WriteToken, scope.JobID, body, http.StatusCreated)
			var result struct {
				AlertsCreated int `json:"alerts_created"`
			}
			if err != nil || json.Unmarshal(data, &result) != nil || result.AlertsCreated != len(findings) {
				c.JSON(http.StatusBadGateway, gin.H{"error": "Event service unavailable"})
				return
			}
		}

		log.Printf("detection completed owner=%d job=%s alerts=%d", scope.OwnerID, scope.JobID, len(findings))
		c.JSON(http.StatusOK, gin.H{
			"job_id":         scope.JobID,
			"events_scanned": len(events),
			"alerts_created": len(findings),
		})
	})

	return router
}

func eventRequest(c *gin.Context, client *http.Client, eventURL, method, path, token, jobID string, body []byte, status int) ([]byte, error) {
	r, err := http.NewRequestWithContext(c.Request.Context(), method, strings.TrimRight(eventURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set(auth.JobHeader, jobID)
	r.Header.Set("Content-Type", "application/json")

	response, err := client.Do(r)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		return nil, errors.New("unexpected Event response")
	}
	return io.ReadAll(response.Body)
}
