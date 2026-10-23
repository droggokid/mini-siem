package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/droggokid/mini-siem/internal/auth"
	"github.com/gin-gonic/gin"
)

func eventHandler(eventURL string, tokens *auth.Tokens) gin.HandlerFunc {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return func(c *gin.Context) {
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
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
			} else {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			}
			return
		}
		action := auth.AddEvent
		if c.Request.Method == http.MethodGet {
			action = auth.ListEvents
			if len(body) != 0 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "GET must not have a body"})
				return
			}
		}
		token, err := tokens.SignEvent(identity.ID, action)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		r, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method,
			strings.TrimRight(eventURL, "/")+"/events", bytes.NewReader(body))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", c.GetHeader("Content-Type"))
		response, err := client.Do(r)
		if err != nil {
			status := http.StatusBadGateway
			if timeout, ok := errors.AsType[*url.Error](err); ok && timeout.Timeout() {
				status = http.StatusGatewayTimeout
			}
			c.JSON(status, gin.H{"error": "Event service unavailable"})
			return
		}
		defer response.Body.Close()
		switch response.StatusCode {
		case http.StatusOK, http.StatusCreated, http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
		default:
			c.JSON(http.StatusBadGateway, gin.H{"error": "Event service unavailable"})
			return
		}
		data, err := io.ReadAll(response.Body)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": "invalid Event service response"})
			return
		}
		c.Data(response.StatusCode, "application/json", data)
	}
}
