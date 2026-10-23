package auth

import (
	"errors"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	AddEvent      = "events:add"
	ListEvents    = "events:list"
	ListAllEvents = "events:list_all"
)

type eventClaims struct {
	Action string `json:"action"`
	jwt.RegisteredClaims
}

// SignEvent uses a dedicated API-to-Event Tokens instance, never the user-JWT key.
func (t *Tokens) SignEvent(ownerID int64, action string) (string, error) {
	if ownerID <= 0 || (action != AddEvent && action != ListEvents && action != ListAllEvents && action != ListAlerts) {
		return "", errors.New("invalid Event authority scope")
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, eventClaims{
		Action:    action,
		Issuer:    "mini-siem-api",
		Audience:  jwt.ClaimStrings{"mini-siem-event"},
		Subject:   strconv.FormatInt(ownerID, 10),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Second)),
	}).SignedString(t.secret)
}

func (t *Tokens) ValidateEvent(raw, action string) (int64, error) {
	var c eventClaims
	_, err := jwt.ParseWithClaims(raw, &c, func(*jwt.Token) (any, error) {
		return t.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("mini-siem-api"),
		jwt.WithAudience("mini-siem-event"), jwt.WithExpirationRequired())
	if err != nil {
		return 0, errors.New("invalid Event authority")
	}

	ownerID, err := strconv.ParseInt(c.Subject, 10, 64)
	if err != nil || ownerID <= 0 || c.Action != action || (action != AddEvent && action != ListEvents && action != ListAllEvents && action != ListAlerts) {
		return 0, errors.New("invalid Event authority scope")
	}

	return ownerID, nil
}
