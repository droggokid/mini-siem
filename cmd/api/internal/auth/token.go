package auth

import (
	"errors"
	"strconv"
	"time"

	"github.com/droggokid/mini-siem/cmd/api/internal/users"
	"github.com/golang-jwt/jwt/v5"
)

const Lifetime = 15 * time.Minute

type Identity struct {
	ID   int64  `json:"id"`
	Role string `json:"role"`
}

type claims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

type Tokens struct {
	secret []byte
}

// New copies the shared signing secret.
func New(secret []byte) (*Tokens, error) {
	if len(secret) < 32 {
		return nil, errors.New("JWT signing secret must be at least 32 bytes")
	}
	return &Tokens{secret: append([]byte(nil), secret...)}, nil
}

func (t *Tokens) Sign(user users.User) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims{
		Role: user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(user.ID, 10),
			Issuer:    "mini-siem",
			Audience:  jwt.ClaimStrings{"mini-siem-api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(Lifetime)),
		},
	}).SignedString(t.secret)
}

func (t *Tokens) Validate(raw string) (Identity, error) {
	var c claims
	_, err := jwt.ParseWithClaims(raw, &c, func(*jwt.Token) (any, error) {
		return t.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("mini-siem"),
		jwt.WithAudience("mini-siem-api"), jwt.WithExpirationRequired())
	if err != nil {
		return Identity{}, errors.New("invalid token")
	}

	id, err := strconv.ParseInt(c.Subject, 10, 64)
	if err != nil || id <= 0 || (c.Role != "user" && c.Role != "admin") {
		return Identity{}, errors.New("invalid token identity")
	}

	return Identity{ID: id, Role: c.Role}, nil
}
