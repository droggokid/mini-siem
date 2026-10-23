package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSignAndValidateEvent(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	tokens, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{AddEvent, ListEvents, ListAlerts} {
		raw, err := tokens.SignEvent(42, action)
		if err != nil {
			t.Fatal(err)
		}
		secret[0] ^= 1
		owner, err := tokens.ValidateEvent(raw, action)
		if err != nil || owner != 42 {
			t.Fatalf("owner=%d err=%v", owner, err)
		}
		parsed, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return tokens.secret, nil })
		if err != nil {
			t.Fatal(err)
		}
		exp, _ := parsed.Claims.GetExpirationTime()
		if exp == nil || time.Until(exp.Time) <= 0 || time.Until(exp.Time) > 30*time.Second {
			t.Fatal("delegation must expire within 30 seconds")
		}
	}
}

func TestRejectInvalidAuthority(t *testing.T) {
	secret := []byte(strings.Repeat("s", 32))
	tokens, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		change func(jwt.MapClaims)
	}{
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"no expiry", func(c jwt.MapClaims) { delete(c, "exp") }},
		{"wrong service", func(c jwt.MapClaims) { c["aud"] = "mini-siem-api" }},
		{"no service", func(c jwt.MapClaims) { delete(c, "aud") }},
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "detection" }},
		{"no issuer", func(c jwt.MapClaims) { delete(c, "iss") }},
		{"no owner", func(c jwt.MapClaims) { delete(c, "sub") }},
		{"zero owner", func(c jwt.MapClaims) { c["sub"] = "0" }},
		{"negative owner", func(c jwt.MapClaims) { c["sub"] = "-1" }},
		{"invalid owner", func(c jwt.MapClaims) { c["sub"] = "Alice" }},
		{"overflow owner", func(c jwt.MapClaims) { c["sub"] = "9223372036854775808" }},
		{"wrong action", func(c jwt.MapClaims) { c["action"] = ListEvents }},
		{"unknown action", func(c jwt.MapClaims) { c["action"] = "events:all" }},
		{"no action", func(c jwt.MapClaims) { delete(c, "action") }},
		{"not yet valid", func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := jwt.MapClaims{"iss": "mini-siem-api", "aud": "mini-siem-event", "sub": "1", "action": AddEvent, "exp": time.Now().Add(time.Minute).Unix()}
			tt.change(c)
			raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(secret)
			if err != nil {
				t.Fatal(err)
			}
			if owner, err := tokens.ValidateEvent(raw, AddEvent); err == nil || owner != 0 {
				t.Fatalf("accepted invalid authority: owner=%d err=%v", owner, err)
			}
		})
	}
	for _, method := range []jwt.SigningMethod{jwt.SigningMethodHS256, jwt.SigningMethodHS384, jwt.SigningMethodNone} {
		key := any([]byte(strings.Repeat("x", 32)))
		if method == jwt.SigningMethodHS384 {
			key = secret
		}
		if method == jwt.SigningMethodNone {
			key = jwt.UnsafeAllowNoneSignatureType
		}
		raw, err := jwt.NewWithClaims(method, jwt.MapClaims{
			"iss": "mini-siem-api", "aud": "mini-siem-event", "sub": "1", "action": AddEvent, "exp": time.Now().Add(time.Minute).Unix(),
		}).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tokens.ValidateEvent(raw, AddEvent); err == nil {
			t.Fatalf("accepted forged token with %s", method.Alg())
		}
	}
	for _, raw := range []string{"", "not-a-jwt"} {
		if _, err := tokens.ValidateEvent(raw, AddEvent); err == nil {
			t.Fatal("accepted missing or malformed token")
		}
	}
}

func TestEventAndUserAuthoritiesAreSeparate(t *testing.T) {
	tokens, _ := testTokens(t)
	user, err := tokens.Sign(Identity{ID: 1, Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	event, err := tokens.SignEvent(1, AddEvent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.ValidateEvent(user, AddEvent); err == nil {
		t.Fatal("accepted user JWT as Event authority even with the same signing key")
	}
	if _, err := tokens.Validate(event); err == nil {
		t.Fatal("accepted Event authority as user JWT even with the same signing key")
	}
	other, _ := testTokens(t)
	if _, err := other.ValidateEvent(event, AddEvent); err == nil {
		t.Fatal("accepted Event authority signed with a different key")
	}
	parts := strings.Split(event, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(payload), `"sub":"1"`, `"sub":"2"`, 1)
	if tampered == string(payload) {
		t.Fatal("fixture did not change the owner")
	}
	raw := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(tampered)) + "." + parts[2]
	if _, err := tokens.ValidateEvent(raw, AddEvent); err == nil {
		t.Fatal("accepted tampered owner")
	}
}

func TestRejectInvalidConfigurationAndScope(t *testing.T) {
	if _, err := New([]byte("short")); err == nil {
		t.Fatal("accepted weak secret")
	}
	tokens, err := New([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		owner  int64
		action string
	}{{0, AddEvent}, {-1, ListEvents}, {1, "events:all"}} {
		if _, err := tokens.SignEvent(tt.owner, tt.action); err == nil {
			t.Fatal("signed invalid scope")
		}
	}
}
