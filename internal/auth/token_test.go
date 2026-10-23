package auth

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testTokens(t *testing.T) (*Tokens, []byte) {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	tokens, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}
	return tokens, secret
}

func TestSignAndValidate(t *testing.T) {
	tokens, key := testTokens(t)
	for _, role := range []string{"user", "admin"} {
		t.Run(role, func(t *testing.T) {
			before := time.Now()
			raw, err := tokens.Sign(Identity{ID: 42, Role: role})
			if err != nil {
				t.Fatal(err)
			}
			identity, err := tokens.Validate(raw)
			if err != nil || identity != (Identity{ID: 42, Role: role}) {
				t.Fatalf("identity=%+v error=%v", identity, err)
			}
			parsed, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return key, nil },
				jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("mini-siem"),
				jwt.WithAudience("mini-siem-api"), jwt.WithExpirationRequired())
			if err != nil {
				t.Fatal("issued token does not satisfy the public contract")
			}
			claims := parsed.Claims.(jwt.MapClaims)
			expires, err := claims.GetExpirationTime()
			if err != nil || expires.Time.Before(before.Add(14*time.Minute)) || expires.Time.After(time.Now().Add(15*time.Minute)) {
				t.Fatal("token must expire in 15 minutes")
			}
			if len(claims) != 5 || claims["sub"] != "42" || claims["role"] != role {
				t.Fatal("unexpected token claims")
			}
		})
	}
}

func TestValidateRejectsInvalidClaims(t *testing.T) {
	tokens, key := testTokens(t)
	for _, tt := range []struct {
		name   string
		change func(jwt.MapClaims)
	}{
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }},
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "other" }},
		{"wrong audience", func(c jwt.MapClaims) { c["aud"] = "event" }},
		{"missing issuer", func(c jwt.MapClaims) { delete(c, "iss") }},
		{"missing audience", func(c jwt.MapClaims) { delete(c, "aud") }},
		{"missing expiration", func(c jwt.MapClaims) { delete(c, "exp") }},
		{"missing subject", func(c jwt.MapClaims) { delete(c, "sub") }},
		{"missing role", func(c jwt.MapClaims) { delete(c, "role") }},
		{"invalid subject", func(c jwt.MapClaims) { c["sub"] = "Alice" }},
		{"zero subject", func(c jwt.MapClaims) { c["sub"] = "0" }},
		{"negative subject", func(c jwt.MapClaims) { c["sub"] = "-1" }},
		{"overflow subject", func(c jwt.MapClaims) { c["sub"] = "9223372036854775808" }},
		{"unknown role", func(c jwt.MapClaims) { c["role"] = "superuser" }},
		{"wrong role type", func(c jwt.MapClaims) { c["role"] = 1 }},
		{"future not before", func(c jwt.MapClaims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.MapClaims{"sub": "1", "role": "user", "iss": "mini-siem", "aud": "mini-siem-api", "exp": time.Now().Add(time.Minute).Unix()}
			tt.change(claims)
			raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			assertRejected(t, tokens, raw)
		})
	}
}

func TestValidateRejectsInvalidSignatures(t *testing.T) {
	tokens, key := testTokens(t)
	valid, err := tokens.Sign(Identity{ID: 1, Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(valid, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	tamperedPayload := strings.Replace(string(payload), `"role":"user"`, `"role":"admin"`, 1)
	if tamperedPayload == string(payload) {
		t.Fatal("tamper fixture did not change the role")
	}
	claims := jwt.MapClaims{"sub": "1", "role": "admin", "iss": "mini-siem", "aud": "mini-siem-api", "exp": time.Now().Add(time.Minute).Unix()}
	otherAlgorithm, err := jwt.NewWithClaims(jwt.SigningMethodHS384, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	_, otherKey := testTokens(t)
	wrongKey, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"missing": "", "malformed": "not-a-jwt",
		"tampered":        parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(tamperedPayload)) + "." + parts[2],
		"other algorithm": otherAlgorithm, "unsigned": none, "wrong secret": wrongKey,
	} {
		t.Run(name, func(t *testing.T) {
			assertRejected(t, tokens, raw)
		})
	}
}

func TestNewRejectsWeakSecrets(t *testing.T) {
	for _, data := range [][]byte{nil, {}, []byte("short-secret"), []byte(strings.Repeat("s", 31))} {
		if _, err := New(data); err == nil {
			t.Fatal("accepted weak signing secret")
		}
	}
}

func TestNewCopiesSecret(t *testing.T) {
	tokens, secret := testTokens(t)
	raw, err := tokens.Sign(Identity{ID: 1, Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	secret[0] ^= 0xff
	if _, err := tokens.Validate(raw); err != nil {
		t.Fatal("changing caller's secret changed the signing secret")
	}
}
