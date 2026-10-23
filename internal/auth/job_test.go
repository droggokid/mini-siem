package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJobAuthority(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	for _, target := range []struct{ service, action string }{
		{DetectionService, RunDetection},
		{EventService, ListEvents},
		{EventService, AddAlerts},
	} {
		raw, err := SignJob(private, 1, "job-a", target.service, target.action)
		if err != nil {
			t.Fatal(err)
		}
		scope, err := VerifyJob(public, raw, target.service, target.action)
		if err != nil || scope.OwnerID != 1 || scope.JobID != "job-a" {
			t.Fatalf("scope=%+v err=%v", scope, err)
		}
		if _, err := VerifyJob(public, raw, target.service, "other"); err == nil {
			t.Fatal("accepted wrong action")
		}
		if _, err := VerifyJob(public, raw, "other", target.action); err == nil {
			t.Fatal("accepted wrong audience")
		}
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		if _, err := VerifyJob(other, raw, target.service, target.action); err == nil {
			t.Fatal("accepted wrong key")
		}
	}
	for _, scope := range []struct {
		owner                int64
		job, service, action string
	}{
		{0, "j", EventService, ListEvents},
		{1, "", EventService, ListEvents},
		{1, "j", EventService, AddEvent},
		{1, "j", DetectionService, ListEvents},
	} {
		if _, err := SignJob(private, scope.owner, scope.job, scope.service, scope.action); err == nil {
			t.Fatalf("signed invalid scope %+v", scope)
		}
	}
}

func TestJobRejectsInvalidClaims(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	for _, field := range []string{"iss", "aud", "sub", "exp", "job_id", "action", "expired", "negative", "algorithm"} {
		t.Run(field, func(t *testing.T) {
			claims := jwt.MapClaims{
				"iss":    "mini-siem-api",
				"aud":    EventService,
				"sub":    "1",
				"exp":    time.Now().Add(time.Minute).Unix(),
				"job_id": "job-a",
				"action": ListEvents,
			}
			method := jwt.SigningMethod(jwt.SigningMethodEdDSA)
			var key any = private
			switch field {
			case "expired":
				claims["exp"] = time.Now().Add(-time.Second).Unix()
			case "negative":
				claims["sub"] = "-1"
			case "algorithm":
				method, key = jwt.SigningMethodHS256, []byte(public)
			default:
				delete(claims, field)
			}
			raw, err := jwt.NewWithClaims(method, claims).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyJob(public, raw, EventService, ListEvents); err == nil {
				t.Fatal("accepted invalid claims")
			}
		})
	}
}
