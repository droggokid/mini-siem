package auth

import (
	"crypto/ed25519"
	"errors"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	DetectionService = "mini-siem-detection"
	EventService     = "mini-siem-event"
	RunDetection     = "detections:run"
	AddAlerts        = "alerts:add"
	ListAlerts       = "alerts:list"
	JobHeader        = "X-Detection-Job"
)

type JobScope struct {
	OwnerID int64
	JobID   string
}

type jobClaims struct {
	Action string `json:"action"`
	JobID  string `json:"job_id"`
	jwt.RegisteredClaims
}

func jobAction(service, action string) bool {
	switch service {
	case DetectionService:
		return action == RunDetection
	case EventService:
		return action == ListEvents || action == AddAlerts
	default:
		return false
	}
}

// SignJob is used only by API; other services receive the public key alone.
// shortcut: tokens can be replayed until expiry; add replay protection before public deployment.
func SignJob(key ed25519.PrivateKey, ownerID int64, jobID, service, action string) (string, error) {
	if len(key) != ed25519.PrivateKeySize || ownerID <= 0 || jobID == "" || !jobAction(service, action) {
		return "", errors.New("invalid job authority scope")
	}

	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, jobClaims{
		Action:    action,
		JobID:     jobID,
		Issuer:    "mini-siem-api",
		Audience:  jwt.ClaimStrings{service},
		Subject:   strconv.FormatInt(ownerID, 10),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Second)),
	}).SignedString(key)
}

func VerifyJob(key ed25519.PublicKey, raw, service, action string) (JobScope, error) {
	var claims jobClaims
	_, err := jwt.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer("mini-siem-api"),
		jwt.WithAudience(service), jwt.WithExpirationRequired())
	if err != nil {
		return JobScope{}, errors.New("invalid job authority")
	}

	owner, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil || owner <= 0 || claims.JobID == "" || claims.Action != action || !jobAction(service, action) {
		return JobScope{}, errors.New("invalid job authority scope")
	}

	return JobScope{OwnerID: owner, JobID: claims.JobID}, nil
}
