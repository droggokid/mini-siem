package events

import "time"

type AlertInput struct {
	SourceIP         string `json:"source_ip"`
	DetectionType    string `json:"detection_type"`
	FailedLoginCount int    `json:"failed_login_count"`
}

type Alert struct {
	ID        string    `json:"id"`
	OwnerID   int64     `json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
	AlertInput
}
