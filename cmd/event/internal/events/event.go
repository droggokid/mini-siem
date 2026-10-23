package events

import "time"

type Event struct {
	ID         string    `json:"id"`
	OwnerID    int64     `json:"owner_id"`
	Type       string    `json:"type"`
	SourceIP   string    `json:"source_ip"`
	IngestedAt time.Time `json:"ingested_at"`
}
