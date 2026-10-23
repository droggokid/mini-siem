package events

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// Store holds events in memory only; its zero value is ready to use.
type Store struct {
	mu     sync.RWMutex
	events []Event
	alerts []Alert
}

// Add accepts an owner ID trusted by the caller and assigns ingestion metadata.
func (s *Store) Add(ownerID int64, eventType, sourceIP string) (Event, error) {
	// Enforce semantic validity here so every caller is checked before storage.
	if ownerID <= 0 {
		return Event{}, errors.New("owner ID must be positive")
	}

	if strings.TrimSpace(eventType) == "" {
		return Event{}, errors.New("event type must not be empty")
	}

	// Parse the address, rather than accepting a string that only resembles an IP.
	if _, err := netip.ParseAddr(sourceIP); err != nil {
		return Event{}, fmt.Errorf("invalid source IP: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	event := Event{
		ID:         rand.Text(),
		OwnerID:    ownerID,
		Type:       eventType,
		SourceIP:   sourceIP,
		IngestedAt: time.Now().UTC(),
	}
	s.events = append(s.events, event)
	return event, nil
}

// ListByOwner returns a snapshot of the trusted owner's events in ingestion order.
func (s *Store) ListByOwner(ownerID int64) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var events []Event
	for _, event := range s.events {
		if event.OwnerID == ownerID {
			events = append(events, event)
		}
	}
	return events
}

// ListAll returns a snapshot of all events; callers must authorize cross-owner access.
func (s *Store) ListAll() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.events)
}
