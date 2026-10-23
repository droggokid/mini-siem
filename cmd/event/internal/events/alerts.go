package events

import (
	"crypto/rand"
	"errors"
	"net/netip"
	"time"
)

// AddAlerts validates the whole run before storing any alerts.
func (s *Store) AddAlerts(ownerID int64, inputs []AlertInput) ([]Alert, error) {
	if ownerID <= 0 {
		return nil, errors.New("owner ID must be positive")
	}

	seen := make(map[netip.Addr]bool, len(inputs))
	var alerts []Alert
	for _, input := range inputs {
		ip, err := netip.ParseAddr(input.SourceIP)
		// A signed job can still submit malformed findings; validate every item.
		if err != nil || input.DetectionType != "failed_login_burst" || input.FailedLoginCount < 5 {
			return nil, errors.New("invalid alert")
		}

		// Normalize equivalent addresses before checking for duplicate findings.
		ip = ip.Unmap()
		if seen[ip] {
			return nil, errors.New("duplicate source IP in detection run")
		}
		seen[ip] = true
		input.SourceIP = ip.String()

		alerts = append(alerts, Alert{
			ID:         rand.Text(),
			OwnerID:    ownerID,
			CreatedAt:  time.Now().UTC(),
			AlertInput: input,
		})
	}

	// Commit only after every item passes, so an invalid batch cannot leave partial writes.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = append(s.alerts, alerts...)
	return alerts, nil
}

// ListAlerts filters by the trusted owner; callers must verify authority first.
func (s *Store) ListAlerts(ownerID int64) []Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var alerts []Alert
	for _, alert := range s.alerts {
		if alert.OwnerID == ownerID {
			alerts = append(alerts, alert)
		}
	}
	return alerts
}
