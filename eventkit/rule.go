// Package eventkit detects failed-login bursts using only event data.
package eventkit

import (
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Event contains the fields used by the detection rule.
type Event struct {
	Type       string    `json:"type"`
	SourceIP   string    `json:"source_ip"`
	IngestedAt time.Time `json:"ingested_at"`
}

// Finding describes an IP's largest qualifying failed-login window.
type Finding struct {
	SourceIP         string `json:"source_ip"`
	DetectionType    string `json:"detection_type"`
	FailedLoginCount int    `json:"failed_login_count"`
}

// Detect returns each IP's largest window of at least five failed logins within
// five minutes, including the boundary. It groups equivalent IP addresses,
// ignores other event types and invalid IPs, and sorts findings by source IP.
// It does not change its input; callers must supply events from a single owner.
func Detect(events []Event) []Finding {
	byIP := make(map[string][]time.Time)
	for _, event := range events {
		if event.Type != "login.failed" {
			continue
		}

		ip, err := netip.ParseAddr(event.SourceIP)
		if err != nil {
			continue
		}

		key := ip.Unmap().String()
		byIP[key] = append(byIP[key], event.IngestedAt)
	}

	var result []Finding
	for ip, times := range byIP {
		slices.SortFunc(times, func(a, b time.Time) int {
			return a.Compare(b)
		})

		start, maximum := 0, 0

		for end, at := range times {
			// Keep timestamps exactly five minutes apart in the same window.
			for at.Sub(times[start]) > 5*time.Minute {
				start++
			}
			maximum = max(maximum, end-start+1)
		}

		if maximum >= 5 {
			result = append(result, Finding{
				SourceIP:         ip,
				DetectionType:    "failed_login_burst",
				FailedLoginCount: maximum,
			})
		}
	}

	slices.SortFunc(result, func(a, b Finding) int {
		return strings.Compare(a.SourceIP, b.SourceIP)
	})

	return result
}
