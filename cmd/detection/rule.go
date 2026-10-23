package main

import (
	"net/netip"
	"slices"
	"strings"
	"time"
)

type event struct {
	OwnerID    int64     `json:"owner_id"`
	Type       string    `json:"type"`
	SourceIP   string    `json:"source_ip"`
	IngestedAt time.Time `json:"ingested_at"`
}

type finding struct {
	SourceIP         string `json:"source_ip"`
	DetectionType    string `json:"detection_type"`
	FailedLoginCount int    `json:"failed_login_count"`
}

// detect returns each IP's largest qualifying window without changing its input.
func detect(events []event) []finding {
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

	var result []finding
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
			result = append(result, finding{
				SourceIP:         ip,
				DetectionType:    "failed_login_burst",
				FailedLoginCount: maximum,
			})
		}
	}

	slices.SortFunc(result, func(a, b finding) int {
		return strings.Compare(a.SourceIP, b.SourceIP)
	})

	return result
}
