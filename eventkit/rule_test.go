package eventkit

import (
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestDetect(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name    string
		offsets []time.Duration
		want    int
	}{
		{"empty", nil, 0},
		{"four", []time.Duration{0, 0, 0, 0}, 0},
		{"five", []time.Duration{0, 0, 0, 0, 0}, 5},
		{"inclusive", []time.Duration{0, time.Minute, 2 * time.Minute, 3 * time.Minute, 5 * time.Minute}, 5},
		{"outside", []time.Duration{0, time.Minute, 2 * time.Minute, 3 * time.Minute, 5*time.Minute + time.Nanosecond}, 0},
		{"rolling", []time.Duration{0, 4 * time.Minute, 5 * time.Minute, 6 * time.Minute, 7 * time.Minute, 8 * time.Minute}, 5},
		{"maximum", []time.Duration{0, 0, 0, 0, 0, time.Minute, 10 * time.Minute}, 6},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var input []Event
			for _, offset := range tt.offsets {
				input = append(input, Event{Type: "login.failed", SourceIP: "192.0.2.1", IngestedAt: base.Add(offset)})
			}
			slices.Reverse(input)
			before := slices.Clone(input)
			got := Detect(input)
			if tt.want == 0 && len(got) != 0 || tt.want > 0 && (len(got) != 1 || got[0].FailedLoginCount != tt.want) {
				t.Fatalf("got %+v want count %d", got, tt.want)
			}
			if !reflect.DeepEqual(input, before) {
				t.Fatal("mutated input")
			}
		})
	}
}

func TestDetectGroupsIPsAndIgnoresOtherTypes(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	var input []Event
	for range 5 {
		for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
			input = append(input, Event{Type: "login.failed", SourceIP: ip, IngestedAt: base})
		}
	}
	input = append(input, Event{Type: "login.failed", SourceIP: "2001:0db8:0:0:0:0:0:1", IngestedAt: base})
	for range 10 {
		input = append(input, Event{Type: "login.success", SourceIP: "192.0.2.1", IngestedAt: base}, Event{Type: "login.failed", SourceIP: "invalid", IngestedAt: base})
	}
	input = append(input, Event{Type: "login.failed", SourceIP: "192.0.2.2", IngestedAt: base})
	got := Detect(input)
	if len(got) != 2 || got[0].SourceIP != "192.0.2.1" || got[0].FailedLoginCount != 5 || got[1].FailedLoginCount != 6 {
		t.Fatalf("mixed events: %+v", got)
	}
}
