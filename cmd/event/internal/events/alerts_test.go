package events

import (
	"sync"
	"testing"
	"time"
)

func TestAlertsValidateAtomically(t *testing.T) {
	valid := AlertInput{
		SourceIP:         "192.0.2.1",
		DetectionType:    "failed_login_burst",
		FailedLoginCount: 5,
	}
	for _, invalid := range []AlertInput{
		{},
		{SourceIP: "bad", DetectionType: valid.DetectionType, FailedLoginCount: 5},
		{SourceIP: valid.SourceIP, DetectionType: "other", FailedLoginCount: 5},
		{SourceIP: valid.SourceIP, DetectionType: valid.DetectionType, FailedLoginCount: 4},
	} {
		var store Store
		if _, err := store.AddAlerts(1, []AlertInput{valid, invalid}); err == nil {
			t.Fatal("accepted invalid batch")
		}
		if len(store.ListAlerts(1)) != 0 {
			t.Fatal("partially stored invalid batch")
		}
	}
	var store Store
	if _, err := store.AddAlerts(0, []AlertInput{valid}); err == nil {
		t.Fatal("accepted invalid owner")
	}
	if _, err := store.AddAlerts(1, []AlertInput{valid, valid}); err == nil {
		t.Fatal("accepted duplicate IP")
	}
}

func TestConcurrentAlerts(t *testing.T) {
	var store Store
	var wg sync.WaitGroup
	before := time.Now()
	for worker := range 8 {
		wg.Go(func() {
			owner := int64(worker%2 + 1)
			for range 20 {
				added, err := store.AddAlerts(owner, []AlertInput{{SourceIP: "192.0.2.1", DetectionType: "failed_login_burst", FailedLoginCount: 5}})
				if err != nil {
					t.Error(err)
					return
				}
				added[0].OwnerID = 99
				for _, alert := range store.ListAlerts(owner) {
					if alert.OwnerID != owner {
						t.Error("owner leak")
					}
				}
				copy := store.ListAlerts(owner)
				copy[0].OwnerID = 99
			}
		})
	}
	wg.Wait()
	ids := map[string]bool{}
	for _, owner := range []int64{1, 2} {
		alerts := store.ListAlerts(owner)
		if len(alerts) != 80 {
			t.Fatalf("got %d alerts", len(alerts))
		}
		for _, alert := range alerts {
			if alert.ID == "" || ids[alert.ID] || alert.CreatedAt.Before(before) || alert.CreatedAt.After(time.Now()) {
				t.Fatalf("bad metadata %+v", alert)
			}
			ids[alert.ID] = true
		}
	}
	if len(store.ListAlerts(3)) != 0 {
		t.Fatal("admin sees another owner's alerts")
	}
}
