package events

import (
	"slices"
	"sync"
	"testing"
	"time"
)

func TestAddAndList(t *testing.T) {
	var store Store
	before := time.Now()
	first, err := store.Add(1, "login.failed", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Add(1, "login.succeeded", "2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	for _, event := range []Event{first, second} {
		if event.ID == "" || event.OwnerID != 1 {
			t.Fatalf("unexpected identity: %+v", event)
		}
		if event.IngestedAt.Before(before) || event.IngestedAt.After(after) {
			t.Fatalf("ingestion timestamp outside Add calls: %v", event.IngestedAt)
		}
	}
	if first.ID == second.ID {
		t.Fatal("events have duplicate IDs")
	}
	if first.Type != "login.failed" || first.SourceIP != "192.0.2.1" ||
		second.Type != "login.succeeded" || second.SourceIP != "2001:db8::1" {
		t.Fatalf("event fields changed: %+v, %+v", first, second)
	}
	want := []Event{first, second}
	if got := store.ListByOwner(1); !slices.Equal(got, want) {
		t.Fatalf("ListByOwner = %+v, want %+v", got, want)
	}
	if got := store.ListAll(); !slices.Equal(got, want) {
		t.Fatalf("ListAll = %+v, want %+v", got, want)
	}
}

func TestListByOwnerIsolation(t *testing.T) {
	var store Store
	alice, err := store.Add(1, "login.failed", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := store.Add(2, "login.failed", "192.0.2.2")
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []Event{alice, bob} {
		if got := store.ListByOwner(event.OwnerID); !slices.Equal(got, []Event{event}) {
			t.Fatalf("owner %d got %+v, want only %+v", event.OwnerID, got, event)
		}
	}
	if got := store.ListByOwner(3); len(got) != 0 {
		t.Fatalf("unknown owner got %+v", got)
	}
	if got := store.ListAll(); !slices.Equal(got, []Event{alice, bob}) {
		t.Fatalf("ListAll = %+v, want both owners' events", got)
	}
}

func TestAddRejectsInvalidInput(t *testing.T) {
	for _, tt := range []struct {
		name     string
		ownerID  int64
		typeName string
		sourceIP string
	}{
		{"zero owner", 0, "login.failed", "192.0.2.1"},
		{"negative owner", -1, "login.failed", "192.0.2.1"},
		{"empty type", 1, "", "192.0.2.1"},
		{"blank type", 1, " \t\n", "192.0.2.1"},
		{"empty IP", 1, "login.failed", ""},
		{"invalid IPv4", 1, "login.failed", "999.999.999.999"},
		{"invalid IPv6", 1, "login.failed", "2001:db8::gg"},
		{"hostname", 1, "login.failed", "localhost"},
		{"port", 1, "login.failed", "192.0.2.1:80"},
		{"CIDR", 1, "login.failed", "192.0.2.0/24"},
		{"whitespace", 1, "login.failed", " 192.0.2.1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var store Store
			valid, err := store.Add(1, "login.failed", "192.0.2.1")
			if err != nil {
				t.Fatal(err)
			}
			event, err := store.Add(tt.ownerID, tt.typeName, tt.sourceIP)
			if err == nil || event != (Event{}) {
				t.Fatalf("Add = %+v, %v; want zero event and error", event, err)
			}
			if got := store.ListAll(); !slices.Equal(got, []Event{valid}) {
				t.Fatalf("invalid input changed store: %+v", got)
			}
		})
	}
}

func TestListsReturnCopies(t *testing.T) {
	var store Store
	event, err := store.Add(1, "login.failed", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	all := store.ListAll()
	all[0] = Event{OwnerID: 2}
	owned := store.ListByOwner(1)
	if !slices.Equal(owned, []Event{event}) {
		t.Fatalf("ListAll exposed stored events: %+v", owned)
	}
	owned[0] = Event{OwnerID: 2}
	if got := store.ListAll(); !slices.Equal(got, []Event{event}) {
		t.Fatalf("ListByOwner exposed stored events: %+v", got)
	}
	if got := store.ListByOwner(2); len(got) != 0 {
		t.Fatalf("mutating results transferred ownership: %+v", got)
	}
}

func TestEmptyStore(t *testing.T) {
	var store Store
	if len(store.ListAll()) != 0 || len(store.ListByOwner(1)) != 0 {
		t.Fatal("new store contains events")
	}
}

func TestConcurrentAccess(t *testing.T) {
	var store Store
	const workers, perWorker = 8, 50
	var wg sync.WaitGroup
	start := make(chan struct{})
	before := time.Now()
	for worker := range workers {
		wg.Go(func() {
			<-start
			ownerID := int64(worker%2 + 1)
			for range perWorker {
				if _, err := store.Add(ownerID, "login.failed", "192.0.2.1"); err != nil {
					t.Error(err)
					return
				}
				for _, event := range store.ListByOwner(ownerID) {
					if event.OwnerID != ownerID {
						t.Errorf("owner %d received event for %d", ownerID, event.OwnerID)
					}
				}
				all := store.ListAll()
				if len(all) > 0 {
					all[0] = Event{}
				}
			}
		})
	}
	close(start)
	wg.Wait()
	after := time.Now()
	all := store.ListAll()
	if len(all) != workers*perWorker {
		t.Fatalf("stored %d events, want %d", len(all), workers*perWorker)
	}
	ids := make(map[string]bool, len(all))
	for _, event := range all {
		if event.ID == "" || ids[event.ID] {
			t.Fatalf("empty or duplicate event ID: %q", event.ID)
		}
		ids[event.ID] = true
		if event.IngestedAt.Before(before) || event.IngestedAt.After(after) {
			t.Fatalf("invalid ingestion timestamp: %v", event.IngestedAt)
		}
	}
	for _, ownerID := range []int64{1, 2} {
		if got := len(store.ListByOwner(ownerID)); got != workers*perWorker/2 {
			t.Errorf("owner %d has %d events, want %d", ownerID, got, workers*perWorker/2)
		}
	}
}
