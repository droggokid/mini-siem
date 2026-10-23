package minisiem_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Set MINI_SIEM_TEST_URL to exercise a fresh Compose stack with the same workflow.
func TestDetectionIntegration(t *testing.T) {
	apiURL := os.Getenv("MINI_SIEM_TEST_URL")
	var eventURL, detectionURL string
	if apiURL == "" {
		apiURL, eventURL, detectionURL = startServices(t)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	call := func(method, url, body, token string, status int) []byte {
		t.Helper()
		r, err := http.NewRequest(method, url, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != status {
			t.Fatalf("%s %s: status=%d, want %d, err=%v", method, url, response.StatusCode, status, err)
		}
		return data
	}

	tokens := make(map[string]string)
	for _, user := range []string{"Alice", "Bob", "Admin"} {
		data := call("POST", apiURL+"/login", fmt.Sprintf(`{"username":%q,"password":%q}`, user, strings.ToLower(user)+"-password"), "", 200)
		var result struct {
			Token string `json:"access_token"`
		}
		if json.Unmarshal(data, &result) != nil || result.Token == "" {
			t.Fatal("login did not return a token")
		}
		tokens[user] = result.Token
	}

	for _, path := range []string{"/detections/run", "/alerts"} {
		method := "GET"
		if path == "/detections/run" {
			method = "POST"
		}
		call(method, apiURL+path, "", "", 401)
		call(method, apiURL+path+"?owner_id=1", "", tokens["Bob"], 400)
	}
	call("POST", apiURL+"/detections/run", `{"owner_id":1}`, tokens["Bob"], 400)

	submit := func(user string, count int) {
		t.Helper()
		for range count {
			call("POST", apiURL+"/events", `{"type":"login.failed","source_ip":"192.0.2.101"}`, tokens[user], 201)
		}
	}
	run := func(user string, scanned, created int) {
		t.Helper()
		data := call("POST", apiURL+"/detections/run", "", tokens[user], 200)
		var summary struct {
			JobID         string `json:"job_id"`
			EventsScanned int    `json:"events_scanned"`
			AlertsCreated int    `json:"alerts_created"`
		}
		if json.Unmarshal(data, &summary) != nil || summary.JobID == "" || summary.EventsScanned != scanned || summary.AlertsCreated != created {
			t.Fatalf("%s summary: %s", user, data)
		}
	}

	submit("Alice", 4)
	submit("Bob", 4)
	run("Alice", 4, 0)
	submit("Alice", 1)
	run("Alice", 5, 1)
	run("Bob", 4, 0)
	run("Admin", 0, 0)

	for index, user := range []string{"Alice", "Bob", "Admin"} {
		data := call("GET", apiURL+"/alerts", "", tokens[user], 200)
		var alerts []struct {
			ID               string    `json:"id"`
			OwnerID          int64     `json:"owner_id"`
			SourceIP         string    `json:"source_ip"`
			DetectionType    string    `json:"detection_type"`
			FailedLoginCount int       `json:"failed_login_count"`
			CreatedAt        time.Time `json:"created_at"`
		}
		if err := json.Unmarshal(data, &alerts); err != nil {
			t.Fatal(err)
		}
		want := 0
		if user == "Alice" {
			want = 1
		}
		if len(alerts) != want {
			t.Fatalf("%s received %d alerts, want %d", user, len(alerts), want)
		}
		for _, alert := range alerts {
			if alert.OwnerID != int64(index+1) || alert.ID == "" || alert.SourceIP != "192.0.2.101" || alert.FailedLoginCount != 5 || alert.DetectionType != "failed_login_burst" || alert.CreatedAt.IsZero() {
				t.Fatalf("incorrect alert: %+v", alert)
			}
		}
	}

	submit("Bob", 1)
	run("Bob", 5, 1)
	submit("Admin", 5)
	run("Admin", 5, 1)

	if eventURL != "" {
		for _, token := range []string{"", tokens["Alice"]} {
			call("GET", eventURL+"/jobs/events", "", token, 401)
			call("POST", eventURL+"/jobs/alerts", "[]", token, 401)
			call("GET", eventURL+"/alerts", "", token, 401)
			call("POST", detectionURL+"/detections/run", "{}", token, 401)
		}
	}
}

func startServices(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	build := exec.Command("go", "build", "-race", "-o", dir, "./cmd/api", "./cmd/event", "./cmd/detection")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build services: %v\n%s", err, output)
	}

	addresses := make([]string, 3)
	for index := range addresses {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addresses[index] = listener.Addr().String()
		listener.Close()
	}
	apiURL, eventURL, detectionURL := "http://"+addresses[0], "http://"+addresses[1], "http://"+addresses[2]
	environment := append(os.Environ(),
		"GIN_MODE=release",
		"API_ADDR="+addresses[0], "EVENT_ADDR="+addresses[1], "DETECTION_ADDR="+addresses[2],
		"EVENT_URL="+eventURL, "DETECTION_URL="+detectionURL,
		"USERS_DB_PATH="+filepath.Join(dir, "users.db"),
		"JWT_SECRET_FILE="+filepath.Join(dir, "jwt-secret"),
		"EVENT_SECRET_FILE="+filepath.Join(dir, "event-secret"),
		"JOB_SEED_FILE="+filepath.Join(dir, "job-seed"),
		"JOB_PUBLIC_KEY_FILE="+filepath.Join(dir, "job-public"),
	)

	for index, service := range []string{"api", "event", "detection"} {
		log, err := os.Create(filepath.Join(dir, service+".log"))
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command(filepath.Join(dir, service))
		command.Env = environment
		command.Stdout, command.Stderr = log, log
		if err := command.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() {
			command.Process.Kill()
			command.Wait()
			log.Close()
			data, err := os.ReadFile(log.Name())
			if err != nil || strings.Contains(string(data), "WARNING: DATA RACE") {
				t.Errorf("%s service log contains a race or could not be read: %v", service, err)
			}
		})

		client := &http.Client{Timeout: time.Second}
		ready := false
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			response, err := client.Get("http://" + addresses[index] + "/health")
			if err == nil {
				response.Body.Close()
				if response.StatusCode == 200 {
					ready = true
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !ready {
			data, _ := os.ReadFile(log.Name())
			t.Fatalf("%s did not become healthy: %s", service, data)
		}
	}
	return apiURL, eventURL, detectionURL
}
