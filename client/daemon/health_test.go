package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/client/protocol"
)

// writeHealthFile writes the readiness file a service manager would produce.
func writeHealthFile(t *testing.T, stateDir, raw string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(stateDir, ServiceHealthFileName), []byte(raw), 0o600); err != nil {
		t.Fatalf("writing %s: %v", ServiceHealthFileName, err)
	}
}

// TestServiceHealthFiles covers the on-disk readiness file: round trip, a
// missing file, and the malformed inputs that must not be half-read.
func TestServiceHealthFiles(t *testing.T) {
	stateDir := t.TempDir()

	if _, err := LoadServiceHealth(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadServiceHealth on an empty directory = %v, want os.ErrNotExist", err)
	}

	writeHealthFile(t, stateDir, `{"services":[{"name":"api","ready":true},{"name":"db","ready":false}]}`)
	loaded, err := LoadServiceHealth(stateDir)
	if err != nil {
		t.Fatalf("LoadServiceHealth: %v", err)
	}
	want := []protocol.ServiceHealth{{Name: "api", Ready: true}, {Name: "db", Ready: false}}
	if len(loaded) != len(want) || loaded[0] != want[0] || loaded[1] != want[1] {
		t.Fatalf("loaded = %+v, want %+v", loaded, want)
	}

	for name, raw := range map[string]string{
		"unknown field":  `{"services":[{"name":"api","ready":true,"extra":1}]}`,
		"trailing data":  `{"services":[]}{"services":[]}`,
		"malformed json": `{"services":`,
		"wrong shape":    `{"services":{"api":true}}`,
		"oversize":       `{"services":[]}` + strings.Repeat(" ", maxServiceHealthBytes),
	} {
		t.Run(name, func(t *testing.T) {
			writeHealthFile(t, stateDir, raw)
			if _, err := LoadServiceHealth(stateDir); err == nil {
				t.Fatalf("LoadServiceHealth(%s) = nil error, want a parse failure", raw)
			}
		})
	}
}

// healthReportsFor runs the agent's report construction over a fresh
// declaration and (optional) readiness file.
func healthReportsFor(t *testing.T, services []protocol.Service, healthFile string, log *slog.Logger) ([]protocol.ServiceHealth, bool) {
	t.Helper()

	stateDir := t.TempDir()
	if err := SaveServices(stateDir, services); err != nil {
		t.Fatalf("SaveServices: %v", err)
	}
	if healthFile != "" {
		writeHealthFile(t, stateDir, healthFile)
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	agent := &Agent{StateDir: stateDir, Logger: log}
	return agent.healthReports()
}

// TestHealthReports covers report construction: only health-tracked services
// are reported, the report is the complete set, and a missing or unreadable
// readiness file is an explicit "nothing is ready".
func TestHealthReports(t *testing.T) {
	plain := protocol.Service{Name: "api", Protocol: "tcp", Port: 8080}
	tracked := protocol.Service{Name: "api", Protocol: "tcp", Port: 8080, Health: true}

	t.Run("no health-tracked services", func(t *testing.T) {
		reports, ok := healthReportsFor(t, []protocol.Service{plain}, `{"services":[{"name":"api","ready":true}]}`, nil)
		if ok || reports != nil {
			t.Fatalf("reports = %+v, ok = %v; want no report", reports, ok)
		}
	})

	t.Run("missing file is not ready", func(t *testing.T) {
		reports, ok := healthReportsFor(t, []protocol.Service{tracked}, "", nil)
		if !ok || len(reports) != 1 || reports[0] != (protocol.ServiceHealth{Name: "api", Ready: false}) {
			t.Fatalf("reports = %+v, ok = %v", reports, ok)
		}
	})

	t.Run("readiness file flips the report", func(t *testing.T) {
		reports, ok := healthReportsFor(t, []protocol.Service{tracked}, `{"services":[{"name":"api","ready":true}]}`, nil)
		if !ok || len(reports) != 1 || reports[0] != (protocol.ServiceHealth{Name: "api", Ready: true}) {
			t.Fatalf("reports = %+v, ok = %v", reports, ok)
		}
	})

	t.Run("untracked entries are ignored with a warning", func(t *testing.T) {
		var logged bytes.Buffer
		log := slog.New(slog.NewTextHandler(&logged, nil))
		reports, ok := healthReportsFor(t, []protocol.Service{tracked},
			`{"services":[{"name":"ghost","ready":true},{"name":"api","ready":true}]}`, log)
		if !ok || len(reports) != 1 || reports[0] != (protocol.ServiceHealth{Name: "api", Ready: true}) {
			t.Fatalf("reports = %+v, ok = %v", reports, ok)
		}
		if !strings.Contains(logged.String(), "ghost") || !strings.Contains(logged.String(), "untracked") {
			t.Errorf("log lacks the untracked warning:\n%s", logged.String())
		}
	})

	t.Run("unreadable file reports nothing", func(t *testing.T) {
		if reports, ok := healthReportsFor(t, []protocol.Service{tracked}, `{"services":`, nil); ok || reports != nil {
			t.Fatalf("reports = %+v, ok = %v; want no report", reports, ok)
		}
	})

	t.Run("report is complete and sorted", func(t *testing.T) {
		services := []protocol.Service{
			{Name: "zebra", Protocol: "tcp", Port: 1, Health: true},
			{Name: "api", Protocol: "tcp", Port: 2, Health: true},
			{Name: "plain", Protocol: "tcp", Port: 3},
		}
		reports, ok := healthReportsFor(t, services, `{"services":[{"name":"api","ready":true}]}`, nil)
		want := []protocol.ServiceHealth{{Name: "api", Ready: true}, {Name: "zebra", Ready: false}}
		if !ok || len(reports) != len(want) || reports[0] != want[0] || reports[1] != want[1] {
			t.Fatalf("reports = %+v, ok = %v; want %+v", reports, ok, want)
		}
	})
}

// TestAgentReportsServiceHealth runs the reporting loop: the readiness file
// is reported on a timer, changes take effect without a restart, and the
// declaration decides which services are reported at all.
func TestAgentReportsServiceHealth(t *testing.T) {
	fake := &fakeAgentServer{
		enroll: protocol.EnrollResponse{Status: "authorized", Token: "t", NodeID: 1, StableID: "s"},
		netmap: `{"Node":{"Name":"agent.example.com."}}`,
	}
	hs := httptest.NewServer(fake)
	defer hs.Close()

	stateDir := t.TempDir()
	state, err := Enroll(context.Background(), EnrollOptions{ServerURL: hs.URL, StateDir: stateDir, AuthKey: "k"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := SaveServices(stateDir, []protocol.Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Health: true},
		{Name: "plain", Protocol: "tcp", Port: 80},
	}); err != nil {
		t.Fatalf("SaveServices: %v", err)
	}
	writeHealthFile(t, stateDir, `{"services":[{"name":"api","ready":true}]}`)

	agent, err := NewAgent(state, protocol.New(hs.URL), nil)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	agent.Interval = 10 * time.Millisecond
	agent.ServicesInterval = 10 * time.Millisecond
	agent.HealthInterval = 10 * time.Millisecond
	agent.StateDir = stateDir

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()

	waitForHealth(t, fake, func(reports int, last []protocol.ServiceHealth) bool {
		return reports >= 2 && len(last) == 1 && last[0] == (protocol.ServiceHealth{Name: "api", Ready: true})
	})
	_, _, auth := fake.healthState()
	if auth != "Bearer t" {
		t.Errorf("health auth = %q, want the bearer token", auth)
	}

	// Readiness is re-read every cycle: flipping the file withdraws the
	// service on the next report without restarting the agent.
	writeHealthFile(t, stateDir, `{"services":[{"name":"api","ready":false}]}`)
	waitForHealth(t, fake, func(_ int, last []protocol.ServiceHealth) bool {
		return len(last) == 1 && last[0] == (protocol.ServiceHealth{Name: "api", Ready: false})
	})

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

// TestAgentStopsReportingOnRevocation checks that a rejected report stops the
// goroutine instead of retrying forever with a dead credential.
func TestAgentStopsReportingOnRevocation(t *testing.T) {
	fake := &fakeAgentServer{
		enroll:     protocol.EnrollResponse{Status: "authorized", Token: "t", NodeID: 1, StableID: "s"},
		netmap:     `{"Node":{"Name":"agent.example.com."}}`,
		healthCode: http.StatusForbidden,
	}
	hs := httptest.NewServer(fake)
	defer hs.Close()

	stateDir := t.TempDir()
	state, err := Enroll(context.Background(), EnrollOptions{ServerURL: hs.URL, StateDir: stateDir, AuthKey: "k"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := SaveServices(stateDir, []protocol.Service{{Name: "api", Protocol: "tcp", Port: 8080, Health: true}}); err != nil {
		t.Fatalf("SaveServices: %v", err)
	}

	agent, err := NewAgent(state, protocol.New(hs.URL), nil)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	agent.HealthInterval = 5 * time.Millisecond
	agent.StateDir = stateDir

	keys, err := state.Keys()
	if err != nil {
		t.Fatalf("state keys: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agent.healthLoop(ctx, keys)

	deadline := time.Now().Add(5 * time.Second)
	for {
		if reports, _, _ := fake.healthState(); reports > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no readiness report arrived")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if reports, _, _ := fake.healthState(); reports > 1 {
		t.Fatalf("health loop kept reporting after a 403: %d reports", reports)
	}
}

// waitForHealth polls the fake until the predicate holds or the deadline
// passes.
func waitForHealth(t *testing.T, fake *fakeAgentServer, ok func(reports int, last []protocol.ServiceHealth) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		reports, last, _ := fake.healthState()
		if ok(reports, last) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for readiness reports: %d reports, last %+v", reports, last)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
