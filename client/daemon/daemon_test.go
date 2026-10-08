package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/client/protocol"
)

// fakeAgentServer implements the three agent endpoints for daemon tests.
type fakeAgentServer struct {
	mu sync.Mutex

	enroll  protocol.EnrollResponse
	status  int
	netmap  string
	hbCode  int
	hbCount int
	nmCount int

	svcCode     int
	svcCount    int
	svcEmpty    int
	svcLast     []protocol.Service
	svcLastAuth string

	healthCode  int
	healthCount int
	healthLast  []protocol.ServiceHealth
	healthAuth  string
}

func (f *fakeAgentServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	raw, _ := io.ReadAll(req.Body)

	f.mu.Lock()
	defer f.mu.Unlock()

	switch req.URL.Path {
	case "/api/agent/v1/enroll":
		code := f.status
		if code == 0 {
			code = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(f.enroll)
	case "/api/agent/v1/netmap":
		f.nmCount++
		if f.netmap == "" {
			http.Error(w, "no netmap", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(f.netmap))
	case "/api/agent/v1/heartbeat":
		f.hbCount++
		if f.hbCode != 0 {
			http.Error(w, "nope", f.hbCode)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "/api/agent/v1/services":
		f.svcCount++
		f.svcLastAuth = req.Header.Get("Authorization")
		var body struct {
			Services []protocol.Service `json:"services"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if len(body.Services) == 0 {
			f.svcEmpty++
		}
		f.svcLast = body.Services
		if f.svcCode != 0 {
			http.Error(w, "nope", f.svcCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"services":[]}`))
	case "/api/agent/v1/services/health":
		f.healthCount++
		f.healthAuth = req.Header.Get("Authorization")
		var body struct {
			Services []protocol.ServiceHealth `json:"services"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		f.healthLast = body.Services
		if f.healthCode != 0 {
			http.Error(w, "nope", f.healthCode)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"services":[]}`))
	default:
		http.NotFound(w, req)
	}
}

func (f *fakeAgentServer) counts() (heartbeats, netmaps int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hbCount, f.nmCount
}

// serviceState returns how many publishes arrived, how many of them were
// empty, and a copy of the most recent set.
func (f *fakeAgentServer) serviceState() (publishes, empty int, last []protocol.Service) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.svcCount, f.svcEmpty, append([]protocol.Service(nil), f.svcLast...)
}

// healthState returns how many readiness reports arrived and a copy of the
// most recent one.
func (f *fakeAgentServer) healthState() (reports int, last []protocol.ServiceHealth, auth string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.healthCount, append([]protocol.ServiceHealth(nil), f.healthLast...), f.healthAuth
}

// TestEnrollPersistsState checks the enrollment round trip and the on-disk
// credentials.
func TestEnrollPersistsState(t *testing.T) {
	fake := &fakeAgentServer{enroll: protocol.EnrollResponse{
		Status: "authorized", Token: "agent-token", NodeID: 42, StableID: "stable-42",
	}}
	hs := httptest.NewServer(fake)
	defer hs.Close()

	stateDir := t.TempDir()
	state, err := Enroll(context.Background(), EnrollOptions{
		ServerURL: hs.URL,
		StateDir:  stateDir,
		AuthKey:   "xunara_authkey_x",
		Hostname:  "test-agent",
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if state.Token != "agent-token" || state.NodeID != 42 || state.StableID != "stable-42" {
		t.Fatalf("state = %+v", state)
	}
	if _, err := state.Keys(); err != nil {
		t.Fatalf("state keys: %v", err)
	}

	loaded, err := LoadState(stateDir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if loaded.Token != state.Token || loaded.MachineKey != state.MachineKey || loaded.NodeKey != state.NodeKey {
		t.Errorf("loaded state = %+v, want the enrolled state", loaded)
	}

	if runtime.GOOS == "linux" {
		info, err := os.Stat(filepath.Join(stateDir, stateFile))
		if err != nil {
			t.Fatalf("stat state file: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("state file mode = %o, want 600", perm)
		}
		dirInfo, err := os.Stat(stateDir)
		if err != nil {
			t.Fatalf("stat state dir: %v", err)
		}
		if perm := dirInfo.Mode().Perm(); perm != 0o700 && perm != 0o755 {
			t.Errorf("state dir mode = %o, want 700", perm)
		}
	}
}

// TestEnrollPendingAndRejected covers the two non-authorized enrollment
// statuses.
func TestEnrollPendingAndRejected(t *testing.T) {
	pending := &fakeAgentServer{enroll: protocol.EnrollResponse{
		Status: "pending", AuthURL: "https://login.example.com/register/abc",
	}}
	hs := httptest.NewServer(pending)
	defer hs.Close()

	stateDir := t.TempDir()
	_, err := Enroll(context.Background(), EnrollOptions{ServerURL: hs.URL, StateDir: stateDir})
	var pendingErr *PendingApprovalError
	if !errors.As(err, &pendingErr) {
		t.Fatalf("Enroll error = %v, want PendingApprovalError", err)
	}
	if pendingErr.AuthURL != "https://login.example.com/register/abc" {
		t.Errorf("auth URL = %q", pendingErr.AuthURL)
	}
	// Pending enrollment persists the generated keys (so the retry reuses
	// them and does not open a second device authorization) but no token.
	pendingState, err := LoadState(stateDir)
	if err != nil {
		t.Fatalf("LoadState after pending enrollment: %v", err)
	}
	if pendingState.Enrolled() {
		t.Error("pending enrollment stored a credential")
	}
	if pendingState.MachineKey == "" || pendingState.NodeKey == "" {
		t.Error("pending enrollment did not persist the generated keys")
	}

	// A rejected enrollment surfaces the server's reason.
	rejected := &fakeAgentServer{
		status: http.StatusForbidden,
		enroll: protocol.EnrollResponse{Status: "rejected", Error: "invalid pre-auth key"},
	}
	hs2 := httptest.NewServer(rejected)
	defer hs2.Close()

	_, err = Enroll(context.Background(), EnrollOptions{ServerURL: hs2.URL, StateDir: t.TempDir(), AuthKey: "bad"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("rejected enrollment error = %v", err)
	}
}

// TestEnrollRefusesForeignState checks that reusing a state directory that
// belongs to another control server fails instead of silently misreporting.
func TestEnrollRefusesForeignState(t *testing.T) {
	stateDir := t.TempDir()
	if err := SaveState(stateDir, State{
		ServerURL:  "https://other.example.com",
		MachineKey: "mkey:aaa",
		NodeKey:    "nodekey:bbb",
		Token:      "t",
	}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	_, err := Enroll(context.Background(), EnrollOptions{
		ServerURL: "https://login.example.com",
		StateDir:  stateDir,
	})
	if err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Errorf("Enroll error = %v, want a server mismatch", err)
	}
}

// TestAgentRunLoopsAndStops checks the steady-state loop: repeated
// heartbeats/netmaps, then a clean stop on context cancellation.
func TestAgentRunLoopsAndStops(t *testing.T) {
	fake := &fakeAgentServer{
		enroll: protocol.EnrollResponse{Status: "authorized", Token: "t", NodeID: 1, StableID: "s"},
		netmap: `{"Node":{"Name":"agent.example.com."},"Peers":[{"ID":2},{"ID":3}]}`,
	}
	hs := httptest.NewServer(fake)
	defer hs.Close()

	stateDir := t.TempDir()
	state, err := Enroll(context.Background(), EnrollOptions{ServerURL: hs.URL, StateDir: stateDir, AuthKey: "k"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	agent, err := NewAgent(state, protocol.New(hs.URL), nil)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	agent.Interval = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()

	// Wait for a couple of cycles.
	deadline := time.Now().Add(5 * time.Second)
	for {
		hb, nm := fake.counts()
		if hb >= 2 && nm >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent produced %d heartbeats, %d netmaps; want at least 2/1", hb, nm)
		}
		time.Sleep(5 * time.Millisecond)
	}
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

// TestAgentRunStopsOnRevokedCredential checks that a 401 ends the loop instead
// of retrying forever with a dead token.
func TestAgentRunStopsOnRevokedCredential(t *testing.T) {
	fake := &fakeAgentServer{
		enroll: protocol.EnrollResponse{Status: "authorized", Token: "t", NodeID: 1, StableID: "s"},
		hbCode: http.StatusUnauthorized,
	}
	hs := httptest.NewServer(fake)
	defer hs.Close()

	stateDir := t.TempDir()
	state, err := Enroll(context.Background(), EnrollOptions{ServerURL: hs.URL, StateDir: stateDir, AuthKey: "k"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	agent, err := NewAgent(state, protocol.New(hs.URL), nil)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	agent.Interval = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = agent.Run(ctx)
	if err == nil || !strings.Contains(err.Error(), "enroll again") {
		t.Fatalf("Run error = %v, want a re-enroll signal", err)
	}
}

// TestServicesDeclarationFiles covers the on-disk declaration: round trip,
// restrictive permissions, a missing file, and idempotent removal.
func TestServicesDeclarationFiles(t *testing.T) {
	stateDir := t.TempDir()

	if _, err := LoadServices(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadServices on an empty directory = %v, want os.ErrNotExist", err)
	}
	if err := RemoveServices(stateDir); err != nil {
		t.Fatalf("RemoveServices without a file: %v", err)
	}

	declaration := []protocol.Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "1"}},
	}
	if err := SaveServices(stateDir, declaration); err != nil {
		t.Fatalf("SaveServices: %v", err)
	}
	loaded, err := LoadServices(stateDir)
	if err != nil {
		t.Fatalf("LoadServices: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Name != "api" || loaded[0].Metadata["version"] != "1" {
		t.Fatalf("loaded services = %+v", loaded)
	}

	if runtime.GOOS == "linux" {
		info, err := os.Stat(filepath.Join(stateDir, servicesFile))
		if err != nil {
			t.Fatalf("stat services file: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("services file mode = %o, want 600", perm)
		}
	}

	if err := RemoveServices(stateDir); err != nil {
		t.Fatalf("RemoveServices: %v", err)
	}
	if _, err := LoadServices(stateDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("LoadServices after removal = %v, want os.ErrNotExist", err)
	}
}

// TestAgentPublishesServices runs the reconciliation loop: the declaration is
// published at bring-up, refreshed on a timer, and re-read from disk so a
// publish next to a running agent takes effect without a restart.
func TestAgentPublishesServices(t *testing.T) {
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
	if err := SaveServices(stateDir, []protocol.Service{{Name: "api", Protocol: "tcp", Port: 8080}}); err != nil {
		t.Fatalf("SaveServices: %v", err)
	}

	agent, err := NewAgent(state, protocol.New(hs.URL), nil)
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}
	agent.Interval = 10 * time.Millisecond
	agent.ServicesInterval = 10 * time.Millisecond
	agent.StateDir = stateDir

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx) }()

	// Bring-up publish plus at least one periodic refresh.
	waitForServices(t, fake, func(publishes, empty int, last []protocol.Service) bool {
		return publishes >= 2 && len(last) == 1 && last[0].Name == "api"
	})

	// The declaration file is authoritative, so replacing it changes what the
	// agent publishes on the next refresh.
	if err := SaveServices(stateDir, []protocol.Service{{Name: "web", Protocol: "tcp", Port: 80}}); err != nil {
		t.Fatalf("SaveServices: %v", err)
	}
	waitForServices(t, fake, func(_, _ int, last []protocol.Service) bool {
		return len(last) == 1 && last[0].Name == "web"
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

	// Removing the declaration stops the publishes; the agent must never
	// withdraw a set on its own.
	if publishes, empty, _ := fake.serviceState(); empty != 0 {
		t.Errorf("%d of %d publishes were empty, want none", empty, publishes)
	}
}

// waitForServices polls the fake until the predicate holds or the deadline
// passes.
func waitForServices(t *testing.T, fake *fakeAgentServer, ok func(publishes, empty int, last []protocol.Service) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		publishes, empty, last := fake.serviceState()
		if ok(publishes, empty, last) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for services: %d publishes, %d empty, last %+v", publishes, empty, last)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
