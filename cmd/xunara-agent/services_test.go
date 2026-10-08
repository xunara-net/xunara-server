package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/client/daemon"
	"github.com/xunara-net/xunara-server/client/protocol"
)

// TestReadServicesFile covers the file format: canonical declarations are
// accepted, typos are refused.
func TestReadServicesFile(t *testing.T) {
	dir := t.TempDir()

	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		return path
	}

	path := write("ok.json", `{"services":[{"name":"api","protocol":"TCP","port":8080,"metadata":{"version":"1"}}]}`)
	services, err := readServicesFile(path)
	if err != nil {
		t.Fatalf("readServicesFile: %v", err)
	}
	if len(services) != 1 || services[0].Protocol != "tcp" || services[0].Metadata["version"] != "1" {
		t.Fatalf("services = %+v", services)
	}

	health, err := readServicesFile(write("health.json", `{"services":[{"name":"api","protocol":"tcp","port":8080,"health":true}]}`))
	if err != nil {
		t.Fatalf("readServicesFile(health): %v", err)
	}
	if len(health) != 1 || !health[0].Health {
		t.Fatalf("health declaration = %+v, want health tracked", health)
	}

	if _, err := readServicesFile(write("typo.json", `{"services":[{"name":"api","protcol":"tcp","port":1}]}`)); err == nil {
		t.Error("an unknown field was accepted")
	}
	if _, err := readServicesFile(write("trailing.json", `{"services":[]} {}`)); err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Errorf("trailing data error = %v", err)
	}
	if _, err := readServicesFile(write("array.json", `[{"name":"api"}]`)); err == nil {
		t.Error("a bare array was accepted")
	}
	if _, err := readServicesFile(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing file was accepted")
	}
}

// TestWriteServicesTable checks both renderings: a local declaration has no
// server fields, a stored set does.
func TestWriteServicesTable(t *testing.T) {
	var buf strings.Builder
	err := writeDeclaredServices(&buf, []protocol.Service{
		{Name: "web", Protocol: "tcp", Port: 80},
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"zone": "eu", "version": "2"}},
		{Name: "db", Protocol: "tcp", Port: 5432, Health: true},
	})
	if err != nil {
		t.Fatalf("writeDeclaredServices: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "NAME") || strings.Contains(out, "DNS NAME") {
		t.Errorf("declaration table has the wrong columns:\n%s", out)
	}
	if strings.Index(out, "api") > strings.Index(out, "web") {
		t.Errorf("declaration table is not sorted by name:\n%s", out)
	}
	if !strings.Contains(out, "api metadata:") || !strings.Contains(out, "zone") {
		t.Errorf("metadata is missing from the declaration table:\n%s", out)
	}
	if !strings.Contains(out, "HEALTH") || !strings.Contains(out, "tracked") {
		t.Errorf("declaration table lacks the health column:\n%s", out)
	}

	buf.Reset()
	err = writePublishedServices(&buf, []protocol.ServiceView{
		{
			Name: "api", Protocol: "tcp", Port: 8080, DNSName: "api.example.com",
			Updated: time.Date(2026, 10, 8, 7, 0, 0, 0, time.UTC),
		},
		{Name: "web", Protocol: "tcp", Port: 80},
		{Name: "db", Protocol: "tcp", Port: 5432, Health: "healthy", Updated: time.Date(2026, 10, 8, 7, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatalf("writePublishedServices: %v", err)
	}
	out = buf.String()
	if !strings.Contains(out, "DNS NAME") || !strings.Contains(out, "api.example.com") {
		t.Errorf("stored table is missing the DNS name:\n%s", out)
	}
	if !strings.Contains(out, "healthy") {
		t.Errorf("stored table is missing the reported health:\n%s", out)
	}
	var webLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "web") {
			webLine = line
		}
	}
	if strings.Count(webLine, "-") != 3 {
		t.Errorf("unknown server fields are not dashed out: %q", webLine)
	}

	buf.Reset()
	if err := writeDeclaredServices(&buf, nil); err != nil {
		t.Fatalf("writeDeclaredServices(nil): %v", err)
	}
	if !strings.Contains(buf.String(), "No services are declared") {
		t.Errorf("empty declaration output = %q", buf.String())
	}
}

// fakeServicesControl answers POST /api/agent/v1/services and records what it
// saw, so the CLI can be driven end to end without a control plane.
type fakeServicesControl struct {
	mu        sync.Mutex
	auth      string
	publishes [][]protocol.Service
	reject    map[string]bool
}

func (f *fakeServicesControl) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/api/agent/v1/services" {
		http.NotFound(w, req)
		return
	}
	var body struct {
		Services []protocol.Service `json:"services"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	f.auth = req.Header.Get("Authorization")
	f.publishes = append(f.publishes, body.Services)
	rejected := false
	for _, svc := range body.Services {
		if f.reject[svc.Name] {
			rejected = true
		}
	}
	f.mu.Unlock()

	if rejected {
		http.Error(w, "a service name is already in use", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"services": body.Services})
}

func (f *fakeServicesControl) state() (string, [][]protocol.Service) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]protocol.Service, len(f.publishes))
	copy(out, f.publishes)
	return f.auth, out
}

// TestServicesPublishListClear drives the CLI against a fake control plane:
// publish sends the declaration and saves it, a rejected publish leaves it
// alone, and clear withdraws it and removes the file.
func TestServicesPublishListClear(t *testing.T) {
	fake := &fakeServicesControl{reject: map[string]bool{"conflict": true}}
	hs := httptest.NewServer(fake)
	defer hs.Close()

	stateDir := t.TempDir()
	writeAgentState(t, stateDir, hs.URL)

	dir := t.TempDir()
	declPath := filepath.Join(dir, "services.json")
	if err := os.WriteFile(declPath, []byte(`{"services":[{"name":"api","protocol":"tcp","port":8080}]}`), 0o600); err != nil {
		t.Fatalf("writing declaration: %v", err)
	}

	if err := runServicesPublish(context.Background(), []string{"-state-dir", stateDir, "-file", declPath}); err != nil {
		t.Fatalf("services publish: %v", err)
	}
	auth, publishes := fake.state()
	if auth != "Bearer agent-token" {
		t.Errorf("publish auth = %q, want the bearer token", auth)
	}
	if len(publishes) != 1 || len(publishes[0]) != 1 || publishes[0][0].Name != "api" || publishes[0][0].Port != 8080 {
		t.Fatalf("publishes = %+v", publishes)
	}
	declared, err := daemon.LoadServices(stateDir)
	if err != nil {
		t.Fatalf("LoadServices after publish: %v", err)
	}
	if len(declared) != 1 || declared[0].Name != "api" {
		t.Fatalf("saved declaration = %+v", declared)
	}

	if err := runServicesList([]string{"-state-dir", stateDir, "-json"}); err != nil {
		t.Fatalf("services list: %v", err)
	}

	// A rejected publish must not replace the working declaration.
	conflictPath := filepath.Join(dir, "conflict.json")
	if err := os.WriteFile(conflictPath, []byte(`{"services":[{"name":"conflict","protocol":"tcp","port":80}]}`), 0o600); err != nil {
		t.Fatalf("writing conflict declaration: %v", err)
	}
	if err := runServicesPublish(context.Background(), []string{"-state-dir", stateDir, "-file", conflictPath}); err == nil {
		t.Fatal("publish accepted a rejected declaration")
	}
	if declared, err := daemon.LoadServices(stateDir); err != nil || len(declared) != 1 || declared[0].Name != "api" {
		t.Errorf("declaration changed after a rejected publish: %+v (%v)", declared, err)
	}

	if err := runServicesClear(context.Background(), []string{"-state-dir", stateDir}); err != nil {
		t.Fatalf("services clear: %v", err)
	}
	_, publishes = fake.state()
	if len(publishes) != 3 || len(publishes[2]) != 0 {
		t.Fatalf("publishes after clear = %+v, want a final empty set", publishes)
	}
	if _, err := daemon.LoadServices(stateDir); !os.IsNotExist(err) {
		t.Errorf("declaration file survived clear: %v", err)
	}
}

// writeAgentState enrolls a fake node on disk: the minimal state a command
// that talks to the control plane needs.
func writeAgentState(t *testing.T, stateDir, serverURL string) {
	t.Helper()
	machine, node := key.NewMachine(), key.NewNode()
	machineText, err := machine.MarshalText()
	if err != nil {
		t.Fatalf("machine marshaling: %v", err)
	}
	nodeText, err := node.MarshalText()
	if err != nil {
		t.Fatalf("node marshaling: %v", err)
	}
	if err := daemon.SaveState(stateDir, daemon.State{
		ServerURL:  serverURL,
		MachineKey: string(machineText),
		NodeKey:    string(nodeText),
		Token:      "agent-token",
		NodeID:     7,
		StableID:   "n7",
	}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
}

// TestServicesImportFromConsul maps a local Consul catalog and publishes it,
// warning about what it skipped; -dry-run needs no enrolled agent.
func TestServicesImportFromConsul(t *testing.T) {
	control := &fakeServicesControl{}
	controlServer := httptest.NewServer(control)
	defer controlServer.Close()

	consulServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/agent/services" {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write([]byte(`{
			"dns": {"ID":"dns","Service":"dns","Tags":["udp"],"Port":53},
			"web": {"ID":"web","Service":"web","Port":8080},
			"proxy": {"ID":"api-proxy","Service":"api-proxy","Kind":"connect-proxy","Port":21000}
		}`))
	}))
	defer consulServer.Close()

	stateDir := t.TempDir()
	writeAgentState(t, stateDir, controlServer.URL)

	err := runServicesImport(context.Background(), []string{
		"-state-dir", stateDir,
		"-from", "consul",
		"-consul-addr", consulServer.URL,
	})
	if err != nil {
		t.Fatalf("services import: %v", err)
	}

	auth, publishes := control.state()
	if auth != "Bearer agent-token" {
		t.Errorf("publish auth = %q, want the bearer token", auth)
	}
	if len(publishes) != 1 || len(publishes[0]) != 2 {
		t.Fatalf("publishes = %+v, want one set of two services", publishes)
	}
	if publishes[0][0].Name != "dns" || publishes[0][0].Protocol != "udp" || publishes[0][1].Name != "web" {
		t.Errorf("published set = %+v", publishes[0])
	}
	if declared, err := daemon.LoadServices(stateDir); err != nil || len(declared) != 2 {
		t.Errorf("saved declaration = %+v (%v)", declared, err)
	}

	// -dry-run prints the declaration and does not need an enrolled agent.
	dryDir := t.TempDir()
	out := captureStdout(t, func() error {
		return runServicesImport(context.Background(), []string{
			"-state-dir", dryDir,
			"-from", "consul",
			"-consul-addr", consulServer.URL,
			"-dry-run",
		})
	})
	if !strings.Contains(out, `"name": "dns"`) || !strings.Contains(out, `"protocol": "udp"`) {
		t.Errorf("dry-run output = %q", out)
	}
	if _, err := daemon.LoadServices(dryDir); !os.IsNotExist(err) {
		t.Errorf("dry-run saved a declaration: %v", err)
	}

	if err := runServicesImport(context.Background(), []string{"-from", "nope"}); err == nil {
		t.Error("an unsupported catalog was accepted")
	}
}

// TestServicesImportFromKubernetes maps a node-local Kubernetes Service and
// publishes it; the Kubernetes node name comes from -k8s-node or NODE_NAME.
func TestServicesImportFromKubernetes(t *testing.T) {
	control := &fakeServicesControl{}
	controlServer := httptest.NewServer(control)
	defer controlServer.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/namespaces/tailnet/services", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"api","annotations":{"xunara.io/advertise":"true"}}}]}`))
	})
	mux.HandleFunc("/apis/discovery.k8s.io/v1/namespaces/tailnet/endpointslices", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"labels":{"kubernetes.io/service-name":"api"}},
			"endpoints":[{"nodeName":"node-a","conditions":{"ready":true}}],
			"ports":[{"name":"http","protocol":"TCP","port":8080}]}]}`))
	})
	api := httptest.NewTLSServer(mux)
	defer api.Close()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("test-token"), 0o600); err != nil {
		t.Fatalf("writing the token: %v", err)
	}
	caFile := filepath.Join(dir, "ca.crt")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("writing the CA: %v", err)
	}

	stateDir := t.TempDir()
	writeAgentState(t, stateDir, controlServer.URL)

	args := []string{
		"-state-dir", stateDir,
		"-from", "kubernetes",
		"-k8s-api", api.URL,
		"-k8s-token-file", tokenFile,
		"-k8s-ca-file", caFile,
		"-k8s-namespace", "tailnet",
		"-k8s-node", "node-a",
	}
	if err := runServicesImport(context.Background(), args); err != nil {
		t.Fatalf("services import: %v", err)
	}
	if _, publishes := control.state(); len(publishes) != 1 || len(publishes[0]) != 1 || publishes[0][0].Name != "api" {
		t.Fatalf("publishes = %+v", publishes)
	}

	// NODE_NAME is the in-pod default, and -dry-run needs no enrolled agent.
	t.Setenv(nodeNameEnv, "node-a")
	dryDir := t.TempDir()
	out := captureStdout(t, func() error {
		return runServicesImport(context.Background(), []string{
			"-state-dir", dryDir,
			"-from", "kubernetes",
			"-k8s-api", api.URL,
			"-k8s-token-file", tokenFile,
			"-k8s-ca-file", caFile,
			"-k8s-namespace", "tailnet",
			"-dry-run",
		})
	})
	if !strings.Contains(out, `"name": "api"`) || !strings.Contains(out, `"port": 8080`) {
		t.Errorf("dry-run output = %q", out)
	}
	if _, err := daemon.LoadServices(dryDir); !os.IsNotExist(err) {
		t.Errorf("dry-run saved a declaration: %v", err)
	}

	t.Setenv(nodeNameEnv, "")
	err := runServicesImport(context.Background(), []string{
		"-from", "kubernetes",
		"-k8s-api", api.URL,
		"-k8s-token-file", tokenFile,
		"-k8s-ca-file", caFile,
		"-dry-run",
	})
	if err == nil || !strings.Contains(err.Error(), "node name is required") {
		t.Errorf("missing node name error = %v", err)
	}
}

// captureStdout runs fn with stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func() error) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating pipe: %v", err)
	}
	os.Stdout = w
	runErr := fn()
	_ = w.Close()
	os.Stdout = old
	if runErr != nil {
		t.Fatalf("command: %v", runErr)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading captured stdout: %v", err)
	}
	return string(out)
}

// TestWriteHealthHint checks the operator guidance printed after publishing a
// health-tracked declaration: the services, the readiness file and the
// interval flag are named.
func TestWriteHealthHint(t *testing.T) {
	out := captureStderr(t, func() {
		writeHealthHint([]protocol.Service{
			{Name: "api", Protocol: "tcp", Port: 8080, Health: true},
			{Name: "web", Protocol: "tcp", Port: 80},
			{Name: "db", Protocol: "tcp", Port: 5432, Health: true},
		})
	})
	for _, want := range []string{"api, db", daemon.ServiceHealthFileName, "-services-health-interval"} {
		if !strings.Contains(out, want) {
			t.Errorf("health hint lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "web") {
		t.Errorf("health hint names an untracked service:\n%s", out)
	}

	if out := captureStderr(t, func() { writeHealthHint([]protocol.Service{{Name: "web", Protocol: "tcp", Port: 80}}) }); out != "" {
		t.Errorf("health hint printed without a tracked service:\n%s", out)
	}
}

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()

	fn()
	if err := w.Close(); err != nil {
		t.Fatalf("closing the pipe: %v", err)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("reading stderr: %v", err)
	}
	return string(raw)
}
