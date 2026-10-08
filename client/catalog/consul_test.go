package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/client/protocol"
)

// consulCatalog is a response with one entry per mapping rule, including
// everything that must be skipped.
const consulCatalog = `{
  "Bad_Name":   {"ID":"Bad_Name","Service":"Bad_Name","Port":80},
  "bigmeta":    {"ID":"bigmeta","Service":"bigmeta","Port":80,"Meta":{"a b":"secret-meta-value"}},
  "conflict-1": {"ID":"conflict-1","Service":"conflict","Port":80},
  "conflict-2": {"ID":"conflict-2","Service":"conflict","Port":81},
  "dns":        {"ID":"dns","Service":"dns","Tags":["udp"],"Port":53},
  "empty":      {"ID":"empty","Service":"","Port":80},
  "noport":     {"ID":"noport","Service":"noport","Port":0},
  "peer":       {"ID":"peer","Service":"remote","PeerName":"dc2","Port":9000},
  "proxy":      {"ID":"api-proxy","Service":"api-proxy","Kind":"connect-proxy","Port":21000},
  "socket":     {"ID":"dockerd","Service":"dockerd","SocketPath":"/var/run/docker.sock"},
  "v6":         {"ID":"v6","Service":"v6","Port":8080,"Ports":[{"Name":"http","Port":80,"Default":true},{"Name":"https","Port":443}]},
  "web-1":      {"ID":"web-1","Service":"web","Tags":["v1"],"Meta":{"version":"2"},"Port":8080},
  "web-2":      {"ID":"web-2","Service":"web","Tags":[],"Meta":{"version":"2"},"Port":8080}
}`

// TestConsulServicesMapping covers the mapping rules end to end against a fake
// agent: what is imported, what is skipped, and how the token is sent.
func TestConsulServicesMapping(t *testing.T) {
	var gotToken, gotQuery string
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/agent/services" {
			http.NotFound(w, req)
			return
		}
		gotToken = req.Header.Get("X-Consul-Token")
		gotQuery = req.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(consulCatalog))
	}))
	defer hs.Close()

	// A bare host:port must work too, and the token must never reach the URL.
	address := strings.TrimPrefix(hs.URL, "http://")
	services, warnings, err := ConsulServices(context.Background(), ConsulConfig{
		Address: address,
		Token:   "consul-secret-token",
	})
	if err != nil {
		t.Fatalf("ConsulServices: %v", err)
	}
	if gotToken != "consul-secret-token" {
		t.Errorf("X-Consul-Token = %q, want the configured token", gotToken)
	}
	if gotQuery != "" || strings.Contains(address, "consul-secret-token") {
		t.Errorf("token leaked into the URL query %q", gotQuery)
	}

	want := []protocol.Service{
		{Name: "dns", Protocol: "udp", Port: 53},
		{Name: "v6", Protocol: "tcp", Port: 80},
		{Name: "web", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "2"}},
	}
	if len(services) != len(want) {
		t.Fatalf("services = %+v, want %+v", services, want)
	}
	for i := range want {
		if services[i].Name != want[i].Name || services[i].Protocol != want[i].Protocol || services[i].Port != want[i].Port {
			t.Errorf("service[%d] = %+v, want %+v", i, services[i], want[i])
		}
	}
	if services[2].Metadata["version"] != "2" {
		t.Errorf("web metadata = %+v", services[2].Metadata)
	}

	if len(warnings) != 8 {
		t.Fatalf("warnings = %d (%v), want 8", len(warnings), warnings)
	}
	for _, want := range []string{"connect-proxy", "unix socket", "peer", "lowercase DNS label", "invalid port", "metadata key", "disagree on protocol/port", "no service name"} {
		found := false
		for _, warning := range warnings {
			if strings.Contains(warning, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no warning mentions %q: %v", want, warnings)
		}
	}
	if strings.Contains(strings.Join(warnings, " "), "secret-meta-value") {
		t.Errorf("warnings leaked a metadata value: %v", warnings)
	}
}

// TestConsulServicesErrors covers the failure paths: a rejected token, a
// malformed body, and a catalog that cannot be represented in full.
func TestConsulServicesErrors(t *testing.T) {
	status := http.StatusForbidden
	body := `{"errors":["Permission denied: token with AccessorID has insufficient permissions"]}`
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer hs.Close()

	_, _, err := ConsulServices(context.Background(), ConsulConfig{Address: hs.URL})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("403 error = %v", err)
	}

	status = http.StatusOK
	body = `not json`
	if _, _, err := ConsulServices(context.Background(), ConsulConfig{Address: hs.URL}); err == nil {
		t.Error("a malformed catalog was accepted")
	}

	// More services than one node may publish: the import fails instead of
	// silently truncating (a truncated declaration would withdraw the rest).
	tooMany := map[string]consulAgentService{}
	for i := 0; i <= protocol.MaxServicesPerNode; i++ {
		name := fmt.Sprintf("svc-%02d", i)
		tooMany[name] = consulAgentService{ID: name, Service: name, Port: 80}
	}
	raw, err := json.Marshal(tooMany)
	if err != nil {
		t.Fatalf("marshaling catalog: %v", err)
	}
	body = string(raw)
	if _, _, err := ConsulServices(context.Background(), ConsulConfig{Address: hs.URL}); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("oversized catalog error = %v", err)
	}
}

// TestConsulServicesEmpty checks the empty catalog: no services, no warnings,
// and no error (the CLI warns before publishing an empty declaration).
func TestConsulServicesEmpty(t *testing.T) {
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer hs.Close()

	services, warnings, err := ConsulServices(context.Background(), ConsulConfig{Address: hs.URL})
	if err != nil {
		t.Fatalf("ConsulServices: %v", err)
	}
	if len(services) != 0 || len(warnings) != 0 {
		t.Errorf("services = %+v, warnings = %v", services, warnings)
	}
}

// TestConsulServicesDeclarations covers the declaration Meta keys (spec
// section 49): they are carried into the declaration, stripped from metadata,
// and anything malformed skips the registration without echoing the value.
func TestConsulServicesDeclarations(t *testing.T) {
	catalog := map[string]consulAgentService{
		"vis": {ID: "vis", Service: "vis", Port: 80, Meta: map[string]string{
			ConsulVisibilityMetaKey: `["tag:prod","group:eng","tag:prod"]`,
			"version":               "2",
		}},
		"acl":    {ID: "acl", Service: "acl", Port: 80, Meta: map[string]string{ConsulVisibilityFromACLMetaKey: "true"}},
		"shared": {ID: "shared", Service: "shared", Port: 80, Meta: map[string]string{ConsulSharedMetaKey: "true"}},
		"off":    {ID: "off", Service: "off", Port: 80, Meta: map[string]string{ConsulSharedMetaKey: "false"}},
		"bad-json": {ID: "bad-json", Service: "bad-json", Port: 80, Meta: map[string]string{
			ConsulVisibilityMetaKey: `{"password":"super-secret"}`,
		}},
		"bad-bool": {ID: "bad-bool", Service: "bad-bool", Port: 80, Meta: map[string]string{ConsulSharedMetaKey: "yes"}},
		"both": {ID: "both", Service: "both", Port: 80, Meta: map[string]string{
			ConsulVisibilityMetaKey:        `["*"]`,
			ConsulVisibilityFromACLMetaKey: "true",
		}},
		"dup-1":  {ID: "dup-1", Service: "dup", Port: 80, Meta: map[string]string{ConsulVisibilityMetaKey: `["tag:prod"]`}},
		"dup-2":  {ID: "dup-2", Service: "dup", Port: 80, Meta: map[string]string{ConsulVisibilityMetaKey: `["tag:dev"]`}},
		"same-1": {ID: "same-1", Service: "same", Port: 80, Meta: map[string]string{ConsulVisibilityMetaKey: `["tag:prod"]`}},
		"same-2": {ID: "same-2", Service: "same", Port: 80, Meta: map[string]string{ConsulVisibilityMetaKey: `["tag:prod"]`}},
	}

	services, warnings, err := mapConsulServices(catalog)
	if err != nil {
		t.Fatalf("mapConsulServices: %v", err)
	}

	byName := make(map[string]protocol.Service, len(services))
	for _, svc := range services {
		byName[svc.Name] = svc
	}
	if len(services) != 5 {
		t.Fatalf("services = %+v, want 5", services)
	}

	vis := byName["vis"]
	if len(vis.Visibility) != 2 || vis.Visibility[0] != "group:eng" || vis.Visibility[1] != "tag:prod" {
		t.Errorf("vis visibility = %v", vis.Visibility)
	}
	if len(vis.Metadata) != 1 || vis.Metadata["version"] != "2" {
		t.Errorf("vis metadata = %+v (declaration keys must not be metadata)", vis.Metadata)
	}
	if !byName["acl"].VisibilityFromACL || byName["acl"].Shared {
		t.Errorf("acl = %+v", byName["acl"])
	}
	if !byName["shared"].Shared || byName["shared"].VisibilityFromACL {
		t.Errorf("shared = %+v", byName["shared"])
	}
	if byName["off"].Shared {
		t.Errorf("off = %+v (explicit false must stay false)", byName["off"])
	}
	if _, ok := byName["dup"]; ok {
		t.Error("a name whose registrations disagree on visibility was kept")
	}
	if len(byName["same"].Visibility) != 1 || byName["same"].Visibility[0] != "tag:prod" {
		t.Errorf("same = %+v", byName["same"])
	}

	joined := strings.Join(warnings, "\n")
	if len(warnings) != 4 {
		t.Fatalf("warnings = %v, want 4", warnings)
	}
	for _, want := range []string{ConsulVisibilityMetaKey, ConsulSharedMetaKey, "visibilityFromACL", "disagree"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no warning mentions %q: %v", want, warnings)
		}
	}
	if strings.Contains(joined, "super-secret") {
		t.Errorf("warnings leaked a Meta value: %v", warnings)
	}
}
