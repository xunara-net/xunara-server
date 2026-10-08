package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
	"github.com/xunara-net/xunara-server/client/protocol"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// reportServiceHealth posts a readiness report for one agent.
func reportServiceHealth(t *testing.T, hs *httptest.Server, agent enrolledServiceAgent, services []agentServiceHealth, keys *enrolledServiceAgent) (agentServicesResponse, int, string) {
	t.Helper()

	machineKey, nodeKey := agent.machineKey, agent.nodeKey
	if keys != nil {
		machineKey, nodeKey = keys.machineKey, keys.nodeKey
	}
	body, status := agentPost(t, hs.Client(), hs.URL, "/api/agent/v1/services/health", agent.token, agentServiceHealthRequest{
		agentRequest: agentRequest{
			MachineKey: machineKey.Public().String(),
			NodeKey:    nodeKey.Public().String(),
		},
		Services: services,
	})

	var resp agentServicesResponse
	_ = json.Unmarshal(body, &resp)
	return resp, status, string(body)
}

// serviceDNSNames lists the MagicDNS records the registry currently produces.
func serviceDNSNames(t *testing.T, s *Server, self state.Node) []string {
	t.Helper()
	var names []string
	for _, record := range s.extraDNSRecordsFor(self) {
		if record.Type == "A" {
			names = append(names, record.Name)
		}
	}
	return names
}

// TestServiceHealthLifecycle walks the whole feature: an opted-in service is
// withdrawn until it is reported ready, comes back while ready, and is
// withdrawn again when the report says otherwise. Untracked services are
// never affected.
func TestServiceHealthLifecycle(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "health-host")

	if _, status, raw := publishServices(t, s, hs, agent, []agentService{
		{Name: "api", Protocol: "tcp", Port: 8080, Health: true},
		{Name: "plain", Protocol: "tcp", Port: 80},
	}, nil); status != http.StatusOK {
		t.Fatalf("publish: %d (%s)", status, raw)
	}

	// Fail-closed: tracked but never reported means no DNS record, and the
	// read surfaces say so.
	if names := serviceDNSNames(t, s, agent.node); len(names) != 1 || names[0] != "plain.example.com" {
		t.Fatalf("records before any report = %v, want only plain", names)
	}
	svc, ok := s.store.GetServiceByName("api")
	if !ok || !svc.Health || svc.Healthy || svc.EffectiveHealth() != state.ServiceHealthUnhealthy {
		t.Fatalf("stored api service = %+v, %v", svc, ok)
	}
	if view := s.serviceView(svc, agent.node); view.Health != "unhealthy" || !view.HealthReportedAt.IsZero() {
		t.Fatalf("view before any report = %+v", view)
	}
	if plain, _ := s.store.GetServiceByName("plain"); plain.EffectiveHealth() != state.ServiceHealthUntracked {
		t.Fatalf("untracked service health = %+v", plain)
	}

	// Ready: the record appears and the transition is audited once.
	before := len(auditEvents(t, s))
	resp, status, raw := reportServiceHealth(t, hs, agent, []agentServiceHealth{{Name: "api", Ready: true}}, nil)
	if status != http.StatusOK {
		t.Fatalf("report: %d (%s)", status, raw)
	}
	if len(resp.Services) != 2 {
		t.Fatalf("report response = %+v", resp.Services)
	}
	var reported serviceView
	for _, view := range resp.Services {
		if view.Name == "api" {
			reported = view
		}
	}
	if reported.Health != "healthy" || reported.HealthReportedAt.IsZero() {
		t.Fatalf("reported view = %+v", reported)
	}
	names := serviceDNSNames(t, s, agent.node)
	if len(names) != 2 || names[0] != "api.example.com" || names[1] != "plain.example.com" {
		t.Fatalf("records after a ready report = %v", names)
	}
	events := auditEvents(t, s)
	if len(events) != before+1 {
		t.Fatalf("ready report wrote %d audit events, want 1", len(events)-before)
	}
	event := events[len(events)-1]
	if event.Action != identity.AuditServiceHealthy || event.Actor != "node:"+agent.node.StableID {
		t.Errorf("health audit = %+v", event)
	}
	if !strings.Contains(event.Detail, "api/tcp:8080") || !strings.Contains(event.Detail, "reported") {
		t.Errorf("health audit detail = %q", event.Detail)
	}

	// Repeating the same report is not a transition: no audit, no change.
	before = len(auditEvents(t, s))
	if _, status, raw := reportServiceHealth(t, hs, agent, []agentServiceHealth{{Name: "api", Ready: true}}, nil); status != http.StatusOK {
		t.Fatalf("repeated report: %d (%s)", status, raw)
	}
	if after := len(auditEvents(t, s)); after != before {
		t.Errorf("repeated report wrote %d audit events", after-before)
	}

	// A complete report that leaves "api" out withdraws it.
	before = len(auditEvents(t, s))
	if _, status, raw := reportServiceHealth(t, hs, agent, nil, nil); status != http.StatusOK {
		t.Fatalf("empty report: %d (%s)", status, raw)
	}
	if names := serviceDNSNames(t, s, agent.node); len(names) != 1 || names[0] != "plain.example.com" {
		t.Fatalf("records after an empty report = %v", names)
	}
	events = auditEvents(t, s)
	if len(events) != before+1 || events[len(events)-1].Action != identity.AuditServiceUnhealthy {
		t.Fatalf("withdrawal audit = %+v", events[before:])
	}

	// A republish of the declaration keeps the (unhealthy) state and does not
	// resurrect the record.
	if _, status, raw := publishServices(t, s, hs, agent, []agentService{
		{Name: "api", Protocol: "tcp", Port: 8080, Health: true},
		{Name: "plain", Protocol: "tcp", Port: 80},
	}, nil); status != http.StatusOK {
		t.Fatalf("republish: %d (%s)", status, raw)
	}
	if names := serviceDNSNames(t, s, agent.node); len(names) != 1 || names[0] != "plain.example.com" {
		t.Fatalf("records after a republish = %v", names)
	}

	// Dropping health tracking makes the service unconditionally discoverable
	// again; the state is cleared with it.
	if _, status, raw := publishServices(t, s, hs, agent, []agentService{
		{Name: "api", Protocol: "tcp", Port: 8080},
		{Name: "plain", Protocol: "tcp", Port: 80},
	}, nil); status != http.StatusOK {
		t.Fatalf("publish without health: %d (%s)", status, raw)
	}
	if svc, _ := s.store.GetServiceByName("api"); svc.Health || !svc.HealthReportedAt.IsZero() {
		t.Errorf("health state after dropping tracking = %+v", svc)
	}
	if names := serviceDNSNames(t, s, agent.node); len(names) != 2 {
		t.Fatalf("records after dropping tracking = %v", names)
	}
}

// TestServiceHealthValidation checks the fail-closed report rules.
func TestServiceHealthValidation(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "health-host")
	other := enrollServiceAgent(t, s, hs, "other-host")

	if _, status, raw := publishServices(t, s, hs, agent, []agentService{
		{Name: "api", Protocol: "tcp", Port: 8080, Health: true},
		{Name: "plain", Protocol: "tcp", Port: 80},
	}, nil); status != http.StatusOK {
		t.Fatalf("publish: %d (%s)", status, raw)
	}

	tooMany := make([]agentServiceHealth, 0, maxServicesPerNode+1)
	for i := 0; i <= maxServicesPerNode; i++ {
		tooMany = append(tooMany, agentServiceHealth{Name: "api", Ready: true})
	}

	cases := []struct {
		name  string
		agent enrolledServiceAgent
		keys  *enrolledServiceAgent
		body  []agentServiceHealth
		want  int
	}{
		{name: "untracked service", agent: agent, body: []agentServiceHealth{{Name: "plain", Ready: true}}, want: http.StatusBadRequest},
		{name: "unknown service", agent: agent, body: []agentServiceHealth{{Name: "missing"}}, want: http.StatusBadRequest},
		{name: "duplicate", agent: agent, body: []agentServiceHealth{{Name: "api"}, {Name: "api", Ready: true}}, want: http.StatusBadRequest},
		{name: "bad name", agent: agent, body: []agentServiceHealth{{Name: "Not A Label"}}, want: http.StatusBadRequest},
		{name: "too many", agent: agent, body: tooMany, want: http.StatusBadRequest},
		{name: "wrong keys", agent: agent, keys: &other, body: []agentServiceHealth{{Name: "api", Ready: true}}, want: http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, status, raw := reportServiceHealth(t, hs, tc.agent, tc.body, tc.keys); status != tc.want {
				t.Fatalf("status = %d (%s), want %d", status, raw, tc.want)
			}
		})
	}

	// None of the rejected reports changed anything.
	if svc, _ := s.store.GetServiceByName("api"); svc.Healthy || !svc.HealthReportedAt.IsZero() {
		t.Fatalf("a rejected report changed the stored service: %+v", svc)
	}
}

// TestServiceHealthExpiry checks the janitor half: a report that stops (agent
// gone) withdraws the service and audits the withdrawal as a system action.
func TestServiceHealthExpiry(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com", ServiceHealthTTL: 30 * time.Second})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "health-host")

	if _, status, raw := publishServices(t, s, hs, agent, []agentService{
		{Name: "api", Protocol: "tcp", Port: 8080, Health: true},
	}, nil); status != http.StatusOK {
		t.Fatalf("publish: %d (%s)", status, raw)
	}
	if _, status, raw := reportServiceHealth(t, hs, agent, []agentServiceHealth{{Name: "api", Ready: true}}, nil); status != http.StatusOK {
		t.Fatalf("report: %d (%s)", status, raw)
	}
	if names := serviceDNSNames(t, s, agent.node); len(names) != 1 {
		t.Fatalf("records after a ready report = %v", names)
	}

	before := len(auditEvents(t, s))
	s.reapServiceHealth(time.Now().UTC().Add(31 * time.Second))

	if names := serviceDNSNames(t, s, agent.node); len(names) != 0 {
		t.Fatalf("records after expiry = %v, want none", names)
	}
	svc, _ := s.store.GetServiceByName("api")
	if svc.Healthy || svc.EffectiveHealth() != state.ServiceHealthUnhealthy {
		t.Fatalf("service after expiry = %+v", svc)
	}
	if svc.HealthReportedAt.IsZero() {
		t.Error("expiry cleared the last-report timestamp")
	}
	events := auditEvents(t, s)
	if len(events) != before+1 {
		t.Fatalf("expiry wrote %d audit events, want 1", len(events)-before)
	}
	event := events[len(events)-1]
	if event.Action != identity.AuditServiceUnhealthy || event.Actor != "system" {
		t.Errorf("expiry audit = %+v", event)
	}
	if !strings.Contains(event.Detail, state.ServiceHealthReasonExpired) {
		t.Errorf("expiry detail = %q", event.Detail)
	}

	// A second sweep has nothing to do.
	before = len(auditEvents(t, s))
	s.reapServiceHealth(time.Now().UTC().Add(time.Hour))
	if after := len(auditEvents(t, s)); after != before {
		t.Errorf("second sweep wrote %d audit events", after-before)
	}
}

// TestServiceHealthReadSurfaces checks the health field on the read-only
// surfaces: /api/v2/services, the console page and the gRPC service.
func TestServiceHealthReadSurfaces(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "health-host")

	if _, status, raw := publishServices(t, s, hs, agent, []agentService{
		{Name: "api", Protocol: "tcp", Port: 8080, Health: true},
		{Name: "plain", Protocol: "tcp", Port: 80},
	}, nil); status != http.StatusOK {
		t.Fatalf("publish: %d (%s)", status, raw)
	}
	if _, status, raw := reportServiceHealth(t, hs, agent, []agentServiceHealth{{Name: "api", Ready: true}}, nil); status != http.StatusOK {
		t.Fatalf("report: %d (%s)", status, raw)
	}

	_, token := seedAPIKey(t, s, identity.ScopeRead)
	resp := apiRequest(t, noRedirectClient(), http.MethodGet, hs.URL+"/api/v2/services", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("services status = %d", resp.StatusCode)
	}
	body := decodeAPI(t, resp)
	items, _ := body["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("services = %v", body["items"])
	}
	byName := map[string]map[string]any{}
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		byName[item["name"].(string)] = item
	}
	if api := byName["api"]; api["health"] != "healthy" || api["healthReportedAt"] == nil {
		t.Errorf("api view = %v", byName["api"])
	}
	if plain := byName["plain"]; plain["health"] != nil || plain["healthReportedAt"] != nil {
		t.Errorf("untracked view = %v", plain)
	}
}

// TestServiceHealthGRPC checks the health fields on the gRPC read surface.
func TestServiceHealthGRPC(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "health-host")

	if _, status, raw := publishServices(t, s, hs, agent, []agentService{
		{Name: "api", Protocol: "tcp", Port: 8080, Health: true},
	}, nil); status != http.StatusOK {
		t.Fatalf("publish: %d (%s)", status, raw)
	}

	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)
	_, token := seedAPIKey(t, s, identity.ScopeRead)

	list, err := client.ListServices(grpcCtx(token), &xunarav2.ListServicesRequest{})
	if err != nil {
		t.Fatalf("ListServices: %v", err)
	}
	if len(list.GetServices()) != 1 || list.GetServices()[0].GetHealth() != "unhealthy" {
		t.Fatalf("services before a report = %+v", list.GetServices())
	}

	if _, status, raw := reportServiceHealth(t, hs, agent, []agentServiceHealth{{Name: "api", Ready: true}}, nil); status != http.StatusOK {
		t.Fatalf("report: %d (%s)", status, raw)
	}
	list, err = client.ListServices(grpcCtx(token), &xunarav2.ListServicesRequest{})
	if err != nil {
		t.Fatalf("ListServices after report: %v", err)
	}
	svc := list.GetServices()[0]
	if svc.GetHealth() != "healthy" || svc.GetHealthReportedAt() == nil {
		t.Fatalf("service after a report = %+v", svc)
	}
}

// TestServiceHealthNativeClientRoundTrip exercises the client/protocol half of
// the wire contract.
func TestServiceHealthNativeClientRoundTrip(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "native-health")

	client := protocol.New(hs.URL)
	keys := protocol.Keys{Machine: agent.machineKey, Node: agent.nodeKey}
	ctx := t.Context()

	if _, err := client.Services(ctx, agent.token, keys, []protocol.Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Health: true},
	}); err != nil {
		t.Fatalf("Services: %v", err)
	}

	views, err := client.ReportServiceHealth(ctx, agent.token, keys, []protocol.ServiceHealth{{Name: "api", Ready: true}})
	if err != nil {
		t.Fatalf("ReportServiceHealth: %v", err)
	}
	if len(views) != 1 || views[0].Health != "healthy" || views[0].HealthReportedAt.IsZero() {
		t.Fatalf("views = %+v", views)
	}

	// A report for a service the declaration did not opt in is rejected, and
	// the error text does not echo request data.
	if _, err := client.ReportServiceHealth(ctx, agent.token, keys, []protocol.ServiceHealth{{Name: "plain"}}); err == nil {
		t.Fatal("reporting an untracked service succeeded")
	} else if !strings.Contains(err.Error(), "400") {
		t.Errorf("error = %v, want a 400", err)
	}
}
