package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/client/protocol"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// enrolledServiceAgent is a native client that can publish services.
type enrolledServiceAgent struct {
	token      string
	machineKey key.MachinePrivate
	nodeKey    key.NodePrivate
	node       state.Node
}

// enrollServiceAgent enrolls an agent with the given hostname and returns its
// credentials plus the stored node.
func enrollServiceAgent(t *testing.T, s *Server, hs *httptest.Server, hostname string) enrolledServiceAgent {
	t.Helper()

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	secret := seedPreAuthKey(t, s, state.PreAuthKey{})

	body, status := agentPost(t, hs.Client(), hs.URL, "/api/agent/v1/enroll", "", agentEnrollRequest{
		Version:    agentProtocolVersion,
		AuthKey:    secret,
		MachineKey: machineKey.Public().String(),
		NodeKey:    nodeKey.Public().String(),
		Hostname:   hostname,
		OS:         "linux",
	})
	if status != http.StatusOK {
		t.Fatalf("enroll %s status = %d (%s)", hostname, status, body)
	}
	var resp agentEnrollResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decoding enroll response: %v", err)
	}
	node, ok := s.store.GetNodeByNodeKey(nodeKey.Public())
	if !ok {
		t.Fatalf("agent %s did not create a node", hostname)
	}
	return enrolledServiceAgent{token: resp.Token, machineKey: machineKey, nodeKey: nodeKey, node: node}
}

// publishServices posts a service set and returns the decoded response.
func publishServices(t *testing.T, s *Server, hs *httptest.Server, agent enrolledServiceAgent, services []agentService, keys *enrolledServiceAgent) (agentServicesResponse, int, string) {
	t.Helper()

	machineKey, nodeKey := agent.machineKey, agent.nodeKey
	if keys != nil {
		machineKey, nodeKey = keys.machineKey, keys.nodeKey
	}
	body, status := agentPost(t, hs.Client(), hs.URL, "/api/agent/v1/services", agent.token, agentServicesRequest{
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

// TestAgentServicesPublishWithdrawAndAudit covers the whole publish path:
// enrollment, a declarative publish, a partial withdrawal, clearing the set,
// and the audit record (which names services but never metadata values).
func TestAgentServicesPublishWithdrawAndAudit(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "web")

	resp, status, raw := publishServices(t, s, hs, agent, []agentService{
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "2"}},
		{Name: "metrics", Protocol: "udp", Port: 9090},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("publish status = %d (%s)", status, raw)
	}
	if len(resp.Services) != 2 || resp.Services[0].Name != "api" || resp.Services[1].Name != "metrics" {
		t.Fatalf("published services = %+v", resp.Services)
	}
	if resp.Services[0].Metadata["version"] != "2" || resp.Services[0].Protocol != "tcp" || resp.Services[0].Port != 8080 {
		t.Errorf("api view = %+v", resp.Services[0])
	}
	if resp.Services[0].NodeID != uint64(agent.node.ID) || resp.Services[0].StableID != agent.node.StableID {
		t.Errorf("api view identity = %+v", resp.Services[0])
	}
	if resp.Services[0].DNSName != "api.example.com" || resp.Services[1].DNSName != "metrics.example.com" {
		t.Errorf("dns names = %q / %q", resp.Services[0].DNSName, resp.Services[1].DNSName)
	}

	event, ok := findAudit(t, s, identity.AuditServicesUpdated)
	if !ok {
		t.Fatal("publishing was not audited")
	}
	if event.Target != nodeTarget(agent.node) || event.Detail != "advertised api/tcp:8080, metrics/udp:9090" {
		t.Errorf("audit event = %+v", event)
	}
	if strings.Contains(event.Detail, "2") && strings.Contains(event.Detail, "version") {
		t.Errorf("audit detail leaked metadata: %q", event.Detail)
	}

	// A republish replaces the set: api is withdrawn without a second call.
	resp, status, raw = publishServices(t, s, hs, agent, []agentService{
		{Name: "metrics", Protocol: "udp", Port: 9090},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("republish status = %d (%s)", status, raw)
	}
	if len(resp.Services) != 1 || resp.Services[0].Name != "metrics" {
		t.Fatalf("services after republish = %+v", resp.Services)
	}
	if _, ok := s.store.GetServiceByName("api"); ok {
		t.Error("the withdrawn service is still stored")
	}

	// An empty set withdraws everything.
	resp, status, raw = publishServices(t, s, hs, agent, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("clear status = %d (%s)", status, raw)
	}
	if len(resp.Services) != 0 {
		t.Fatalf("services after clearing = %+v", resp.Services)
	}
	if got := s.store.ListServices(); len(got) != 0 {
		t.Errorf("store still holds services: %+v", got)
	}
	if event, ok := lastAudit(t, s, identity.AuditServicesUpdated); !ok || event.Detail != "withdrew all services" {
		t.Errorf("last audit event = %+v", event)
	}
}

// TestAgentServicesRepublishUnchangedIsNoOp covers the periodic refresh path:
// re-publishing the stored set must not touch rows, timestamps or the audit
// log, while a real change still does.
func TestAgentServicesRepublishUnchangedIsNoOp(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "noop")

	declaration := []agentService{
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "1"}},
		{Name: "web", Protocol: "tcp", Port: 80},
	}
	first, status, raw := publishServices(t, s, hs, agent, declaration, nil)
	if status != http.StatusOK {
		t.Fatalf("first publish status = %d (%s)", status, raw)
	}
	audits := countAudit(t, s, identity.AuditServicesUpdated)

	// Reordered, with protocol spelling differences that normalize away: the
	// declaration is the same set, so nothing may change.
	second, status, raw := publishServices(t, s, hs, agent, []agentService{
		{Name: "web", Protocol: " TCP ", Port: 80},
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "1"}},
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("identical republish status = %d (%s)", status, raw)
	}
	if len(second.Services) != len(first.Services) {
		t.Fatalf("identical republish returned %d services, want %d", len(second.Services), len(first.Services))
	}
	for i := range second.Services {
		if second.Services[i].Name != first.Services[i].Name {
			t.Fatalf("identical republish reordered the response: %+v", second.Services)
		}
		if !second.Services[i].Updated.Equal(first.Services[i].Updated) {
			t.Errorf("identical republish moved %s updated from %v to %v",
				first.Services[i].Name, first.Services[i].Updated, second.Services[i].Updated)
		}
	}
	if got := countAudit(t, s, identity.AuditServicesUpdated); got != audits {
		t.Errorf("audit events after an identical republish = %d, want %d", got, audits)
	}

	// A changed set is still written and audited.
	if _, status, raw := publishServices(t, s, hs, agent, []agentService{{Name: "web", Protocol: "tcp", Port: 80}}, nil); status != http.StatusOK {
		t.Fatalf("changed republish status = %d (%s)", status, raw)
	}
	if got := countAudit(t, s, identity.AuditServicesUpdated); got != audits+1 {
		t.Errorf("audit events after a changed republish = %d, want %d", got, audits+1)
	}
}

// countAudit returns how many stored events carry the given action.
func countAudit(t *testing.T, s *Server, action string) int {
	t.Helper()
	count := 0
	for _, event := range auditEvents(t, s) {
		if event.Action == action {
			count++
		}
	}
	return count
}

// lastAudit returns the most recent event with the given action.
func lastAudit(t *testing.T, s *Server, action string) (identity.AuditEvent, bool) {
	t.Helper()
	events := auditEvents(t, s)
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Action == action {
			return events[i], true
		}
	}
	return identity.AuditEvent{}, false
}

// TestAgentServicesAuthentication checks the credential rules: the token, the
// machine key and the node key must all agree with the stored node.
func TestAgentServicesAuthentication(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	first := enrollServiceAgent(t, s, hs, "first")
	second := enrollServiceAgent(t, s, hs, "second")

	services := []agentService{{Name: "api", Protocol: "tcp", Port: 8080}}

	// No token at all.
	body, status := agentPost(t, hs.Client(), hs.URL, "/api/agent/v1/services", "", agentServicesRequest{
		agentRequest: agentRequest{MachineKey: first.machineKey.Public().String(), NodeKey: first.nodeKey.Public().String()},
		Services:     services,
	})
	if status != http.StatusUnauthorized {
		t.Errorf("anonymous publish status = %d, want 401 (%s)", status, body)
	}

	// A valid token with another agent's keys.
	if _, status, raw := publishServices(t, s, hs, first, services, &second); status != http.StatusForbidden {
		t.Errorf("mismatched keys status = %d, want 403 (%s)", status, raw)
	}

	// A valid token with the right node key but a made-up machine key.
	impostor := enrolledServiceAgent{token: first.token, machineKey: key.NewMachine(), nodeKey: first.nodeKey}
	if _, status, raw := publishServices(t, s, hs, impostor, services, nil); status != http.StatusForbidden {
		t.Errorf("wrong machine key status = %d, want 403 (%s)", status, raw)
	}

	if got := s.store.ListServices(); len(got) != 0 {
		t.Errorf("failed publishes left services behind: %+v", got)
	}
}

// TestAgentServicesValidation checks the fail-closed input rules: one bad
// service fails the whole publish and never leaves a partial set.
func TestAgentServicesValidation(t *testing.T) {
	longName := strings.Repeat("a", maxServiceNameLen+1)
	longKey := strings.Repeat("k", maxServiceMetadataKeyLen+1)
	longValue := strings.Repeat("v", maxServiceMetadataValueLen+1)

	bigMetadata := map[string]string{}
	for i := range maxServiceMetadataEntries + 1 {
		bigMetadata[fmt.Sprintf("k%d", i)] = "v"
	}
	// Nine values at the per-value limit exceed the encoded-total limit while
	// passing every single-value rule.
	wideValue := strings.Repeat("v", maxServiceMetadataValueLen-6)
	wideMetadata := map[string]string{
		"key1": wideValue, "key2": wideValue, "key3": wideValue,
		"key4": wideValue, "key5": wideValue, "key6": wideValue,
		"key7": wideValue, "key8": wideValue, "key9": wideValue,
	}
	manyServices := make([]agentService, 0, maxServicesPerNode+1)
	for i := range maxServicesPerNode + 1 {
		manyServices = append(manyServices, agentService{Name: fmt.Sprintf("svc-%d", i), Protocol: "tcp", Port: 80})
	}

	tests := []struct {
		name     string
		services []agentService
		wantSub  string
	}{
		{"empty name", []agentService{{Protocol: "tcp", Port: 80}}, "empty"},
		{"uppercase name", []agentService{{Name: "API", Protocol: "tcp", Port: 80}}, "lowercase"},
		{"leading hyphen", []agentService{{Name: "-api", Protocol: "tcp", Port: 80}}, "hyphen"},
		{"trailing hyphen", []agentService{{Name: "api-", Protocol: "tcp", Port: 80}}, "hyphen"},
		{"underscore", []agentService{{Name: "api_v1", Protocol: "tcp", Port: 80}}, "lowercase"},
		{"dot", []agentService{{Name: "api.example.com", Protocol: "tcp", Port: 80}}, "lowercase"},
		{"control characters", []agentService{{Name: "api\x1b[31m", Protocol: "tcp", Port: 80}}, "lowercase"},
		{"too long", []agentService{{Name: longName, Protocol: "tcp", Port: 80}}, "longer"},
		{"protocol missing", []agentService{{Name: "api", Port: 80}}, "protocol"},
		{"protocol unknown", []agentService{{Name: "api", Protocol: "sctp", Port: 80}}, "protocol"},
		{"port zero", []agentService{{Name: "api", Protocol: "tcp"}}, "port"},
		{"port too large", []agentService{{Name: "api", Protocol: "tcp", Port: 65536}}, "port"},
		{"duplicate name", []agentService{
			{Name: "api", Protocol: "tcp", Port: 80},
			{Name: "api", Protocol: "udp", Port: 53},
		}, "twice"},
		{"metadata key invalid", []agentService{{Name: "api", Protocol: "tcp", Port: 80, Metadata: map[string]string{"bad key": "v"}}}, "metadata key"},
		{"metadata key long", []agentService{{Name: "api", Protocol: "tcp", Port: 80, Metadata: map[string]string{longKey: "v"}}}, "metadata key"},
		{"metadata value control", []agentService{{Name: "api", Protocol: "tcp", Port: 80, Metadata: map[string]string{"k": "a\nb"}}}, "metadata value"},
		{"metadata value long", []agentService{{Name: "api", Protocol: "tcp", Port: 80, Metadata: map[string]string{"k": longValue}}}, "metadata value"},
		{"metadata too many entries", []agentService{{Name: "api", Protocol: "tcp", Port: 80, Metadata: bigMetadata}}, "entries"},
		{"metadata too large", []agentService{{Name: "api", Protocol: "tcp", Port: 80, Metadata: wideMetadata}}, "larger"},
		{"too many services", manyServices, "at most"},
	}

	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "web")

	// A good set the failed publishes must not disturb.
	if _, status, raw := publishServices(t, s, hs, agent, []agentService{
		{Name: "keep", Protocol: "tcp", Port: 1},
	}, nil); status != http.StatusOK {
		t.Fatalf("seeding services: %d (%s)", status, raw)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Every case is paired with a valid service: the whole batch must
			// be refused when one entry is invalid.
			services := append([]agentService{{Name: "extra", Protocol: "tcp", Port: 2}}, tc.services...)
			_, status, raw := publishServices(t, s, hs, agent, services, nil)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s)", status, raw)
			}
			if !strings.Contains(raw, tc.wantSub) {
				t.Errorf("body = %s, want it to mention %q", raw, tc.wantSub)
			}
			if strings.ContainsRune(raw, 0x1b) {
				t.Errorf("error body carries a raw escape character: %q", raw)
			}
			got, ok := s.store.GetServiceByName("keep")
			if !ok || got.Port != 1 {
				t.Errorf("the previous set was disturbed: %+v", got)
			}
			if _, ok := s.store.GetServiceByName("extra"); ok {
				t.Error("a partially applied publish stored a valid entry")
			}
		})
	}
}

// TestAgentServicesNameConflicts checks the names another owner or an existing
// MagicDNS record has already taken.
func TestAgentServicesNameConflicts(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	first := enrollServiceAgent(t, s, hs, "first")
	second := enrollServiceAgent(t, s, hs, "second")

	if _, status, raw := publishServices(t, s, hs, first, []agentService{{Name: "api", Protocol: "tcp", Port: 8080}}, nil); status != http.StatusOK {
		t.Fatalf("first publish: %d (%s)", status, raw)
	}

	// Another node's service name.
	_, status, raw := publishServices(t, s, hs, second, []agentService{
		{Name: "other", Protocol: "tcp", Port: 1},
		{Name: "api", Protocol: "tcp", Port: 9999},
	}, nil)
	if status != http.StatusConflict {
		t.Fatalf("conflicting name status = %d, want 409 (%s)", status, raw)
	}
	if _, ok := s.store.GetServiceByName("other"); ok {
		t.Error("a rejected publish stored part of the set")
	}
	if svc, _ := s.store.GetServiceByName("api"); svc.NodeID != first.node.ID || svc.Port != 8080 {
		t.Errorf("the name was taken over: %+v", svc)
	}

	// A node hostname in the same MagicDNS domain.
	web := seedAPIMachine(t, s, "web", nil)
	_ = web
	_, status, raw = publishServices(t, s, hs, second, []agentService{{Name: "web", Protocol: "tcp", Port: 80}}, nil)
	if status != http.StatusConflict {
		t.Errorf("hostname conflict status = %d, want 409 (%s)", status, raw)
	}

	// An existing DNS record.
	if err := s.store.UpsertDNSRecord(&state.DNSRecord{
		Name: "taken.example.com", Type: "A", Value: "100.64.0.9", NodeID: second.node.ID,
	}); err != nil {
		t.Fatalf("UpsertDNSRecord: %v", err)
	}
	_, status, raw = publishServices(t, s, hs, second, []agentService{{Name: "taken", Protocol: "tcp", Port: 80}}, nil)
	if status != http.StatusConflict {
		t.Errorf("record conflict status = %d, want 409 (%s)", status, raw)
	}
}

// TestAgentServicesBudget checks the organization-wide registry limit.
func TestAgentServicesBudget(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "web")

	// Fill the registry from other nodes directly, faster than publishing.
	var other []state.Service
	for len(other) < maxServicesPerOrg {
		node := seedAPIMachine(t, s, fmt.Sprintf("filler-%d", len(other)), nil)
		batch := make([]state.Service, 0, maxServicesPerNode)
		for i := 0; i < maxServicesPerNode && len(other)+i < maxServicesPerOrg; i++ {
			batch = append(batch, state.Service{Name: fmt.Sprintf("fill-%d", len(other)+i), Protocol: "tcp", Port: 1})
		}
		if err := s.store.ReplaceNodeServices(node.ID, batch); err != nil {
			t.Fatalf("ReplaceNodeServices: %v", err)
		}
		other = append(other, batch...)
	}

	_, status, raw := publishServices(t, s, hs, agent, []agentService{{Name: "api", Protocol: "tcp", Port: 80}}, nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("publish into a full registry status = %d, want 429 (%s)", status, raw)
	}

	// The same node replacing its own (empty) set is still within budget once
	// room exists: withdrawing a filler frees a slot.
	if err := s.store.ReplaceNodeServices(seedAPIMachine(t, s, "unused", nil).ID, nil); err != nil {
		t.Fatalf("ReplaceNodeServices: %v", err)
	}
	counts, err := s.store.NodeServiceCounts()
	if err != nil {
		t.Fatalf("NodeServiceCounts: %v", err)
	}
	total := 0
	for id, count := range counts {
		if id == agent.node.ID {
			continue
		}
		total += count
	}
	if total != maxServicesPerOrg {
		t.Fatalf("registry holds %d services, want %d", total, maxServicesPerOrg)
	}
}

// TestServiceDNSRecordsFromRegistry checks that advertised services appear in
// MagicDNS as A/AAAA records for the publishing node and disappear when the
// node withdraws them.
func TestServiceDNSRecordsFromRegistry(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "web")

	if got := s.extraDNSRecordsFor(agent.node); len(got) != 0 {
		t.Fatalf("records before publishing = %+v, want none", got)
	}

	if _, status, raw := publishServices(t, s, hs, agent, []agentService{{Name: "api", Protocol: "tcp", Port: 8080}}, nil); status != http.StatusOK {
		t.Fatalf("publish: %d (%s)", status, raw)
	}

	records := s.extraDNSRecordsFor(agent.node)
	var v4, v6 *state.DNSRecord
	for i := range records {
		switch records[i].Type {
		case "A":
			v4 = &records[i]
		case "AAAA":
			v6 = &records[i]
		}
	}
	if v4 == nil || v4.Name != "api.example.com" || v4.Value != agent.node.IPv4.String() || v4.NodeID != agent.node.ID {
		t.Errorf("A record = %+v, want api.example.com -> %v", v4, agent.node.IPv4)
	}
	if v6 == nil || v6.Name != "api.example.com" || v6.Value != agent.node.IPv6.String() {
		t.Errorf("AAAA record = %+v, want api.example.com -> %v", v6, agent.node.IPv6)
	}

	// Without a MagicDNS domain there is no name to publish records under.
	noDomain := newServerWithConfig(t, Config{})
	if got := noDomain.serviceDNSRecordsFor(agent.node); len(got) != 0 {
		t.Errorf("records without a domain = %+v", got)
	}

	// Withdrawing the service removes its records.
	if _, status, raw := publishServices(t, s, hs, agent, nil, nil); status != http.StatusOK {
		t.Fatalf("withdraw: %d (%s)", status, raw)
	}
	if got := s.extraDNSRecordsFor(agent.node); len(got) != 0 {
		t.Errorf("records after withdrawing = %+v", got)
	}
}

// TestAgentServicesNativeClientRoundTrip runs the real native client against
// the real server: the wire contract between client/protocol and this package
// is what the CLI and the daemon speak, so it is exercised end to end here.
func TestAgentServicesNativeClientRoundTrip(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "native")

	client := protocol.New(hs.URL)
	keys := protocol.Keys{Machine: agent.machineKey, Node: agent.nodeKey}
	ctx := context.Background()

	views, err := client.Services(ctx, agent.token, keys, []protocol.Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "1"}},
	})
	if err != nil {
		t.Fatalf("Services: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("published views = %+v", views)
	}
	view := views[0]
	if view.Name != "api" || view.Protocol != "tcp" || view.Port != 8080 || view.DNSName != "api.example.com" {
		t.Errorf("view = %+v", view)
	}
	if view.NodeID != uint64(agent.node.ID) || view.StableID != agent.node.StableID || view.Hostname != "native" {
		t.Errorf("view publisher = %+v", view)
	}
	if view.Metadata["version"] != "1" || view.Created.IsZero() || view.Updated.IsZero() {
		t.Errorf("view bookkeeping = %+v", view)
	}

	// The service resolves through MagicDNS for official clients.
	found := false
	for _, rec := range s.extraDNSRecordsFor(agent.node) {
		if rec.Name == "api.example.com" && rec.Value == agent.node.IPv4.String() {
			found = true
		}
	}
	if !found {
		t.Error("api.example.com is missing from MagicDNS")
	}

	// A token without the matching key pair must not publish for this node.
	impostor := enrollServiceAgent(t, s, hs, "impostor")
	impostorKeys := protocol.Keys{Machine: impostor.machineKey, Node: impostor.nodeKey}
	if _, err := client.Services(ctx, agent.token, impostorKeys, []protocol.Service{{Name: "evil", Protocol: "tcp", Port: 1}}); err == nil {
		t.Error("a mismatched key pair was accepted")
	}
	if _, ok := s.store.GetServiceByName("evil"); ok {
		t.Error("a rejected publish stored a service")
	}

	// An unchanged republish is a no-op, and an empty set withdraws.
	if _, err := client.Services(ctx, agent.token, keys, []protocol.Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "1"}},
	}); err != nil {
		t.Fatalf("identical republish: %v", err)
	}
	views, err = client.Services(ctx, agent.token, keys, nil)
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if len(views) != 0 {
		t.Errorf("withdraw left services: %+v", views)
	}
	if _, ok := s.store.GetServiceByName("api"); ok {
		t.Error("withdrawn service is still stored")
	}
	if records := s.extraDNSRecordsFor(agent.node); len(records) != 0 {
		t.Errorf("records after withdrawing = %+v", records)
	}
}
