package control

import (
	"context"
	"reflect"
	"slices"
	"testing"
	"time"

	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// publishStoreServices writes a service set straight to the store. The agent
// publish path has its own tests; here the store is the source of truth.
func publishStoreServices(t *testing.T, s *Server, nodeID state.NodeID, services []state.Service) {
	t.Helper()
	if err := s.store.ReplaceNodeServices(nodeID, services); err != nil {
		t.Fatalf("ReplaceNodeServices: %v", err)
	}
}

// dnsRecordsByName collects a node's MagicDNS records, keyed by name.
func dnsRecordsByName(t *testing.T, s *Server, self state.Node) map[string][]string {
	t.Helper()
	out := make(map[string][]string)
	for _, record := range s.extraDNSRecordsFor(self) {
		out[record.Name] = append(out[record.Name], record.Value)
	}
	return out
}

// TestSharedServiceProjection checks the project of a shared service into the
// sharee's MagicDNS: the record name is namespaced by the source organization,
// the address is this organization's masquerade address, and services that did
// not opt in never appear.
func TestSharedServiceProjection(t *testing.T) {
	f := newShareFixture(t)
	publishStoreServices(t, f.acme, f.y.ID, []state.Service{
		{Name: "db", Protocol: "tcp", Port: 5432, Shared: true},
		{Name: "metrics", Protocol: "tcp", Port: 9090},
	})

	masqV4, masqV6, err := f.globex.store.EnsureShareAddress("acme", shareNodeKey(f.y))
	if err != nil {
		t.Fatalf("EnsureShareAddress: %v", err)
	}

	records := dnsRecordsByName(t, f.globex, f.x)
	name := "db-acme.globex.example.com"
	if got := records[name]; !slices.Equal(got, []string{masqV4.String(), masqV6.String()}) {
		t.Errorf("shared service records = %v, want [%s %s]", got, masqV4, masqV6)
	}
	if _, ok := records["metrics-acme.globex.example.com"]; ok {
		t.Error("a service without the shared flag was projected")
	}
	for _, value := range records[name] {
		if value == f.y.IPv4.String() || value == f.y.IPv6.String() {
			t.Errorf("shared service record leaks the source address %s", value)
		}
	}

	// The projection is deterministic: repeated builds produce the same set.
	if again := dnsRecordsByName(t, f.globex, f.x); !reflect.DeepEqual(records, again) {
		t.Errorf("projection is not deterministic:\n%v\n%v", records, again)
	}
}

// TestSharedServiceOnlyForSharee checks who sees the projection: only the
// nodes of the user who accepted the share, and never the source organization.
func TestSharedServiceOnlyForSharee(t *testing.T) {
	f := newShareFixture(t)
	publishStoreServices(t, f.acme, f.y.ID, []state.Service{
		{Name: "db", Protocol: "tcp", Port: 5432, Shared: true},
	})

	other := state.Node{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		UserID:     4242,
		Hostname:   "other",
	}
	if err := f.globex.store.CreateNode(&other); err != nil {
		t.Fatalf("CreateNode(other): %v", err)
	}
	if records := dnsRecordsByName(t, f.globex, other); len(records) != 0 {
		t.Errorf("a node of another user sees foreign services: %v", records)
	}
	records := dnsRecordsByName(t, f.acme, f.y)
	if _, ok := records["db-acme.acme.example.com"]; ok {
		t.Errorf("the source organization sees its shared service as foreign: %v", records)
	}
	if _, ok := records["db.acme.example.com"]; !ok {
		t.Errorf("the source organization lost its own service name: %v", records)
	}
}

// TestSharedServiceCollisionKeepsLocal checks fail-closed naming: a local
// service whose name equals the projected name keeps the name, and the foreign
// record is skipped rather than shadowing it.
func TestSharedServiceCollisionKeepsLocal(t *testing.T) {
	f := newShareFixture(t)
	publishStoreServices(t, f.acme, f.y.ID, []state.Service{
		{Name: "db", Protocol: "tcp", Port: 5432, Shared: true},
	})
	publishStoreServices(t, f.globex, f.x.ID, []state.Service{
		{Name: "db-acme", Protocol: "tcp", Port: 80},
	})

	records := dnsRecordsByName(t, f.globex, f.x)
	name := "db-acme.globex.example.com"
	want := []string{f.x.IPv4.String(), f.x.IPv6.String()}
	if got := records[name]; !slices.Equal(got, want) {
		t.Errorf("colliding name resolves to %v, want the local node %v", got, want)
	}
}

// TestSharedServiceHealthWithdrawal checks that readiness applies across the
// share boundary: an unready service is not projected until the node reports
// it ready.
func TestSharedServiceHealthWithdrawal(t *testing.T) {
	f := newShareFixture(t)
	publishStoreServices(t, f.acme, f.y.ID, []state.Service{
		{Name: "db", Protocol: "tcp", Port: 5432, Shared: true, Health: true},
	})

	if records := dnsRecordsByName(t, f.globex, f.x); len(records) != 0 {
		t.Fatalf("an unready shared service was projected: %v", records)
	}
	if _, err := f.acme.store.ReportServiceHealth(f.y.ID,
		[]state.ServiceHealthReport{{Name: "db", Ready: true}}, time.Minute); err != nil {
		t.Fatalf("ReportServiceHealth: %v", err)
	}
	if records := dnsRecordsByName(t, f.globex, f.x); len(records) != 1 {
		t.Fatalf("ready shared service records = %v, want one name", records)
	}
}

// TestSharedServiceRevokedWithShare checks fail-closed teardown: revoking the
// share removes the projected records immediately.
func TestSharedServiceRevokedWithShare(t *testing.T) {
	f := newShareFixture(t)
	publishStoreServices(t, f.acme, f.y.ID, []state.Service{
		{Name: "db", Protocol: "tcp", Port: 5432, Shared: true},
	})
	if records := dnsRecordsByName(t, f.globex, f.x); len(records) != 1 {
		t.Fatalf("projection precondition failed: %v", records)
	}

	if _, err := f.acme.revokeShare(context.Background(),
		shareTestPrincipal(state.DefaultUserID, identity.RoleOwner), f.share.ID); err != nil {
		t.Fatalf("revokeShare: %v", err)
	}
	if records := dnsRecordsByName(t, f.globex, f.x); len(records) != 0 {
		t.Errorf("revoked share still projects services: %v", records)
	}
}

// TestAgentServiceSharedRoundTrip covers the wire flag end to end: the agent
// publish path stores it, the read view reports it, and a republish without it
// flips the service back.
func TestAgentServiceSharedRoundTrip(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	hs := newTestHTTPServer(t, s)
	agent := enrollServiceAgent(t, s, hs, "web")

	resp, status, raw := publishServices(t, s, hs, agent, []agentService{
		{Name: "api", Protocol: "tcp", Port: 8080, Shared: true},
	}, nil)
	if status != 200 || len(resp.Services) != 1 {
		t.Fatalf("publish shared = %d (%s)", status, raw)
	}
	if !resp.Services[0].Shared {
		t.Errorf("published view = %+v, want shared", resp.Services[0])
	}

	resp, status, raw = publishServices(t, s, hs, agent, []agentService{
		{Name: "api", Protocol: "tcp", Port: 8080},
	}, nil)
	if status != 200 || len(resp.Services) != 1 {
		t.Fatalf("republish = %d (%s)", status, raw)
	}
	if resp.Services[0].Shared {
		t.Errorf("service stayed shared after a publish without the flag: %+v", resp.Services[0])
	}
}

// TestSharedServiceDeclarationComparison checks the no-op rule: adding or
// removing the shared flag is a real change, everything else equal.
func TestSharedServiceDeclarationComparison(t *testing.T) {
	base := state.Service{Name: "api", Protocol: "tcp", Port: 8080, Visibility: []string{"*"}}
	shared := base
	shared.Shared = true

	if !sameServiceSet([]state.Service{shared}, []state.Service{shared}) {
		t.Error("identical shared declarations compared unequal")
	}
	if sameServiceSet([]state.Service{base}, []state.Service{shared}) {
		t.Error("declarations differing only in the shared flag compared equal")
	}
}

// TestSharedServiceReachesClientDNS checks the projection end to end: the
// record appears in the node's client-facing DNS configuration, pointing at
// the masquerade address.
func TestSharedServiceReachesClientDNS(t *testing.T) {
	f := newShareFixture(t)
	publishStoreServices(t, f.acme, f.y.ID, []state.Service{
		{Name: "db", Protocol: "tcp", Port: 5432, Shared: true},
	})
	masqV4, _, err := f.globex.store.EnsureShareAddress("acme", shareNodeKey(f.y))
	if err != nil {
		t.Fatalf("EnsureShareAddress: %v", err)
	}

	cfg := f.globex.dnsConfigFor(f.x)
	if cfg == nil {
		t.Fatal("dnsConfigFor returned nil")
	}
	want := "db-acme.globex.example.com."
	for _, record := range cfg.ExtraRecords {
		if record.Name == want && record.Type == "A" && record.Value == masqV4.String() {
			return
		}
	}
	t.Errorf("client DNS config lacks %s -> %s: %+v", want, masqV4, cfg.ExtraRecords)
}
