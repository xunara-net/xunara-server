package control

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/state"
)

func TestDNSNameNoiseRegistrationRenameAndProtection(test *testing.T) {
	server := newDNSAuthServer(test)
	host := newTestHTTPServer(test, server)
	record := state.DNSRecord{Name: "laptop.xunara.test", Type: "A", Value: "100.64.0.90"}
	if err := server.store.UpsertDNSRecord(&record); err != nil {
		test.Fatal(err)
	}
	connection, client, nodeKey := registerNode(test, server, host, "Laptop")
	defer connection.Close()
	secondConnection, secondClient, secondKey := registerNode(test, server, host, "laptop")
	defer secondConnection.Close()
	first := decodeMapResponse(test, postRaw(test, client, "/machine/map", tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: nodeKey.Public()}), "")
	second := decodeMapResponse(test, postRaw(test, secondClient, "/machine/map", tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: secondKey.Public()}), "")
	if first.Node.Name == second.Node.Name || first.Node.Name == record.FQDN() || second.Node.Name == record.FQDN() {
		test.Fatal("Noise registration shadowed a device or custom record")
	}
	if first.Node.Hostinfo.Hostname() != "Laptop" {
		test.Fatal("assigned DNS name overwrote machine facts")
	}
	provider := seedAPIMachine(test, server, "provider", nil)
	if err := server.store.ReplaceNodeServices(provider.ID, []state.Service{{Name: "files", Protocol: "tcp", Port: 445}}); err != nil {
		test.Fatal(err)
	}
	renamed := decodeMapResponse(test, postRaw(test, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion, NodeKey: nodeKey.Public(), Hostinfo: &tailcfg.Hostinfo{Hostname: "Files"},
	}), "")
	wanted := fmt.Sprintf("files-%d.xunara.test.", first.Node.ID)
	if renamed.Node.Name != wanted || renamed.Node.ID != first.Node.ID || !reflect.DeepEqual(renamed.Node.Addresses, first.Node.Addresses) {
		test.Fatalf("MapRequest name allocation changed identity/IP or used service name: %+v", renamed.Node)
	}
	for _, name := range []string{renamed.Node.Name, "files.xunara.test."} {
		_, status := postRawStatus(test, client, "/machine/set-dns", tailcfg.SetDNSRequest{
			Version: tailcfg.CurrentCapabilityVersion, NodeKey: nodeKey.Public(), Name: name, Type: "A", Value: "100.64.0.91",
		})
		if status != http.StatusConflict {
			test.Fatalf("machine DNS publication shadowed protected name: %s %d", name, status)
		}
	}
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	response := accountRequest(test, server, http.MethodPost, "/api/v2/dns/records",
		map[string]string{"name": wanted, "type": "A", "value": "100.64.0.92"}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "DNS_RECORD_PROTECTED") {
		test.Fatalf("human DNS publication shadowed allocated alias: %d %s", response.Code, response.Body.String())
	}
	if records := server.store.ListDNSRecords(); len(records) != 1 || records[0].Name != record.Name || records[0].Value != record.Value {
		test.Fatal("protected writes damaged original DNS record")
	}
}

func TestDNSNameRotationAndNativeHeartbeat(test *testing.T) {
	server := newDNSAuthServer(test)
	host := newTestHTTPServer(test, server)
	provider := seedAPIMachine(test, server, "provider", nil)
	if err := server.store.ReplaceNodeServices(provider.ID, []state.Service{{Name: "reserved", Protocol: "tcp", Port: 80}}); err != nil {
		test.Fatal(err)
	}
	agent := enrollServiceAgent(test, server, host, "reserved")
	original := agent.node
	if original.DNSName == "reserved" {
		test.Fatal("native enrollment shadowed service")
	}
	secret := seedPreAuthKey(test, server, state.PreAuthKey{Reusable: true})
	newKey := key.NewNode().Public()
	if _, err := registerWithKey(test, server, agent.machineKey.Public(), newKey, secret, "reserved"); err != nil {
		test.Fatal(err)
	}
	rotated, found := server.store.GetNodeByNodeKey(newKey)
	if !found || rotated.DNSName != original.DNSName || rotated.ID != original.ID || rotated.IPv4 != original.IPv4 {
		test.Fatal("key rotation lost the stable alias or machine identity")
	}
	secondAgent := enrollServiceAgent(test, server, host, "second")
	_, status := agentPost(test, host.Client(), host.URL, "/api/agent/v1/heartbeat", secondAgent.token, agentHeartbeatRequest{
		agentRequest: agentRequest{MachineKey: secondAgent.machineKey.Public().String(), NodeKey: secondAgent.nodeKey.Public().String()},
		Hostname:     "reserved", AgentVersion: "dns-test",
	})
	updated, found := server.store.GetNodeByNodeKey(secondAgent.nodeKey.Public())
	if status != http.StatusNoContent || !found || updated.DNSName != fmt.Sprintf("reserved-%d", updated.ID) || updated.Hostname != "reserved" {
		test.Fatalf("native heartbeat bypassed assignment: status=%d node=%+v", status, updated)
	}
}

func TestDNSNameMapFailureRetainsCommittedFacts(test *testing.T) {
	server := newDNSAuthServer(test)
	node := seedAPIMachine(test, server, "committed", nil)
	if _, err := server.store.(*state.SQLiteStore).DB().ExecContext(test.Context(), "CREATE TRIGGER reject_node_rename BEFORE UPDATE ON nodes BEGIN SELECT RAISE(ABORT, 'injected failure'); END"); err != nil {
		test.Fatal(err)
	}
	returned := server.recordMapRequest(node, tailcfg.MapRequest{Hostinfo: &tailcfg.Hostinfo{Hostname: "uncommitted"}})
	if !reflect.DeepEqual(returned, node) || returned.FQDN(server.cfg.Domain) != "committed.xunara.test." {
		test.Fatal("failed persistence was advertised as a successful rename")
	}
}

func TestDNSNameSharedProjectionUsesAssignedAlias(test *testing.T) {
	fixture := newShareFixture(test)
	record := state.DNSRecord{Name: "nas.acme.example.com", Type: "A", Value: "100.64.0.90"}
	if err := fixture.acme.store.UpsertDNSRecord(&record); err != nil {
		test.Fatal(err)
	}
	node := fixture.y
	node.Hostname = "NAS"
	if err := fixture.acme.store.UpdateNodeWithDNS(&node); err != nil {
		test.Fatal(err)
	}
	peers := fixture.globex.sharePeersFor(fixture.x)
	if peers == nil || len(peers.nodes) != 1 {
		test.Fatal("accepted share disappeared after rename")
	}
	expected := shareHostname(node.DNSName, "acme") + ".globex.example.com."
	if peers.nodes[0].FQDN(fixture.globex.cfg.Domain) != expected || !strings.HasPrefix(node.DNSName, "nas-") {
		test.Fatal("shared projection ignored allocated source name")
	}
	local := seedAPIMachine(test, fixture.globex, "local", nil)
	if !fixture.globex.localDNSNames(fixture.globex.cfg.Domain)[strings.TrimSuffix(local.FQDN(fixture.globex.cfg.Domain), ".")] {
		test.Fatal("trailing dot bypassed shared-service device name protection")
	}
}
