package control

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// relayPolicy authorizes tag:client to allocate relay endpoints from
// tag:relay and tag:blocked, disables serving on tag:blocked and allocating
// on tag:client, and leaves tag:relay fully enabled.
const relayPolicy = `{
	"tagOwners": {
		"tag:relay": ["local"],
		"tag:blocked": ["local"],
		"tag:client": ["local"],
	},
	"grants": [{
		"src": ["tag:client"],
		"dst": ["tag:relay", "tag:blocked"],
		"app": {"tailscale.com/cap/relay": []},
	}],
	"nodeAttrs": [
		{"target": ["tag:blocked"], "attr": ["disable-relay-server"]},
		{"target": ["tag:client"], "attr": ["disable-relay-client"]},
	],
}`

// relayFixture seeds the four postures the page has to tell apart: an enabled
// relay, a relay disabled by policy, a grant source, and a willing node no
// grant points at.
type relayFixture struct {
	server   *Server
	relay    state.Node
	disabled state.Node
	client   state.Node
	willing  state.Node
	plain    state.Node
}

func newRelayFixture(t *testing.T) *relayFixture {
	t.Helper()

	s := newServerWithConfig(t, Config{PolicyPath: policyFile(t, relayPolicy)})
	f := &relayFixture{server: s}

	setPeerRelay := func(node state.Node, willing bool) state.Node {
		t.Helper()
		node.Hostinfo = &tailcfg.Hostinfo{Hostname: node.Hostname, PeerRelay: willing}
		if err := s.store.UpdateNode(node); err != nil {
			t.Fatalf("UpdateNode(%s): %v", node.Hostname, err)
		}
		return node
	}

	f.relay = setPeerRelay(seedAPIMachine(t, s, "relay", []string{"tag:relay"}), true)
	f.disabled = setPeerRelay(seedAPIMachine(t, s, "blocked-relay", []string{"tag:blocked"}), true)
	f.client = setPeerRelay(seedAPIMachine(t, s, "client", []string{"tag:client"}), false)
	f.willing = setPeerRelay(seedAPIMachine(t, s, "willing", nil), true)
	f.plain = seedAPIMachine(t, s, "plain", nil)
	return f
}

// TestRelaysView checks the join between relay offers and relay grants.
func TestRelaysView(t *testing.T) {
	f := newRelayFixture(t)

	view := f.server.relaysView()

	// Candidates are the nodes that offer to relay or are named as relays;
	// the grant source is neither, so it does not appear as a candidate.
	got := make([]string, 0, len(view.Relays))
	for _, relay := range view.Relays {
		got = append(got, relay.Hostname)
	}
	if want := []string{"relay", "blocked-relay", "willing"}; !slices.Equal(got, want) {
		t.Fatalf("relays = %v, want %v", got, want)
	}
	byHost := make(map[string]relayNodeView, len(view.Relays))
	for _, relay := range view.Relays {
		byHost[relay.Hostname] = relay
	}
	if relay := byHost["relay"]; !relay.Announced || !relay.Targeted || relay.Disabled || relay.ClientDisabled {
		t.Errorf("enabled relay = %+v, want announced and targeted", relay)
	}
	if blocked := byHost["blocked-relay"]; !blocked.Announced || !blocked.Targeted || !blocked.Disabled {
		t.Errorf("blocked relay = %+v, want targeted but disabled", blocked)
	}
	if willing := byHost["willing"]; !willing.Announced || willing.Targeted {
		t.Errorf("willing node = %+v, want announced and not targeted", willing)
	}

	if len(view.Grants) != 1 {
		t.Fatalf("grants = %+v, want one", view.Grants)
	}
	grant := view.Grants[0]
	if len(grant.Sources) != 1 || grant.Sources[0].Hostname != "client" {
		t.Fatalf("grant sources = %+v, want the client", grant.Sources)
	}
	if !grant.Sources[0].ClientDisabled {
		t.Errorf("grant source = %+v, want disable-relay-client visible", grant.Sources[0])
	}
	targets := make([]string, 0, len(grant.Targets))
	for _, target := range grant.Targets {
		targets = append(targets, target.Hostname)
	}
	if want := []string{"relay", "blocked-relay"}; !slices.Equal(targets, want) {
		t.Errorf("grant targets = %v, want %v", targets, want)
	}
}

// TestAPIV2Relays checks the read-only HTTP surface.
func TestAPIV2Relays(t *testing.T) {
	f := newRelayFixture(t)
	hs := newTestHTTPServer(t, f.server)
	client := noRedirectClient()

	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/relays", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}

	_, token := seedAPIKey(t, f.server, identity.ScopeRead)
	resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/relays", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	raw := bodyString(t, resp)
	var view relaysView
	if err := json.Unmarshal([]byte(raw), &view); err != nil {
		t.Fatalf("decoding relays: %v", err)
	}
	if len(view.Relays) != 3 || len(view.Grants) != 1 {
		t.Errorf("view = %+v", view)
	}

	// A member may read the mesh posture too.
	member := seedRoleUser(t, f.server, "member@example.com", identity.RoleMember)
	memberToken := seedAPIKeyForUser(t, f.server, member, identity.ScopeRead)
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/relays", memberToken, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("member status = %d, want 200", resp.StatusCode)
	}
}

// TestConsoleRelays checks the console page renders the join, stays read-only
// and is available to every role.
func TestConsoleRelays(t *testing.T) {
	f := newRelayFixture(t)
	hs := newTestHTTPServer(t, f.server)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/relays")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/relays", cookie))
	for _, want := range []string{
		"Relay candidates", "Relay grants", "relay", "blocked-relay", "willing", "client",
		"disable-relay-server", "disable-relay-client", "not in any relay grant",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("relays page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, `action="/console/relays"`) {
		t.Errorf("page renders a form:\n%s", page)
	}

	member := seedRoleUser(t, f.server, "member@example.com", identity.RoleMember)
	memberCookie, _ := seedUserSession(t, f.server, member)
	if resp := getRequest(t, client, hs.URL+"/console/relays", memberCookie); resp.StatusCode != http.StatusOK {
		t.Errorf("member page status = %d, want 200", resp.StatusCode)
	}
}

// TestRelayGrantReachesTheNetmap is the compatibility half of the relay
// plane: a relay grant reaches the official client's packet filter, the
// disable-relay-* attributes reach the self node's capability map, and a
// peer's relay offer is visible in the netmap.
func TestRelayGrantReachesTheNetmap(t *testing.T) {
	s := newServerWithConfig(t, Config{
		PolicyPath: policyFile(t, `{
			"grants": [{
				"src": ["*"],
				"dst": ["*"],
				"app": {"tailscale.com/cap/relay": []},
			}],
			"nodeAttrs": [
				{"target": ["*"], "attr": ["disable-relay-server", "disable-relay-client"]},
			],
		}`),
	})
	hs := newTestHTTPServer(t, s)

	relayConn, _, relayKey := registerNode(t, s, hs, "relay")
	defer relayConn.Close()
	clientConn, client, nodeKey := registerNode(t, s, hs, "client")
	defer clientConn.Close()

	relay, ok := s.Store().GetNodeByNodeKey(relayKey.Public())
	if !ok {
		t.Fatal("relay node not found")
	}
	relay.Hostinfo = &tailcfg.Hostinfo{Hostname: "relay", PeerRelay: true}
	if err := s.Store().UpdateNode(relay); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}

	resp := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")

	// The grant reaches the client's filter with the relay capability.
	var seenRelayCap bool
	for _, rule := range resp.PacketFilters["base"] {
		for _, grant := range rule.CapGrant {
			if _, ok := grant.CapMap[tailcfg.PeerCapabilityRelay]; ok {
				seenRelayCap = true
			}
		}
	}
	if !seenRelayCap {
		t.Fatalf("packet filter carries no relay cap: %+v", resp.PacketFilters["base"])
	}

	// Policy node attributes reach the self node's capability map, which is
	// what tells the client to refuse serving and allocating.
	if resp.Node == nil {
		t.Fatal("map response carries no self node")
	}
	for _, attr := range []nodecap.Cap{
		tailcfg.NodeAttrDisableRelayServer,
		tailcfg.NodeAttrDisableRelayClient,
	} {
		if _, ok := resp.Node.CapMap[attr]; !ok {
			t.Errorf("self CapMap = %+v, want %s", resp.Node.CapMap, attr)
		}
	}

	// Peers see the relay offer.
	var sawOffer bool
	for _, peer := range resp.Peers {
		if peer.StableID == tailcfg.StableNodeID(relay.StableID) && peer.Hostinfo.PeerRelay() {
			sawOffer = true
		}
	}
	if !sawOffer {
		t.Errorf("peers = %+v, want the relay node's PeerRelay offer", resp.Peers)
	}
}
