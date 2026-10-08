package control

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// exitFixture seeds one approved exit node plus the three kinds of clients:
// one selecting it, one selecting a node that does not exist, and one with no
// selection at all.
type exitFixture struct {
	server     *Server
	exit       state.Node
	stale      state.Node
	client     state.Node
	unresolved state.Node
	plain      state.Node
}

func newExitFixture(t *testing.T) *exitFixture {
	t.Helper()

	s := newTestServer(t)
	f := &exitFixture{server: s}

	// Approved and advertising: an exit node in effect.
	f.exit = seedAPIMachine(t, s, "exit", nil)
	f.exit.ApprovedRoutes = []netip.Prefix{state.ExitRouteV4}
	f.exit.Hostinfo = &tailcfg.Hostinfo{Hostname: "exit", RoutableIPs: []netip.Prefix{state.ExitRouteV4}}
	if err := s.store.UpdateNode(f.exit); err != nil {
		t.Fatalf("UpdateNode(exit): %v", err)
	}

	// Approved but no longer advertising: still an exit node by approval, and
	// the page must say so.
	f.stale = seedAPIMachine(t, s, "stale", nil)
	f.stale.ApprovedRoutes = []netip.Prefix{state.ExitRouteV4}
	if err := s.store.UpdateNode(f.stale); err != nil {
		t.Fatalf("UpdateNode(stale): %v", err)
	}

	// Advertises the default route but is not approved: not an exit node.
	unapproved := seedAPIMachine(t, s, "unapproved", nil)
	unapproved.Hostinfo = &tailcfg.Hostinfo{Hostname: "unapproved", RoutableIPs: []netip.Prefix{state.ExitRouteV4}}
	if err := s.store.UpdateNode(unapproved); err != nil {
		t.Fatalf("UpdateNode(unapproved): %v", err)
	}

	f.client = seedAPIMachine(t, s, "laptop", nil)
	f.client.Hostinfo = &tailcfg.Hostinfo{Hostname: "laptop", ExitNodeID: tailcfg.StableNodeID(f.exit.StableID)}
	if err := s.store.UpdateNode(f.client); err != nil {
		t.Fatalf("UpdateNode(client): %v", err)
	}
	f.unresolved = seedAPIMachine(t, s, "lost", nil)
	f.unresolved.Hostinfo = &tailcfg.Hostinfo{Hostname: "lost", ExitNodeID: "n-deleted"}
	if err := s.store.UpdateNode(f.unresolved); err != nil {
		t.Fatalf("UpdateNode(unresolved): %v", err)
	}
	f.plain = seedAPIMachine(t, s, "plain", nil)
	return f
}

// TestExitNodesView checks the join between approvals and client selections.
func TestExitNodesView(t *testing.T) {
	f := newExitFixture(t)
	f.server.markOnline(f.exit)
	defer f.server.markOffline(f.exit)

	view := f.server.exitNodesView()
	if len(view.ExitNodes) != 2 {
		t.Fatalf("exit nodes = %d, want 2 (approved, advertising or not): %+v", len(view.ExitNodes), view.ExitNodes)
	}
	var approved, stale *exitNodeView
	for i := range view.ExitNodes {
		switch view.ExitNodes[i].StableID {
		case f.exit.StableID:
			approved = &view.ExitNodes[i]
		case f.stale.StableID:
			stale = &view.ExitNodes[i]
		}
	}
	if approved == nil || stale == nil {
		t.Fatalf("missing an exit node: %+v", view.ExitNodes)
	}
	if !approved.Online || !approved.Announced || approved.ClientCount != 1 || len(approved.Clients) != 1 {
		t.Errorf("advertising exit node = %+v", approved)
	}
	if approved.Clients[0].StableID != f.client.StableID || approved.Clients[0].Hostname != "laptop" {
		t.Errorf("exit node clients = %+v", approved.Clients)
	}
	if stale.Announced || stale.ClientCount != 0 {
		t.Errorf("stale exit node = %+v, want approved but not advertising", stale)
	}

	if len(view.Clients) != 2 {
		t.Fatalf("clients = %d, want the two nodes with a selection: %+v", len(view.Clients), view.Clients)
	}
	if view.Clients[0].NodeID > view.Clients[1].NodeID {
		t.Errorf("clients are not sorted by node ID: %+v", view.Clients)
	}
	byStable := map[string]exitNodeSelectionView{}
	for _, selection := range view.Clients {
		byStable[selection.StableID] = selection
	}
	if got := byStable[f.client.StableID]; !got.Resolved || got.ExitNodeStableID != f.exit.StableID || got.ExitNodeHostname != "exit" {
		t.Errorf("resolved selection = %+v", got)
	}
	if got := byStable[f.unresolved.StableID]; got.Resolved || got.ExitNodeHostname != "" {
		t.Errorf("unresolved selection = %+v, want resolved=false and no hostname", got)
	}
	for _, selection := range view.Clients {
		if selection.StableID == f.plain.StableID {
			t.Errorf("node without a selection appears in clients: %+v", selection)
		}
	}
}

// TestExitNodesViewRevoked checks that withdrawing the approval makes the
// exit node disappear and turns its clients' selections unresolved, while
// keeping the selected node's name visible.
func TestExitNodesViewRevoked(t *testing.T) {
	f := newExitFixture(t)
	f.exit.ApprovedRoutes = nil
	if err := f.server.store.UpdateNode(f.exit); err != nil {
		t.Fatalf("UpdateNode(revoke): %v", err)
	}

	view := f.server.exitNodesView()
	if len(view.ExitNodes) != 1 || view.ExitNodes[0].StableID != f.stale.StableID {
		t.Fatalf("exit nodes after withdrawal = %+v, want only the stale one", view.ExitNodes)
	}
	var selection exitNodeSelectionView
	for _, got := range view.Clients {
		if got.StableID == f.client.StableID {
			selection = got
		}
	}
	if selection.Resolved {
		t.Errorf("selection still resolved after withdrawal: %+v", selection)
	}
	if selection.ExitNodeHostname != "exit" {
		t.Errorf("withdrawn exit node lost its name: %+v", selection)
	}
}

// TestAPIV2ExitNodes checks the read-only HTTP surface.
func TestAPIV2ExitNodes(t *testing.T) {
	f := newExitFixture(t)
	hs := newTestHTTPServer(t, f.server)
	client := noRedirectClient()

	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/exit-nodes", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}
	_, token := seedAPIKey(t, f.server, identity.ScopeRead)
	resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/exit-nodes", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var view exitNodesView
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		t.Fatalf("decoding exit nodes: %v", err)
	}
	if len(view.ExitNodes) != 2 || len(view.Clients) != 2 {
		t.Errorf("view = %+v", view)
	}

	// A member may read the posture too.
	member := seedRoleUser(t, f.server, "member@example.com", identity.RoleMember)
	memberToken := seedAPIKeyForUser(t, f.server, member, identity.ScopeRead)
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/exit-nodes", memberToken, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("member status = %d, want 200", resp.StatusCode)
	}
}

// TestConsoleExitNodes checks the console page renders the join and stays
// read-only for every role.
func TestConsoleExitNodes(t *testing.T) {
	f := newExitFixture(t)
	hs := newTestHTTPServer(t, f.server)
	client := noRedirectClient()
	cookie := loginLocal(t, client, hs.URL, "/console/exit-nodes")

	page := bodyString(t, getRequest(t, client, hs.URL+"/console/exit-nodes", cookie))
	for _, want := range []string{"Exit nodes", "Approved exit nodes", "Clients", "exit", "laptop", "n-deleted", "unresolved", "not advertising"} {
		if !strings.Contains(page, want) {
			t.Errorf("exit-nodes page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, `action="/console/exit-nodes"`) {
		t.Errorf("page renders a form:\n%s", page)
	}

	member := seedRoleUser(t, f.server, "member@example.com", identity.RoleMember)
	memberCookie, _ := seedUserSession(t, f.server, member)
	resp := getRequest(t, client, hs.URL+"/console/exit-nodes", memberCookie)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("member console status = %d, want 200", resp.StatusCode)
	}
}
