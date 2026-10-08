package control

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// shareFixture is a router with one accepted cross-organization share:
// Acme's machine y is shared with Globex's user u, who owns the node x.
type shareFixture struct {
	router *Router
	acme   *Server
	globex *Server
	y      state.Node
	x      state.Node
	share  Share
	user   tailcfg.UserID
}

// shareTestPrincipal builds the API principal a signed-in user presents.
func shareTestPrincipal(userID tailcfg.UserID, role identity.Role) apiPrincipal {
	return apiPrincipal{
		Kind:   "session",
		UserID: userID,
		Role:   role,
		Scopes: map[string]bool{identity.ScopeRead: true, identity.ScopeWrite: true},
	}
}

// openShareRouter wires two organizations and the platform share registry
// over the given state directories. Reusing the directories is how the
// restart test observes durable state.
func openShareRouter(t *testing.T, acmeDir, globexDir, platformDir string) (*Router, *Server, *Server) {
	t.Helper()

	acme := newServerWithConfig(t, Config{StateDir: acmeDir, Domain: "acme.example.com"})
	globex := newServerWithConfig(t, Config{StateDir: globexDir, Domain: "globex.example.com"})
	registry := newTestShareRegistryAt(t, filepath.Join(platformDir, "shares.db"))
	router := newTestRouter(t, RouterConfig{
		Orgs: []OrgSite{
			{ID: "acme", Name: "Acme", Domains: []string{"login.acme.example.com"}, Server: acme},
			{ID: "globex", Name: "Globex", Domains: []string{"login.globex.example.com"}, Server: globex},
		},
		Shares: registry,
	})
	return router, acme, globex
}

// newShareFixture builds the accepted-share pair over fresh state
// directories.
func newShareFixture(t *testing.T) *shareFixture {
	t.Helper()

	router, acme, globex := openShareRouter(t, t.TempDir(), t.TempDir(), t.TempDir())
	f := &shareFixture{router: router, acme: acme, globex: globex}
	f.y = seedAPIMachine(t, acme, "laptop", nil)
	f.y.Hostinfo = &tailcfg.Hostinfo{
		Hostname:     "laptop",
		OS:           "linux",
		OSVersion:    "6.1",
		Cloud:        "aws",
		NetInfo:      &tailcfg.NetInfo{},
		Services:     []tailcfg.Service{{Proto: "tcp", Port: 8080}},
		SSH_HostKeys: []string{"ssh-ed25519 AAAA"},
		RequestTags:  []string{"tag:secret"},
		WoLMACs:      []string{"00:11:22:33:44:55"},
		RoutableIPs:  []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")},
	}
	if err := acme.store.UpdateNode(f.y); err != nil {
		t.Fatalf("UpdateNode(hostinfo): %v", err)
	}
	f.user = seedExternalUser(t, globex, "user@globex.example.com", testShareProvider, testShareSubject)
	f.x = state.Node{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		UserID:     f.user,
		Hostname:   "phone",
	}
	if err := globex.store.CreateNode(&f.x); err != nil {
		t.Fatalf("CreateNode(sharee): %v", err)
	}

	ctx := context.Background()
	share, err := acme.createShare(ctx, shareTestPrincipal(state.DefaultUserID, identity.RoleOwner),
		f.y.StableID, "globex", testShareProvider, testShareSubject)
	if err != nil {
		t.Fatalf("createShare: %v", err)
	}
	accepted, err := globex.acceptShare(ctx, shareTestPrincipal(f.user, identity.RoleMember), share.ID)
	if err != nil {
		t.Fatalf("acceptShare: %v", err)
	}
	f.share = accepted
	return f
}

// TestShareNetmapMasquerade checks the two netmaps a share creates: synthetic
// identifiers and addresses on both sides, symmetric masquerade hints, and
// none of the source organization's real identifiers.
func TestShareNetmapMasquerade(t *testing.T) {
	f := newShareFixture(t)

	// The sharee's netmap sees Acme's machine.
	inbound := f.globex.sharePeersFor(f.x)
	if inbound == nil || len(inbound.nodes) != 1 {
		t.Fatalf("sharee netmap peers = %+v, want one", inbound)
	}
	shown := inbound.nodes[0]
	if shown.ID < state.ShareNodeIDBase {
		t.Errorf("synthetic node ID = %d, want >= %d", shown.ID, state.ShareNodeIDBase)
	}
	if shown.ID == f.y.ID {
		t.Errorf("synthetic node ID = the source node ID %d", shown.ID)
	}
	if shown.StableID != "share:acme:"+f.y.StableID {
		t.Errorf("synthetic stable ID = %q", shown.StableID)
	}
	if shown.IPv4 == f.y.IPv4 || shown.IPv6 == f.y.IPv6 {
		t.Errorf("masquerade reuses the source addresses %v/%v", shown.IPv4, shown.IPv6)
	}
	if !state.ShareMasqIPv4Prefix.Contains(shown.IPv4) || !state.ShareMasqIPv6Prefix.Contains(shown.IPv6) {
		t.Errorf("masquerade %v/%v is outside the share ranges", shown.IPv4, shown.IPv6)
	}
	if len(shown.Tags) != 0 {
		t.Errorf("shared node exposes tags: %v", shown.Tags)
	}
	if shown.Hostinfo != nil && shown.Hostinfo.ShareeNode {
		t.Error("inbound shared machine is marked ShareeNode")
	}
	if shown.Hostinfo == nil {
		t.Fatal("inbound shared machine lost its display hostinfo")
	}
	// Display fields cross the boundary; topology, credentials and metadata
	// do not (AGENTS.md section 12).
	if shown.Hostinfo.Hostname != "laptop" || shown.Hostinfo.OS != "linux" || shown.Hostinfo.OSVersion != "6.1" {
		t.Errorf("display hostinfo = %+v", shown.Hostinfo)
	}
	if shown.Hostinfo.NetInfo != nil || len(shown.Hostinfo.Services) != 0 || len(shown.Hostinfo.SSH_HostKeys) != 0 ||
		len(shown.Hostinfo.RequestTags) != 0 || len(shown.Hostinfo.WoLMACs) != 0 || len(shown.Hostinfo.RoutableIPs) != 0 ||
		shown.Hostinfo.Cloud != "" {
		t.Errorf("shared hostinfo leaks tenant data: %+v", shown.Hostinfo)
	}
	if shown.UserID < identity.ShareUserIDBase {
		t.Errorf("synthetic owner ID = %d, want >= %d", shown.UserID, identity.ShareUserIDBase)
	}
	if shown.Hostname != "laptop-acme" {
		t.Errorf("shared hostname = %q, want laptop-acme", shown.Hostname)
	}
	profile, ok := inbound.profiles[shown.UserID]
	if !ok {
		t.Fatalf("netmap lacks the profile for the synthetic owner %d", shown.UserID)
	}
	if profile.ID != shown.UserID || !strings.HasPrefix(profile.LoginName, "shared+acme+") || !strings.HasSuffix(profile.LoginName, "@xunara.invalid") {
		t.Errorf("synthetic profile = %+v", profile)
	}
	if profile.LoginName == "" || strings.Contains(profile.LoginName, "@acme.example.com") {
		t.Errorf("synthetic profile leaks a routable login name: %+v", profile)
	}

	// The sharer's netmap sees the sharee's node, marked as such.
	outbound := f.acme.sharePeersFor(f.y)
	if outbound == nil || len(outbound.nodes) != 1 {
		t.Fatalf("sharer netmap peers = %+v, want one", outbound)
	}
	shareeNode := outbound.nodes[0]
	if shareeNode.StableID != "share:globex:"+f.x.StableID {
		t.Errorf("sharee stable ID = %q", shareeNode.StableID)
	}
	if shareeNode.IPv4 == f.x.IPv4 || shareeNode.IPv6 == f.x.IPv6 {
		t.Errorf("sharee masquerade reuses the real addresses %v/%v", shareeNode.IPv4, shareeNode.IPv6)
	}
	if !state.ShareMasqIPv4Prefix.Contains(shareeNode.IPv4) {
		t.Errorf("sharee masquerade %v is outside the share range", shareeNode.IPv4)
	}
	if shareeNode.Hostinfo == nil || !shareeNode.Hostinfo.ShareeNode {
		t.Errorf("sharee node is not marked ShareeNode: %+v", shareeNode.Hostinfo)
	}
	if shareeNode.Hostname != "phone-globex" {
		t.Errorf("sharee hostname = %q, want phone-globex", shareeNode.Hostname)
	}

	// Both hints point at the address the other side knows this node by.
	if hint := inbound.peers[shown.ID]; hint.SelfV4 != shareeNode.IPv4 || hint.SelfV6 != shareeNode.IPv6 {
		t.Errorf("sharee-side masquerade hint = %v/%v, want %v/%v", hint.SelfV4, hint.SelfV6, shareeNode.IPv4, shareeNode.IPv6)
	}
	if hint := outbound.peers[shareeNode.ID]; hint.SelfV4 != shown.IPv4 || hint.SelfV6 != shown.IPv6 {
		t.Errorf("sharer-side masquerade hint = %v/%v, want %v/%v", hint.SelfV4, hint.SelfV6, shown.IPv4, shown.IPv6)
	}
	// Each organization has its own address space, so the two organizations
	// may reuse the same numeric value; what must not happen is a masquerade
	// colliding with a real local address on the side that sends traffic.
	if shown.IPv4 == f.x.IPv4 || shown.IPv6 == f.x.IPv6 {
		t.Errorf("masquerade for the peer collides with the sharee's own address: %v/%v", shown.IPv4, shown.IPv6)
	}
	if shareeNode.IPv4 == f.y.IPv4 || shareeNode.IPv6 == f.y.IPv6 {
		t.Errorf("masquerade for the peer collides with the sharer's own address: %v/%v", shareeNode.IPv4, shareeNode.IPv6)
	}

	// A third node in the target organization sees nothing.
	outsider := state.Node{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		UserID:     seedRoleUser(t, f.globex, "outsider@globex.example.com", identity.RoleMember),
		Hostname:   "outsider",
	}
	if err := f.globex.store.CreateNode(&outsider); err != nil {
		t.Fatalf("CreateNode(outsider): %v", err)
	}
	if peers := f.globex.sharePeersFor(outsider); peers != nil {
		t.Errorf("third-party netmap has %d shared peers, want none", len(peers.nodes))
	}
	if peers := f.acme.sharePeersFor(f.y); peers == nil || len(peers.nodes) != 1 {
		t.Error("outsider in the source organization affected the sharer's netmap")
	}

	// The full wire netmap carries the masquerade hints and the synthetic
	// profile; the raw node is absent.
	resp := f.globex.fullMap(f.x, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion})
	var peer *tailcfg.Node
	for _, p := range resp.Peers {
		if p.ID == tailcfg.NodeID(shown.ID) {
			peer = p
		}
	}
	if peer == nil {
		t.Fatalf("wire netmap lacks the shared peer %d", shown.ID)
	}
	if peer.SelfNodeV4MasqAddrForThisPeer == nil || *peer.SelfNodeV4MasqAddrForThisPeer != shareeNode.IPv4 {
		t.Errorf("wire masquerade hint = %v, want %v", peer.SelfNodeV4MasqAddrForThisPeer, shareeNode.IPv4)
	}
	if len(peer.Addresses) != 2 || !peer.Addresses[0].Addr().IsValid() || peer.Addresses[0].Addr().Is4() != shown.IPv4.Is4() {
		t.Errorf("wire addresses = %v, want the masquerade pair", peer.Addresses)
	}
	if len(peer.Addresses) != 2 || peer.Addresses[0].Addr() != shown.IPv4 {
		t.Errorf("wire addresses = %v, want the masquerade pair (%v, ...)", peer.Addresses, shown.IPv4)
	}
	if peer.Name != "laptop-acme.globex.example.com." {
		t.Errorf("wire name = %q, want the globex MagicDNS name", peer.Name)
	}
	if peer.StableID != tailcfg.StableNodeID("share:acme:"+f.y.StableID) {
		t.Errorf("wire stable ID = %q", peer.StableID)
	}
	foundProfile := false
	for _, p := range resp.UserProfiles {
		if p.ID == shown.UserID {
			foundProfile = true
		}
		if p.ID == f.y.UserID {
			t.Error("wire netmap leaks the source organization's real user ID")
		}
	}
	if !foundProfile {
		t.Error("wire netmap lacks the synthetic owner profile")
	}

	// Repeated builds reuse the same synthetic namespace.
	again := f.globex.sharePeersFor(f.x)
	if again == nil || len(again.nodes) != 1 || again.nodes[0].ID != shown.ID || again.nodes[0].IPv4 != shown.IPv4 {
		t.Errorf("second build changed the synthetic namespace: %+v", again)
	}
	if !netip.MustParsePrefix("100.127.0.0/16").Contains(again.nodes[0].IPv4) {
		t.Errorf("second build moved the masquerade: %v", again.nodes[0].IPv4)
	}
}

// TestShareHostnameBounded checks the foreign hostname stays one valid DNS
// label for pathological source hostnames and organization IDs.
func TestShareHostnameBounded(t *testing.T) {
	long := strings.Repeat("a", 200)
	for name, tc := range map[string]struct{ host, org string }{
		"long host": {long, "globex"},
		"long org":  {"laptop", long},
		"both":      {long, long},
		"empty":     {"", ""},
		"odd chars": {"My Laptop!", "Team #1"},
	} {
		got := shareHostname(tc.host, tc.org)
		if got == "" || len(got) > 63 {
			t.Errorf("%s: shareHostname = %q (len %d)", name, got, len(got))
		}
		if strings.Trim(got, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			t.Errorf("%s: shareHostname = %q, want a DNS label", name, got)
		}
	}
	if got := shareHostname("Laptop", "Globex"); got != "laptop-globex" {
		t.Errorf("shareHostname = %q, want laptop-globex", got)
	}
}

// TestShareNetmapSharerProfile checks that a share by a user who does not own
// the machine keeps both identities separate in the synthetic namespace.
func TestShareNetmapSharerProfile(t *testing.T) {
	f := newShareFixture(t)

	// Alice (a second Acme user) shares another machine owned by the built-in
	// user, so the sharer and the owner are different people.
	alice := seedRoleUser(t, f.acme, "alice@acme.example.com", identity.RoleAdmin)
	second := seedAPIMachine(t, f.acme, "desktop", nil)
	ctx := context.Background()
	share, err := f.acme.createShare(ctx, shareTestPrincipal(alice, identity.RoleAdmin),
		second.StableID, "globex", testShareProvider, testShareSubject)
	if err != nil {
		t.Fatalf("createShare: %v", err)
	}
	if _, err := f.globex.acceptShare(ctx, shareTestPrincipal(f.user, identity.RoleMember), share.ID); err != nil {
		t.Fatalf("acceptShare: %v", err)
	}

	inbound := f.globex.sharePeersFor(f.x)
	if inbound == nil || len(inbound.nodes) != 2 {
		t.Fatalf("netmap peers = %+v, want two (the owner and the sharer)", inbound)
	}
	hints := inbound.peers
	seenOwners := make(map[tailcfg.UserID]bool)
	sharedByAlice := false
	for _, node := range inbound.nodes {
		seenOwners[node.UserID] = true
		hint := hints[node.ID]
		if node.StableID == "share:acme:"+second.StableID {
			sharedByAlice = true
			if hint.Sharer == 0 {
				t.Error("the machine Alice shared has no synthetic sharer")
			}
		}
		if hint.Sharer == 0 {
			continue
		}
		if hint.Sharer == node.UserID {
			t.Errorf("node %d maps sharer and owner to the same ID", node.ID)
		}
		if _, ok := inbound.profiles[hint.Sharer]; !ok {
			t.Errorf("node %d sharer %d has no profile", node.ID, hint.Sharer)
		}
	}
	if !sharedByAlice {
		t.Error("netmap lacks the machine shared by the second user")
	}
	if len(seenOwners) != 1 {
		t.Errorf("owner synthetic IDs = %v, want one shared owner", seenOwners)
	}
}

// TestShareNetmapRevoked checks that revoking removes the peers and that the
// namespace, once allocated, is reused (not recycled).
func TestShareNetmapRevoked(t *testing.T) {
	f := newShareFixture(t)
	before := f.globex.sharePeersFor(f.x)
	if before == nil || len(before.nodes) != 1 {
		t.Fatalf("pre-revoke peers = %+v", before)
	}

	ctx := context.Background()
	if _, err := f.acme.revokeShare(ctx, shareTestPrincipal(state.DefaultUserID, identity.RoleOwner), f.share.ID); err != nil {
		t.Fatalf("revokeShare: %v", err)
	}
	if peers := f.globex.sharePeersFor(f.x); peers != nil {
		t.Errorf("revoked share still exposes %d peers", len(peers.nodes))
	}
	if peers := f.acme.sharePeersFor(f.y); peers != nil {
		t.Errorf("revoked share still exposes %d peers on the source side", len(peers.nodes))
	}

	// Re-sharing reuses the same synthetic identifiers: the client sees a
	// stable peer, not a new one.
	share, err := f.acme.createShare(ctx, shareTestPrincipal(state.DefaultUserID, identity.RoleOwner),
		f.y.StableID, "globex", testShareProvider, testShareSubject)
	if err != nil {
		t.Fatalf("re-share: %v", err)
	}
	if _, err := f.globex.acceptShare(ctx, shareTestPrincipal(f.user, identity.RoleMember), share.ID); err != nil {
		t.Fatalf("re-accept: %v", err)
	}
	after := f.globex.sharePeersFor(f.x)
	if after == nil || len(after.nodes) != 1 {
		t.Fatalf("post-revoke peers = %+v", after)
	}
	if after.nodes[0].ID != before.nodes[0].ID || after.nodes[0].IPv4 != before.nodes[0].IPv4 {
		t.Errorf("namespace changed across revoke: %d/%v -> %d/%v",
			before.nodes[0].ID, before.nodes[0].IPv4, after.nodes[0].ID, after.nodes[0].IPv4)
	}
}

// TestShareNetmapPolicy checks that the receiving organization's packet
// filter names the shared node: the pair is reachable under a wildcard rule
// even though the shared node has no tags and no local login name.
func TestShareNetmapPolicy(t *testing.T) {
	policyDir := t.TempDir()
	// autogroup:member resolves to member node addresses, which is where the
	// shared node must show up: it is untagged and has no local login name.
	policyPath := writePolicy(t, policyDir, `{"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"]}]}`)

	acme := newServerWithConfig(t, Config{Domain: "acme.example.com"})
	globex := newServerWithConfig(t, Config{Domain: "globex.example.com", PolicyPath: policyPath})
	registry := newTestShareRegistryAt(t, filepath.Join(t.TempDir(), "shares.db"))
	newTestRouter(t, RouterConfig{
		Orgs: []OrgSite{
			{ID: "acme", Name: "Acme", Domains: []string{"login.acme.example.com"}, Server: acme},
			{ID: "globex", Name: "Globex", Domains: []string{"login.globex.example.com"}, Server: globex},
		},
		Shares: registry,
	})

	y := seedAPIMachine(t, acme, "laptop", nil)
	user := seedExternalUser(t, globex, "user@globex.example.com", testShareProvider, testShareSubject)
	x := state.Node{MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), UserID: user, Hostname: "phone"}
	if err := globex.store.CreateNode(&x); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	ctx := context.Background()
	share, err := acme.createShare(ctx, shareTestPrincipal(state.DefaultUserID, identity.RoleOwner),
		y.StableID, "globex", testShareProvider, testShareSubject)
	if err != nil {
		t.Fatalf("createShare: %v", err)
	}
	if _, err := globex.acceptShare(ctx, shareTestPrincipal(user, identity.RoleMember), share.ID); err != nil {
		t.Fatalf("acceptShare: %v", err)
	}

	peers := globex.sharePeersFor(x)
	if peers == nil || len(peers.nodes) != 1 {
		t.Fatalf("peers = %+v", peers)
	}
	shared := peers.nodes[0]
	resp := globex.fullMap(x, tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion})
	rules := resp.PacketFilter
	if len(resp.PacketFilters) > 0 {
		rules = resp.PacketFilters["base"]
	}
	if len(rules) == 0 {
		t.Fatalf("compiled policy is empty; the member rule must resolve")
	}
	found := false
	for _, rule := range rules {
		for _, dst := range rule.DstPorts {
			if dst.IP == netip.PrefixFrom(shared.IPv4, shared.IPv4.BitLen()).String() {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("packet filter does not name the shared node %v: %+v", shared.IPv4, rules)
	}
}

// TestShareNetmapStableAcrossRestart checks the namespace survives a full
// server restart: same share row, same synthetic node, same masquerade.
func TestShareNetmapStableAcrossRestart(t *testing.T) {
	acmeDir, globexDir, platformDir := t.TempDir(), t.TempDir(), t.TempDir()
	firstRouter, firstAcme, firstGlobex := openShareRouter(t, acmeDir, globexDir, platformDir)
	firstY := seedAPIMachine(t, firstAcme, "laptop", nil)
	firstUser := seedExternalUser(t, firstGlobex, "user@globex.example.com", testShareProvider, testShareSubject)
	firstX := state.Node{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		UserID:     firstUser,
		Hostname:   "phone",
	}
	if err := firstGlobex.store.CreateNode(&firstX); err != nil {
		t.Fatalf("CreateNode: %v", err)
	}
	ctx := context.Background()
	share, err := firstAcme.createShare(ctx, shareTestPrincipal(state.DefaultUserID, identity.RoleOwner),
		firstY.StableID, "globex", testShareProvider, testShareSubject)
	if err != nil {
		t.Fatalf("createShare: %v", err)
	}
	if _, err := firstGlobex.acceptShare(ctx, shareTestPrincipal(firstUser, identity.RoleMember), share.ID); err != nil {
		t.Fatalf("acceptShare: %v", err)
	}

	before := firstGlobex.sharePeersFor(firstX)
	if before == nil || len(before.nodes) != 1 {
		t.Fatalf("pre-restart peers = %+v", before)
	}
	if err := firstRouter.Close(); err != nil {
		t.Fatalf("router.Close: %v", err)
	}

	// A second router opens the same state directories and share registry.
	_, _, secondGlobex := openShareRouter(t, acmeDir, globexDir, platformDir)
	x, ok := secondGlobex.store.GetNodeByStableID(firstX.StableID)
	if !ok {
		t.Fatalf("sharee node did not survive the restart")
	}
	after := secondGlobex.sharePeersFor(x)
	if after == nil || len(after.nodes) != 1 {
		t.Fatalf("post-restart peers = %+v", after)
	}
	if after.nodes[0].ID != before.nodes[0].ID || after.nodes[0].IPv4 != before.nodes[0].IPv4 || after.nodes[0].IPv6 != before.nodes[0].IPv6 {
		t.Errorf("namespace changed across restart: %v/%v/%v -> %v/%v/%v",
			before.nodes[0].ID, before.nodes[0].IPv4, before.nodes[0].IPv6,
			after.nodes[0].ID, after.nodes[0].IPv4, after.nodes[0].IPv6)
	}
}
