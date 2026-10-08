package mapper

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/state"
)

func testNode(id state.NodeID, hostname string) state.Node {
	return state.Node{
		ID:         id,
		StableID:   fmt.Sprintf("n%d", id),
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		UserID:     state.DefaultUserID,
		Hostname:   hostname,
		IPv4:       netip.MustParseAddr(fmt.Sprintf("100.64.0.%d", id)),
		IPv6:       netip.MustParseAddr(fmt.Sprintf("fd7a:115c:a1e0::%d", id)),
		Created:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		CapVer:     tailcfg.CurrentCapabilityVersion,
	}
}

func neverOnline(state.NodeID) bool { return false }

func TestFullIncludesSelfPeersAndPolicy(t *testing.T) {
	self := testNode(1, "self")
	peer := testNode(2, "peer")

	resp := Full(self, []state.Node{peer, self}, Config{Domain: "xunara.test"}, neverOnline, tailcfg.CurrentCapabilityVersion)

	if resp.Node == nil || resp.Node.ID != tailcfg.NodeID(self.ID) {
		t.Fatalf("self node = %+v, want id %d", resp.Node, self.ID)
	}
	if resp.Node.Name != "self.xunara.test." {
		t.Errorf("self name = %q, want self.xunara.test.", resp.Node.Name)
	}
	if len(resp.Peers) != 1 {
		t.Fatalf("peers = %d, want 1 (self must be filtered out)", len(resp.Peers))
	}
	if resp.Peers[0].ID != tailcfg.NodeID(peer.ID) {
		t.Errorf("peer id = %d, want %d", resp.Peers[0].ID, peer.ID)
	}
	if len(resp.Peers[0].Addresses) != 2 {
		t.Errorf("peer addresses = %v, want 2 entries", resp.Peers[0].Addresses)
	}

	if resp.Domain != "xunara.test" {
		t.Errorf("domain = %q, want xunara.test", resp.Domain)
	}
	if resp.DNSConfig == nil || len(resp.DNSConfig.Domains) != 1 || !resp.DNSConfig.Proxied {
		t.Errorf("dns config = %+v, want proxied MagicDNS for the domain", resp.DNSConfig)
	}
	if _, ok := resp.PacketFilters["base"]; !ok {
		t.Error("missing base packet filter")
	}
	if len(resp.UserProfiles) != 1 {
		t.Errorf("user profiles = %d, want 1", len(resp.UserProfiles))
	}
}

func TestFullPeersSortedByID(t *testing.T) {
	self := testNode(1, "self")
	resp := Full(self, []state.Node{testNode(9, "nine"), testNode(3, "three"), testNode(5, "five")}, Config{}, neverOnline, tailcfg.CurrentCapabilityVersion)

	got := make([]tailcfg.NodeID, 0, len(resp.Peers))
	for _, p := range resp.Peers {
		got = append(got, p.ID)
	}
	want := []tailcfg.NodeID{3, 5, 9}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("peer order = %v, want %v", got, want)
		}
	}
}

func TestFullUsesLegacyPacketFilterForOldClients(t *testing.T) {
	// capver 81 introduced MapResponse.PacketFilters.
	resp := Full(testNode(1, "self"), nil, Config{}, neverOnline, 80)

	if resp.PacketFilters != nil {
		t.Error("PacketFilters must not be set for pre-81 clients")
	}
	if len(resp.PacketFilter) == 0 {
		t.Error("PacketFilter must be set for pre-81 clients")
	}
}

func TestOnlineReflectsSessions(t *testing.T) {
	self := testNode(1, "self")
	peer := testNode(2, "peer")

	online := func(id state.NodeID) bool { return id == peer.ID }

	resp := Full(self, []state.Node{self, peer}, Config{}, online, tailcfg.CurrentCapabilityVersion)

	if resp.Node.Online == nil || !*resp.Node.Online {
		t.Error("the requesting node is online by construction")
	}
	if resp.Peers[0].Online == nil || !*resp.Peers[0].Online {
		t.Error("peer with a live session must be reported online")
	}
}

func TestDNSConfigOmittedWithoutDomain(t *testing.T) {
	resp := Full(testNode(1, "self"), nil, Config{}, neverOnline, tailcfg.CurrentCapabilityVersion)
	if resp.DNSConfig != nil {
		t.Errorf("dns config = %+v, want nil without a domain", resp.DNSConfig)
	}
}

func TestUpdateCarriesOnlyMutableFields(t *testing.T) {
	self := testNode(1, "self")
	peer := testNode(2, "peer")

	resp := Update(self, []state.Node{self, peer}, Config{}, neverOnline)

	if resp.Node == nil || len(resp.Peers) != 1 {
		t.Fatalf("update = %+v, want self node and one peer", resp)
	}
	if resp.DNSConfig != nil || resp.DERPMap != nil || resp.Domain != "" {
		t.Error("update must not restate DNSConfig/DERPMap/Domain (nil means unchanged)")
	}
	if resp.PacketFilters != nil || resp.PacketFilter != nil {
		t.Error("update must not restate the packet filter")
	}
}

// TestNodeCarriesTags checks ACL tags reach the wire, where clients and ACL
// consumers read them.
func TestNodeCarriesTags(t *testing.T) {
	n := testNode(1, "tagged")
	n.Tags = []string{"tag:prod"}

	got := Node(n, true, neverOnline, nil, Config{})
	if len(got.Tags) != 1 || got.Tags[0] != "tag:prod" {
		t.Errorf("Tags = %v, want [tag:prod]", got.Tags)
	}
	if got.User != TaggedDevicesUserID {
		t.Errorf("User = %d, want the tagged-devices pseudo user", got.User)
	}
}

func TestUserProfilesIncludeTaggedDevices(t *testing.T) {
	tagged := testNode(1, "tagged")
	tagged.Tags = []string{"tag:prod"}
	plain := testNode(2, "plain")

	profiles := userProfiles(tagged, []state.Node{tagged, plain}, Config{})

	var haveUser, haveTagged bool
	for _, p := range profiles {
		switch p.ID {
		case state.DefaultUserID:
			haveUser = true
		case TaggedDevicesUserID:
			haveTagged = true
			if p.LoginName != "tagged-devices" || p.DisplayName != "Tagged Devices" {
				t.Errorf("tagged-devices profile = %+v", p)
			}
		}
	}
	if !haveUser {
		t.Error("the owning user's profile is missing")
	}
	if !haveTagged {
		t.Errorf("profiles = %+v, want the tagged-devices profile", profiles)
	}

	// An untagged node keeps its real owner.
	if got := Node(plain, true, neverOnline, nil, Config{}); got.User != state.DefaultUserID {
		t.Errorf("untagged node User = %d, want %d", got.User, state.DefaultUserID)
	}
}

func TestNodeMarksExpiredKeys(t *testing.T) {
	expired := testNode(1, "expired")
	expired.Expiry = time.Now().Add(-time.Hour)

	if got := Node(expired, true, neverOnline, nil, Config{}); !got.Expired {
		t.Error("Expired = false for a node whose key expiry has passed")
	}

	future := testNode(2, "future")
	future.Expiry = time.Now().Add(time.Hour)

	if got := Node(future, true, neverOnline, nil, Config{}); got.Expired {
		t.Error("Expired = true for a node whose key expiry is in the future")
	}

	never := testNode(3, "never")
	if got := Node(never, true, neverOnline, nil, Config{}); got.Expired {
		t.Error("Expired = true for a node that never expires")
	}
}

// TestNodeCarriesMachineAuthorization pins the field the client's ipn state
// machine reads: without MachineAuthorized a registered, approved and online
// node still parks every client in NeedsMachineAuth, which the apps render as
// "Admin approval required".
func TestNodeCarriesMachineAuthorization(t *testing.T) {
	valid := testNode(1, "valid")
	if got := Node(valid, true, neverOnline, nil, Config{}); !got.MachineAuthorized {
		t.Error("MachineAuthorized = false for an unexpired node")
	}

	if got := Node(valid, false, neverOnline, nil, Config{}); !got.MachineAuthorized {
		t.Error("MachineAuthorized = false for a peer")
	}

	expired := testNode(2, "expired")
	expired.Expiry = time.Now().Add(-time.Hour)
	if got := Node(expired, true, neverOnline, nil, Config{}); got.MachineAuthorized {
		t.Error("MachineAuthorized = true for a node whose key expiry has passed")
	}
}

// withRoutes marks a node as advertising and being approved for routes.
func withRoutes(n state.Node, announced, approved []netip.Prefix) state.Node {
	n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: announced}
	n.ApprovedRoutes = approved
	return n
}

func prefixList(t *testing.T, in []netip.Prefix) []string {
	t.Helper()
	out := make([]string, 0, len(in))
	for _, p := range in {
		out = append(out, p.String())
	}
	return out
}

func TestSelfAddressesAreAlwaysAllowed(t *testing.T) {
	self := testNode(1, "self")

	got := Node(self, true, neverOnline, NewRouteTable([]state.Node{self}), Config{})
	if len(got.AllowedIPs) != 2 {
		t.Fatalf("AllowedIPs = %v, want the two self addresses", got.AllowedIPs)
	}
	if len(got.PrimaryRoutes) != 0 {
		t.Errorf("PrimaryRoutes = %v, want empty", got.PrimaryRoutes)
	}
}

func TestAllowedIPsUseApprovedAnnouncedRoutesOnly(t *testing.T) {
	subnet := netip.MustParsePrefix("192.168.1.0/24")
	notApproved := netip.MustParsePrefix("10.0.0.0/8")
	approvedNotAnnounced := netip.MustParsePrefix("172.16.0.0/12")

	self := withRoutes(testNode(1, "router"),
		[]netip.Prefix{subnet, notApproved},
		[]netip.Prefix{subnet, approvedNotAnnounced})

	got := Node(self, true, neverOnline, NewRouteTable([]state.Node{self}), Config{})

	want := []string{"100.64.0.1/32", "192.168.1.0/24", "fd7a:115c:a1e0::1/128"}
	if diff := prefixList(t, got.AllowedIPs); !slices.Equal(diff, want) {
		t.Errorf("AllowedIPs = %v, want %v", diff, want)
	}
	if diff := prefixList(t, got.PrimaryRoutes); !slices.Equal(diff, []string{"192.168.1.0/24"}) {
		t.Errorf("PrimaryRoutes = %v, want [192.168.1.0/24]", diff)
	}
}

func TestExitRoutesAreAllowedButNotPrimary(t *testing.T) {
	self := withRoutes(testNode(1, "exit"),
		[]netip.Prefix{state.ExitRouteV4, state.ExitRouteV6},
		[]netip.Prefix{state.ExitRouteV4, state.ExitRouteV6})

	got := Node(self, true, neverOnline, NewRouteTable([]state.Node{self}), Config{})

	want := []string{"0.0.0.0/0", "100.64.0.1/32", "::/0", "fd7a:115c:a1e0::1/128"}
	if diff := prefixList(t, got.AllowedIPs); !slices.Equal(diff, want) {
		t.Errorf("AllowedIPs = %v, want %v", diff, want)
	}
	if len(got.PrimaryRoutes) != 0 {
		t.Errorf("PrimaryRoutes = %v, want empty for an exit-only node", got.PrimaryRoutes)
	}
}

func TestRouteElectionPicksLowestNodeID(t *testing.T) {
	route := netip.MustParsePrefix("10.10.0.0/16")

	first := withRoutes(testNode(3, "three"), []netip.Prefix{route}, []netip.Prefix{route})
	second := withRoutes(testNode(7, "seven"), []netip.Prefix{route}, []netip.Prefix{route})

	nodes := []state.Node{first, second}
	routes := NewRouteTable(nodes)

	if got := routes[route]; got != first.ID {
		t.Fatalf("elected primary = %d, want %d", got, first.ID)
	}

	// Both nodes still carry the prefix in PrimaryRoutes? No: only the elected
	// router serves it, the other must not claim the prefix to peers.
	primary := Node(first, true, neverOnline, routes, Config{})
	backup := Node(second, true, neverOnline, routes, Config{})

	if diff := prefixList(t, primary.PrimaryRoutes); !slices.Equal(diff, []string{"10.10.0.0/16"}) {
		t.Errorf("primary PrimaryRoutes = %v", diff)
	}
	if len(backup.PrimaryRoutes) != 0 {
		t.Errorf("backup PrimaryRoutes = %v, want empty", backup.PrimaryRoutes)
	}

	// The backup keeps its own addresses in AllowedIPs.
	for _, a := range backup.AllowedIPs {
		if a == route {
			t.Errorf("backup AllowedIPs still contains the elected route: %v", backup.AllowedIPs)
		}
	}
}

func TestFQDNIncludesTheMagicDNSDomain(t *testing.T) {
	self := testNode(1, "My Laptop")

	got := Node(self, true, neverOnline, NewRouteTable([]state.Node{self}), Config{Domain: "example.com"})
	if want := "my-laptop.example.com."; got.Name != want {
		t.Errorf("Name = %q, want %q", got.Name, want)
	}

	// Without a MagicDNS domain the name stays a single label.
	got = Node(self, true, neverOnline, NewRouteTable([]state.Node{self}), Config{})
	if want := "my-laptop."; got.Name != want {
		t.Errorf("Name = %q, want %q", got.Name, want)
	}
}

func TestDNSConfigIncludesResolversRoutesAndRecords(t *testing.T) {
	cfg := Config{
		Domain:    "example.com",
		Resolvers: []*dnstype.Resolver{{Addr: "9.9.9.9"}},
		Routes:    map[string][]*dnstype.Resolver{"corp.example.com": {{Addr: "10.0.0.53"}}},
		ExtraRecords: []state.DNSRecord{
			{Name: "_acme-challenge.web.example.com", Type: "TXT", Value: "token"},
		},
	}

	dns := DNSConfig(cfg, state.Node{})
	if dns == nil {
		t.Fatal("DNSConfig = nil, want a configuration")
	}
	if len(dns.Domains) != 1 || dns.Domains[0] != "example.com" {
		t.Errorf("Domains = %v, want [example.com]", dns.Domains)
	}
	if !dns.Proxied {
		t.Error("Proxied = false, want true for MagicDNS")
	}
	if len(dns.Resolvers) != 1 || dns.Resolvers[0].Addr != "9.9.9.9" {
		t.Errorf("Resolvers = %v", dns.Resolvers)
	}
	if got := dns.Routes["corp.example.com"]; len(got) != 1 || got[0].Addr != "10.0.0.53" {
		t.Errorf("Routes = %v", dns.Routes)
	}
	// Without a CertDomainsFor hook the tailnet offers no certificates: the
	// hook is only set when a public DNS zone writer exists.
	if len(dns.CertDomains) != 0 {
		t.Errorf("CertDomains = %v, want none without the hook", dns.CertDomains)
	}
	if len(dns.ExtraRecords) != 1 {
		t.Fatalf("ExtraRecords = %v, want one record", dns.ExtraRecords)
	}
	rec := dns.ExtraRecords[0]
	if rec.Name != "_acme-challenge.web.example.com." || rec.Type != "TXT" || rec.Value != "token" {
		t.Errorf("ExtraRecords[0] = %+v", rec)
	}

	if got := DNSConfig(Config{}, state.Node{}); got != nil {
		t.Errorf("DNSConfig without a domain = %+v, want nil", got)
	}
}

func TestCertDomainsHook(t *testing.T) {
	self := testNode(1, "Web Server")
	cfg := Config{
		Domain: "example.com",
		CertDomainsFor: func(n state.Node) []string {
			return []string{
				strings.TrimSuffix(n.FQDN("example.com"), "."),
				"extra.example.com",
			}
		},
	}

	dns := DNSConfig(cfg, self)
	if dns == nil {
		t.Fatal("DNSConfig = nil, want a configuration")
	}
	// DNSConfig normalises and sorts the names.
	want := []string{"extra.example.com", "web-server.example.com"}
	if !slices.Equal(dns.CertDomains, want) {
		t.Errorf("CertDomains = %v, want %v", dns.CertDomains, want)
	}

	// A hook that returns nothing still reports "no certificates", not an
	// empty-but-present list.
	cfg.CertDomainsFor = func(state.Node) []string { return nil }
	if got := DNSConfig(cfg, self); len(got.CertDomains) != 0 {
		t.Errorf("CertDomains = %v, want none", got.CertDomains)
	}
}
