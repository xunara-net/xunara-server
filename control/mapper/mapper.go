// Package mapper builds the tailnet map (the "netmap") that the control plane
// sends to clients.
//
// The wire types are the authority and live in tailscale.com/tailcfg; this
// package only decides what goes in them. It is deliberately pure — node state
// in, wire types out — so it can be unit-tested without a server.
//
// Reference: reference/headscale/hscontrol/mapper.
package mapper

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"

	"github.com/xunara-net/xunara-server/state"
)

// packetFiltersCapVer is the capability version that introduced the
// incremental MapResponse.PacketFilters map (2023-11-17).
const packetFiltersCapVer tailcfg.CapabilityVersion = 81

// TaggedDevicesUserID is the reserved user ID the wire protocol uses for
// tagged nodes: a tag, not a human, owns them. It mirrors the pseudo user
// headscale uses to reproduce the Tailscale protocol, so clients render tagged
// devices as owned by "Tagged Devices".
const TaggedDevicesUserID tailcfg.UserID = 2147455555

// TaggedDevicesProfile returns the user profile the wire protocol advertises
// for [TaggedDevicesUserID].
func TaggedDevicesProfile() tailcfg.UserProfile {
	return tailcfg.UserProfile{
		ID:          TaggedDevicesUserID,
		LoginName:   "tagged-devices",
		DisplayName: "Tagged Devices",
	}
}

// OnlineFunc reports whether a node currently holds a live control session.
type OnlineFunc func(state.NodeID) bool

// Config carries the tailnet-wide values the mapper needs.
type Config struct {
	// Domain is the MagicDNS domain of the tailnet, without a trailing dot.
	// Empty disables MagicDNS in the netmap.
	Domain string

	// Resolvers are the tailnet's global DNS resolvers, in preference order.
	Resolvers []*dnstype.Resolver

	// Routes is the split-DNS table: DNS suffix to the resolvers that answer
	// it.
	Routes map[string][]*dnstype.Resolver

	// ExtraRecords are administrator- and ACME-created records published to
	// every client through MagicDNS.
	ExtraRecords []state.DNSRecord

	// UserProfile describes a user to clients. A nil function falls back to the
	// single-user default profile.
	UserProfile func(id tailcfg.UserID) tailcfg.UserProfile

	// FilterFor returns the packet filter a node should receive. A nil
	// function means the tailnet has no policy document, which allows
	// everything (the official default for a tailnet without a policy).
	//
	// The returned slice may be empty, which means "block everything": an
	// empty rule set is a meaningful policy, not a missing one.
	FilterFor func(self state.Node) []tailcfg.FilterRule

	// SSHPolicyFor returns the SSH policy a node receives as the destination
	// of incoming SSH connections, or nil when no SSH rule applies to it.
	SSHPolicyFor func(self state.Node) *tailcfg.SSHPolicy

	// NodeCaps returns the capability map a node advertises: the policy's
	// nodeAttrs grants plus capabilities derived from other policy sections
	// (such as tailscale.com/cap/ssh for SSH destinations). Nil means the
	// node advertises no capabilities.
	NodeCaps func(state.Node) tailcfg.NodeCapMap

	// ClientVersion returns the update advisory for a node, or nil when there
	// is nothing to tell it. A nil function disables the field entirely.
	ClientVersion func(state.Node) *tailcfg.ClientVersion

	// CertDomainsFor returns the DNS names for which a node may obtain TLS
	// certificates (ACME DNS-01). Nil, or an empty result, tells the client
	// this tailnet cannot issue certificates.
	CertDomainsFor func(state.Node) []string

	// DERPMap is advertised to clients when non-nil.
	DERPMap *tailcfg.DERPMap

	// TKAInfo is the tailnet-lock state advertised to every client. Nil means
	// the tailnet never had tailnet lock: clients then keep whatever local
	// state they have instead of receiving an explicit disablement.
	TKAInfo *tailcfg.TKAInfo

	// UnsignedPeers are the peers whose node keys tailnet lock does not
	// authorize. They are advertised to *other* nodes with
	// UnsignedPeerAPIOnly set, so clients confine them to the peer API
	// instead of the tailnet. Empty when the tailnet is not locked.
	UnsignedPeers map[state.NodeID]bool

	// PeerShare carries the share-only fields of foreign peers (Xunara Share,
	// spec section 38): the user who shared the node and the addresses the
	// peer knows the viewing node as. Peers without an entry are local.
	PeerShare map[state.NodeID]PeerShare
}

// PeerShare is the wire-visible share metadata of one peer.
type PeerShare struct {
	// Sharer is the user who shared the node, when different from its owner.
	Sharer tailcfg.UserID
	// SelfV4 and SelfV6 are the addresses this peer knows the viewing node
	// as; the client masquerades its traffic to the peer from them.
	SelfV4 netip.Addr
	SelfV6 netip.Addr
}

// Full builds the first MapResponse of a session: everything a client needs to
// construct its netmap.
//
// nodes must include the requesting node; it is filtered out of Peers.
func Full(self state.Node, nodes []state.Node, cfg Config, online OnlineFunc, capVer tailcfg.CapabilityVersion) *tailcfg.MapResponse {
	routes := NewRouteTable(nodes)
	resp := &tailcfg.MapResponse{
		Node:          Node(self, true, online, routes, cfg),
		Peers:         peerNodes(self, nodes, online, routes, cfg),
		Domain:        cfg.Domain,
		DNSConfig:     DNSConfig(cfg, self),
		DERPMap:       cfg.DERPMap,
		UserProfiles:  userProfiles(self, nodes, cfg),
		SSHPolicy:     sshPolicyFor(cfg, self),
		ClientVersion: clientVersionFor(cfg, self),
		TKAInfo:       cfg.TKAInfo,
	}
	SetPacketFilters(resp, capVer, packetFilterFor(cfg, self))
	return resp
}

// Update builds a MapResponse for a netmap change.
//
// Only fields that can change are set: nil means "unchanged" on the client, so
// DNSConfig, DERPMap, Domain and the packet filter are left alone.
func Update(self state.Node, nodes []state.Node, cfg Config, online OnlineFunc) *tailcfg.MapResponse {
	routes := NewRouteTable(nodes)
	return &tailcfg.MapResponse{
		Node:          Node(self, true, online, routes, cfg),
		Peers:         peerNodes(self, nodes, online, routes, cfg),
		UserProfiles:  userProfiles(self, nodes, cfg),
		SSHPolicy:     sshPolicyFor(cfg, self),
		ClientVersion: clientVersionFor(cfg, self),
		TKAInfo:       cfg.TKAInfo,
	}
}

// clientVersionFor builds a node's client-version advisory, tolerating a nil
// hook.
func clientVersionFor(cfg Config, self state.Node) *tailcfg.ClientVersion {
	if cfg.ClientVersion == nil {
		return nil
	}
	return cfg.ClientVersion(self)
}

// sshPolicyFor builds a node's SSH policy, tolerating a nil hook.
func sshPolicyFor(cfg Config, self state.Node) *tailcfg.SSHPolicy {
	if cfg.SSHPolicyFor == nil {
		return nil
	}
	return cfg.SSHPolicyFor(self)
}

// RouteTable maps a served route prefix to the node elected to serve it.
//
// A route can be advertised by more than one node. The tailnet serves it
// through exactly one of them ("primary"), chosen deterministically as the
// lowest node ID so that every mapper instance in a cluster agrees. This is
// what upstream calls the primary route election; without it two routers would
// both claim the prefix and traffic would flap.
type RouteTable map[netip.Prefix]state.NodeID

// NewRouteTable elects a primary node for every effectively served route among
// nodes.
func NewRouteTable(nodes []state.Node) RouteTable {
	table := make(RouteTable)
	for _, n := range nodes {
		for _, r := range n.EffectiveRoutes() {
			if id, ok := table[r]; !ok || n.ID < id {
				table[r] = n.ID
			}
		}
	}
	return table
}

// Node converts a stored node into its wire representation.
//
// AllowedIPs carries the node's own addresses plus the routes it serves (the
// approved subset of what it advertises, minus prefixes another node is the
// elected primary for). PrimaryRoutes carries the served subnet routes only:
// exit routes reach the client through AllowedIPs and must not appear there,
// matching upstream.
func Node(n state.Node, self bool, online OnlineFunc, routes RouteTable, cfg Config) *tailcfg.Node {
	addresses := make([]netip.Prefix, 0, 2)
	if n.IPv4.IsValid() {
		addresses = append(addresses, netip.PrefixFrom(n.IPv4, n.IPv4.BitLen()))
	}
	if n.IPv6.IsValid() {
		addresses = append(addresses, netip.PrefixFrom(n.IPv6, n.IPv6.BitLen()))
	}

	allowed := slices.Clone(addresses)
	var primary []netip.Prefix
	for _, r := range n.EffectiveRoutes() {
		if id, ok := routes[r]; ok && id != n.ID {
			continue
		}
		allowed = append(allowed, r)
		if !state.IsExitRoute(r) {
			primary = append(primary, r)
		}
	}
	slices.SortFunc(allowed, netip.Prefix.Compare)

	expired := n.Expired(time.Now())

	out := &tailcfg.Node{
		ID:            tailcfg.NodeID(n.ID),
		StableID:      tailcfg.StableNodeID(n.StableID),
		Name:          n.FQDN(cfg.Domain),
		User:          nodeUserID(n),
		Key:           n.NodeKey,
		KeyExpiry:     n.Expiry,
		Expired:       expired,
		Machine:       n.MachineKey,
		DiscoKey:      n.DiscoKey,
		Addresses:     addresses,
		AllowedIPs:    allowed,
		PrimaryRoutes: primary,
		Endpoints:     slices.Clone(n.Endpoints),
		HomeDERP:      n.HomeDERP,
		Created:       n.Created,
		Cap:           n.CapVer,
		LastSeen:      n.LastSeen,
		Tags:          slices.Clone(n.Tags),
		KeySignature:  slices.Clone(n.KeySignature),
		// The client's ipn state machine reads this field to decide between
		// ipn.Running and ipn.NeedsMachineAuth ("Admin approval required");
		// a node only reaches the netmap after an administrator approved it,
		// so it is authorized until its key expires, as in headscale.
		MachineAuthorized: !expired,
	}

	if n.Hostinfo != nil {
		out.Hostinfo = n.Hostinfo.View()
	}

	if cfg.NodeCaps != nil {
		if caps := cfg.NodeCaps(n); len(caps) > 0 {
			out.CapMap = caps
		}
	}

	if share, ok := cfg.PeerShare[n.ID]; ok {
		out.Sharer = share.Sharer
		if share.SelfV4.IsValid() {
			addr := share.SelfV4
			out.SelfNodeV4MasqAddrForThisPeer = &addr
		}
		if share.SelfV6.IsValid() {
			addr := share.SelfV6
			out.SelfNodeV6MasqAddrForThisPeer = &addr
		}
	}

	// The requesting node is online by construction; peers are online when they
	// hold a live control session.
	out.Online = boolPtr(self || online(n.ID))

	return out
}

// peerNodes converts every node except self, sorted by ID as the wire requires.
func peerNodes(self state.Node, nodes []state.Node, online OnlineFunc, routes RouteTable, cfg Config) []*tailcfg.Node {
	out := make([]*tailcfg.Node, 0, len(nodes))
	for _, n := range nodes {
		if n.ID == self.ID {
			continue
		}
		peer := Node(n, false, online, routes, cfg)
		if cfg.UnsignedPeers[n.ID] {
			peer.UnsignedPeerAPIOnly = true
		}
		out = append(out, peer)
	}
	slices.SortFunc(out, func(a, b *tailcfg.Node) int {
		return int(a.ID) - int(b.ID)
	})
	return out
}

// userProfiles builds the profiles for the requesting node and its peers,
// sorted by user ID as the wire requires.
func userProfiles(self state.Node, nodes []state.Node, cfg Config) []tailcfg.UserProfile {
	seen := make(map[tailcfg.UserID]bool)
	out := make([]tailcfg.UserProfile, 0, len(nodes)+1)

	profile := cfg.UserProfile
	if profile == nil {
		profile = state.DefaultUserProfile
	}

	add := func(id tailcfg.UserID) {
		if id == TaggedDevicesUserID {
			if !seen[id] {
				seen[id] = true
				out = append(out, TaggedDevicesProfile())
			}
			return
		}
		if seen[id] {
			return
		}
		seen[id] = true
		out = append(out, profile(id))
	}

	add(nodeUserID(self))
	for _, n := range nodes {
		add(nodeUserID(n))
	}

	slices.SortFunc(out, func(a, b tailcfg.UserProfile) int {
		return int(a.ID) - int(b.ID)
	})
	return out
}

// nodeUserID maps a stored node to its wire owner: tagged nodes carry the
// reserved tagged-devices user instead of the user that owns their tags.
func nodeUserID(n state.Node) tailcfg.UserID {
	if len(n.Tags) > 0 {
		return TaggedDevicesUserID
	}
	return n.UserID
}

// certDomainsFor runs the CertDomainsFor hook, tolerating a nil one.
func certDomainsFor(cfg Config, self state.Node) []string {
	if cfg.CertDomainsFor == nil {
		return nil
	}
	return cfg.CertDomainsFor(self)
}

// DNSConfig builds the MagicDNS configuration, or nil when the tailnet has
// neither a domain nor a certificate service (nil means "unchanged"/"none" to
// the client).
//
// CertDomains advertises the names for which this control plane will answer
// ACME DNS-01 challenges: a client that runs "tailscale cert" POSTs the
// challenge record to /machine/set-dns, and the control plane writes it to the
// tailnet's public DNS zone. The hook returns nil when no external DNS
// provider is configured, so a client reports "not supported" instead of
// starting a challenge that could never be validated.
func DNSConfig(cfg Config, self state.Node) *tailcfg.DNSConfig {
	domain := strings.Trim(cfg.Domain, ".")
	certDomains := dedupeDomains(certDomainsFor(cfg, self))
	if domain == "" && len(certDomains) == 0 {
		return nil
	}

	out := &tailcfg.DNSConfig{
		Resolvers:   cfg.Resolvers,
		Routes:      cfg.Routes,
		CertDomains: certDomains,
	}
	if domain != "" {
		out.Domains = []string{domain}
		out.Proxied = true
	}
	for _, r := range cfg.ExtraRecords {
		out.ExtraRecords = append(out.ExtraRecords, tailcfg.DNSRecord{
			Name:  r.FQDN(),
			Type:  r.Type,
			Value: r.Value,
		})
	}
	return out
}

// dedupeDomains normalises, sorts and de-duplicates DNS names.
func dedupeDomains(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, d := range in {
		d = strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	slices.Sort(out)
	return out
}

// packetFilterFor returns the rules a node receives, defaulting to allow-all
// when the tailnet has no policy document.
//
// The result is always non-nil so that an empty policy is sent as "no rules"
// rather than "no change".
func packetFilterFor(cfg Config, self state.Node) []tailcfg.FilterRule {
	if cfg.FilterFor == nil {
		return slices.Clone(tailcfg.FilterAllowAll)
	}
	rules := cfg.FilterFor(self)
	if rules == nil {
		return []tailcfg.FilterRule{}
	}
	return rules
}

// SetPacketFilters attaches packet filter rules to a response using the field
// the client's capability version understands.
//
// rules must be non-nil: an empty non-nil slice means "block everything",
// while a nil slice would mean "no change" in an update frame.
func SetPacketFilters(resp *tailcfg.MapResponse, capVer tailcfg.CapabilityVersion, rules []tailcfg.FilterRule) {
	if capVer >= packetFiltersCapVer {
		resp.PacketFilters = map[string][]tailcfg.FilterRule{"base": rules}
		return
	}
	resp.PacketFilter = rules
}

func boolPtr(b bool) *bool { return &b }
