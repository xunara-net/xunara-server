package control

import (
	"fmt"
	"slices"
	"strings"

	"tailscale.com/tailcfg"
	"tailscale.com/util/dnsname"

	"github.com/xunara-net/xunara-server/control/mapper"
	"github.com/xunara-net/xunara-server/state"
)

// Xunara Share netmap exposure (PROJECT_SPEC section 38.4).
//
// A shared-in node is presented with this organization's own synthetic node
// ID, its own synthetic user IDs and its own masquerade addresses; the foreign
// side presents the sharee's nodes the same way. Both sides derive the
// WireGuard-visible addresses from the same pair of allocations, so the
// official client's tstun/router masquerade path (SelfNodeV4/V6MasqAddrForThisPeer)
// carries the traffic without either organization learning the other's real
// addresses.

// shareNetmap is the foreign-peer addition to one node's netmap.
type shareNetmap struct {
	// nodes are the foreign peers, already carrying synthetic IDs, synthetic
	// owners and masquerade addresses.
	nodes []state.Node
	// peers carries the mapper hints for those nodes.
	peers map[state.NodeID]mapper.PeerShare
	// profiles are the synthesized profiles the netmap must include.
	profiles map[tailcfg.UserID]tailcfg.UserProfile
	// online is the foreign liveness the mapper's OnlineFunc cannot know.
	online map[state.NodeID]bool
}

// profileFunc wraps the local profile lookup with the synthesized profiles.
func (sn *shareNetmap) profileFunc(base func(tailcfg.UserID) tailcfg.UserProfile) func(tailcfg.UserID) tailcfg.UserProfile {
	if sn == nil || len(sn.profiles) == 0 {
		return base
	}
	return func(id tailcfg.UserID) tailcfg.UserProfile {
		if profile, ok := sn.profiles[id]; ok {
			return profile
		}
		return base(id)
	}
}

// onlineFunc wraps the local liveness lookup with the foreign liveness.
func (sn *shareNetmap) onlineFunc(base mapper.OnlineFunc) mapper.OnlineFunc {
	if sn == nil || len(sn.online) == 0 {
		return base
	}
	return func(id state.NodeID) bool {
		if online, ok := sn.online[id]; ok {
			return online
		}
		return base(id)
	}
}

// sharePeersFor builds the foreign peers visible to self: the machines shared
// with self's user (inbound) and, when self is a shared machine itself, the
// nodes of every user who accepted a share of it (outbound).
//
// Sharing is disabled while either organization enforces tailnet lock
// (spec 38.5): a foreign node has no signature this tailnet can verify.
func (s *Server) sharePeersFor(self state.Node) *shareNetmap {
	if !s.sharingEnabled() || self.Tags != nil || s.TKAStatus().Enabled {
		return nil
	}
	orgID := s.Organization().ID
	if orgID == "" {
		return nil
	}

	sn := &shareNetmap{
		peers:    make(map[state.NodeID]mapper.PeerShare),
		profiles: make(map[tailcfg.UserID]tailcfg.UserProfile),
		online:   make(map[state.NodeID]bool),
	}

	// Inbound: machines shared with this user.
	for _, share := range s.shares.ListShares(ShareFilter{
		TargetOrg:  orgID,
		TargetUser: int64(self.UserID),
		Statuses:   []string{ShareAccepted},
	}) {
		source := s.shareDir.Org(share.SourceOrg)
		if source == nil || source.ShareTKAEnabled() {
			continue
		}
		node, ok := source.ShareNode(state.NodeID(share.SourceNode))
		if !ok {
			continue
		}
		s.addForeignNode(sn, self, share.SourceOrg, node, share.CreatedBy, false, source)
	}

	// Outbound: this machine is shared, so its netmap learns the sharees'
	// nodes (otherwise the sharee could never receive a response).
	for _, share := range s.shares.ListShares(ShareFilter{
		SourceOrg:  orgID,
		SourceNode: int64(self.ID),
		Statuses:   []string{ShareAccepted},
	}) {
		target := s.shareDir.Org(share.TargetOrg)
		if target == nil || target.ShareTKAEnabled() {
			continue
		}
		for _, node := range target.ShareNodesOfUser(tailcfg.UserID(share.AcceptedBy)) {
			s.addForeignNode(sn, self, share.TargetOrg, node, share.AcceptedBy, true, target)
		}
	}

	if len(sn.nodes) == 0 {
		return nil
	}
	return sn
}

// addForeignNode appends one foreign node to the netmap addition, allocating
// (or reusing) the synthetic identifiers and masquerade addresses both sides
// need. A node that cannot be allocated for is skipped, never half-added: an
// unallocated peer would be unreachable or ambiguous.
func (s *Server) addForeignNode(sn *shareNetmap, self state.Node, remoteOrg string, node state.Node, sharerRemote int64, shareeNode bool, remote ShareOrg) {
	logf := func(step string, err error) {
		s.log.Warn("sharing: preparing a foreign peer", "org", remoteOrg, "step", step, "err", err)
	}

	syntheticID, err := s.store.EnsureShareNode(remoteOrg, shareNodeKey(node))
	if err != nil {
		logf("node id", err)
		return
	}
	ownerRemote := shareOwner(node)
	ownerSynthetic, err := s.identity.EnsureShareUser(remoteOrg, shareUserKey(ownerRemote))
	if err != nil {
		logf("owner id", err)
		return
	}

	sharerSynthetic := tailcfg.UserID(0)
	if sharerRemote != 0 && tailcfg.UserID(sharerRemote) != ownerRemote {
		sharerSynthetic, err = s.identity.EnsureShareUser(remoteOrg, shareUserKey(tailcfg.UserID(sharerRemote)))
		if err != nil {
			logf("sharer id", err)
			return
		}
	}

	// This organization's masquerade address for the foreign node...
	masqV4, masqV6, err := s.store.EnsureShareAddress(remoteOrg, shareNodeKey(node))
	if err != nil {
		logf("local masquerade", err)
		return
	}
	// ...and the foreign organization's masquerade address for self, which is
	// what self's traffic to the peer must be sourced from.
	selfV4, selfV6, err := remote.ShareEnsureAddress(s.Organization().ID, shareNodeKey(self))
	if err != nil {
		logf("remote masquerade", err)
		return
	}

	foreign := state.Node{
		ID:        syntheticID,
		StableID:  shareStableID(remoteOrg, node.StableID),
		UserID:    ownerSynthetic,
		Hostname:  shareHostname(node.Hostname, remoteOrg),
		DNSName:   shareHostname(strings.TrimSuffix(node.FQDN(""), "."), remoteOrg),
		IPv4:      masqV4,
		IPv6:      masqV6,
		Endpoints: slices.Clone(node.Endpoints),
		HomeDERP:  node.HomeDERP,
		CapVer:    node.CapVer,
		Hostinfo:  shareHostinfo(node.Hostinfo, shareeNode),
		LastSeen:  node.LastSeen,
		Expiry:    node.Expiry,
		Created:   node.Created,
		Method:    node.Method,
	}

	sn.nodes = append(sn.nodes, foreign)
	sn.peers[syntheticID] = mapper.PeerShare{
		Sharer: sharerSynthetic,
		SelfV4: selfV4,
		SelfV6: selfV6,
	}
	sn.profiles[ownerSynthetic] = s.shareUserProfile(remote, remoteOrg, ownerRemote, ownerSynthetic)
	if sharerSynthetic != 0 {
		sn.profiles[sharerSynthetic] = s.shareUserProfile(remote, remoteOrg, tailcfg.UserID(sharerRemote), sharerSynthetic)
	}
	sn.online[syntheticID] = remote.ShareOnline(node.ID)
}

// shareStableID namespaces a foreign node's stable ID. Stable IDs are random,
// but the namespace prefix makes it impossible to mistake a shared-in node for
// a local one in logs, cursors and support requests.
func shareStableID(remoteOrg, stableID string) string {
	return "share:" + remoteOrg + ":" + stableID
}

// shareOwner maps a foreign node to its wire owner. Tags never cross the
// share boundary (spec 38.4), so the synthetic peer is always owned by the
// foreign node's user, never by the reserved tagged-devices user.
func shareOwner(node state.Node) tailcfg.UserID {
	return node.UserID
}

// shareHostname namespaces a foreign node's MagicDNS name. The local sanitizer
// turns the whole string into one label, so "<host>-<org>" is both unique per
// source organization and impossible to confuse with a local hostname.
func shareHostname(hostname, remoteOrg string) string {
	host := dnsname.SanitizeLabel(hostname)
	if host == "" {
		host = "node"
	}
	org := dnsname.SanitizeLabel(remoteOrg)
	if org == "" {
		org = "org"
	}
	const maxLabel = 63
	suffix := "-" + org
	// Keep the organization hint if at all possible, but never slice past the
	// label limit: sanitized names are ASCII, so byte lengths are stable.
	if len(suffix) > maxLabel-4 {
		org = org[:maxLabel-5]
		suffix = "-" + org
	}
	if room := maxLabel - len(suffix); len(host) > room {
		host = strings.Trim(host[:room], "-")
		if host == "" {
			host = "node"
		}
	}
	return host + suffix
}

// shareHostinfo clones the display-relevant part of a foreign node's host
// info, marking it as a sharee node when that is what it is (the sharer's side
// hides those from `tailscale status` by default).
//
// The clone is a whitelist, not a copy: a Hostinfo carries fields that must
// not cross a tenant boundary — NetInfo (interface addresses), SSH host keys,
// advertised services, Wake-on-LAN MACs, routable prefixes, requested tags,
// location, cloud and logtail identifiers — and new upstream fields default
// to stripped rather than leaked (AGENTS.md sections 12 and 18).
func shareHostinfo(hostinfo *tailcfg.Hostinfo, shareeNode bool) *tailcfg.Hostinfo {
	if hostinfo == nil {
		if !shareeNode {
			return nil
		}
		return &tailcfg.Hostinfo{ShareeNode: true}
	}
	return &tailcfg.Hostinfo{
		IPNVersion:      hostinfo.IPNVersion,
		OS:              hostinfo.OS,
		OSVersion:       hostinfo.OSVersion,
		Distro:          hostinfo.Distro,
		DistroVersion:   hostinfo.DistroVersion,
		DistroCodeName:  hostinfo.DistroCodeName,
		App:             hostinfo.App,
		Package:         hostinfo.Package,
		DeviceModel:     hostinfo.DeviceModel,
		Hostname:        hostinfo.Hostname,
		ShieldsUp:       hostinfo.ShieldsUp,
		NoLogsNoSupport: hostinfo.NoLogsNoSupport,
		Machine:         hostinfo.Machine,
		GoArch:          hostinfo.GoArch,
		GoArchVar:       hostinfo.GoArchVar,
		GoVersion:       hostinfo.GoVersion,
		Userspace:       hostinfo.Userspace,
		StateEncrypted:  hostinfo.StateEncrypted,
		ShareeNode:      shareeNode,
	}
}

// shareUserProfile synthesizes the profile of a foreign user. Display names
// cross the tenant boundary (that is what makes sharing legible); login names,
// emails and avatars do not: the login name is a synthetic, non-routable
// label.
func (s *Server) shareUserProfile(remote ShareOrg, remoteOrg string, remoteUser, synthetic tailcfg.UserID) tailcfg.UserProfile {
	display := fmt.Sprintf("User %d", remoteUser)
	if remote != nil {
		if user, ok := remote.ShareUser(remoteUser); ok && user.DisplayName != "" {
			display = user.DisplayName
		}
	}
	return tailcfg.UserProfile{
		ID:          synthetic,
		LoginName:   fmt.Sprintf("shared+%s+%d@xunara.invalid", remoteOrg, remoteUser),
		DisplayName: display,
	}
}
