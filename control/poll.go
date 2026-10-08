package control

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"

	"github.com/xunara-net/xunara-server/control/mapper"
	"github.com/xunara-net/xunara-server/policy"
	"github.com/xunara-net/xunara-server/state"
)

// reservedResponseHeaderSize is the 4-byte little-endian length prefix that
// precedes every MapResponse on the wire.
const reservedResponseHeaderSize = 4

// keepAliveInterval is how often a keep-alive MapResponse is sent on a
// streaming (long-poll) map session.
const keepAliveInterval = 50 * time.Second

// errNodeNotInStore distinguishes an unknown node key from a node key presented
// with the wrong machine key. Both are answered 404, but only the former means
// the node is gone and the client should re-authenticate.
var errNodeNotInStore = errors.New("node not found")

// handleMap implements POST /machine/map inside a Noise session.
//
// This is the busiest endpoint: it carries endpoint/hostinfo updates (the "lite"
// update) and maintains the long poll that pushes netmap changes.
func (ns *noiseServer) handleMap(w http.ResponseWriter, req *http.Request) {
	var mapRequest tailcfg.MapRequest
	if err := json.NewDecoder(req.Body).Decode(&mapRequest); err != nil {
		httpError(w, err)
		return
	}

	if ns.rejectUnsupported(w, mapRequest.Version, mapRequest.NodeKey) {
		return
	}

	node, err := ns.getAndValidateNode(mapRequest)
	if err != nil {
		// A streaming client whose node is gone needs a signalled "expired"
		// response to drive it back to NeedsLogin; there is no explicit
		// "deleted" field. See tailscale/tailscale#14636 semantics via
		// reference/headscale/hscontrol/noise.go.
		if errors.Is(err, errNodeNotInStore) && mapRequest.Stream {
			expired := &tailcfg.MapResponse{
				Node: &tailcfg.Node{
					Key:       mapRequest.NodeKey,
					KeyExpiry: time.Unix(1, 0).UTC(),
					Expired:   true,
				},
			}
			if werr := writeMapResponse(w, mapRequest.Compress, true, expired); werr != nil {
				ns.server.log.Warn("writing expired map response", "err", werr)
			}
			return
		}
		httpError(w, err)
		return
	}

	// Persist anything the request advertises about the node.
	node = ns.server.recordMapRequest(node, mapRequest)

	// Lite update: the client wants its endpoints refreshed without a new
	// netmap. It only checks the status code.
	if !mapRequest.Stream && mapRequest.OmitPeers {
		w.WriteHeader(http.StatusOK)
		return
	}

	if mapRequest.Stream {
		ns.serveStreamingMap(req.Context(), w, node, mapRequest)
		return
	}

	if err := writeMapResponse(w, mapRequest.Compress, true, ns.server.fullMap(node, mapRequest)); err != nil {
		ns.server.log.Warn("writing map response", "err", err)
	}
}

// serveStreamingMap sends the initial netmap and then pushes a fresh netmap on
// every change, interleaved with keep-alives, until the client goes away.
func (ns *noiseServer) serveStreamingMap(ctx context.Context, w http.ResponseWriter, node state.Node, req tailcfg.MapRequest) {
	s := ns.server

	s.markOnline(node)
	defer s.markOffline(node)

	updates, cancel := s.watch()
	defer cancel()

	sess, err := newMapSession()
	if err != nil {
		s.log.Error("creating map session", "err", err)
		return
	}

	// The first frame is always the full netmap; later frames are deltas
	// against it (PeersChanged/PeersRemoved).
	initial := s.fullMap(node, req)
	sess.initial(initial)
	if err := writeMapResponse(w, req.Compress, true, initial); err != nil {
		s.log.Debug("writing initial map response", "err", err)
		return
	}

	ticker := time.NewTicker(keepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			if err := writeMapResponse(w, req.Compress, true, &tailcfg.MapResponse{KeepAlive: true}); err != nil {
				return
			}

		case <-updates:
			self, ok := s.store.GetNodeByID(node.ID)
			if !ok {
				return
			}
			msg := s.updateMap(self)
			peers := msg.Peers
			selfNode := msg.Node
			changed := sess.diff(msg, peers)
			if sess.syncDNS(msg, s.dnsConfigFor(self)) {
				changed = true
			}
			if sess.syncPacketFilter(msg, s.packetFilterFor(self), req.Version) {
				changed = true
			}
			if sess.syncClientVersion(msg) {
				changed = true
			}
			if sess.syncTKA(msg) {
				changed = true
			}
			if !changed {
				// Nothing the client can observe changed (for example a
				// keep-alive woke us); sending a frame would only burn battery.
				continue
			}
			if req.OmitPeers {
				msg.Peers = nil
				msg.PeersChanged = nil
				msg.PeersChangedPatch = nil
				msg.PeersRemoved = nil
			}
			sess.commit(msg, selfNode, peers)
			if err := writeMapResponse(w, req.Compress, true, msg); err != nil {
				return
			}
		}
	}
}

// packetFilterFor returns the packet filter a node receives: the compiled ACL
// policy when the tailnet has one, allow-all otherwise.
//
// While tailnet lock is enforced the filter must not name an unsigned peer as
// a source; clients reject such a filter wholesale and block everything.
func (s *Server) packetFilterFor(self state.Node) []tailcfg.FilterRule {
	return s.packetFilterForNodes(self, s.netmapNodes(self))
}

// packetFilterForNodes compiles the filter against an explicit node set, so
// one netmap build resolves the share namespace once.
func (s *Server) packetFilterForNodes(self state.Node, nodes []state.Node) []tailcfg.FilterRule {
	engine := s.policy.Load()

	var rules []tailcfg.FilterRule
	if engine == nil {
		rules = slices.Clone(tailcfg.FilterAllowAll)
	} else {
		rules = engine.FilterFor(self, nodes)
		if rules == nil {
			// A policy that grants nothing must still be sent explicitly, or the
			// client keeps the rules it had.
			return []tailcfg.FilterRule{}
		}
	}
	return restrictFilterToSignedPeers(rules, s.unsignedPeers(nodes), nodes)
}

// netmapNodes is the node set one netmap build sees: this organization's own
// nodes plus the foreign peers Xunara Share exposes to self (spec section 38).
func (s *Server) netmapNodes(self state.Node) []state.Node {
	return s.netmapNodesFor(self, s.sharePeersFor(self))
}

// netmapNodesFor is [Server.netmapNodes] with an already-resolved share
// addition, avoiding a second allocation pass per build.
func (s *Server) netmapNodesFor(self state.Node, shares *shareNetmap) []state.Node {
	nodes := s.store.ListNodes()
	if shares != nil {
		nodes = append(nodes, shares.nodes...)
	}
	return nodes
}

// fullMap builds the first netmap for a node: everything a client needs.
func (s *Server) fullMap(self state.Node, req tailcfg.MapRequest) *tailcfg.MapResponse {
	shares := s.sharePeersFor(self)
	nodes := s.netmapNodesFor(self, shares)
	cfg := s.mapperConfigFor(shares)
	cfg.FilterFor = func(self state.Node) []tailcfg.FilterRule { return s.packetFilterForNodes(self, nodes) }
	cfg.ExtraRecords = s.extraDNSRecordsFor(self)
	resp := mapper.Full(self, nodes, cfg, shares.onlineFunc(s.isOnline), req.Version)
	if req.OmitPeers {
		resp.Peers = nil
	}
	return resp
}

// updateMap builds a netmap update for a node: only the fields that can change.
func (s *Server) updateMap(self state.Node) *tailcfg.MapResponse {
	shares := s.sharePeersFor(self)
	nodes := s.netmapNodesFor(self, shares)
	return mapper.Update(self, nodes, s.mapperConfigFor(shares), shares.onlineFunc(s.isOnline))
}

// mapperConfig snapshots the tailnet-wide configuration for one netmap build.
func (s *Server) mapperConfig() mapper.Config {
	return s.mapperConfigFor(nil)
}

// mapperConfigFor is [mapperConfig] with the share addition of one netmap
// build folded in. A nil addition is a purely local netmap.
func (s *Server) mapperConfigFor(shares *shareNetmap) mapper.Config {
	cfg := mapper.Config{
		Domain:         s.cfg.Domain,
		Resolvers:      s.resolvers,
		Routes:         s.dnsRoutes,
		CertDomainsFor: s.certDomainsFor,
		DERPMap:        s.derpMap,
		FilterFor:      s.packetFilterFor,
		UserProfile:    s.UserProfile,
		SSHPolicyFor:   s.sshPolicyFor,
		NodeCaps:       s.nodeCapsFunc(),
		ClientVersion:  s.clientVersionFor(),
		TKAInfo:        s.tkaInfo(),
		UnsignedPeers:  s.unsignedPeers(s.store.ListNodes()),
	}
	if shares != nil {
		cfg.PeerShare = shares.peers
		cfg.UserProfile = shares.profileFunc(s.UserProfile)
	}
	return cfg
}

// dnsConfigFor builds the DNS configuration of one node. Only the Atlas
// service records depend on the viewer (section 46); everything else is
// tailnet-wide.
func (s *Server) dnsConfigFor(self state.Node) *tailcfg.DNSConfig {
	cfg := s.mapperConfig()
	cfg.ExtraRecords = s.extraDNSRecordsFor(self)
	return mapper.DNSConfig(cfg, self)
}

// extraDNSRecordsFor returns the records published through MagicDNS to one
// node: administrator- and ACME-created records, plus the services that node
// may discover. ACME challenge records are excluded: only the public
// certificate authority needs them, and they can live outside the tailnet
// domain.
func (s *Server) extraDNSRecordsFor(self state.Node) []state.DNSRecord {
	records := s.store.ListDNSRecords()
	out := records[:0:0]
	for _, r := range records {
		if isACMEChallengeName(r.Name) {
			continue
		}
		out = append(out, r)
	}
	// Services a node advertises about itself (Xunara Atlas) resolve through
	// MagicDNS to the node that publishes them; the records are derived from
	// the registry rather than stored, so a withdrawal removes them.
	out = append(out, s.serviceDNSRecordsFor(self)...)
	// Services shared from another organization resolve to this
	// organization's masquerade address for the advertising machine
	// (section 47); they are projection, never stored, so revoking the share
	// removes them.
	return append(out, s.sharedServiceDNSRecordsFor(self)...)
}

// clientVersionFor builds the client-version advisory from the configured
// latest version and the version each node reported in its Hostinfo. It
// returns nil when the feature is disabled or the node's version is unknown.
//
// The comparison is on the short version ("1.88.3"), so a client running
// "1.88.3-t1234abcd" matches and gets RunningLatest.
func (s *Server) clientVersionFor() func(state.Node) *tailcfg.ClientVersion {
	latest := shortVersion(s.cfg.LatestClientVersion)
	if latest == "" {
		return nil
	}
	return func(n state.Node) *tailcfg.ClientVersion {
		if n.Hostinfo == nil || shortVersion(n.Hostinfo.IPNVersion) == "" {
			// The node never told us what it runs; advising would be a guess.
			return nil
		}
		if shortVersion(n.Hostinfo.IPNVersion) == latest {
			return &tailcfg.ClientVersion{RunningLatest: true}
		}
		return &tailcfg.ClientVersion{
			LatestVersion: latest,
			Notify:        true,
			NotifyURL:     s.cfg.ClientVersionURL,
			NotifyText:    "A newer Tailscale client (" + latest + ") is available.",
		}
	}
}

// shortVersion strips the build suffix from a Tailscale version string, so
// "1.88.3-t1234abcd" and "1.88.3" compare equal.
func shortVersion(v string) string {
	short, _, _ := strings.Cut(v, "-")
	return strings.TrimSpace(short)
}

// sshPolicyFor compiles the SSH policy for a node as an SSH destination.
func (s *Server) sshPolicyFor(self state.Node) *tailcfg.SSHPolicy {
	engine := s.policy.Load()
	if engine == nil {
		return nil
	}
	return engine.CompileSSHPolicy(self, s.store.ListNodes())
}

// nodeCapsFunc snapshots the capabilities each node advertises: the policy's
// nodeAttrs grants, tailscale.com/cap/ssh for the nodes the SSH policy names
// as destinations, and tailscale.com/cap/tailnet-lock once the tailnet has a
// key authority. Nil when the tailnet grants no capabilities at all.
func (s *Server) nodeCapsFunc() func(state.Node) tailcfg.NodeCapMap {
	return nodeCapsAdvertiser(s.policy.Load(), s.store.ListNodes(), s.tkaInfo() != nil)
}

// nodeCapMap returns the capability map for one node, for handlers that need
// the same view the netmap advertises (feature queries).
func (s *Server) nodeCapMap(node state.Node) tailcfg.NodeCapMap {
	advertise := nodeCapsAdvertiser(s.policy.Load(), s.store.ListNodes(), s.tkaInfo() != nil)
	if advertise == nil {
		return nil
	}
	return advertise(node)
}

// nodeCapsAdvertiser compiles the policy into a per-node capability lookup.
// It returns nil when the tailnet grants no capabilities at all, which lets
// the mapper omit CapMap entirely.
//
// tailnetLock adds tailscale.com/cap/tailnet-lock to every node once the
// tailnet has a key authority: official clients only run their
// /machine/tka* synchronization loop when the netmap self node carries it.
func nodeCapsAdvertiser(engine *policy.Engine, nodes []state.Node, tailnetLock bool) func(state.Node) tailcfg.NodeCapMap {
	if engine == nil && !tailnetLock {
		return nil
	}

	var grants map[state.NodeID]tailcfg.NodeCapMap
	var sshDests map[state.NodeID]bool
	if engine != nil {
		grants = engine.NodeCapMaps(nodes)
		sshDests = engine.SSHDestinations(nodes)
	}

	return func(n state.Node) tailcfg.NodeCapMap {
		caps := grants[n.ID]
		sshDest := sshDests[n.ID]
		if !tailnetLock && !sshDest {
			return caps
		}
		// Copy so the snapshot stays immutable and safe to reuse across the
		// nodes of one netmap build.
		merged := make(tailcfg.NodeCapMap, len(caps)+2)
		for name, value := range caps {
			merged[name] = value
		}
		if tailnetLock {
			merged[tailcfg.CapabilityTailnetLock] = nil
		}
		if sshDest {
			merged[tailcfg.CapabilitySSH] = nil
		}
		return merged
	}
}

// getAndValidateNode looks the node up by node key and confirms the Noise
// session's machine key matches the stored one (identity binding).
func (ns *noiseServer) getAndValidateNode(req tailcfg.MapRequest) (state.Node, error) {
	node, ok := ns.server.store.GetNodeByNodeKey(req.NodeKey)
	if !ok {
		return state.Node{}, NewHTTPError(http.StatusNotFound, "node not found", errNodeNotInStore)
	}
	if node.MachineKey != ns.machineKey {
		return state.Node{}, NewHTTPError(http.StatusNotFound, "machine key does not match node", nil)
	}
	return node, nil
}

// recordMapRequest persists the node facts a MapRequest advertises, wakes
// netmap watchers when something actually changed, and returns the updated
// node.
func (s *Server) recordMapRequest(node state.Node, req tailcfg.MapRequest) state.Node {
	changed := false

	if req.Version != 0 && req.Version != node.CapVer {
		node.CapVer = req.Version
		changed = true
	}
	if !req.DiscoKey.IsZero() && node.DiscoKey != req.DiscoKey {
		node.DiscoKey = req.DiscoKey
		changed = true
	}
	if len(req.Endpoints) > 0 && !slices.Equal(node.Endpoints, req.Endpoints) {
		node.Endpoints = slices.Clone(req.Endpoints)
		changed = true
	}
	if req.Hostinfo != nil {
		hi := *req.Hostinfo
		// Clients only send NetInfo when it changed. Carrying the stored value
		// over keeps PreferredDERP (hence the node's HomeDERP input) from being
		// clobbered by a routine update. Mirrors
		// reference/headscale/hscontrol/state/maprequest.go:netInfoFromMapRequest.
		if hi.NetInfo == nil && node.Hostinfo != nil {
			hi.NetInfo = node.Hostinfo.NetInfo
		}
		if !node.Hostinfo.Equal(&hi) {
			node.Hostinfo = &hi
			if hi.Hostname != "" {
				node.Hostname = hi.Hostname
			}
			changed = true
		}
	}
	// A node homed in a region the organization no longer serves (the policy
	// changed) is re-homed; leaving it there would advertise a peer DERP
	// home that no client can reach.
	if node.HomeDERP != 0 && !s.derpRegionKnown(node.HomeDERP) {
		node.HomeDERP = 0
		changed = true
	}
	if node.Hostinfo != nil && node.Hostinfo.NetInfo != nil {
		if region := node.Hostinfo.NetInfo.PreferredDERP; region != 0 && region != node.HomeDERP && s.derpRegionKnown(region) {
			// Home DERP selection is delegated to the client: it measures DERP
			// latency and reports the winner, and the control plane adopts it
			// (mirrors headscale's mapper, which publishes
			// NetInfo.PreferredDERP as the node's HomeDERP). The report is
			// untrusted input, so only regions this server advertises count.
			node.HomeDERP = region
			changed = true
		}
	}
	if node.HomeDERP == 0 {
		if region, ok := s.singleDERPRegion(); ok {
			node.HomeDERP = region
			changed = true
		}
	}

	if !changed {
		return node
	}
	if err := s.store.UpdateNode(node); err != nil {
		s.log.Warn("updating node from map request", "node_id", int(node.ID), "err", err)
		return node
	}
	s.notifyNodePeers(node)
	return node
}

// singleDERPRegion returns the served DERP region when the tailnet has exactly
// one, so nodes can be homed without a latency hunt.
func (s *Server) singleDERPRegion() (tailcfg.DERPRegionID, bool) {
	m := s.derpMap
	if m == nil || len(m.Regions) != 1 {
		return 0, false
	}
	for id := range m.Regions {
		return id, true
	}
	return 0, false
}

// derpRegionKnown reports whether a DERP region is part of the DERP map this
// organization serves. A region the policy filtered out is not known, so it is
// neither adopted as a home region nor admitted to DERP.
func (s *Server) derpRegionKnown(region tailcfg.DERPRegionID) bool {
	m := s.derpMap
	if m == nil {
		return false
	}
	r, ok := m.Regions[region]
	return ok && r != nil
}

// writeMapResponse writes a length-prefixed (optionally zstd-compressed)
// MapResponse.
func writeMapResponse(w http.ResponseWriter, compress string, flush bool, msg *tailcfg.MapResponse) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	if compress == "zstd" {
		body = zstdframe.AppendEncode(nil, body, zstdframe.FastestCompression)
	}

	data := make([]byte, reservedResponseHeaderSize, reservedResponseHeaderSize+len(body))
	// The JSON/zstd body length is bounded by the request body limit; the cast
	// is safe.
	binary.LittleEndian.PutUint32(data, uint32(len(body)))
	data = append(data, body...)

	if _, err := w.Write(data); err != nil {
		return err
	}

	if flush {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}

	return nil
}
