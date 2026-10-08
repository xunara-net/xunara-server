package control

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"slices"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/control/mapper"
)

// mapSession tracks what a streaming client has already been told about the
// tailnet, so later frames can be delta-encoded instead of resending every
// peer.
//
// It also owns the session identity: MapSessionHandle (sent once, on the first
// frame) and the monotonic Seq that a client echoes back in
// MapRequest.MapSessionSeq when it reattaches.
type mapSession struct {
	handle string
	seq    int64

	self  *tailcfg.Node
	peers map[tailcfg.NodeID]*tailcfg.Node

	// dns fingerprints the DNS configuration this session already sent. The
	// netmap update path normally omits DNSConfig (it forces clients into a
	// full rebuild), so it is added back only when it actually changed.
	dns string

	// filter fingerprints the packet filter this session already sent, for the
	// same reason as dns.
	filter string

	// clientVersion fingerprints the update advisory this session already
	// sent. Like DNSConfig, ClientVersion forces a client-side rebuild, so it
	// is attached only when it actually changed.
	clientVersion string

	// tka fingerprints the tailnet-lock state this session already sent. It
	// is attached only when it changed, because nil means "unchanged" and a
	// repeated or absent value would leave clients stuck on stale state.
	tka string
}

// newMapSession starts a session with a fresh opaque handle.
//
// Xunara does not resume a previous session's sequence across connections: a
// client that reattaches always receives a fresh handle and a full netmap,
// which tailcfg.MapResponse explicitly allows ("the server may choose to
// ignore the request for any reason and start a new map session").
func newMapSession() (*mapSession, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return &mapSession{handle: hex.EncodeToString(b[:])}, nil
}

// initial stamps resp as the first frame of the session: it carries the full
// netmap and the handle, so the client can tell a resumed session from a fresh
// one.
func (s *mapSession) initial(resp *tailcfg.MapResponse) {
	s.record(resp.Node, peersOf(resp))
	s.dns = fingerprintDNS(resp.DNSConfig)
	s.filter = fingerprintFilter(filterFromResponse(resp))
	s.clientVersion = fingerprintClientVersion(resp.ClientVersion)
	s.tka = fingerprintTKA(resp.TKAInfo)

	s.seq = 1
	resp.MapSessionHandle = s.handle
	resp.Seq = s.seq
}

// diff rewrites resp's peer fields as a delta against what this session already
// sent, and reports whether the frame carries anything a client can observe.
//
// The caller stamps the frame with [mapSession.commit] once it knows the frame
// carries something, which may also be a DNS change rather than a peer change.
//
// Existing peers whose differences all fit a tailcfg.PeerChange are promoted to
// PeersChangedPatch; peers with structural changes (name, addresses, hostinfo,
// tags, ...) are resent in full through PeersChanged, and peers this session has
// not shown yet are added the same way. An unchanged self node is omitted: any
// node-shaped field would make every client rebuild its whole netmap.
func (s *mapSession) diff(resp *tailcfg.MapResponse, peers []*tailcfg.Node) bool {
	var added, changed []*tailcfg.Node
	seen := make(map[tailcfg.NodeID]bool, len(peers))
	for _, p := range peers {
		seen[p.ID] = true
		old, ok := s.peers[p.ID]
		if !ok {
			added = append(added, p)
			continue
		}
		if !old.Equal(p) {
			changed = append(changed, p)
		}
	}

	var removed []tailcfg.NodeID
	for id := range s.peers {
		if !seen[id] {
			removed = append(removed, id)
		}
	}
	slices.Sort(removed)

	// Nil means "unchanged" on the wire for every delta field.
	resp.Peers, resp.PeersChanged, resp.PeersChangedPatch, resp.PeersRemoved = nil, nil, nil, nil

	observable := false
	switch {
	case len(added) == 0 && len(changed) == 0 && len(removed) == 0:
		// Nothing peer-shaped changed.
	case len(removed) == 0 && len(changed) == 0 && len(added) > 0 && len(added) == len(peers):
		// Every peer is new to this session: the plain list is both smaller
		// and unambiguous, exactly as on the first frame. A non-empty Peers
		// makes clients ignore the delta fields, so it can never carry
		// PeersRemoved alongside.
		resp.Peers = peers
		observable = true
	default:
		resp.PeersRemoved = removed
		resp.PeersChanged = added
		for _, p := range changed {
			pc, patchable := peerChangeDiff(s.peers[p.ID], p)
			if !patchable {
				resp.PeersChanged = append(resp.PeersChanged, p)
				continue
			}
			if pc != nil {
				resp.PeersChangedPatch = append(resp.PeersChangedPatch, pc)
			}
			// patchable with a nil change means the difference is invisible
			// to clients (for example client-computed display names), so it
			// is dropped rather than sent.
		}
		slices.SortFunc(resp.PeersChanged, func(a, b *tailcfg.Node) int {
			return int(a.ID) - int(b.ID)
		})
		if len(resp.PeersChanged) == 0 {
			resp.PeersChanged = nil
		}
		observable = len(resp.PeersChanged) > 0 || len(resp.PeersChangedPatch) > 0 || len(resp.PeersRemoved) > 0
	}

	selfChanged := s.self == nil || (resp.Node != nil && !s.self.Equal(resp.Node))
	if !selfChanged {
		resp.Node = nil
	}
	return selfChanged || observable
}

// syncDNS attaches dns to resp when it differs from what this session already
// sent, and reports whether it did.
func (s *mapSession) syncDNS(resp *tailcfg.MapResponse, dns *tailcfg.DNSConfig) bool {
	fp := fingerprintDNS(dns)
	if fp == s.dns {
		return false
	}
	s.dns = fp
	resp.DNSConfig = dns
	return true
}

// syncPacketFilter attaches rules to resp when they differ from what this
// session already sent, and reports whether it did.
func (s *mapSession) syncPacketFilter(resp *tailcfg.MapResponse, rules []tailcfg.FilterRule, capVer tailcfg.CapabilityVersion) bool {
	fp := fingerprintFilter(rules)
	if fp == s.filter {
		return false
	}
	s.filter = fp
	mapper.SetPacketFilters(resp, capVer, rules)
	return true
}

// syncClientVersion attaches the update advisory when it differs from what
// this session already sent, and clears it otherwise. ClientVersion is one of
// the fields that make clients rebuild their whole netmap, so a repeated
// advisory would defeat the incremental path.
func (s *mapSession) syncClientVersion(resp *tailcfg.MapResponse) bool {
	fp := fingerprintClientVersion(resp.ClientVersion)
	if fp == s.clientVersion {
		resp.ClientVersion = nil
		return false
	}
	s.clientVersion = fp
	if resp.ClientVersion == nil {
		// nil means "unchanged", so a withdrawn advisory cannot be expressed;
		// there is nothing to send.
		return false
	}
	return true
}

// syncTKA attaches the tailnet-lock state when it differs from what this
// session already sent, and clears it otherwise.
//
// The three states (absent, enabled with a head, explicitly disabled) must be
// distinguishable on the wire: nil means "no change", so a tailnet that went
// from enabled to disabled has to send Disabled: true rather than nothing.
func (s *mapSession) syncTKA(resp *tailcfg.MapResponse) bool {
	fp := fingerprintTKA(resp.TKAInfo)
	if fp == s.tka {
		resp.TKAInfo = nil
		return false
	}
	s.tka = fp
	return resp.TKAInfo != nil
}

// commit stamps a frame that is about to be written with the session sequence
// number and records the state it puts the client in.
//
// self is the node the frame describes even when resp.Node was cleared by
// [mapSession.diff] because it did not change.
func (s *mapSession) commit(resp *tailcfg.MapResponse, self *tailcfg.Node, peers []*tailcfg.Node) {
	s.record(self, peers)
	s.seq++
	resp.Seq = s.seq
}

// fingerprintDNS renders a DNS configuration into a comparable string. An
// empty string means "no configuration".
func fingerprintDNS(dns *tailcfg.DNSConfig) string {
	if dns == nil {
		return ""
	}
	b, err := json.Marshal(dns)
	if err != nil {
		return ""
	}
	return string(b)
}

// fingerprintFilter renders packet filter rules into a comparable string.
func fingerprintFilter(rules []tailcfg.FilterRule) string {
	if len(rules) == 0 {
		return ""
	}
	b, err := json.Marshal(rules)
	if err != nil {
		return ""
	}
	return string(b)
}

// fingerprintTKA renders tailnet-lock state into a comparable string. An
// empty string means "no tailnet lock".
func fingerprintTKA(info *tailcfg.TKAInfo) string {
	if info == nil {
		return ""
	}
	b, err := json.Marshal(info)
	if err != nil {
		return ""
	}
	return string(b)
}

// fingerprintClientVersion renders an update advisory into a comparable
// string. An empty string means "no advisory".
func fingerprintClientVersion(cv *tailcfg.ClientVersion) string {
	if cv == nil {
		return ""
	}
	b, err := json.Marshal(cv)
	if err != nil {
		return ""
	}
	return string(b)
}

// filterFromResponse extracts the rules a response carries, whichever field the
// client's capability version uses.
func filterFromResponse(resp *tailcfg.MapResponse) []tailcfg.FilterRule {
	if rules, ok := resp.PacketFilters["base"]; ok {
		return rules
	}
	return resp.PacketFilter
}

// record remembers the state a frame put the client in.
func (s *mapSession) record(self *tailcfg.Node, peers []*tailcfg.Node) {
	s.self = self
	s.peers = make(map[tailcfg.NodeID]*tailcfg.Node, len(peers))
	for _, p := range peers {
		s.peers[p.ID] = p
	}
}

func peersOf(resp *tailcfg.MapResponse) []*tailcfg.Node {
	if resp.Peers == nil {
		return nil
	}
	return resp.Peers
}
