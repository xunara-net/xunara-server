package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xunara-net/xunara-server/netspace"

	"tailscale.com/types/key"
)

// Default address ranges for the tailnet. These mirror the ranges the official
// Tailscale clients expect for a tailnet's CGNAT space.
var (
	defaultIPv4Prefix = netip.MustParsePrefix("100.64.0.0/10")
	defaultIPv6Prefix = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// MemoryStore is an in-memory [Store].
//
// It is safe for concurrent use. It provides no durability; a durable backing
// store is a follow-up milestone. Keeping it behind the [Store] interface means
// the Compatibility Core does not change when durability lands.
type MemoryStore struct {
	mu sync.RWMutex

	nextID    NodeID
	nextKeyID uint64

	byID   map[NodeID]Node
	byNode map[key.NodePublic]NodeID
	byStab map[string]NodeID
	byMach map[key.MachinePublic][]NodeID

	preauth map[string]PreAuthKey

	dns       map[uint64]DNSRecord
	nextDNSID uint64

	deviceAttrs map[NodeID]map[string]any

	// services are keyed by name because names are unique per organization.
	services map[string]Service

	// flux holds Xunara Flux transfer metadata, keyed by transfer ID.
	flux map[string]FluxTransfer

	// rateLimits holds fixed-window counters, keyed by scope.
	rateLimits map[string]rateBucket

	// reach holds remote command sessions, keyed by session ID.
	reach map[string]ReachSession
	// reachChunks holds output per session, keyed by session ID then stream.
	reachChunks map[string]map[string][]ReachChunk

	tka TKAMeta

	// configRevision counts out-of-band configuration changes.
	configRevision atomic.Uint64

	ip4 *ipAllocator
	ip6 *ipAllocator

	// share is the synthetic-ID/masquerade namespace for shared-in nodes
	// (section 38).
	share *memoryShareStore

	// relay holds enrolled DERP/STUN relays and their enrollment tokens.
	relay *memoryRelayStore
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	store := &MemoryStore{
		nextID:      1,
		nextKeyID:   1,
		nextDNSID:   1,
		byID:        make(map[NodeID]Node),
		preauth:     make(map[string]PreAuthKey),
		dns:         make(map[uint64]DNSRecord),
		deviceAttrs: make(map[NodeID]map[string]any),
		services:    make(map[string]Service),
		flux:        make(map[string]FluxTransfer),
		rateLimits:  make(map[string]rateBucket),
		reach:       make(map[string]ReachSession),
		reachChunks: make(map[string]map[string][]ReachChunk),
		byNode:      make(map[key.NodePublic]NodeID),
		byStab:      make(map[string]NodeID),
		byMach:      make(map[key.MachinePublic][]NodeID),
		ip4:         newIPAllocator(defaultIPv4Prefix),
		ip6:         newIPAllocator(defaultIPv6Prefix),
		share:       newMemoryShareStore(),
		relay:       newMemoryRelayStore(),
	}

	// Allocation skips addresses that are already assigned, so a changed
	// tenant range can safely overlap the previous one (prefix.go).
	store.ip4.skip = store.addrInUseLocked
	store.ip6.skip = store.addrInUseLocked
	return store
}

// EnsureShareNode implements [ShareStore].
func (s *MemoryStore) EnsureShareNode(remoteOrg, remoteKey string) (NodeID, error) {
	return s.share.EnsureShareNode(remoteOrg, remoteKey)
}

// ShareNode implements [ShareStore].
func (s *MemoryStore) ShareNode(remoteOrg, remoteKey string) (NodeID, bool) {
	return s.share.ShareNode(remoteOrg, remoteKey)
}

// EnsureShareAddress implements [ShareStore].
func (s *MemoryStore) EnsureShareAddress(remoteOrg, remoteKey string) (netip.Addr, netip.Addr, error) {
	return s.share.EnsureShareAddress(remoteOrg, remoteKey)
}

// ShareAddress implements [ShareStore].
func (s *MemoryStore) ShareAddress(remoteOrg, remoteKey string) (netip.Addr, netip.Addr, bool) {
	return s.share.ShareAddress(remoteOrg, remoteKey)
}

var _ Store = (*MemoryStore)(nil)

func (s *MemoryStore) GetNodeByID(id NodeID) (Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.byID[id]
	return n, ok
}

func (s *MemoryStore) GetNodeByNodeKey(nk key.NodePublic) (Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byNode[nk]
	if !ok {
		return Node{}, false
	}
	n, ok := s.byID[id]
	return n, ok
}

func (s *MemoryStore) GetNodesByMachineKey(mk key.MachinePublic) []Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.byMach[mk]
	out := make([]Node, 0, len(ids))
	for _, id := range ids {
		if n, ok := s.byID[id]; ok {
			out = append(out, n)
		}
	}
	return out
}

func (s *MemoryStore) GetNodeByStableID(id string) (Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	nid, ok := s.byStab[id]
	if !ok {
		return Node{}, false
	}
	n, ok := s.byID[nid]
	return n, ok
}

func (s *MemoryStore) ListNodes() []Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Node, 0, len(s.byID))
	for _, n := range s.byID {
		out = append(out, n)
	}
	return out
}

func (s *MemoryStore) CreateNode(n *Node) error {
	if n == nil {
		return fmt.Errorf("state: nil node")
	}
	if n.NodeKey.IsZero() {
		return fmt.Errorf("state: node key is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.byNode[n.NodeKey]; ok {
		return ErrNodeKeyExists
	}

	n.ID = s.nextID
	s.nextID++

	if n.StableID == "" {
		n.StableID = newStableID()
	}
	if n.Created.IsZero() {
		n.Created = time.Now().UTC()
	}
	if !n.IPv4.IsValid() {
		addr, ok := s.ip4.next()
		if !ok {
			return fmt.Errorf("state: IPv4 space exhausted")
		}
		n.IPv4 = addr
	}
	if !n.IPv6.IsValid() {
		addr, ok := s.ip6.next()
		if !ok {
			return fmt.Errorf("state: IPv6 space exhausted")
		}
		n.IPv6 = addr
	}

	s.byID[n.ID] = *n
	s.byNode[n.NodeKey] = n.ID
	s.byStab[n.StableID] = n.ID
	s.byMach[n.MachineKey] = append(s.byMach[n.MachineKey], n.ID)
	return nil
}

func (s *MemoryStore) UpdateNode(n Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	old, ok := s.byID[n.ID]
	if !ok {
		return fmt.Errorf("state: node %d not found", n.ID)
	}
	if old.NodeKey != n.NodeKey {
		delete(s.byNode, old.NodeKey)
		s.byNode[n.NodeKey] = n.ID
	}
	if old.StableID != n.StableID {
		delete(s.byStab, old.StableID)
		s.byStab[n.StableID] = n.ID
	}
	if old.MachineKey != n.MachineKey {
		s.byMach[old.MachineKey] = removeID(s.byMach[old.MachineKey], n.ID)
		s.byMach[n.MachineKey] = append(s.byMach[n.MachineKey], n.ID)
	}
	n.IPv4, n.IPv6 = old.IPv4, old.IPv6
	s.byID[n.ID] = n
	return nil
}

func (s *MemoryStore) DeleteNode(id NodeID) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.byID[id]
	if !ok {
		return nil
	}
	delete(s.byID, id)
	delete(s.byNode, n.NodeKey)
	delete(s.byStab, n.StableID)
	delete(s.deviceAttrs, id)
	for name, svc := range s.services {
		if svc.NodeID == id {
			delete(s.services, name)
		}
	}
	for transferID, transfer := range s.flux {
		if transfer.SenderNode == id || transfer.RecipientNode == id {
			delete(s.flux, transferID)
		}
	}
	s.byMach[n.MachineKey] = removeID(s.byMach[n.MachineKey], id)
	return nil
}

// SetNodeDeviceAttrs implements [DeviceAttrStore].
func (s *MemoryStore) SetNodeDeviceAttrs(id NodeID, update map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.byID[id]; !ok {
		return fmt.Errorf("state: node %d is unknown", id)
	}
	if len(update) == 0 {
		return nil
	}

	attrs := s.deviceAttrs[id]
	if attrs == nil {
		attrs = make(map[string]any)
	}
	for name, value := range update {
		if value == nil {
			delete(attrs, name)
			continue
		}
		attrs[name] = value
	}
	if len(attrs) == 0 {
		delete(s.deviceAttrs, id)
		for name, svc := range s.services {
			if svc.NodeID == id {
				delete(s.services, name)
			}
		}
		return nil
	}
	s.deviceAttrs[id] = attrs
	return nil
}

// NodeDeviceAttrs implements [DeviceAttrStore].
func (s *MemoryStore) NodeDeviceAttrs(id NodeID) (map[string]any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	attrs := s.deviceAttrs[id]
	if len(attrs) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(attrs))
	for name, value := range attrs {
		out[name] = value
	}
	return out, nil
}

// NodeDeviceAttrCounts implements [DeviceAttrStore].
func (s *MemoryStore) NodeDeviceAttrCounts() (map[NodeID]int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := make(map[NodeID]int, len(s.deviceAttrs))
	for id, attrs := range s.deviceAttrs {
		counts[id] = len(attrs)
	}
	return counts, nil
}

func (s *MemoryStore) SetNodeApprovedRoutes(id NodeID, routes []netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	n, ok := s.byID[id]
	if !ok {
		return fmt.Errorf("state: node %d not found", id)
	}

	n.ApprovedRoutes = normalizeRoutes(routes)
	s.byID[id] = n
	return nil
}

// TKAMeta implements [TKAStore].
func (s *MemoryStore) TKAMeta() TKAMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tka
}

// SetTKAMeta implements [TKAStore].
func (s *MemoryStore) SetTKAMeta(meta TKAMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tka = meta
	return nil
}

// ConfigRevision returns the in-process configuration revision.
func (s *MemoryStore) ConfigRevision() uint64 { return s.configRevision.Load() }

// BumpConfigRevision advances the configuration revision.
func (s *MemoryStore) BumpConfigRevision() error {
	s.configRevision.Add(1)
	return nil
}

func removeID(ids []NodeID, id NodeID) []NodeID {
	out := ids[:0]
	for _, v := range ids {
		if v != id {
			out = append(out, v)
		}
	}
	return out
}

// newStableID returns a random stable node ID.
func newStableID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read never fails on supported platforms; fall back to a
		// deterministic-ish value rather than panicking.
		return "n00000000"
	}
	return "n" + hex.EncodeToString(b[:])
}

// ipAllocator hands out sequential addresses from a prefix.
type ipAllocator struct {
	prefix netip.Prefix
	last   netip.Addr
	// skip reports whether an address is already assigned to a node. It is
	// consulted after a tenant's range changed, when the previous range may
	// overlap the new one.
	skip func(netip.Addr) bool
}

func newIPAllocator(p netip.Prefix) *ipAllocator {
	masked := p.Masked()
	return &ipAllocator{prefix: masked, last: masked.Addr()}
}

func (a *ipAllocator) next() (netip.Addr, bool) {
	for {
		next := a.last.Next()
		if !next.IsValid() || !a.prefix.Contains(next) {
			return netip.Addr{}, false
		}
		a.last = next
		if isShareMasqAddr(next) || netspace.IsClientReservedIPv4(next) {
			continue
		}
		if a.skip != nil && a.skip(next) {
			continue
		}
		return next, true
	}
}

// The relay store is a sub-store: these methods keep [MemoryStore] a complete
// [RelayStore] without mixing relay maps into the node maps above.

// CreateRelayEnrollmentToken implements [RelayStore].
func (s *MemoryStore) CreateRelayEnrollmentToken(tok RelayEnrollmentToken, secret string) error {
	return s.relay.CreateRelayEnrollmentToken(tok, secret)
}

// RelayEnrollmentTokenBySecret implements [RelayStore].
func (s *MemoryStore) RelayEnrollmentTokenBySecret(secret string) (RelayEnrollmentToken, bool) {
	return s.relay.RelayEnrollmentTokenBySecret(secret)
}

// RelayEnrollmentTokenByID implements [RelayStore].
func (s *MemoryStore) RelayEnrollmentTokenByID(id string) (RelayEnrollmentToken, bool) {
	return s.relay.RelayEnrollmentTokenByID(id)
}

// ListRelayEnrollmentTokens implements [RelayStore].
func (s *MemoryStore) ListRelayEnrollmentTokens() []RelayEnrollmentToken {
	return s.relay.ListRelayEnrollmentTokens()
}

func (store *MemoryStore) LookupRelayEnrollmentToken(ctx context.Context, secret string) (RelayEnrollmentToken, error) {
	return store.relay.LookupRelayEnrollmentToken(ctx, secret)
}

func (store *MemoryStore) EnrollRelay(ctx context.Context, enrollmentSecret string, relay Relay, token string, maxRelays int) (Relay, error) {
	return store.relay.EnrollRelay(ctx, enrollmentSecret, relay, token, maxRelays)
}

// DeleteRelayEnrollmentToken implements [RelayStore].
func (s *MemoryStore) DeleteRelayEnrollmentToken(id string) error {
	return s.relay.DeleteRelayEnrollmentToken(id)
}

// CreateRelay implements [RelayStore].
func (s *MemoryStore) CreateRelay(relay Relay, token string) error {
	return s.relay.CreateRelay(relay, token)
}

// RelayByToken implements [RelayStore].
func (s *MemoryStore) RelayByToken(token string) (Relay, bool) {
	return s.relay.RelayByToken(token)
}

// RelayByID implements [RelayStore].
func (s *MemoryStore) RelayByID(id string) (Relay, bool) {
	return s.relay.RelayByID(id)
}

// RelayByNodeKey implements [RelayStore].
func (s *MemoryStore) RelayByNodeKey(nodeKey string) (Relay, bool) {
	return s.relay.RelayByNodeKey(nodeKey)
}

// ListRelays implements [RelayStore].
func (s *MemoryStore) ListRelays() []Relay {
	return s.relay.ListRelays()
}

// UpdateRelayHeartbeat implements [RelayStore].
func (s *MemoryStore) UpdateRelayHeartbeat(id string, hb RelayHeartbeat) error {
	return s.relay.UpdateRelayHeartbeat(id, hb)
}

func (store *MemoryStore) RecordRelayHeartbeat(ctx context.Context, token string, heartbeat RelayHeartbeat) (Relay, error) {
	return store.relay.RecordRelayHeartbeat(ctx, token, heartbeat)
}

// UpdateRelayConfig implements [RelayStore].
func (s *MemoryStore) UpdateRelayConfig(id string, update RelayConfigUpdate) (Relay, error) {
	return s.relay.UpdateRelayConfig(id, update)
}

// DeleteRelay implements [RelayStore].
func (s *MemoryStore) DeleteRelay(id string) error {
	return s.relay.DeleteRelay(id)
}
