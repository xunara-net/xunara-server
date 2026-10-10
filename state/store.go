package state

import (
	"errors"
	"net/netip"

	"tailscale.com/types/key"
)

// ErrNodeKeyExists is returned by [Store.CreateNode] when a node with the same
// node key already exists.
var ErrNodeKeyExists = errors.New("node key already registered")

// Store is the persistence boundary for tailnet state.
//
// Implementations must be safe for concurrent use. Node values returned by the
// getters are copies: mutating them must not affect stored state. Callers
// persist changes through [Store.UpdateNode].
type Store interface {
	PreAuthKeyStore
	DNSRecordStore
	TKAStore
	DeviceAttrStore
	ServiceStore
	FluxStore
	RateLimitStore
	ReachStore
	ShareStore
	RelayStore

	// GetNodeByID returns the node with the given server-local ID.
	GetNodeByID(id NodeID) (Node, bool)
	// GetNodeByNodeKey returns the node registered under a node key.
	GetNodeByNodeKey(nk key.NodePublic) (Node, bool)
	// GetNodesByMachineKey returns all nodes sharing a machine key. A machine
	// can host more than one node, so this is a list.
	GetNodesByMachineKey(mk key.MachinePublic) []Node
	// GetNodeByStableID returns the node with the given stable ID.
	GetNodeByStableID(id string) (Node, bool)
	// ListNodes returns every node in the store.
	ListNodes() []Node

	// CreateNode assigns an ID, stable ID, addresses and creation time to a new
	// node and stores it.
	CreateNode(n *Node) error
	// UpdateNode replaces runtime node facts, keeping independently managed addresses.
	// It fails if the node is unknown.
	UpdateNode(n Node) error
	// DeleteNode removes a node. It is a no-op if the node is unknown.
	DeleteNode(id NodeID) error

	// SetNodeApprovedRoutes replaces the set of subnet routes approved for a
	// node. It fails if the node is unknown. Approval is stored independently
	// of announcement; see [Node.EffectiveRoutes].
	SetNodeApprovedRoutes(id NodeID, routes []netip.Prefix) error

	// SetAddressPrefixes replaces the ranges new nodes are allocated from
	// (spec section 54). An invalid prefix leaves that address family
	// unchanged; existing nodes keep their addresses. Implementations must
	// make the change visible to subsequent allocations atomically.
	SetAddressPrefixes(v4, v6 netip.Prefix) error
	// AddressPrefixes returns the ranges new nodes are allocated from.
	AddressPrefixes() (netip.Prefix, netip.Prefix)

	// ConfigRevision returns a counter that increases whenever tailnet
	// configuration changes outside a control session's request path, such as
	// when the administration CLI approves a route or edits a user. Servers
	// poll it to learn that a netmap re-push is due. Implementations must make
	// the counter durable so that it works across processes.
	ConfigRevision() uint64
	// BumpConfigRevision advances the configuration revision.
	BumpConfigRevision() error
}
