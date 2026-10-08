package control

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// Node key rotation.
//
// An official client keeps its machine key (the long-lived Noise identity) but
// can present a new node key when it re-authorizes: after node key expiry, on
// `tailscale up` against a reset client state, or when the control plane asks
// for a re-login. Upstream headscale updates the existing node in place in
// that case (hscontrol/state/state.go HandleNodeFromPreAuthKey /
// HandleNodeFromAuthPath); registering a second node would leak a duplicate
// peer, a new StableID and a second address pair for one machine.
//
// Rotation is never implied by the node key alone. The caller must have
// authorized the new key first (valid pre-auth key, or a human approving the
// device), and the machine key from the Noise session must match the stored
// node. The node identity (ID, StableID, addresses, creation time) is
// preserved; the node key, hostname/hostinfo and authorization method move to
// the new values.

// rotationCandidate returns the single existing node a same-machine
// re-authorization may rotate in place.
//
// owner is the (human) identity the new authorization belongs to. A node is a
// candidate when it is already tagged, or when it belongs to owner. When
// matchAll is true (a tags-only pre-auth key) any node of the machine is a
// candidate, mirroring upstream: a tagged key may convert a user-owned node
// in place.
//
// More than one candidate means the machine key is in an ambiguous state
// (tagged node plus user-owned node, or several user-owned nodes). Rotating an
// arbitrary one could orphan the rest, so the rotation is refused and the
// caller falls back to the normal registration error path.
func (s *Server) rotationCandidate(machineKey key.MachinePublic, owner tailcfg.UserID, matchAll bool) (state.Node, bool, error) {
	nodes := s.store.GetNodesByMachineKey(machineKey)
	if len(nodes) == 0 {
		return state.Node{}, false, nil
	}

	candidates := make([]state.Node, 0, 1)
	for _, n := range nodes {
		if matchAll || len(n.Tags) > 0 || n.UserID == owner {
			candidates = append(candidates, n)
		}
	}

	switch len(candidates) {
	case 0:
		return state.Node{}, false, nil
	case 1:
		return candidates[0], true, nil
	default:
		s.log.Warn("refusing to rotate node key: machine key is bound to multiple nodes",
			"machine_key", machineKey.ShortString(), "nodes", len(candidates))
		return state.Node{}, false, NewHTTPError(http.StatusConflict,
			"this machine key is bound to more than one node", nil)
	}
}

// rotateNodeKey updates existing in place so that it carries want's freshly
// authorized identity.
//
// want is a fully prepared registration (node key, hostname, hostinfo,
// method, ownership, tags and expiry already resolved). The existing node's
// identity and history survive: ID, StableID, addresses, routes, endpoint
// state, last-seen and creation time.
//
// applyTags is true for interactive re-authorization, where the approving
// human's decision decides the tag set (an empty set converts a tagged node
// back to a user-owned node, as upstream does). For a pre-auth key the key's
// tags are applied only when the key carries some: an untagged key
// re-registering a tagged node preserves the node's tags, matching upstream's
// "reusing the last key preserves subsequent admin tag changes".
func (s *Server) rotateNodeKey(existing, want state.Node, applyTags bool, actor string) (state.Node, error) {
	// Enforce the same 1:1 NodeKey<->MachineKey binding as creation and poll
	// time: claiming a node key already bound to another machine would poison
	// the node key index and deny the victim service (AGENTS.md section 11).
	if other, ok := s.store.GetNodeByNodeKey(want.NodeKey); ok && other.MachineKey != want.MachineKey {
		return state.Node{}, NewHTTPError(http.StatusConflict, "node key already registered", nil)
	}

	updated := existing
	updated.NodeKey = want.NodeKey
	updated.Method = want.Method
	// A signature (or its absence) always moves with the node key: a signature
	// naming the old key is worthless for the new one, and publishing it would
	// only make peers treat the node as unsigned.
	updated.KeySignature = slices.Clone(want.KeySignature)
	// The network-lock key belongs to the machine and outlives rotations; only
	// replace it when the client reported a new one.
	if !want.NLKey.IsZero() {
		updated.NLKey = want.NLKey
	}
	if want.Hostname != "" {
		updated.Hostname = want.Hostname
	}
	if want.Hostinfo != nil {
		updated.Hostinfo = want.Hostinfo
	}
	updated.Expiry = want.Expiry
	updated.Ephemeral = existing.Ephemeral || want.Ephemeral
	if applyTags || len(want.Tags) > 0 {
		updated.Tags = want.Tags
		updated.UserID = want.UserID
	}

	if err := s.store.UpdateNode(updated); err != nil {
		if errors.Is(err, state.ErrNodeKeyExists) {
			return state.Node{}, NewHTTPError(http.StatusConflict, "node key already registered", nil)
		}
		return state.Node{}, fmt.Errorf("rotating node key: %w", err)
	}

	s.log.Info("rotated node key in place",
		"node_id", updated.ID,
		"stable_id", updated.StableID,
		"old_node_key", existing.NodeKey.ShortString(),
		"new_node_key", updated.NodeKey.ShortString())

	s.audit(actor, identity.AuditNodeKeyRotated, nodeTarget(updated), fmt.Sprintf(
		"node key rotated in place; machine identity unchanged (old %s, new %s)",
		existing.NodeKey.ShortString(), updated.NodeKey.ShortString()))
	s.notifyNodePeers(updated)

	return updated, nil
}
