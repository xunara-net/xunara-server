// Package state holds Xunara's tailnet state model: the nodes registered on a
// tailnet and the operations the control plane performs on them.
//
// The package deliberately exposes a small [Store] interface so that the
// Compatibility Core (control/) depends on an interface rather than a concrete
// database, keeping the dependency direction Platform -> Core interfaces
// (AGENTS.md section 13).
package state

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"
)

// NodeID is the server-local, stable identifier of a node. It is distinct from
// the wire [tailcfg.NodeID] only in package ownership; the numeric value is
// what is sent to clients.
type NodeID uint64

// RegisterMethod records how a node's identity became authorized.
//
// Human and machine identity stay separate (AGENTS.md section 5): an
// interactive login authorizes a *machine*, it never turns a NodeKey into a
// human user.
type RegisterMethod string

const (
	// RegisterMethodAuthKey is a node authorized by a pre-authentication key.
	RegisterMethodAuthKey RegisterMethod = "auth_key"
	// RegisterMethodInteractive is a node authorized through the browser login
	// flow (OIDC/OAuth/WebAuthn/... at a later milestone).
	RegisterMethodInteractive RegisterMethod = "interactive"
)

// Node is a registered machine on a tailnet.
//
// A Node is a value type so that reads from the [Store] never hand out a
// pointer that could be mutated concurrently.
type Node struct {
	ID       NodeID
	StableID string

	// MachineKey is the machine's long-lived Noise key, bound at the TS2021
	// handshake. It is one half of machine identity.
	MachineKey key.MachinePublic
	// NodeKey is the node's WireGuard key, derived from the machine's tailscale
	// state. It is one half of node identity.
	NodeKey key.NodePublic
	// DiscoKey is the node's magicsock discovery key.
	DiscoKey key.DiscoPublic

	// KeySignature is the node's tailnet-lock node-key signature, present only
	// when the tailnet has tailnet lock enabled and this node has been signed.
	// It is published to every client (tailcfg.Node.KeySignature) so peers can
	// verify the node key without trusting the control plane.
	KeySignature tkatype.MarshaledSignature

	// NLKey is the node's tailnet-lock public key (key.NLPublic), reported in
	// RegisterRequest.NLKey while the tailnet has a key authority. It is
	// persisted because TKASignInfo.RotationPubkey (the raw ed25519 public
	// key) is needed so an administrator can sign a node key that survives
	// later rotations.
	NLKey key.NLPublic

	// UserID is the owning user. In the single-tenant milestone this is always
	// [DefaultUserID].
	UserID tailcfg.UserID

	// Hostname is the machine's self-reported hostname.
	Hostname string

	// DNSName 是控制面分配的持久 DNS label，与机器自报的 Hostname 分开。
	DNSName string

	// IPv4 and IPv6 are the tailnet addresses assigned to this node.
	IPv4 netip.Addr
	IPv6 netip.Addr

	// Endpoints are the node's most recently reported magicsock endpoints, as
	// carried in MapRequest.Endpoints.
	Endpoints []netip.AddrPort

	// HomeDERP is the DERP region the node is homed to, if known.
	HomeDERP tailcfg.DERPRegionID

	// CapVer is the capability version the node last advertised. It is
	// advertised to peers so they can gate behaviour per node.
	CapVer tailcfg.CapabilityVersion

	// Hostinfo is the most recent host info seen for the node. It is treated as
	// immutable after it is set; callers must not mutate it in place.
	Hostinfo *tailcfg.Hostinfo

	// LastSeen is when the node's last control session ended. It is nil for a
	// node that has never completed a session.
	LastSeen *time.Time

	// Expiry is when the node key expires. The zero value means the key never
	// expires.
	Expiry time.Time
	// RequestedExpiry is the expiry the client asked for, before server policy
	// is applied. It is not persisted.
	RequestedExpiry time.Time `json:"-"`
	// Created is when the node was created.
	Created time.Time
	// Method records how the node was authorized.
	Method RegisterMethod

	// ApprovedRoutes are the subnet routes an administrator has approved for
	// this node. Approval is independent of announcement: a route takes effect
	// only while the node announces it, and stays approved across restarts.
	ApprovedRoutes []netip.Prefix

	// Tags are the ACL tags the node carries, in "tag:<name>" form.
	//
	// Tag assignment (tagged pre-auth keys and the tagOwners section of the
	// policy) is not implemented yet, so this is always empty; policies that
	// use tag selectors therefore match no node and the server warns at load
	// time.
	Tags []string

	// Ephemeral marks nodes that should be reaped once inactive.
	Ephemeral bool
}

// DefaultUserID is the user every node is attributed to until multi-user
// identity lands.
const DefaultUserID tailcfg.UserID = 1

// Identity attribute values for [DefaultUserID]. They are the single source of
// truth for how the local user is described to clients.
const (
	// DefaultLoginName is the login name reported for the local user.
	DefaultLoginName = "local"
	// DefaultDisplayName is the display name reported for the local user.
	DefaultDisplayName = "Xunara User"
	// DefaultProvider is the identity provider name reported for the local user.
	DefaultProvider = "xunara"
)

// DefaultUserProfile builds the wire profile for a user in the single-user
// milestone.
func DefaultUserProfile(id tailcfg.UserID) tailcfg.UserProfile {
	return tailcfg.UserProfile{
		ID:          id,
		LoginName:   DefaultLoginName,
		DisplayName: DefaultDisplayName,
	}
}

// DefaultUser builds the wire user for a user in the single-user milestone.
func DefaultUser(id tailcfg.UserID, created time.Time) tailcfg.User {
	return tailcfg.User{
		ID:          id,
		DisplayName: DefaultDisplayName,
		Created:     created,
	}
}

// Expired reports whether the node's key expiry has passed. The zero expiry is
// never expired.
func (n Node) Expired(now time.Time) bool {
	return !n.Expiry.IsZero() && n.Expiry.Before(now)
}

// The two prefixes that make a node an exit node when it advertises and gets
// approved for them. Mirror of the upstream helper of the same name
// (tsaddr.IsExitRoute) without pulling in another module.
var (
	// ExitRouteV4 is the IPv4 default route.
	ExitRouteV4 = netip.MustParsePrefix("0.0.0.0/0")
	// ExitRouteV6 is the IPv6 default route.
	ExitRouteV6 = netip.MustParsePrefix("::/0")
)

// IsExitRoute reports whether p is one of the default routes, which turn a
// subnet router into an exit node.
func IsExitRoute(p netip.Prefix) bool {
	return p == ExitRouteV4 || p == ExitRouteV6
}

// AnnouncedRoutes returns the subnet routes the node currently advertises, as
// reported in its Hostinfo.RoutableIPs and persisted with the Hostinfo.
//
// Announcing a route is only a request: the node serves it once an
// administrator approves it. Announcements disappear when the client stops
// advertising them, so they are not stored separately.
func (n Node) AnnouncedRoutes() []netip.Prefix {
	if n.Hostinfo == nil {
		return nil
	}
	return slices.Clone(n.Hostinfo.RoutableIPs)
}

// EffectiveRoutes returns the advertised routes that are also approved, sorted
// by prefix. These are the routes the node actually serves to the tailnet.
func (n Node) EffectiveRoutes() []netip.Prefix {
	if n.Hostinfo == nil || len(n.ApprovedRoutes) == 0 {
		return nil
	}

	approved := make(map[netip.Prefix]bool, len(n.ApprovedRoutes))
	for _, r := range n.ApprovedRoutes {
		approved[r] = true
	}

	out := make([]netip.Prefix, 0, len(n.Hostinfo.RoutableIPs))
	for _, r := range n.Hostinfo.RoutableIPs {
		if approved[r] {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, netip.Prefix.Compare)
	return out
}

// IsExitNode reports whether the node serves an approved default route.
func (n Node) IsExitNode() bool {
	for _, r := range n.EffectiveRoutes() {
		if IsExitRoute(r) {
			return true
		}
	}
	return false
}

// normalizeRoutes returns a sorted, de-duplicated copy of routes with invalid
// prefixes dropped. It returns nil for an empty result so that stored and
// in-memory values compare equal.
func normalizeRoutes(routes []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(routes))
	for _, r := range routes {
		if r.IsValid() {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, netip.Prefix.Compare)
	out = slices.Compact(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// FQDN returns the node's fully-qualified MagicDNS name, always with a
// trailing dot. baseDomain is the tailnet's MagicDNS suffix, without a
// trailing dot; an empty baseDomain yields a single-label name.
//
// The hostname is sanitised into a DNS label because clients report whatever
// the operating system calls the machine, which is not necessarily a legal
// DNS label (and can be long, or non-ASCII).
func (n Node) FQDN(baseDomain string) string {
	name := n.DNSName
	if name == "" {
		name = defaultDNSLabel(n)
	}

	base := strings.Trim(baseDomain, ".")
	if base == "" {
		return name + "."
	}
	return name + "." + base + "."
}

// maxDNSLabelLength is the wire limit for a single DNS label.
const maxDNSLabelLength = 63
