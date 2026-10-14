package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// Xunara Share: cross-organization machine sharing (PROJECT_SPEC section 38).
//
// The registry (share_registry.go) is the platform-level lifecycle table.
// This file adds the organization-side halves: the directory a sharing-enabled
// server uses to read the other organizations of the same router, the
// validation and lifecycle rules shared by the HTTP API and the console, and
// the wire views.

// ShareOrg is one hosted organization, as cross-organization sharing sees it.
// Every method is read-only except ShareEnsureAddress, which idempotently
// allocates this organization's own masquerade address for a foreign party.
type ShareOrg interface {
	// Organization returns the organization's platform identity.
	Organization() OrgIdentity
	// ShareNode returns a node snapshot.
	ShareNode(nodeID state.NodeID) (state.Node, bool)
	// ShareNodesOfUser returns the nodes owned by one user.
	ShareNodesOfUser(userID tailcfg.UserID) []state.Node
	// ShareServices returns the services a node advertises. Only the fields
	// the other side of a share needs cross the boundary: the caller decides
	// which of them are projected (spec section 47).
	ShareServices(nodeID state.NodeID) []state.Service
	// ShareUser returns one user.
	ShareUser(userID tailcfg.UserID) (identity.User, bool)
	ShareGeneration() string
	ShareIdentityMatches(userID tailcfg.UserID, provider, subject string) bool
	// ShareOnline reports whether a node holds a live control session.
	ShareOnline(nodeID state.NodeID) bool
	// ShareTKAEnabled reports whether the organization enforces tailnet lock.
	ShareTKAEnabled() bool
	// ShareEnsureAddress returns this organization's masquerade addresses for
	// the foreign party identified by (remoteOrg, remoteKey).
	ShareEnsureAddress(remoteOrg, remoteKey string) (netip.Addr, netip.Addr, error)
	// ShareNotify wakes this organization's netmap watchers.
	ShareNotify()
	// shareRegistry returns the organization's share registry handle, so a
	// router can address the same registry from every tenant.
	shareRegistry() *ShareRegistry
}

// ShareDirectory resolves the organizations one router hosts.
type ShareDirectory interface {
	// Org returns the organization with this ID, or nil when it is not hosted
	// here.
	Org(id string) ShareOrg
}

type AccountShareDirectory interface {
	ResolveShareAccount(ctx context.Context, login string) (ShareOrg, identity.User, error)
}

// Sharing errors, mapped to HTTP status codes by the API and console layers.
var (
	// errShareDisabled is returned when the deployment has no share registry.
	errShareDisabled = errors.New("sharing is not enabled")
	// errShareNodeUnknown is returned when the node to share does not exist.
	errShareNodeUnknown = errors.New("unknown node")
	// errShareOrgUnknown is returned when the target organization is not
	// hosted by this router.
	errShareOrgUnknown = errors.New("unknown target organization")
	// errShareIdentityInvalid is returned for a target identity that cannot be
	// an identity key (missing provider/subject or the per-org local provider).
	errShareIdentityInvalid = errors.New("invalid target identity")
	// errShareSelf is returned when source and target organizations are equal.
	errShareSelf = errors.New("cannot share a machine with its own organization")
	// errShareNotMine is returned when the caller may not see a share: it is
	// deliberately the same error as "unknown" so existence never leaks.
	errShareNotMine = errors.New("unknown share")
	// errShareTKA is returned while either organization enforces tailnet lock.
	errShareTKA = errors.New("sharing is not available while tailnet lock is enabled")
	// errShareDecision is returned when an action does not apply to the
	// share's current status.
	errShareDecision = errors.New("share is not in a state for this action")
	// errShareForbidden is returned when the caller could see the share but
	// may not administer this side of it.
	errShareForbidden      = errors.New("not allowed to revoke this share")
	errShareAccountUnknown = errors.New("SHARE_RECIPIENT_UNAVAILABLE: recipient is unavailable or ambiguous; verify the login name")
	errShareUnavailable    = errors.New("SHARE_UNAVAILABLE: device or account changed; create a new share")
)

// shareNodeView is the summary of a shared machine the other side may see.
// It never carries addresses, keys or local IDs.
type shareNodeView struct {
	StableID string `json:"stableId,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	OS       string `json:"os,omitempty"`
	// Missing is set when the node no longer exists in the source
	// organization (the share is kept for the record).
	Missing bool `json:"missing,omitempty"`
}

// shareView is the wire and console shape of one share.
type shareView struct {
	ID         string         `json:"id"`
	Status     string         `json:"status"`
	Direction  string         `json:"direction"`
	Node       *shareNodeView `json:"node,omitempty"`
	SourceOrg  string         `json:"sourceOrganization"`
	TargetOrg  string         `json:"targetOrganization"`
	Provider   string         `json:"provider"`
	Subject    string         `json:"subject"`
	CreatedBy  string         `json:"createdBy,omitempty"`
	CreatedAt  time.Time      `json:"createdAt"`
	TargetUser string         `json:"targetUser,omitempty"`
	AcceptedAt *time.Time     `json:"acceptedAt,omitempty"`
	RejectedAt *time.Time     `json:"rejectedAt,omitempty"`
	RevokedAt  *time.Time     `json:"revokedAt,omitempty"`
	// RevokedBy is "source" or "target" once a share was revoked.
	RevokedBy string `json:"revokedBy,omitempty"`
}

// shareDir and shares are wired by the router; both nil disables sharing.
func (s *Server) enableSharing(shares *ShareRegistry, dir ShareDirectory) {
	s.shares = shares
	s.shareDir = dir
}

// sharingEnabled reports whether this server can manage shares.
func (s *Server) sharingEnabled() bool {
	return s.shares != nil && s.shareDir != nil
}

// ShareNode implements [ShareOrg].
func (s *Server) ShareNode(nodeID state.NodeID) (state.Node, bool) {
	return s.store.GetNodeByID(nodeID)
}

// ShareNodesOfUser implements [ShareOrg].
func (s *Server) ShareNodesOfUser(userID tailcfg.UserID) []state.Node {
	var out []state.Node
	for _, node := range s.store.ListNodes() {
		if node.UserID == userID {
			out = append(out, node)
		}
	}
	return out
}

// ShareServices implements [ShareOrg].
func (s *Server) ShareServices(nodeID state.NodeID) []state.Service {
	services, err := s.store.ServicesForNode(nodeID)
	if err != nil {
		s.log.Warn("sharing: reading a shared node's services", "node_id", int(nodeID), "err", err)
		return nil
	}
	return services
}

// ShareUser implements [ShareOrg].
func (s *Server) ShareUser(userID tailcfg.UserID) (identity.User, bool) {
	return s.identity.GetUser(userID)
}

func (s *Server) ShareGeneration() string { return s.noiseKey.Public().String() }

func (s *Server) ShareIdentityMatches(userID tailcfg.UserID, provider, subject string) bool {
	for _, link := range s.identity.ListExternalIdentities(userID) {
		if link.ProviderID == provider && link.Subject == subject {
			return true
		}
	}
	return false
}

// 登录名仅用于定位现存人类账户；重复名字不按默认网络、邮箱或密码猜测。
func (r *Router) ResolveShareAccount(ctx context.Context, login string) (ShareOrg, identity.User, error) {
	var target ShareOrg
	var user identity.User
	for _, org := range r.orgSnapshot() {
		candidate, err := org.site.Server.identity.LookupUserByLoginName(ctx, login)
		if errors.Is(err, identity.ErrUserNotFound) {
			continue
		}
		if err != nil {
			return nil, identity.User{}, err
		}
		if target != nil {
			return nil, identity.User{}, errShareAccountUnknown
		}
		target, user = org.site.Server, candidate
	}
	if target == nil || !user.DisabledAt.IsZero() {
		return nil, identity.User{}, errShareAccountUnknown
	}
	return target, user, nil
}

// ShareOnline implements [ShareOrg].
func (s *Server) ShareOnline(nodeID state.NodeID) bool {
	return s.isOnline(nodeID)
}

// ShareTKAEnabled implements [ShareOrg].
func (s *Server) ShareTKAEnabled() bool {
	return s.TKAStatus().Enabled
}

// ShareEnsureAddress implements [ShareOrg].
func (s *Server) ShareEnsureAddress(remoteOrg, remoteKey string) (netip.Addr, netip.Addr, error) {
	return s.store.EnsureShareAddress(remoteOrg, remoteKey)
}

// ShareNotify implements [ShareOrg].
func (s *Server) ShareNotify() {
	s.notifyWatchers()
}

// shareRegistry implements [ShareOrg].
func (s *Server) shareRegistry() *ShareRegistry {
	return s.shares
}

// Org implements [ShareDirectory].
func (r *Router) Org(id string) ShareOrg {
	r.mu.RLock()
	defer r.mu.RUnlock()

	org := r.orgByIDLocked(id)
	if org == nil {
		return nil
	}
	return org.site.Server
}

// shareNodeKey names a node in the share namespace: the stable ID survives
// re-registration, unlike the numeric local ID.
func shareNodeKey(node state.Node) string {
	return node.StableID
}

// shareUserKey names a user in the share namespace. IDs are per organization
// and stable, so the ID is the key.
func shareUserKey(userID tailcfg.UserID) string {
	return fmt.Sprintf("user:%d", userID)
}

// validateShareTarget checks the parts of a share request that do not need the
// registry: the node, the target organization and the identity key.
func (s *Server) validateShareTarget(nodeRef, targetOrg, provider, subject string) (state.Node, error) {
	node, ok := s.lookupAPINode(nodeRef)
	if !ok {
		return state.Node{}, errShareNodeUnknown
	}
	targetOrg = strings.TrimSpace(targetOrg)
	provider = strings.TrimSpace(provider)
	subject = strings.TrimSpace(subject)
	if targetOrg == "" || provider == "" || subject == "" {
		return state.Node{}, errShareIdentityInvalid
	}
	if provider == identity.LocalProviderID {
		// The built-in local user exists once per organization, so it is not
		// a global identity and cannot be a share target (AGENTS.md section 6).
		return state.Node{}, errShareIdentityInvalid
	}
	if targetOrg == s.Organization().ID {
		return state.Node{}, errShareSelf
	}
	if s.shareDir.Org(targetOrg) == nil {
		return state.Node{}, errShareOrgUnknown
	}
	if s.TKAStatus().Enabled || s.shareDir.Org(targetOrg).ShareTKAEnabled() {
		return state.Node{}, errShareTKA
	}
	return node, nil
}

// createShare creates a pending share of a local node to a target identity.
func (s *Server) createShare(ctx context.Context, actor apiPrincipal, nodeRef, targetOrg, provider, subject string) (Share, error) {
	if !s.sharingEnabled() {
		return Share{}, errShareDisabled
	}
	node, err := s.validateShareTarget(nodeRef, targetOrg, provider, subject)
	if err != nil {
		return Share{}, err
	}

	creator, err := s.identity.LookupUser(ctx, actor.UserID)
	if err != nil {
		return Share{}, err
	}
	share, err := s.shares.CreateShare(ctx, Share{
		SourceOrg:        s.Organization().ID,
		SourceNode:       int64(node.ID),
		TargetOrg:        strings.TrimSpace(targetOrg),
		Provider:         strings.TrimSpace(provider),
		Subject:          strings.TrimSpace(subject),
		CreatedBy:        int64(actor.UserID),
		SourceGeneration: s.ShareGeneration(), SourceStableID: node.StableID, SourceUserCreated: creator.CreatedAt.UnixNano(),
		TargetGeneration: s.shareDir.Org(strings.TrimSpace(targetOrg)).ShareGeneration(),
	}, time.Now().UTC())
	if err != nil {
		return Share{}, err
	}
	s.audit(actor.actor(), identity.AuditShareCreated, shareTarget(share),
		fmt.Sprintf("shared %s with %s via %s", nodeTarget(node), share.TargetOrg, share.Provider))
	s.shareDir.Org(share.TargetOrg).ShareNotify()
	return share, nil
}

// shareTarget names a share in audit events.
func shareTarget(share Share) string {
	return "share:" + share.ID
}

// shareForCaller loads a share the caller is allowed to see: either it belongs
// to the caller's organization (as source) or the caller's user is its target.
// Everything else reports errShareNotMine.
func (s *Server) shareForCaller(id string, actor apiPrincipal) (Share, error) {
	if !s.sharingEnabled() {
		return Share{}, errShareDisabled
	}
	share, ok := s.shares.GetShare(id)
	if !ok {
		return Share{}, errShareNotMine
	}
	if share.SourceOrg == s.Organization().ID && share.SourceGeneration == s.ShareGeneration() {
		return share, nil
	}
	if share.TargetOrg == s.Organization().ID && share.TargetGeneration == s.ShareGeneration() && s.callerMatchesShare(share, actor) {
		return share, nil
	}
	return Share{}, errShareNotMine
}

// callerMatchesShare reports whether the caller's user holds the share's
// target identity. An accepted share additionally requires the bound user.
func (s *Server) callerMatchesShare(share Share, actor apiPrincipal) bool {
	if share.TargetGeneration != s.ShareGeneration() {
		return false
	}
	if share.TargetKind == ShareTargetAccount {
		if actor.Kind != "session" || share.TargetAccount != int64(actor.UserID) {
			return false
		}
		user, ok := s.identity.GetUser(actor.UserID)
		return ok && user.DisabledAt.IsZero() && user.CreatedAt.UnixNano() == share.TargetAccountCreated
	}
	if share.Status == ShareAccepted && share.AcceptedBy != int64(actor.UserID) {
		return false
	}
	for _, ei := range s.identity.ListExternalIdentities(actor.UserID) {
		if ei.ProviderID == share.Provider && ei.Subject == share.Subject {
			return true
		}
	}
	return false
}

// acceptShare implements POST /api/v2/shares/{id}/accept: only the target
// identity may accept, and only while the share is pending.
func (s *Server) acceptShare(ctx context.Context, actor apiPrincipal, id string) (Share, error) {
	if !s.sharingEnabled() {
		return Share{}, errShareDisabled
	}
	share, ok := s.shares.GetShare(id)
	if !ok || share.TargetOrg != s.Organization().ID || !s.callerMatchesShare(share, actor) {
		return Share{}, errShareNotMine
	}
	if share.TargetKind == ShareTargetAccount {
		return Share{}, errShareForbidden
	}
	if _, _, _, ok := s.boundShareParties(share); !ok {
		return Share{}, errShareUnavailable
	}
	if s.TKAStatus().Enabled {
		return Share{}, errShareTKA
	}
	if source := s.shareDir.Org(share.SourceOrg); source != nil && source.ShareTKAEnabled() {
		return Share{}, errShareTKA
	}

	updated, err := s.shares.AcceptShare(id, s.Organization().ID, int64(actor.UserID), time.Now().UTC())
	if err != nil {
		if errors.Is(err, ErrShareState) {
			return Share{}, errShareDecision
		}
		return Share{}, err
	}
	s.audit(actor.actor(), identity.AuditShareAccepted, shareTarget(updated),
		fmt.Sprintf("accepted a machine shared by %s", updated.SourceOrg))
	s.notifyShareParties(updated)
	return updated, nil
}

// rejectShare implements POST /api/v2/shares/{id}/reject.
func (s *Server) rejectShare(ctx context.Context, actor apiPrincipal, id string) (Share, error) {
	if !s.sharingEnabled() {
		return Share{}, errShareDisabled
	}
	share, ok := s.shares.GetShare(id)
	if !ok || share.TargetOrg != s.Organization().ID || !s.callerMatchesShare(share, actor) {
		return Share{}, errShareNotMine
	}
	if share.TargetKind == ShareTargetAccount {
		return Share{}, errShareForbidden
	}
	updated, err := s.shares.RejectShare(id, s.Organization().ID, int64(actor.UserID), time.Now().UTC())
	if err != nil {
		if errors.Is(err, ErrShareState) {
			return Share{}, errShareDecision
		}
		return Share{}, err
	}
	s.audit(actor.actor(), identity.AuditShareRejected, shareTarget(updated),
		fmt.Sprintf("rejected a machine shared by %s", updated.SourceOrg))
	s.notifyShareParties(updated)
	return updated, nil
}

// revokeShare implements DELETE /api/v2/shares/{id}: both sides may withdraw,
// and revoking twice is a no-op.
func (s *Server) revokeShare(ctx context.Context, actor apiPrincipal, id string) (Share, error) {
	share, err := s.shareForCaller(id, actor)
	if err != nil {
		return Share{}, err
	}
	if share.TargetKind == ShareTargetAccount {
		return Share{}, errShareForbidden
	}
	if share.SourceOrg == s.Organization().ID && !actor.Role.CanWrite() {
		// Revoking an outgoing share is administration; a member may only
		// revoke the share they accepted.
		return Share{}, errShareForbidden
	}
	if share.TargetOrg == s.Organization().ID && share.SourceOrg != s.Organization().ID &&
		!s.callerMatchesShare(share, actor) {
		return Share{}, errShareNotMine
	}
	updated, err := s.shares.RevokeShare(id, s.Organization().ID, int64(actor.UserID), time.Now().UTC())
	if err != nil {
		if errors.Is(err, ErrShareState) {
			return Share{}, errShareDecision
		}
		return Share{}, err
	}
	if !updated.RevokedAt.IsZero() && updated.RevokedAt.Equal(share.RevokedAt) && share.Status == ShareRevoked {
		// Idempotent repeat: no second audit event.
		return updated, nil
	}
	s.audit(actor.actor(), identity.AuditShareRevoked, shareTarget(updated),
		fmt.Sprintf("revoked the share from %s to %s", updated.SourceOrg, updated.TargetOrg))
	s.notifyShareParties(updated)
	return updated, nil
}

// notifyShareParties wakes both organizations' netmap watchers.
func (s *Server) notifyShareParties(share Share) {
	for _, orgID := range []string{share.SourceOrg, share.TargetOrg} {
		if org := s.shareDir.Org(orgID); org != nil {
			org.ShareNotify()
		}
	}
}

// notifyNodePeers wakes this organization's netmap watchers and the
// organizations on the other side of every accepted share this node takes
// part in. Node state a shared peer can observe - endpoints, hostinfo,
// liveness, deletion, service declarations - must reach the peer's netmap
// without waiting for a client reconnect (spec section 38.6).
//
// It is a superset of notifyWatchers, so call sites announcing node changes
// use it unconditionally; a deployment without sharing just wakes itself.
func (s *Server) notifyNodePeers(node state.Node) {
	s.notifyWatchers()
	if !s.sharingEnabled() {
		return
	}
	orgID := s.Organization().ID
	if orgID == "" {
		return
	}
	// Outbound: this machine is shared into other organizations.
	for _, share := range s.shares.ListShares(ShareFilter{
		SourceOrg:  orgID,
		SourceNode: int64(node.ID),
		Statuses:   []string{ShareAccepted},
	}) {
		if org := s.shareDir.Org(share.TargetOrg); org != nil {
			org.ShareNotify()
		}
	}
	// Inbound: this machine belongs to a user who accepted a share, so the
	// source organization's netmap shows it to the shared machine.
	for _, share := range s.shares.ListShares(ShareFilter{
		TargetOrg:  orgID,
		TargetUser: int64(node.UserID),
		Statuses:   []string{ShareAccepted},
	}) {
		if org := s.shareDir.Org(share.SourceOrg); org != nil {
			org.ShareNotify()
		}
	}
}

// shareView builds the wire view of one share. direction is "outgoing" or
// "incoming" from the caller's organization point of view.
func (s *Server) shareView(share Share, direction string) shareView {
	view := shareView{
		ID:        share.ID,
		Status:    share.Status,
		Direction: direction,
		SourceOrg: share.SourceOrg,
		TargetOrg: share.TargetOrg,
		Provider:  share.Provider,
		Subject:   share.Subject,
		CreatedAt: share.CreatedAt,
	}
	view.Node = &shareNodeView{Missing: true}
	if source := s.shareDir.Org(share.SourceOrg); source != nil && source.ShareGeneration() == share.SourceGeneration {
		if node, ok := source.ShareNode(state.NodeID(share.SourceNode)); ok && node.StableID == share.SourceStableID {
			view.Node = shareNodeSummary(node, false)
		}
		if creator, ok := source.ShareUser(tailcfg.UserID(share.CreatedBy)); ok && creator.CreatedAt.UnixNano() == share.SourceUserCreated {
			view.CreatedBy = creator.LoginName
		}
	}
	targetID := share.AcceptedBy
	if share.TargetKind == ShareTargetAccount {
		targetID = share.TargetAccount
	}
	if target := s.shareDir.Org(share.TargetOrg); target != nil && target.ShareGeneration() == share.TargetGeneration && targetID != 0 {
		if user, ok := target.ShareUser(tailcfg.UserID(targetID)); ok && (share.TargetKind != ShareTargetAccount || user.CreatedAt.UnixNano() == share.TargetAccountCreated) {
			view.TargetUser = user.LoginName
		}
	}
	if !share.AcceptedAt.IsZero() {
		at := share.AcceptedAt
		view.AcceptedAt = &at
	}
	if !share.RejectedAt.IsZero() {
		at := share.RejectedAt
		view.RejectedAt = &at
	}
	if !share.RevokedAt.IsZero() {
		at := share.RevokedAt
		view.RevokedAt = &at
		if share.RevokedByOrg == share.SourceOrg {
			view.RevokedBy = "source"
		} else {
			view.RevokedBy = "target"
		}
	}
	return view
}

// shareNodeSummary renders the share-safe summary of a node.
func shareNodeSummary(node state.Node, missing bool) *shareNodeView {
	view := &shareNodeView{
		StableID: node.StableID,
		Hostname: node.Hostname,
		Missing:  missing,
	}
	if node.Hostinfo != nil {
		view.OS = node.Hostinfo.OS
		if view.Hostname == "" {
			view.Hostname = node.Hostinfo.Hostname
		}
	}
	return view
}

// listShares returns the caller's shares in one direction.
func (s *Server) listShares(direction string, actor apiPrincipal) ([]Share, error) {
	switch direction {
	case "outgoing":
		var out []Share
		for _, share := range s.shares.ListShares(ShareFilter{SourceOrg: s.Organization().ID}) {
			if share.SourceGeneration == s.ShareGeneration() {
				out = append(out, share)
			}
		}
		return out, nil
	case "incoming":
		out := make([]Share, 0, 4)
		seen := make(map[string]bool)
		if actor.Kind == "session" {
			for _, share := range s.shares.ListShares(ShareFilter{TargetOrg: s.Organization().ID, TargetKind: ShareTargetAccount, TargetAccount: int64(actor.UserID)}) {
				if s.callerMatchesShare(share, actor) {
					out = append(out, share)
					seen[share.ID] = true
				}
			}
		}
		for _, ei := range s.identity.ListExternalIdentities(actor.UserID) {
			for _, share := range s.shares.ListShares(ShareFilter{
				TargetOrg: s.Organization().ID,
				Provider:  ei.ProviderID,
				Subject:   ei.Subject,
			}) {
				if share.TargetGeneration != s.ShareGeneration() {
					continue
				}
				if share.Status == ShareAccepted && share.AcceptedBy != int64(actor.UserID) {
					// Another user in the same organization completed an
					// identity-colliding invite; it is not this caller's.
					continue
				}
				if seen[share.ID] {
					// Two links with the same (provider, subject) would list
					// the share twice; one identity key is one row.
					continue
				}
				seen[share.ID] = true
				out = append(out, share)
			}
		}
		return out, nil
	default:
		return nil, errShareIdentityInvalid
	}
}

// 控制面每次投影都校验双方实例和账户，不能只相信曾经 accepted 的记录。
func (s *Server) boundShareParties(share Share) (ShareOrg, ShareOrg, state.Node, bool) {
	source, target := s.shareDir.Org(share.SourceOrg), s.shareDir.Org(share.TargetOrg)
	if source == nil || target == nil || source.ShareGeneration() != share.SourceGeneration || target.ShareGeneration() != share.TargetGeneration || source.ShareTKAEnabled() || target.ShareTKAEnabled() {
		return nil, nil, state.Node{}, false
	}
	node, ok := source.ShareNode(state.NodeID(share.SourceNode))
	if !ok || node.StableID != share.SourceStableID {
		return nil, nil, state.Node{}, false
	}
	creator, ok := source.ShareUser(tailcfg.UserID(share.CreatedBy))
	if !ok || !creator.DisabledAt.IsZero() || creator.CreatedAt.UnixNano() != share.SourceUserCreated {
		return nil, nil, state.Node{}, false
	}
	owner, ok := source.ShareUser(node.UserID)
	if !ok || !owner.DisabledAt.IsZero() {
		return nil, nil, state.Node{}, false
	}
	userID := share.AcceptedBy
	if share.TargetKind == ShareTargetAccount {
		userID = share.TargetAccount
	}
	if userID != 0 {
		user, ok := target.ShareUser(tailcfg.UserID(userID))
		if !ok || !user.DisabledAt.IsZero() || (share.TargetKind == ShareTargetAccount && (user.CreatedAt.UnixNano() != share.TargetAccountCreated || (share.Status == ShareAccepted && share.AcceptedBy != userID))) {
			return nil, nil, state.Node{}, false
		}
		if share.TargetKind == ShareTargetExternal && !target.ShareIdentityMatches(user.ID, share.Provider, share.Subject) {
			return nil, nil, state.Node{}, false
		}
	}
	return source, target, node, true
}

func (s *Server) notifyUserShares(userID tailcfg.UserID) {
	if !s.sharingEnabled() {
		return
	}
	for _, share := range s.shares.ListShares(ShareFilter{SourceOrg: s.Organization().ID, Statuses: []string{ShareAccepted}}) {
		s.notifyShareParties(share)
	}
	for _, share := range s.shares.ListShares(ShareFilter{TargetOrg: s.Organization().ID, TargetUser: int64(userID), Statuses: []string{ShareAccepted}}) {
		s.notifyShareParties(share)
	}
}
