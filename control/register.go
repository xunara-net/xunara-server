package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"

	"github.com/xunara-net/xunara-server/control/mapper"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/networkconfig"
	"github.com/xunara-net/xunara-server/state"
)

// registrationTTL bounds how long an interactive registration may stay pending
// before a follow-up restarts it.
const registrationTTL = 10 * time.Minute

// pendingRegistration tracks a node that is mid interactive login. It is
// deliberately separate from node state and from any future session: an
// authorization transaction is not a session (AGENTS.md section 10).
type pendingRegistration struct {
	id         string
	machineKey key.MachinePublic
	req        tailcfg.RegisterRequest
	created    time.Time

	done     chan struct{}
	approved bool
}

// handleRegister implements POST /machine/register inside a Noise session.
func (ns *noiseServer) handleRegister(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		httpError(w, NewHTTPError(http.StatusMethodNotAllowed, "method not allowed", nil))
		return
	}

	var registerRequest tailcfg.RegisterRequest
	decodeErr := json.NewDecoder(req.Body).Decode(&registerRequest)

	// Enforce the version floor even when the body failed to decode: whatever
	// version was read is what is checked.
	if ns.rejectUnsupported(w, registerRequest.Version, registerRequest.NodeKey) {
		return
	}

	resp := func() *tailcfg.RegisterResponse {
		if decodeErr != nil {
			return &tailcfg.RegisterResponse{Error: decodeErr.Error()}
		}

		out, err := ns.server.handleRegister(req.Context(), registerRequest, ns.machineKey)
		if err != nil {
			var he HTTPError
			if errors.As(err, &he) {
				return &tailcfg.RegisterResponse{Error: he.Msg}
			}
			return &tailcfg.RegisterResponse{Error: err.Error()}
		}
		return out
	}()

	writeJSON(w, http.StatusOK, resp)

	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// handleRegister is the transport-independent registration decision.
func (s *Server) handleRegister(ctx context.Context, req tailcfg.RegisterRequest, machineKey key.MachinePublic) (*tailcfg.RegisterResponse, error) {
	if scope := s.deviceScope.Load(); scope != nil {
		if err := scope.Check(ctx, machineKey, req.NodeKey); err != nil {
			return nil, NewHTTPError(http.StatusUnauthorized, "device network unavailable", nil)
		}
	}
	// Tailnet lock: a registration that presents a node-key signature claims
	// the node key is authorized by the tailnet's key authority. Verify that
	// claim before the request can create or rotate a node, so an
	// unverifiable signature is never silently downgraded to an unsigned
	// registration.
	//
	// While the tailnet is unlocked a signature carries no authority: it is
	// dropped from the request copy so it can never reach state. Once lock is
	// enabled, init/finish issues signatures for every existing node, and a
	// node that has not been signed is filtered out of the netmap instead.
	if len(req.NodeKeySignature) > 0 {
		if !s.tka.view().Enabled {
			req.NodeKeySignature = nil
		} else if err := s.tka.nodeKeyAuthorized(req.NodeKey, req.NodeKeySignature); err != nil {
			s.log.Warn("rejecting registration with an unauthorized node key signature",
				"node.key", req.NodeKey.ShortString(),
				"machine.key", machineKey.ShortString(),
				"err", err)
			return nil, NewHTTPError(http.StatusUnauthorized, "node key signature is not authorized", err)
		}
	}

	// Tailnet lock: a client that regenerates its node key (expired key,
	// `tailscale up` re-auth) can carry the old key's signature forward by
	// re-signing it locally with the node's network-lock key, producing a
	// rotation signature. It cannot do that until it has the old signature, so
	// a non-empty RegisterResponse.NodeKeySignature means "resign and retry"
	// (upstream control/controlclient doLoginOrRegen).
	if resp, ok := s.rotationSignatureHint(req, machineKey); ok {
		return resp, nil
	}

	resp, err := s.decideRegistration(ctx, req, machineKey)
	if err != nil {
		return nil, err
	}
	s.storeRegistrationKeys(ctx, req, machineKey)
	return resp, nil
}

// rotationSignatureHint answers a registration that rotates a signed node key
// with the signature the client must chain-resign.
//
// The client re-registers with a fresh node key while naming its previous key
// in OldNodeKey. If that previous key's node carries a stored node-key
// signature, the control plane hands the signature back: the client wraps it
// in a rotation signature signed by its own network-lock key and retries. The
// hint is deliberately narrow:
//
//   - only when tailnet lock is enabled (an unsigned tailnet needs no
//     authorization for the new key),
//   - only when the request brings no signature (a rotation signature is
//     already the answer),
//   - never for a logout, which must not be turned into a re-registration,
//   - only when OldNodeKey names a signed node of the same machine, and
//   - never for a follow-up poll, which belongs to a pending registration that
//     already validated its own signature.
func (s *Server) rotationSignatureHint(req tailcfg.RegisterRequest, machineKey key.MachinePublic) (*tailcfg.RegisterResponse, bool) {
	if !s.tka.view().Enabled || len(req.NodeKeySignature) > 0 || req.Followup != "" {
		return nil, false
	}
	// A request whose expiry is in the past is a logout (see
	// decideRegistration); the client is leaving, not rotating a key.
	if !req.Expiry.IsZero() && req.Expiry.Before(time.Now()) {
		return nil, false
	}
	if req.OldNodeKey.IsZero() || req.OldNodeKey == req.NodeKey {
		return nil, false
	}
	if _, ok := s.store.GetNodeByNodeKey(req.NodeKey); ok {
		// The presented node key is already registered: this is an ordinary
		// re-registration, not a rotation in flight.
		return nil, false
	}
	old, ok := s.store.GetNodeByNodeKey(req.OldNodeKey)
	if !ok || old.MachineKey != machineKey || len(old.KeySignature) == 0 {
		return nil, false
	}
	// Only a signature issued against the node's RotationPubkey can be chained
	// by the node itself, and only the matching network-lock key can do the
	// chaining. Handing the signature back in any other case would cost the
	// client a retry that can only fail verification.
	var decoded tka.NodeKeySignature
	if err := decoded.Unserialize(old.KeySignature); err != nil {
		s.log.Warn("stored node key signature does not decode", "stable_id", old.StableID, "err", err)
		return nil, false
	}
	wrapping, ok := decoded.UnverifiedWrappingPublic()
	if !ok || len(wrapping) != ed25519.PublicKeySize {
		s.log.Warn("node key signature has no rotation key, sign the node again to enable node-key rotation",
			"stable_id", old.StableID, "node_key", old.NodeKey.ShortString())
		return nil, false
	}
	if req.NLKey.IsZero() || !bytes.Equal(wrapping, req.NLKey.Verifier()) {
		s.log.Warn("node reports a different network-lock key than its signature wraps, sign the node again",
			"stable_id", old.StableID, "node_key", old.NodeKey.ShortString())
		return nil, false
	}

	s.log.Info("asking node to rotate its node-key signature",
		"stable_id", old.StableID,
		"old_node_key", req.OldNodeKey.ShortString(),
		"new_node_key", req.NodeKey.ShortString())
	return &tailcfg.RegisterResponse{NodeKeySignature: slices.Clone(old.KeySignature)}, true
}

// storeRegistrationKeys persists what a successful registration reported about
// the node's keys: its tailnet-lock public key (used to authorize later node
// key rotations) and the node-key signature it presented.
//
// Signatures only reach this point when they were verified against the key
// authority (handleRegister drops unverified ones), and they are only stored
// once the node they belong to exists. A pending interactive registration
// keeps them in its device authorization instead, and applies them at
// approval.
func (s *Server) storeRegistrationKeys(ctx context.Context, req tailcfg.RegisterRequest, machineKey key.MachinePublic) {
	if req.NLKey.IsZero() && len(req.NodeKeySignature) == 0 {
		return
	}
	node, changed, err := s.networkConfig.RegistrationKeys(ctx, machineKey, req.NodeKey, req.NLKey, req.NodeKeySignature)
	if errors.Is(err, state.ErrRouteNodeNotFound) {
		return
	}
	if err != nil {
		s.log.Error("storing registration keys", "err", err)
		return
	}
	if changed {
		s.notifyNodePeers(node)
	}
}

// decideRegistration applies the registration state machine.
func (s *Server) decideRegistration(ctx context.Context, req tailcfg.RegisterRequest, machineKey key.MachinePublic) (*tailcfg.RegisterResponse, error) {
	// 1. Logout: a request whose expiry is in the past is a logout, regardless
	//    of any other field. It takes precedence over an auth key.
	if !req.Expiry.IsZero() && req.Expiry.Before(time.Now()) {
		if node, ok := s.store.GetNodeByNodeKey(req.NodeKey); ok {
			if node.MachineKey != machineKey {
				return nil, NewHTTPError(http.StatusUnauthorized,
					"machine key does not match node", nil)
			}
			if err := s.store.DeleteNode(node.ID); err != nil {
				return nil, fmt.Errorf("deleting logged-out node: %w", err)
			}
			s.audit(nodeActor(node), identity.AuditNodeDeleted, nodeTarget(node), "client logout")
			// Peers must drop the node from their netmaps.
			s.notifyNodePeers(node)
		}
		return &tailcfg.RegisterResponse{}, nil
	}

	// 2. Known node: re-registration after a client restart. The machine key
	//    from the Noise session must match the stored one, otherwise a holder of
	//    the node key could impersonate the machine.
	if node, ok := s.store.GetNodeByNodeKey(req.NodeKey); ok {
		if node.MachineKey != machineKey {
			return nil, NewHTTPError(http.StatusUnauthorized,
				"machine key does not match existing node key", nil)
		}
		// A non-zero expiry on an existing node is the client asking for its
		// key to expire sooner (upstream LocalBackend.SetExpirySooner).
		if !req.Expiry.IsZero() {
			shortened, err := s.shortenNodeExpiry(ctx, node, req.Expiry)
			if err != nil {
				return nil, err
			}
			node = shortened
		}
		return s.nodeToRegisterResponse(node), nil
	}

	// 3. Follow-up: the client already started a login and is polling for the
	//    result.
	if req.Followup != "" {
		return s.waitForFollowup(ctx, req, machineKey)
	}

	// 4. Pre-authentication key: the client can be authorized synchronously.
	if req.Auth != nil && req.Auth.AuthKey != "" {
		return s.registerWithAuthKey(ctx, req, machineKey)
	}

	// 预授权路径在写事务内区分新建与轮换；满额不能阻止现有机器重新认证。
	if err := s.assertDeviceQuota(); err != nil {
		return nil, err
	}

	// 5. Interactive login: create a pending registration and hand the client a
	//    URL to visit.
	return s.startInteractiveRegistration(ctx, req, machineKey)
}

// shortenNodeExpiry applies a client-requested key expiry to an existing node.
//
// The request may only ever shorten: a node cannot extend its own key expiry
// (that is an administrator decision), and a value in the past is a logout,
// which the caller handles before reaching here. Both refusals are explicit so
// a client never believes an extension took effect.
func (s *Server) shortenNodeExpiry(ctx context.Context, node state.Node, requested time.Time) (state.Node, error) {
	now := time.Now()
	if !requested.After(now) {
		return node, NewHTTPError(http.StatusBadRequest, "an expiry in the past is a logout", nil)
	}
	if node.Expiry.IsZero() {
		// Zero means "never expires" (tagged nodes, or a deployment without a
		// key expiry policy): switching to a finite expiry is not a
		// shortening, and tag ownership, not the node, decides the lifetime.
		return node, NewHTTPError(http.StatusBadRequest, "this node key does not expire", nil)
	}
	if !requested.Before(node.Expiry) {
		return node, NewHTTPError(http.StatusBadRequest, "extending the node key expiry is not allowed", nil)
	}

	updated, err := s.networkConfig.ShortenNodeExpiry(ctx, node, requested)
	if err != nil {
		if errors.Is(err, state.ErrExpiryNotEarlier) || errors.Is(err, state.ErrDeviceChanged) {
			return node, NewHTTPError(http.StatusBadRequest, "node key expiry may only be shortened; refresh the node state", nil)
		}
		return node, fmt.Errorf("updating node expiry: %w", err)
	}
	// Peers see the new expiry in the netmap, so wake the streaming sessions.
	s.notifyNodePeers(updated)
	return updated, nil
}

// registerWithAuthKey authorizes a node from a pre-authentication key.
//
// The key authorizes a *machine*; the resulting node is still an independent
// identity. A key is single-use unless it was created reusable.
func (s *Server) registerWithAuthKey(ctx context.Context, req tailcfg.RegisterRequest, machineKey key.MachinePublic) (*tailcfg.RegisterResponse, error) {
	want := state.Node{MachineKey: machineKey, NodeKey: req.NodeKey, Hostinfo: req.Hostinfo,
		Ephemeral: req.Ephemeral, RequestedExpiry: req.Expiry, NLKey: req.NLKey, KeySignature: slices.Clone(req.NodeKeySignature)}
	if req.Hostinfo != nil {
		want.Hostname = req.Hostinfo.Hostname
	}
	node, err := s.networkConfig.EnrollAuthKey(ctx, req.Auth.AuthKey, want, s.Plan().MaxDevices, s.applyRegistrationDefaults)
	if err != nil {
		switch {
		case errors.Is(err, state.ErrPreAuthKeyNotUsable):
			return nil, NewHTTPError(http.StatusUnauthorized, "invalid pre-auth key", nil)
		case errors.Is(err, state.ErrDeviceLimit):
			return nil, planGateError(MsgDeviceLimitReached)
		case errors.Is(err, state.ErrNodeKeyExists), errors.Is(err, state.ErrAmbiguousMachine):
			return nil, NewHTTPError(http.StatusConflict, "machine or node key is already bound", nil)
		default:
			return nil, NewHTTPError(http.StatusServiceUnavailable, "device enrollment could not be committed", err)
		}
	}
	s.notifyNodePeers(node)
	return s.nodeToRegisterResponse(node), nil
}

// nodeActor names a node as an audit actor for machine-initiated events.
func nodeActor(n state.Node) string { return "node:" + n.StableID }

// nodeTarget names a node as an audit target.
func nodeTarget(n state.Node) string { return "node:" + n.StableID }

// nodeToRegisterResponse builds an authorized registration response for a node.
//
// The user and login name come from the trust plane, so a client shows the
// actual human the node belongs to.
//
// An expired node key is reported through NodeKeyExpired: the client answers by
// generating a fresh node key and re-registering with the old key named in
// OldNodeKey (upstream controlclient doLoginOrRegen). Without the flag the
// client would keep presenting the expired key until it rebuilt the netmap,
// only to learn from KeyExpiry that it must log in again.
func (s *Server) nodeToRegisterResponse(n state.Node) *tailcfg.RegisterResponse {
	// The node key, not the machine, expires: the client replaces it and keeps
	// the machine identity, which is what this response authorizes.
	expired := n.Expired(time.Now())

	// Tagged nodes belong to their tags, not to a human: report the reserved
	// tagged-devices identity, as headscale does via node.Owner().
	if len(n.Tags) > 0 {
		profile := mapper.TaggedDevicesProfile()
		return &tailcfg.RegisterResponse{
			NodeKeyExpired:    expired,
			MachineAuthorized: true,
			User: tailcfg.User{
				ID:          profile.ID,
				DisplayName: profile.DisplayName,
				Created:     n.Created,
			},
			Login: tailcfg.Login{
				ID:          tailcfg.LoginID(profile.ID),
				LoginName:   profile.LoginName,
				DisplayName: profile.DisplayName,
			},
		}
	}

	profile := s.UserProfile(n.UserID)

	provider := state.DefaultProvider
	if links := s.identity.ListExternalIdentities(n.UserID); len(links) > 0 {
		provider = links[0].ProviderID
	}

	return &tailcfg.RegisterResponse{
		NodeKeyExpired:    expired,
		MachineAuthorized: true,
		User: tailcfg.User{
			ID:          n.UserID,
			DisplayName: profile.DisplayName,
			Created:     n.Created,
		},
		Login: tailcfg.Login{
			ID:          tailcfg.LoginID(n.UserID),
			Provider:    provider,
			LoginName:   profile.LoginName,
			DisplayName: profile.DisplayName,
		},
	}
}

// deviceMetadata is the durable description of a pending registration. It
// lives with the device authorization so that any instance can render the
// approval page and create the node without a server-local map.
type deviceMetadata struct {
	Hostname        string            `json:"hostname,omitempty"`
	OS              string            `json:"os,omitempty"`
	Ephemeral       bool              `json:"ephemeral,omitempty"`
	RequestedExpiry time.Time         `json:"requested_expiry,omitempty"`
	Hostinfo        *tailcfg.Hostinfo `json:"hostinfo,omitempty"`

	// NLKey is the device's tailnet-lock public key. It is captured here so
	// that a node approved later (possibly on another instance) learns the
	// key its administrator needs to sign a rotatable node key.
	NLKey key.NLPublic `json:"nl_key,omitempty"`
	// NodeKeySignature is the node-key signature the device presented when it
	// started this registration. It is verified before it is recorded, and
	// applied to the node at approval.
	NodeKeySignature tkatype.MarshaledSignature `json:"node_key_signature,omitempty"`
}

// requestedTags are the ACL tags the client asked to claim during
// registration ("tailscale up --advertise-tags").
func (m deviceMetadata) requestedTags() []string {
	if m.Hostinfo == nil {
		return nil
	}
	return m.Hostinfo.RequestTags
}

// authorizedTags resolves the tags a client asked to claim for a device.
//
// Every requested tag must be well-formed and owned by the authorizing user
// under the current policy. One rejected tag fails the whole registration:
// silently dropping a tag would let a client believe it holds a capability it
// does not have (this matches the upstream behaviour).
func (s *Server) authorizedTags(userID tailcfg.UserID, requested []string, target string) ([]string, error) {
	if len(requested) == 0 {
		return nil, nil
	}

	login := s.UserProfile(userID).LoginName
	engine := s.policy.Load()
	if engine == nil {
		s.audit(fmt.Sprintf("user:%d", userID), identity.AuditTagRejected, target,
			"the tailnet has no policy, so no tag can be claimed")
		return nil, NewHTTPError(http.StatusForbidden,
			"This tailnet has no ACL policy, so no tag can be claimed.", nil)
	}

	for _, raw := range requested {
		tag := strings.TrimSpace(raw)
		if tag == "" {
			continue
		}
		if _, err := state.NormalizeTags([]string{tag}); err != nil {
			s.audit(fmt.Sprintf("user:%d", userID), identity.AuditTagRejected, target,
				"a requested tag is malformed")
			return nil, NewHTTPError(http.StatusBadRequest,
				"The device requested a malformed tag.", nil)
		}
		if !engine.UserOwnsTag(login, tag) {
			s.audit(fmt.Sprintf("user:%d", userID), identity.AuditTagRejected, target,
				tag+" is not owned by "+login)
			return nil, NewHTTPError(http.StatusForbidden,
				"Tag "+tag+" is not owned by "+login+" in this tailnet's policy.", nil)
		}
	}

	tags, err := state.NormalizeTags(requested)
	if err != nil {
		return nil, NewHTTPError(http.StatusBadRequest,
			"The device requested a malformed tag.", nil)
	}
	return tags, nil
}

// encodeDeviceMetadata serialises the client-provided registration details.
func encodeDeviceMetadata(req tailcfg.RegisterRequest) string {
	meta := deviceMetadata{
		Ephemeral:        req.Ephemeral,
		RequestedExpiry:  req.Expiry,
		NLKey:            req.NLKey,
		NodeKeySignature: slices.Clone(req.NodeKeySignature),
	}
	if req.Hostinfo != nil {
		meta.Hostname = req.Hostinfo.Hostname
		meta.OS = req.Hostinfo.OS
		meta.Hostinfo = req.Hostinfo
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// decodeDeviceMetadata parses stored metadata, tolerating rows written by
// older builds.
func decodeDeviceMetadata(raw string) deviceMetadata {
	var meta deviceMetadata
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &meta)
	}
	return meta
}

// startInteractiveRegistration creates a pending registration and returns the
// login URL the client should show to the user.
func (s *Server) startInteractiveRegistration(ctx context.Context, req tailcfg.RegisterRequest, machineKey key.MachinePublic) (*tailcfg.RegisterResponse, error) {
	// The durable half of the device flow: the approval page and node
	// creation both work from this row, so an approval can be served by any
	// instance.
	authorization, err := s.identity.CreatePendingDeviceAuthorization(ctx, identity.NewDeviceAuthorizationOptions{
		ID:              newAuthID(),
		MachineKey:      machineKey.String(),
		NodeKey:         req.NodeKey.String(),
		RequestedAction: "register",
		ClientMetadata:  encodeDeviceMetadata(req),
		TTL:             registrationTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("recording device authorization: %w", err)
	}

	pr := &pendingRegistration{
		id:         authorization.ID,
		machineKey: machineKey,
		req:        req,
		created:    authorization.CreatedAt,
		done:       make(chan struct{}),
	}

	s.mu.Lock()
	if existing := s.pending[pr.id]; existing == nil {
		s.pending[pr.id] = pr
	}
	s.pendingByNode[req.NodeKey] = pr.id
	s.mu.Unlock()

	return &tailcfg.RegisterResponse{AuthURL: s.authURL(pr.id)}, nil
}

// waitForFollowup blocks until a pending interactive registration completes.
//
// The in-memory pending registration is only a fast-path wakeup for the
// instance that created it; the durable device authorization decides what the
// client is told, so follow-ups work across instances.
func (s *Server) waitForFollowup(ctx context.Context, req tailcfg.RegisterRequest, machineKey key.MachinePublic) (*tailcfg.RegisterResponse, error) {
	s.mu.Lock()
	id, ok := s.pendingByNode[req.NodeKey]
	var pr *pendingRegistration
	if ok {
		pr = s.pending[id]
	}
	s.mu.Unlock()

	if pr != nil && pr.machineKey == machineKey && time.Since(pr.created) <= registrationTTL {
		select {
		case <-pr.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if node, ok := s.store.GetNodeByNodeKey(req.NodeKey); ok {
			if node.MachineKey != machineKey {
				return nil, NewHTTPError(http.StatusUnauthorized, "machine key does not match node", nil)
			}
			return s.nodeToRegisterResponse(node), nil
		}
	}

	if node, ok := s.store.GetNodeByNodeKey(req.NodeKey); ok {
		if node.MachineKey != machineKey {
			return nil, NewHTTPError(http.StatusUnauthorized, "machine key does not match node", nil)
		}
		return s.nodeToRegisterResponse(node), nil
	}

	if da, err := s.identity.LookupDeviceAuthorizationByKeys(ctx, machineKey.String(), req.NodeKey.String()); err == nil {
		switch {
		case da.State == identity.DeviceDenied:
			return nil, NewHTTPError(http.StatusForbidden, "registration denied", nil)
		case da.Pending() && !da.Expired(time.Now()):
			// Keep the client polling the same URL: approval may land on any
			// instance and will be visible in the store.
			return &tailcfg.RegisterResponse{AuthURL: s.authURL(da.ID)}, nil
		}
	} else if !errors.Is(err, identity.ErrDeviceNotFound) {
		return nil, err
	}

	if pr != nil {
		s.dropPending(pr.id)
	}
	return s.startInteractiveRegistration(ctx, req, machineKey)
}

// ApproveRegistration authorizes a pending interactive registration as the
// built-in local user.
//
// This is the seam tests and embedding code call; the web flow uses
// approveDevice with the signed-in user.
func (s *Server) ApproveRegistration(authID string) error {
	_, err := s.approveDevice(authID, state.DefaultUserID, "admin")
	return err
}

// approveDevice 仅供私有内嵌管理调用；HTTP 请求传递实际会话或服务凭据。
func (s *Server) approveDevice(authID string, userID tailcfg.UserID, actor string) (identity.DeviceAuthorization, error) {
	return s.decideDevice(context.Background(), authID, userID, actor, nil, true)
}

func (server *Server) decideDevice(ctx context.Context, authID string, userID tailcfg.UserID, actor string, writer *networkconfig.Writer, approve bool) (identity.DeviceAuthorization, error) {
	authorization, err := server.identity.LookupDeviceAuthorization(ctx, authID)
	if err != nil {
		return authorization, deviceDecisionError(err)
	}
	decision := networkconfig.DeviceDecision{UserID: userID, Actor: actor, Writer: writer, Approve: approve, DeviceLimit: server.Plan().MaxDevices}
	if scope := server.deviceScope.Load(); scope != nil && approve {
		var machine key.MachinePublic
		var nodeKey key.NodePublic
		if machine.UnmarshalText([]byte(authorization.MachineKey)) != nil || nodeKey.UnmarshalText([]byte(authorization.NodeKey)) != nil {
			return authorization, NewHTTPError(http.StatusConflict, "invalid device identity", nil)
		}
		if err := scope.Check(ctx, machine, nodeKey); err != nil {
			return authorization, NewHTTPError(http.StatusConflict, "DEVICE_NETWORK_REQUIRED: restart device sign-in and log in to your account", nil)
		}
	}
	if approve && authorization.Pending() && !authorization.Expired(time.Now()) {
		server.networkMu.Lock()
		err := server.loadPolicyLocked(ctx)
		if err == nil {
			decision.Node, err = server.nodeForAuthorization(authorization, userID, time.Now().UTC())
			if configuration := server.policyConfig.Load(); configuration != nil {
				decision.PolicyRevision = configuration.Revision
			}
		}
		server.networkMu.Unlock()
		if err != nil {
			return authorization, deviceDecisionError(err)
		}
	}
	decided, node, err := server.networkConfig.DecideDevice(ctx, authorization, decision)
	if err != nil {
		return authorization, deviceDecisionError(err)
	}
	server.wakePending(authID)
	if node.ID != 0 {
		server.notifyNodePeers(node)
	}
	return decided, nil
}

func deviceDecisionError(err error) error {
	switch {
	case errors.Is(err, identity.ErrDeviceNotFound):
		return NewHTTPError(http.StatusNotFound, "unknown registration", err)
	case errors.Is(err, identity.ErrDeviceExpired):
		return NewHTTPError(http.StatusGone, "registration expired", err)
	case errors.Is(err, identity.ErrDeviceDecided):
		return NewHTTPError(http.StatusConflict, "registration was already decided", err)
	case errors.Is(err, identity.ErrNetworkWriterForbidden), errors.Is(err, identity.ErrSessionRevoked):
		return NewHTTPError(http.StatusForbidden, "device approval permission is no longer valid", err)
	case errors.Is(err, state.ErrDeviceLimit):
		return planGateError(MsgDeviceLimitReached)
	case errors.Is(err, state.ErrDeviceChanged), errors.Is(err, state.ErrAmbiguousMachine), errors.Is(err, networkconfig.ErrConflict):
		return NewHTTPError(http.StatusConflict, "device identity or policy changed; refresh before approving", err)
	default:
		return err
	}
}

// nodeForAuthorization builds the node an approved device authorization
// describes.
func (s *Server) nodeForAuthorization(da identity.DeviceAuthorization, userID tailcfg.UserID, now time.Time) (state.Node, error) {
	var machineKey key.MachinePublic
	if err := machineKey.UnmarshalText([]byte(da.MachineKey)); err != nil {
		return state.Node{}, fmt.Errorf("device authorization %s has an invalid machine key: %w", da.ID, err)
	}
	var nodeKey key.NodePublic
	if err := nodeKey.UnmarshalText([]byte(da.NodeKey)); err != nil {
		return state.Node{}, fmt.Errorf("device authorization %s has an invalid node key: %w", da.ID, err)
	}

	meta := decodeDeviceMetadata(da.ClientMetadata)
	tags, err := s.authorizedTags(userID, meta.requestedTags(), "device:"+da.ID)
	if err != nil {
		return state.Node{}, err
	}
	node := state.Node{
		MachineKey:      machineKey,
		NodeKey:         nodeKey,
		KeySignature:    meta.NodeKeySignature,
		NLKey:           meta.NLKey,
		UserID:          userID,
		Hostname:        meta.Hostname,
		Hostinfo:        meta.Hostinfo,
		Method:          state.RegisterMethodInteractive,
		Ephemeral:       meta.Ephemeral,
		RequestedExpiry: meta.RequestedExpiry,
		Tags:            tags,
	}
	s.applyRegistrationDefaults(&node, now)
	return node, nil
}

// wakePending wakes the waiter blocked on a pending registration, if this
// instance holds one.
func (s *Server) wakePending(authID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pr, ok := s.pending[authID]
	if !ok {
		return
	}
	delete(s.pending, authID)
	if cur, ok := s.pendingByNode[pr.req.NodeKey]; ok && cur == authID {
		delete(s.pendingByNode, pr.req.NodeKey)
	}
	if !pr.approved {
		pr.approved = true
		close(pr.done)
	}
}

// dropPending removes a pending registration from the index.
func (s *Server) dropPending(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pr, ok := s.pending[id]
	if !ok {
		return
	}
	delete(s.pending, id)
	if cur, ok := s.pendingByNode[pr.req.NodeKey]; ok && cur == id {
		delete(s.pendingByNode, pr.req.NodeKey)
	}
}

func (s *Server) authURL(authID string) string {
	return fmt.Sprintf("%s/register/%s", s.consoleURL(), authID)
}

// handleRegisterPage serves the device approval page a user opens from the
// AuthURL the client printed.
func (s *Server) handleRegisterPage(w http.ResponseWriter, req *http.Request) {
	authID := chi.URLParam(req, "authID")

	da, ok := s.identity.GetDeviceAuthorization(authID)
	if !ok {
		s.renderError(w, req, http.StatusNotFound, "Unknown login link",
			"This login link is unknown or has expired. Re-run `tailscale up` to get a new one.")
		return
	}
	switch {
	case da.Expired(time.Now()):
		s.renderError(w, req, http.StatusGone, "Login link expired",
			"This login link has expired. Re-run `tailscale up` to get a new one.")
		return
	case da.State != identity.DevicePending:
		s.renderDecidedPage(w, req, string(da.State))
		return
	}

	session, ok := s.currentSession(req)
	if !ok {
		http.Redirect(w, req, "/login?return_to="+url.QueryEscape("/register/"+authID), http.StatusFound)
		return
	}

	profile := s.UserProfile(session.UserID)
	meta := decodeDeviceMetadata(da.ClientMetadata)
	hostname := meta.Hostname
	if hostname == "" {
		hostname = "unnamed device"
	}
	os := meta.OS
	if os == "" {
		os = "unknown"
	}

	s.renderApprovePage(w, req, map[string]any{
		"AuthID":      authID,
		"CanWrite":    s.userCanWrite(session.UserID),
		"Hostname":    hostname,
		"OS":          os,
		"Created":     s.consoleTime(da.CreatedAt),
		"LoginName":   profile.LoginName,
		"CSRF":        csrfTokenFor(s.sessionToken(req)),
		"ApprovalURL": s.consoleURL() + "/register/" + authID + "/approve",
		"DenialURL":   s.consoleURL() + "/register/" + authID + "/deny",
		"NetworkID":   s.Organization().ID,
	})
}

// handleApproveDevice implements POST /register/{authID}/approve.
func (s *Server) handleApproveDevice(w http.ResponseWriter, req *http.Request) {
	authID := chi.URLParam(req, "authID")

	session, token, ok := s.requireSession(w, req, "/register/"+authID)
	if !ok {
		return
	}
	if !s.userCanWrite(session.UserID) {
		s.renderError(w, req, http.StatusForbidden, "Approval rejected",
			"Your role does not allow admitting devices.")
		return
	}
	if !checkCSRF(req, token) {
		s.renderError(w, req, http.StatusForbidden, "Approval rejected",
			"The form token is invalid. Reload the page and try again.")
		return
	}

	writer := networkconfig.Writer{UserID: session.UserID, SessionID: session.ID}
	if _, err := s.decideDevice(req.Context(), authID, session.UserID, writer.Actor(), &writer, true); err != nil {
		s.renderDeviceError(w, req, err, "Approval failed")
		return
	}
	s.renderDecidedPage(w, req, string(identity.DeviceApproved))
}

// handleDenyDevice implements POST /register/{authID}/deny.
func (s *Server) handleDenyDevice(w http.ResponseWriter, req *http.Request) {
	authID := chi.URLParam(req, "authID")

	session, token, ok := s.requireSession(w, req, "/register/"+authID)
	if !ok {
		return
	}
	if !s.userCanWrite(session.UserID) {
		s.renderError(w, req, http.StatusForbidden, "Denial rejected",
			"Your role does not allow deciding device registrations.")
		return
	}
	if !checkCSRF(req, token) {
		s.renderError(w, req, http.StatusForbidden, "Denial rejected",
			"The form token is invalid. Reload the page and try again.")
		return
	}

	writer := networkconfig.Writer{UserID: session.UserID, SessionID: session.ID}
	if _, err := s.decideDevice(req.Context(), authID, session.UserID, writer.Actor(), &writer, false); err != nil {
		s.renderDeviceError(w, req, err, "Denial failed")
		return
	}
	s.renderDecidedPage(w, req, string(identity.DeviceDenied))
}

// renderDeviceError maps a device approval error to a page.
func (s *Server) renderDeviceError(w http.ResponseWriter, req *http.Request, err error, title string) {
	var he HTTPError
	if errors.As(err, &he) {
		s.renderError(w, req, he.Code, title, s.translateMessage(req, he.Msg))
		return
	}
	s.log.Error("device registration failed", "err", err)
	s.renderError(w, req, http.StatusInternalServerError, title, "Please try again.")
}

// newAuthID returns an unguessable registration identifier.
func newAuthID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("control: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
