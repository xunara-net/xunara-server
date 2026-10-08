package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"

	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// This file implements the tailnet-lock (TKA) inner endpoints official clients
// call. All of them are GET requests with a JSON body, follow the wire shapes
// in tailcfg.TKA*, and are authenticated the same way as the rest of the
// machine API: the body's NodeKey must belong to the Noise session's machine
// key, and the client must meet the capability floor.
//
// Reference: reference/tailscale/ipn/ipnlocal/tailnet-lock.go (client shape),
// reference/tailscale/tstest/tkatest (mock-control semantics).

// authorizeTKA validates the version floor of a TKA request and resolves the
// calling node, writing the error response itself when it fails.
func (ns *noiseServer) authorizeTKA(w http.ResponseWriter, version tailcfg.CapabilityVersion, nodeKey key.NodePublic) (state.Node, bool) {
	if ns.rejectUnsupported(w, version, nodeKey) {
		return state.Node{}, false
	}
	node, err := ns.getAndValidateNode(tailcfg.MapRequest{NodeKey: nodeKey})
	if err != nil {
		httpError(w, err)
		return state.Node{}, false
	}
	return node, true
}

// handleTKAInitBegin implements GET /machine/tka/init/begin: an administrator
// node submits the genesis AUM created by `tailscale lock init`, and learns
// which existing node keys must be signed before enforcement starts.
func (ns *noiseServer) handleTKAInitBegin(w http.ResponseWriter, req *http.Request) {
	var body tailcfg.TKAInitBeginRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, err)
		return
	}
	node, ok := ns.authorizeTKA(w, body.Version, body.NodeKey)
	if !ok {
		return
	}

	var genesis tka.AUM
	if err := genesis.Unserialize(body.GenesisAUM); err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, "invalid genesis AUM", err))
		return
	}
	if err := ns.server.tka.initBegin(genesis); err != nil {
		if errors.Is(err, errTKAAlreadyEnabled) {
			httpError(w, NewHTTPError(http.StatusConflict, "tailnet lock is already enabled", err))
			return
		}
		ns.server.log.Warn("tka init begin", "err", err)
		httpError(w, NewHTTPError(http.StatusBadRequest, "genesis AUM rejected", err))
		return
	}

	// Every registered node needs a signature before the next netmap turns
	// enforcement on, or its peers would not be able to verify it.
	nodes := ns.server.store.ListNodes()
	infos := make([]tailcfg.TKASignInfo, 0, len(nodes))
	for _, n := range nodes {
		info := tailcfg.TKASignInfo{
			NodeID:     tailcfg.NodeID(n.ID),
			NodePublic: n.NodeKey,
		}
		// The node's own tailnet-lock public key lets it rotate this node key
		// later without another trusted signer: an administrator signature
		// that wraps this key can be chained into a rotation signature by the
		// node itself (tailcfg.TKASignInfo.RotationPubkey).
		if !n.NLKey.IsZero() {
			info.RotationPubkey = slices.Clone(n.NLKey.Verifier())
		}
		infos = append(infos, info)
	}

	// No netmap wakeup yet: enforcement turns on at init/finish, so clients
	// must keep working while the administrator signs every node.
	ns.server.audit(nodeActor(node), identity.AuditTailnetLockEnabled, "", "tailnet lock initialized")

	writeJSON(w, http.StatusOK, tailcfg.TKAInitBeginResponse{NeedSignatures: infos})
}

// handleTKAInitFinish implements GET /machine/tka/init/finish: the genesis
// administrator submits a node-key signature for every existing node,
// completing enablement.
func (ns *noiseServer) handleTKAInitFinish(w http.ResponseWriter, req *http.Request) {
	var body tailcfg.TKAInitFinishRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, err)
		return
	}
	node, ok := ns.authorizeTKA(w, body.Version, body.NodeKey)
	if !ok {
		return
	}

	// Verify every signature before storing any of them: a partially applied
	// enablement would leave the tailnet in a state the client did not ask
	// for.
	type signedNode struct {
		node state.Node
		sig  tkatype.MarshaledSignature
	}
	signed := make([]signedNode, 0, len(body.Signatures))
	for nodeID, sig := range body.Signatures {
		n, ok := ns.server.store.GetNodeByID(state.NodeID(nodeID))
		if !ok {
			httpError(w, NewHTTPError(http.StatusBadRequest, "signature for an unknown node", nil))
			return
		}
		pub, err := ns.server.tka.verifyNodeSignatureForInit(sig)
		if err != nil {
			httpError(w, NewHTTPError(http.StatusBadRequest, "node key signature does not verify", err))
			return
		}
		if pub != n.NodeKey {
			httpError(w, NewHTTPError(http.StatusBadRequest, "signature is for a different node key", nil))
			return
		}
		signed = append(signed, signedNode{node: n, sig: sig})
	}

	for _, sn := range signed {
		n := sn.node
		n.KeySignature = slices.Clone(sn.sig)
		if err := ns.server.store.UpdateNode(n); err != nil {
			ns.server.log.Error("storing node key signature", "node", n.StableID, "err", err)
			httpError(w, err)
			return
		}
	}
	if err := ns.server.tka.enable(body.SupportDisablement); err != nil {
		ns.server.log.Error("storing the support disablement secret", "err", err)
		httpError(w, err)
		return
	}

	ns.server.audit(nodeActor(node), identity.AuditTailnetLockNodeSigned, "",
		"tailnet lock enabled, node signatures stored")
	ns.server.notifyWatchers()

	writeJSON(w, http.StatusOK, tailcfg.TKAInitFinishResponse{})
}

// handleTKABootstrap implements GET /machine/tka/bootstrap: a node fetches the
// genesis AUM (to enable tailnet lock locally) or the support disablement
// secret (to disable it).
func (ns *noiseServer) handleTKABootstrap(w http.ResponseWriter, req *http.Request) {
	var body tailcfg.TKABootstrapRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, err)
		return
	}
	if _, ok := ns.authorizeTKA(w, body.Version, body.NodeKey); !ok {
		return
	}

	genesis, secret, err := ns.server.tka.bootstrap()
	if err != nil {
		ns.server.log.Error("tka bootstrap", "err", err)
		httpError(w, err)
		return
	}
	if len(genesis) == 0 && len(secret) == 0 {
		// Nothing to enable or disable: the tailnet never had a chain, so
		// answering with an empty AUM would only make the client fail later.
		httpError(w, NewHTTPError(http.StatusBadRequest, "tailnet lock is not configured", nil))
		return
	}

	writeJSON(w, http.StatusOK, tailcfg.TKABootstrapResponse{
		GenesisAUM:        genesis,
		DisablementSecret: secret,
	})
}

// handleTKASyncOffer implements GET /machine/tka/sync/offer, the first half of
// AUM synchronization.
func (ns *noiseServer) handleTKASyncOffer(w http.ResponseWriter, req *http.Request) {
	var body tailcfg.TKASyncOfferRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, err)
		return
	}
	if _, ok := ns.authorizeTKA(w, body.Version, body.NodeKey); !ok {
		return
	}

	offer, missing, err := ns.server.tka.syncOffer(body.Head, body.Ancestors)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errTKANotEnabled) {
			httpError(w, NewHTTPError(code, "tailnet lock is not enabled", err))
			return
		}
		ns.server.log.Warn("tka sync offer", "err", err)
		httpError(w, NewHTTPError(code, "invalid sync offer", err))
		return
	}

	head, ancestors, err := tka.FromSyncOffer(offer)
	if err != nil {
		ns.server.log.Error("encoding tka sync offer", "err", err)
		httpError(w, err)
		return
	}
	resp := tailcfg.TKASyncOfferResponse{
		Head:        head,
		Ancestors:   ancestors,
		MissingAUMs: make([]tkatype.MarshaledAUM, len(missing)),
	}
	for i, aum := range missing {
		resp.MissingAUMs[i] = aum.Serialize()
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleTKASyncSend implements GET /machine/tka/sync/send, the second half of
// AUM synchronization: the node submits AUMs it believes the control plane is
// missing.
func (ns *noiseServer) handleTKASyncSend(w http.ResponseWriter, req *http.Request) {
	var body tailcfg.TKASyncSendRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, err)
		return
	}
	if _, ok := ns.authorizeTKA(w, body.Version, body.NodeKey); !ok {
		return
	}

	if err := ns.server.tka.syncSend(body.MissingAUMs); err != nil {
		if errors.Is(err, errTKANotEnabled) {
			httpError(w, NewHTTPError(http.StatusBadRequest, "tailnet lock is not enabled", err))
			return
		}
		ns.server.log.Warn("tka sync send", "err", err, "interactive", body.Interactive)
		httpError(w, NewHTTPError(http.StatusBadRequest, "AUMs rejected", err))
		return
	}
	if len(body.MissingAUMs) > 0 {
		ns.server.notifyWatchers()
	}

	writeJSON(w, http.StatusOK, tailcfg.TKASyncSendResponse{Head: ns.server.tka.view().Head})
}

// handleTKADisable implements GET /machine/tka/disable: an administrator
// disables the tailnet key authority with the support disablement secret.
func (ns *noiseServer) handleTKADisable(w http.ResponseWriter, req *http.Request) {
	var body tailcfg.TKADisableRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, err)
		return
	}
	node, ok := ns.authorizeTKA(w, body.Version, body.NodeKey)
	if !ok {
		return
	}

	if err := ns.server.tka.disable(body.DisablementSecret); err != nil {
		switch {
		case errors.Is(err, errTKADisablement):
			httpError(w, NewHTTPError(http.StatusForbidden, "incorrect disablement secret", err))
		case errors.Is(err, errTKANotEnabled):
			httpError(w, NewHTTPError(http.StatusBadRequest, "tailnet lock is not enabled", err))
		default:
			ns.server.log.Error("tka disable", "err", err)
			httpError(w, err)
		}
		return
	}

	ns.server.audit(nodeActor(node), identity.AuditTailnetLockDisabled, "", "tailnet lock disabled")
	ns.server.notifyWatchers()

	writeJSON(w, http.StatusOK, tailcfg.TKADisableResponse{})
}

// handleTKASign implements GET /machine/tka/sign: an administrator node
// submits a node-key signature for another node.
func (ns *noiseServer) handleTKASign(w http.ResponseWriter, req *http.Request) {
	var body tailcfg.TKASubmitSignatureRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, err)
		return
	}
	node, ok := ns.authorizeTKA(w, body.Version, body.NodeKey)
	if !ok {
		return
	}

	pub, err := ns.server.tka.verifyNodeSignature(body.Signature)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, "node key signature does not verify", err))
		return
	}
	signed, ok := ns.server.store.GetNodeByNodeKey(pub)
	if !ok {
		httpError(w, NewHTTPError(http.StatusNotFound, "signature is for an unregistered node key", nil))
		return
	}

	signed.KeySignature = slices.Clone(body.Signature)
	if err := ns.server.store.UpdateNode(signed); err != nil {
		ns.server.log.Error("storing node key signature", "node", signed.StableID, "err", err)
		httpError(w, err)
		return
	}

	ns.server.audit(nodeActor(node), identity.AuditTailnetLockNodeSigned, nodeTarget(signed), "node key signed")
	ns.server.notifyWatchers()

	writeJSON(w, http.StatusOK, tailcfg.TKASubmitSignatureResponse{})
}

// handleTKAAffectedSigs implements GET /machine/tka/affected-sigs: the caller
// asks which stored node-key signatures were made with a given key, so it can
// see the blast radius before revoking that key.
func (ns *noiseServer) handleTKAAffectedSigs(w http.ResponseWriter, req *http.Request) {
	var body tailcfg.TKASignaturesUsingKeyRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, err)
		return
	}
	if _, ok := ns.authorizeTKA(w, body.Version, body.NodeKey); !ok {
		return
	}

	resp := tailcfg.TKASignaturesUsingKeyResponse{}
	for _, n := range ns.server.store.ListNodes() {
		if len(n.KeySignature) == 0 {
			continue
		}
		var sig tka.NodeKeySignature
		if err := sig.Unserialize(n.KeySignature); err != nil {
			// A stored signature that cannot be decoded is already broken;
			// skip it rather than failing the whole query.
			continue
		}
		keyID, err := sig.UnverifiedAuthorizingKeyID()
		if err != nil {
			continue
		}
		if !slices.Equal(keyID, body.KeyID) {
			continue
		}
		resp.Signatures = append(resp.Signatures, slices.Clone(n.KeySignature))
	}

	writeJSON(w, http.StatusOK, resp)
}
