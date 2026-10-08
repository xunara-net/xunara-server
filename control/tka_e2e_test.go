package control

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path"
	"slices"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"

	"github.com/xunara-net/xunara-server/state"
)

// tkaRPC performs a tailnet-lock RPC (GET with a JSON body, over the Noise
// session) and returns the raw response, failing the test on an unexpected
// status.
func tkaRPC(t *testing.T, client *http.Client, path string, req any, wantStatus int) []byte {
	t.Helper()

	out, code := doRaw(t, client, http.MethodGet, path, req)
	if code != wantStatus {
		t.Fatalf("GET %s = %d (%s), want %d", path, code, out, wantStatus)
	}
	return out
}

// tkaJSON performs a TKA RPC and decodes its JSON response into T.
func tkaJSON[T any](t *testing.T, client *http.Client, path string, req any, wantStatus int) T {
	t.Helper()

	var out T
	if err := json.Unmarshal(tkaRPC(t, client, path, req, wantStatus), &out); err != nil {
		t.Fatalf("decoding %s response: %v", path, err)
	}
	return out
}

// storedNode returns the stored node for a node key.
func storedNode(t *testing.T, s *Server, nodeKey key.NodePublic) state.Node {
	t.Helper()

	node, ok := s.store.GetNodeByNodeKey(nodeKey)
	if !ok {
		t.Fatalf("node %v is not registered", nodeKey.ShortString())
	}
	return node
}

// nodeIDOf returns the stored node ID for a node key.
func nodeIDOf(t *testing.T, s *Server, nodeKey key.NodePublic) tailcfg.NodeID {
	t.Helper()

	node, ok := s.store.GetNodeByNodeKey(nodeKey)
	if !ok {
		t.Fatalf("node %v is not registered", nodeKey.ShortString())
	}
	return tailcfg.NodeID(node.ID)
}

// fullMapFor fetches a node's full netmap.
func fullMapFor(t *testing.T, client *http.Client, nodeKey key.NodePublic) *tailcfg.MapResponse {
	t.Helper()

	return decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey,
	}), "")
}

// peerByKey finds a peer in a netmap by node key.
func peerByKey(resp *tailcfg.MapResponse, nodeKey key.NodePublic) *tailcfg.Node {
	for _, p := range resp.Peers {
		if p.Key == nodeKey {
			return p
		}
	}
	return nil
}

// TestTailnetLockEndToEnd drives the full tailnet-lock lifecycle through the
// inner machine API: enablement, netmap advertisement, synchronization,
// signing, and disablement.
func TestTailnetLockEndToEnd(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	connA, clientA, nodeKeyA := registerNode(t, s, hs, "lock-admin")
	defer connA.Close()
	connB, clientB, nodeKeyB := registerNode(t, s, hs, "lock-peer")
	defer connB.Close()

	adminKey, genesis := newTestTKAKey(t)
	genesisHead := genesis.Hash().String()

	// Enablement, phase 1: submit the genesis AUM. Control must collect
	// signatures for the nodes that already exist before enforcing.
	begin := tkaJSON[tailcfg.TKAInitBeginResponse](t, clientA, "/machine/tka/init/begin", tailcfg.TKAInitBeginRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		NodeKey:    nodeKeyA.Public(),
		GenesisAUM: genesis.Serialize(),
	}, http.StatusOK)
	if len(begin.NeedSignatures) != 2 {
		t.Fatalf("NeedSignatures = %+v, want both existing nodes", begin.NeedSignatures)
	}

	// Until init/finish the chain exists but is not advertised: the tailnet
	// keeps working while the administrator signs everyone.
	if got := fullMapFor(t, clientA, nodeKeyA.Public()); got.TKAInfo != nil {
		t.Errorf("TKAInfo before init/finish = %+v, want none", got.TKAInfo)
	}
	if _, ok := fullMapFor(t, clientA, nodeKeyA.Public()).Node.CapMap[tailcfg.CapabilityTailnetLock]; ok {
		t.Error("tailnet lock capability advertised before init/finish")
	}

	// Phase 2: sign every existing node and turn enforcement on.
	sigs := map[tailcfg.NodeID]tkatype.MarshaledSignature{
		nodeIDOf(t, s, nodeKeyA.Public()): signTestNodeKey(t, adminKey, nodeKeyA.Public()),
		nodeIDOf(t, s, nodeKeyB.Public()): signTestNodeKey(t, adminKey, nodeKeyB.Public()),
	}
	tkaRPC(t, clientA, "/machine/tka/init/finish", tailcfg.TKAInitFinishRequest{
		Version:            tailcfg.CurrentCapabilityVersion,
		NodeKey:            nodeKeyA.Public(),
		Signatures:         sigs,
		SupportDisablement: testDisablementSecret,
	}, http.StatusOK)

	mapA := fullMapFor(t, clientA, nodeKeyA.Public())
	if mapA.TKAInfo == nil || mapA.TKAInfo.Head != genesisHead || mapA.TKAInfo.Disabled {
		t.Fatalf("TKAInfo = %+v, want the current head %q", mapA.TKAInfo, genesisHead)
	}
	if _, ok := mapA.Node.CapMap[tailcfg.CapabilityTailnetLock]; !ok {
		t.Errorf("self CapMap = %v, want %s", mapA.Node.CapMap, tailcfg.CapabilityTailnetLock)
	}
	if !bytes.Equal(mapA.Node.KeySignature, sigs[nodeIDOf(t, s, nodeKeyA.Public())]) {
		t.Error("self node does not carry the signature submitted at init/finish")
	}
	peerB := peerByKey(mapA, nodeKeyB.Public())
	if peerB == nil {
		t.Fatal("peer B is missing from the netmap")
	}
	if !bytes.Equal(peerB.KeySignature, sigs[nodeIDOf(t, s, nodeKeyB.Public())]) {
		t.Error("peer B does not carry its signature")
	}
	if peerB.UnsignedPeerAPIOnly {
		t.Error("signed peer B is marked UnsignedPeerAPIOnly")
	}

	// A node bootstraps the genesis AUM to enable tailnet lock locally.
	bs := tkaJSON[tailcfg.TKABootstrapResponse](t, clientB, "/machine/tka/bootstrap", tailcfg.TKABootstrapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyB.Public(),
	}, http.StatusOK)
	if !bytes.Equal(bs.GenesisAUM, genesis.Serialize()) {
		t.Error("bootstrap returned a different genesis AUM")
	}
	if len(bs.DisablementSecret) != 0 {
		t.Error("bootstrap handed out a disablement secret before any disablement")
	}

	// A device that joins without a signature is confined to the peer API:
	// peers must not be able to route to it, or their clients would reject
	// the whole packet filter.
	connC, clientC, nodeKeyC := registerNode(t, s, hs, "lock-unsigned")
	defer connC.Close()

	mapA = fullMapFor(t, clientA, nodeKeyA.Public())
	peerC := peerByKey(mapA, nodeKeyC.Public())
	if peerC == nil {
		t.Fatal("unsigned node C is missing from the netmap")
	}
	if !peerC.UnsignedPeerAPIOnly {
		t.Error("unsigned node C is not marked UnsignedPeerAPIOnly")
	}
	// The signed nodes must stay reachable: the wildcard sources expand to
	// exactly their addresses.
	for _, want := range []string{mapA.Node.Addresses[0].String(), peerB.Addresses[0].String()} {
		if !slices.Contains(mapA.PacketFilters["base"][0].SrcIPs, want) {
			t.Errorf("packet filter sources %v do not include the signed node %s",
				mapA.PacketFilters["base"][0].SrcIPs, want)
		}
	}

	cAddr := netip.PrefixFrom(peerC.Addresses[0].Addr(), peerC.Addresses[0].Addr().BitLen())
	for _, rule := range mapA.PacketFilters["base"] {
		for _, src := range rule.SrcIPs {
			if src == "*" {
				t.Errorf("packet filter still permits a wildcard source: %+v", rule)
				continue
			}
			p, err := netip.ParsePrefix(src)
			if err != nil {
				t.Errorf("packet filter source %q is not a prefix", src)
				continue
			}
			if p.Overlaps(cAddr) {
				t.Errorf("packet filter permits unsigned peer %v: %+v", cAddr, rule)
			}
		}
	}

	// Synchronization: C offers the genesis head, then pulls the update.
	offer := tkaJSON[tailcfg.TKASyncOfferResponse](t, clientC, "/machine/tka/sync/offer", tailcfg.TKASyncOfferRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyC.Public(),
		Head:    genesisHead,
	}, http.StatusOK)
	if offer.Head != genesisHead || len(offer.MissingAUMs) != 0 {
		t.Fatalf("sync offer = %+v, want an up-to-date node", offer)
	}

	// Announce a new chain update (as `tailscale lock revoke-keys` would) and
	// check the node pulls it, then reports it back.
	commitTestAUM(t, s, adminKey)
	newHead := s.tka.view().Head
	offer = tkaJSON[tailcfg.TKASyncOfferResponse](t, clientC, "/machine/tka/sync/offer", tailcfg.TKASyncOfferRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyC.Public(),
		Head:    genesisHead,
	}, http.StatusOK)
	if len(offer.MissingAUMs) != 1 || offer.Head != newHead {
		t.Fatalf("sync offer after an update = %+v, want one missing AUM at %q", offer, newHead)
	}
	send := tkaJSON[tailcfg.TKASyncSendResponse](t, clientC, "/machine/tka/sync/send", tailcfg.TKASyncSendRequest{
		Version:     tailcfg.CurrentCapabilityVersion,
		NodeKey:     nodeKeyC.Public(),
		Head:        newHead,
		MissingAUMs: offer.MissingAUMs,
	}, http.StatusOK)
	if send.Head != newHead {
		t.Errorf("sync send head = %q, want %q", send.Head, newHead)
	}

	// An administrator signs C, which un-confines it.
	tkaRPC(t, clientA, "/machine/tka/sign", tailcfg.TKASubmitSignatureRequest{
		Version:   tailcfg.CurrentCapabilityVersion,
		NodeKey:   nodeKeyA.Public(),
		Signature: signTestNodeKey(t, adminKey, nodeKeyC.Public()),
	}, http.StatusOK)

	mapA = fullMapFor(t, clientA, nodeKeyA.Public())
	if peerC = peerByKey(mapA, nodeKeyC.Public()); peerC == nil || peerC.UnsignedPeerAPIOnly {
		t.Fatalf("node C after signing = %+v, want a signed peer", peerC)
	}
	// C now sees its own signature too, which clients need to verify
	// themselves against the chain.
	mapC := fullMapFor(t, clientC, nodeKeyC.Public())
	if len(mapC.Node.KeySignature) == 0 {
		t.Error("signed node C has no self node-key signature")
	}

	// affected-sigs lists every signature the key made.
	affected := tkaJSON[tailcfg.TKASignaturesUsingKeyResponse](t, clientA, "/machine/tka/affected-sigs", tailcfg.TKASignaturesUsingKeyRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyA.Public(),
		KeyID:   adminKey.KeyID(),
	}, http.StatusOK)
	if len(affected.Signatures) != 3 {
		t.Errorf("affected signatures = %d, want 3", len(affected.Signatures))
	}
	other := tkaJSON[tailcfg.TKASignaturesUsingKeyResponse](t, clientA, "/machine/tka/affected-sigs", tailcfg.TKASignaturesUsingKeyRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyA.Public(),
		KeyID:   key.NewNLPrivate().KeyID(),
	}, http.StatusOK)
	if len(other.Signatures) != 0 {
		t.Errorf("signatures for an untrusted key = %d, want 0", len(other.Signatures))
	}

	// Disablement: a wrong secret is refused, the generated one works, and
	// clients are told to clear their local state.
	tkaRPC(t, clientA, "/machine/tka/disable", tailcfg.TKADisableRequest{
		Version:           tailcfg.CurrentCapabilityVersion,
		NodeKey:           nodeKeyA.Public(),
		Head:              newHead,
		DisablementSecret: []byte("not-the-secret"),
	}, http.StatusForbidden)
	tkaRPC(t, clientA, "/machine/tka/disable", tailcfg.TKADisableRequest{
		Version:           tailcfg.CurrentCapabilityVersion,
		NodeKey:           nodeKeyA.Public(),
		Head:              newHead,
		DisablementSecret: testDisablementSecret,
	}, http.StatusOK)

	mapA = fullMapFor(t, clientA, nodeKeyA.Public())
	if mapA.TKAInfo == nil || !mapA.TKAInfo.Disabled {
		t.Fatalf("TKAInfo after disablement = %+v, want Disabled", mapA.TKAInfo)
	}
	if peerC = peerByKey(mapA, nodeKeyC.Public()); peerC == nil || peerC.UnsignedPeerAPIOnly {
		t.Errorf("peer after disablement = %+v, want no unsigned confinement", peerC)
	}
	// The chain is kept, so a node that is still enabled locally can fetch
	// the secret and clear its state.
	bs = tkaJSON[tailcfg.TKABootstrapResponse](t, clientA, "/machine/tka/bootstrap", tailcfg.TKABootstrapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKeyA.Public(),
	}, http.StatusOK)
	if !bytes.Equal(bs.GenesisAUM, genesis.Serialize()) {
		t.Error("bootstrap lost the genesis AUM after disablement")
	}
	if !bytes.Equal(bs.DisablementSecret, testDisablementSecret) {
		t.Error("bootstrap did not hand out the disablement secret")
	}
}

// commitTestAUM appends a new key to the tailnet's authority, as an
// interactive `tailscale lock revoke-keys` would through sync/send.
func commitTestAUM(t *testing.T, s *Server, signer key.NLPrivate) {
	t.Helper()

	updater := s.tka.authority.NewUpdater(signer)
	newKey := key.NewNLPrivate()
	if err := updater.AddKey(tka.Key{Kind: tka.Key25519, Public: newKey.Public().Verifier(), Votes: 1}); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	updates, err := updater.Finalize(s.tka.chonk)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if err := s.tka.authority.Inform(s.tka.chonk, updates); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	s.notifyWatchers()
}

// TestTailnetLockStreamsTransitions checks that a client with a live netmap
// stream is told about tailnet-lock transitions: nil means "unchanged" in a
// delta response, so an enablement and a disablement must both arrive as
// explicit non-nil frames.
func TestTailnetLockStreamsTransitions(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "lock-stream")
	defer conn.Close()

	sess := openMapSession(t, client, nodeKey.Public())
	defer sess.Body.Close()
	frames := mapFrames(sess.Body)

	first := waitForFrame(t, frames, func(m *tailcfg.MapResponse) bool { return m.Node != nil })
	if first.TKAInfo != nil {
		t.Errorf("TKAInfo before enablement = %+v, want none", first.TKAInfo)
	}
	if _, ok := first.Node.CapMap[tailcfg.CapabilityTailnetLock]; ok {
		t.Error("tailnet lock capability advertised before enablement")
	}

	// Enabling tailnet lock out-of-band must reach the running session.
	_, genesis := newTestTKAKey(t)
	if err := s.tka.initBegin(genesis); err != nil {
		t.Fatalf("initBegin: %v", err)
	}
	if err := s.tka.enable(nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	s.notifyWatchers()

	on := waitForFrame(t, frames, func(m *tailcfg.MapResponse) bool {
		return m.TKAInfo != nil && !m.TKAInfo.Disabled
	})
	if on.TKAInfo.Head != genesis.Hash().String() {
		t.Errorf("TKAInfo.Head = %q, want %q", on.TKAInfo.Head, genesis.Hash().String())
	}
	if on.Node == nil {
		t.Fatal("the enablement frame must carry the self node with the new capability")
	}
	if _, ok := on.Node.CapMap[tailcfg.CapabilityTailnetLock]; !ok {
		t.Errorf("self CapMap = %v, want %s", on.Node.CapMap, tailcfg.CapabilityTailnetLock)
	}

	// Disablement must be explicit too.
	if err := s.tka.disable(testDisablementSecret); err != nil {
		t.Fatalf("disable: %v", err)
	}
	s.notifyWatchers()

	off := waitForFrame(t, frames, func(m *tailcfg.MapResponse) bool {
		return m.TKAInfo != nil && m.TKAInfo.Disabled
	})
	if off.TKAInfo.Head != "" {
		t.Errorf("disabled TKAInfo still carries head %q", off.TKAInfo.Head)
	}
}

// TestTailnetLockRegistrationSignatures checks the registration half of the
// protocol: a verifying node-key signature is stored and published, and an
// unverifiable one is refused instead of silently downgrading the node to
// unsigned.
func TestTailnetLockRegistrationSignatures(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	connA, clientA, nodeKeyA := registerNode(t, s, hs, "lock-admin")
	defer connA.Close()

	adminKey, genesis := newTestTKAKey(t)
	if err := s.tka.initBegin(genesis); err != nil {
		t.Fatalf("initBegin: %v", err)
	}
	if err := s.tka.enable(nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	sigs := map[tailcfg.NodeID]tkatype.MarshaledSignature{
		nodeIDOf(t, s, nodeKeyA.Public()): signTestNodeKey(t, adminKey, nodeKeyA.Public()),
	}
	tkaRPC(t, clientA, "/machine/tka/init/finish", tailcfg.TKAInitFinishRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		NodeKey:    nodeKeyA.Public(),
		Signatures: sigs,
	}, http.StatusOK)

	// A node joining with a pre-auth key and a valid tailnet-lock credential
	// is signed from the start.
	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	machineKeyD := key.NewMachine()
	nodeKeyD := key.NewNode()
	connD := dialNoise(t, hs, machineKeyD)
	defer connD.Close()
	clientD := h2Client(connD)

	sigD := signTestNodeKey(t, adminKey, nodeKeyD.Public())
	regD := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, clientD, "/machine/register", tailcfg.RegisterRequest{
		Version:          tailcfg.CurrentCapabilityVersion,
		NodeKey:          nodeKeyD.Public(),
		NodeKeySignature: sigD,
		Auth:             &tailcfg.RegisterResponseAuth{AuthKey: secret},
	}))
	if !regD.MachineAuthorized {
		t.Fatalf("registration with a valid signature failed: %+v", regD)
	}
	if got := fullMapFor(t, clientD, nodeKeyD.Public()).Node.KeySignature; !bytes.Equal(got, sigD) {
		t.Error("the signature presented at registration did not reach the netmap")
	}

	// A signature made by a key the tailnet does not trust is refused, and no
	// node is created.
	secretE := seedPreAuthKey(t, s, state.PreAuthKey{})
	machineKeyE := key.NewMachine()
	nodeKeyE := key.NewNode()
	connE := dialNoise(t, hs, machineKeyE)
	defer connE.Close()
	clientE := h2Client(connE)

	regE := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, clientE, "/machine/register", tailcfg.RegisterRequest{
		Version:          tailcfg.CurrentCapabilityVersion,
		NodeKey:          nodeKeyE.Public(),
		NodeKeySignature: signTestNodeKey(t, key.NewNLPrivate(), nodeKeyE.Public()),
		Auth:             &tailcfg.RegisterResponseAuth{AuthKey: secretE},
	}))
	if regE.Error == "" {
		t.Fatalf("registration with an untrusted signature was accepted: %+v", regE)
	}
	if _, ok := s.store.GetNodeByNodeKey(nodeKeyE.Public()); ok {
		t.Error("a rejected registration still created a node")
	}
}

// registerNodeWithNLKey registers a node through the interactive flow with the
// registration reporting a tailnet-lock public key, as an official client does
// while the tailnet has a key authority.
func registerNodeWithNLKey(t *testing.T, s *Server, hs *httptest.Server, hostname string, nlPub key.NLPublic) (net.Conn, *http.Client, key.NodePrivate) {
	t.Helper()

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	conn := dialNoise(t, hs, machineKey)
	client := h2Client(conn)

	reg := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		NLKey:    nlPub,
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
	}))
	if reg.AuthURL == "" {
		t.Fatalf("first registration returned no AuthURL: %+v", reg)
	}
	authID := path.Base(reg.AuthURL)
	if err := s.ApproveRegistration(authID); err != nil {
		t.Fatalf("ApproveRegistration: %v", err)
	}

	final := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Followup: s.authURL(authID),
	}))
	if !final.MachineAuthorized {
		t.Fatalf("registration not authorized: %+v", final)
	}
	return conn, client, nodeKey
}

// signInfoFor picks a node out of an init/begin response.
func signInfoFor(t *testing.T, resp tailcfg.TKAInitBeginResponse, nodeKey key.NodePublic) tailcfg.TKASignInfo {
	t.Helper()

	for _, info := range resp.NeedSignatures {
		if info.NodePublic == nodeKey {
			return info
		}
	}
	t.Fatalf("no signature request for node %v in %+v", nodeKey.ShortString(), resp.NeedSignatures)
	return tailcfg.TKASignInfo{}
}

// TestTailnetLockNodeKeyRotation drives the rotation protocol end to end: a
// client that regenerated its node key asks for the new key to be authorized,
// control answers with the old signature ("resign and retry"), the client
// chain-signs with its own network-lock key (tka.ResignNKS), and the node
// rotates in place.
func TestTailnetLockNodeKeyRotation(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	adminKey, genesis := newTestTKAKey(t)
	nlPriv := key.NewNLPrivate()

	conn, client, oldKey := registerNodeWithNLKey(t, s, hs, "lock-rotate", nlPriv.Public())
	defer conn.Close()

	// A node signed without a rotation key cannot be rotated by its client, so
	// it is the negative case for the hint below.
	connB, clientB, plainKey := registerNode(t, s, hs, "lock-plain")
	defer connB.Close()

	stored := storedNode(t, s, oldKey.Public())
	if stored.NLKey != nlPriv.Public() {
		t.Fatalf("stored NLKey = %v, want the reported key", stored.NLKey)
	}

	// Enablement: control tells the administrator which raw ed25519 key may
	// wrap the signature, so the node can rotate its node key on its own.
	begin := tkaJSON[tailcfg.TKAInitBeginResponse](t, client, "/machine/tka/init/begin", tailcfg.TKAInitBeginRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		NodeKey:    oldKey.Public(),
		GenesisAUM: genesis.Serialize(),
	}, http.StatusOK)
	info := signInfoFor(t, begin, oldKey.Public())
	if !bytes.Equal(info.RotationPubkey, nlPriv.Public().Verifier()) {
		t.Fatalf("RotationPubkey = %x, want the node's network-lock key", info.RotationPubkey)
	}
	sig := signTestNodeKeyWithRotation(t, adminKey, oldKey.Public(), info.RotationPubkey)
	tkaRPC(t, client, "/machine/tka/init/finish", tailcfg.TKAInitFinishRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: oldKey.Public(),
		Signatures: map[tailcfg.NodeID]tkatype.MarshaledSignature{
			nodeIDOf(t, s, oldKey.Public()):   sig,
			nodeIDOf(t, s, plainKey.Public()): signTestNodeKey(t, adminKey, plainKey.Public()),
		},
		SupportDisablement: testDisablementSecret,
	}, http.StatusOK)

	// The node signed without a rotation key is not offered a rotation: the
	// client could not chain the signature, so the registration falls through
	// to the ordinary interactive path instead.
	plainRotate := tailcfg.RegisterRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		OldNodeKey: plainKey.Public(),
		NodeKey:    key.NewNode().Public(),
	}
	plainResp := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, clientB, "/machine/register", plainRotate))
	if len(plainResp.NodeKeySignature) != 0 {
		t.Error("control offered a rotation signature without a rotation key")
	}
	if plainResp.AuthURL == "" {
		t.Errorf("registration without a rotatable signature = %+v, want the interactive path", plainResp)
	}

	// A client whose network-lock key no longer matches the signature it was
	// issued cannot chain it either; control falls back to the ordinary path
	// instead of a retry that would fail verification.
	mismatch := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		OldNodeKey: oldKey.Public(),
		NodeKey:    key.NewNode().Public(),
		NLKey:      key.NewNLPrivate().Public(),
		Hostinfo:   &tailcfg.Hostinfo{Hostname: "lock-rotate"},
	}))
	if len(mismatch.NodeKeySignature) != 0 {
		t.Error("control offered a rotation signature for a different network-lock key")
	}
	if mismatch.AuthURL == "" {
		t.Errorf("mismatched network-lock key registration = %+v, want the interactive path", mismatch)
	}

	newKey := key.NewNode()
	rotateReq := tailcfg.RegisterRequest{
		Version:    tailcfg.CurrentCapabilityVersion,
		OldNodeKey: oldKey.Public(),
		NodeKey:    newKey.Public(),
		NLKey:      nlPriv.Public(),
		Hostinfo:   &tailcfg.Hostinfo{Hostname: "lock-rotate"},
	}

	// First attempt: control refuses to register the new key and hands the old
	// signature back instead of authorizing anything.
	hint := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", rotateReq))
	if !bytes.Equal(hint.NodeKeySignature, sig) {
		t.Fatalf("rotation hint = %d bytes, want the old signature", len(hint.NodeKeySignature))
	}
	if hint.MachineAuthorized || hint.AuthURL != "" {
		t.Errorf("the hint response must neither authorize nor start a login: %+v", hint)
	}
	if _, ok := s.store.GetNodeByNodeKey(newKey.Public()); ok {
		t.Fatal("the hint registered the new node key")
	}

	// Second attempt: the client nests the old signature in a rotation
	// signature signed by its own network-lock key.
	rotation, err := tka.ResignNKS(nlPriv, newKey.Public(), hint.NodeKeySignature)
	if err != nil {
		t.Fatalf("ResignNKS: %v", err)
	}
	if got, err := s.tka.verifyNodeSignature(rotation); err != nil || got != newKey.Public() {
		t.Fatalf("rotation signature does not verify for the new key: %v", err)
	}
	rotateReq.NodeKeySignature = rotation

	// The machine still has to re-authorize interactively; the verified
	// signature travels with the pending registration.
	pending := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", rotateReq))
	if pending.AuthURL == "" {
		t.Fatalf("no AuthURL for the rotated key: %+v", pending)
	}
	authID := path.Base(pending.AuthURL)
	if err := s.ApproveRegistration(authID); err != nil {
		t.Fatalf("ApproveRegistration: %v", err)
	}

	// The follow-up poll carries no signature of its own: the node must have
	// been created with the one the pending registration validated.
	final := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  newKey.Public(),
		Followup: s.authURL(authID),
	}))
	if !final.MachineAuthorized {
		t.Fatalf("registration not authorized: %+v", final)
	}

	rotated := storedNode(t, s, newKey.Public())
	if rotated.ID != stored.ID || rotated.StableID != stored.StableID {
		t.Errorf("rotation replaced the node: id %d -> %d, stable %q -> %q",
			stored.ID, rotated.ID, stored.StableID, rotated.StableID)
	}
	if !bytes.Equal(rotated.KeySignature, rotation) {
		t.Error("the rotated node does not carry the rotation signature")
	}
	if rotated.NLKey != nlPriv.Public() {
		t.Error("the rotated node lost its network-lock key")
	}
	if _, ok := s.store.GetNodeByNodeKey(oldKey.Public()); ok {
		t.Error("the old node key is still registered")
	}

	// The netmap publishes the rotated signature, so peers keep trusting the
	// node without a further administrator action.
	if got := fullMapFor(t, client, newKey.Public()).Node.KeySignature; !bytes.Equal(got, rotation) {
		t.Error("the netmap does not publish the rotation signature")
	}

	// Re-registering the current key is an ordinary registration: no hint and
	// no further rotation.
	again := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", rotateReq))
	if !again.MachineAuthorized || len(again.NodeKeySignature) != 0 {
		t.Errorf("re-registration = %+v, want a plain authorized response", again)
	}
	if got := storedNode(t, s, newKey.Public()); got.ID != stored.ID {
		t.Errorf("re-registration changed the node id to %d, want %d", got.ID, stored.ID)
	}
}

// TestRegistrationRecordsNetworkLockKey checks the persistence half of
// RegisterRequest.NLKey: a node that reports its tailnet-lock public key keeps
// it across registrations, and a client that stops reporting one does not clear
// it.
func TestRegistrationRecordsNetworkLockKey(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "nl-key")
	defer conn.Close()

	if got := storedNode(t, s, nodeKey.Public()).NLKey; !got.IsZero() {
		t.Fatalf("NLKey = %v, want the zero value before a client reports one", got)
	}

	nlPriv := key.NewNLPrivate()
	reg := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
		NLKey:   nlPriv.Public(),
	}))
	if !reg.MachineAuthorized {
		t.Fatalf("re-registration failed: %+v", reg)
	}
	if got := storedNode(t, s, nodeKey.Public()).NLKey; got != nlPriv.Public() {
		t.Fatalf("stored NLKey = %v, want the reported key", got)
	}

	// Older clients omit the field; the stored key must survive.
	reg = decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}))
	if !reg.MachineAuthorized {
		t.Fatalf("re-registration without NLKey failed: %+v", reg)
	}
	if got := storedNode(t, s, nodeKey.Public()).NLKey; got != nlPriv.Public() {
		t.Errorf("stored NLKey = %v after an older client registered, want %v", got, nlPriv.Public())
	}
}

// TestUnlockedTailnetIgnoresNodeKeySignature checks that a node-key signature
// presented while the tailnet is unlocked is neither verified nor stored: it
// carries no authority, and TKA init/finish issues real signatures later.
func TestUnlockedTailnetIgnoresNodeKeySignature(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)

	secret := seedPreAuthKey(t, s, state.PreAuthKey{})
	machineKey := key.NewMachine()
	nodeKey := key.NewNode()
	conn := dialNoise(t, hs, machineKey)
	defer conn.Close()
	client := h2Client(conn)

	adminKey, _ := newTestTKAKey(t)
	reg := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version:          tailcfg.CurrentCapabilityVersion,
		NodeKey:          nodeKey.Public(),
		NodeKeySignature: signTestNodeKey(t, adminKey, nodeKey.Public()),
		Auth:             &tailcfg.RegisterResponseAuth{AuthKey: secret},
	}))
	if !reg.MachineAuthorized {
		t.Fatalf("registration failed: %+v", reg)
	}
	if got := storedNode(t, s, nodeKey.Public()); len(got.KeySignature) != 0 {
		t.Errorf("an unverified signature reached the store: %d bytes", len(got.KeySignature))
	}
	if got := fullMapFor(t, client, nodeKey.Public()).Node.KeySignature; len(got) != 0 {
		t.Error("an unverified signature reached the netmap")
	}
}
