package control

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"

	"github.com/xunara-net/xunara-server/state"
)

// testDisablementSecret matches the value [tka.CreateStateForTest] installs in
// the genesis state.
var testDisablementSecret = makeTestBytes(0xa5, 32)

func makeTestBytes(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// newTestTKAKey returns a tailnet-lock key pair and a genesis AUM that trusts
// it, exactly like `tailscale lock init` would produce on a client.
func newTestTKAKey(t *testing.T) (key.NLPrivate, tka.AUM) {
	t.Helper()

	priv := key.NewNLPrivate()
	k := tka.Key{Kind: tka.Key25519, Public: priv.Public().Verifier(), Votes: 1}
	_, genesis, err := tka.Create(tka.ChonkMem(), tka.CreateStateForTest(k), priv)
	if err != nil {
		t.Fatalf("tka.Create: %v", err)
	}
	return priv, genesis
}

// signTestNodeKey builds a direct node-key signature with a tailnet-lock key.
func signTestNodeKey(t *testing.T, priv key.NLPrivate, nodeKey key.NodePublic) tkatype.MarshaledSignature {
	t.Helper()

	return signTestNodeKeyWithRotation(t, priv, nodeKey, nil)
}

// signTestNodeKeyWithRotation builds a direct node-key signature that wraps the
// node's raw ed25519 network-lock key (tailcfg.TKASignInfo.RotationPubkey), the
// way an administrator signs a node key that must survive rotation.
func signTestNodeKeyWithRotation(t *testing.T, priv key.NLPrivate, nodeKey key.NodePublic, rotationPubkey []byte) tkatype.MarshaledSignature {
	t.Helper()

	raw, err := nodeKey.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	sig := tka.NodeKeySignature{
		SigKind:        tka.SigDirect,
		KeyID:          priv.KeyID(),
		Pubkey:         raw,
		WrappingPubkey: rotationPubkey,
	}
	sig.Signature, err = priv.SignNKS(sig.SigHash())
	if err != nil {
		t.Fatalf("SignNKS: %v", err)
	}
	return sig.Serialize()
}

func testTKALogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestTKAManager(t *testing.T, dir string, store state.TKAStore) *tkaManager {
	t.Helper()

	m, err := newTKAManager(dir, store, testTKALogger())
	if err != nil {
		t.Fatalf("newTKAManager: %v", err)
	}
	return m
}

func TestTKAManagerInitPersistsAndBootstraps(t *testing.T) {
	dir := t.TempDir()
	store := state.NewMemoryStore()
	m := newTestTKAManager(t, dir, store)

	if view := m.view(); view != (tkaView{}) {
		t.Fatalf("fresh view = %+v, want the zero value", view)
	}
	if _, _, err := m.bootstrap(); err != nil {
		t.Fatalf("bootstrap without a chain: %v", err)
	}

	_, genesis := newTestTKAKey(t)
	if err := m.initBegin(genesis); err != nil {
		t.Fatalf("initBegin: %v", err)
	}
	// Between init/begin and init/finish the chain exists but is not
	// advertised: the tailnet keeps working while signatures are collected.
	if view := m.view(); !view.EverEnabled || view.Enabled || view.Disabled {
		t.Fatalf("view after initBegin = %+v, want an unpublished chain", view)
	}
	if err := m.enable(nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	view := m.view()
	if !view.Enabled || !view.EverEnabled || view.Head == "" {
		t.Fatalf("view after init = %+v", view)
	}
	if view.Head != m.authority.Head().String() {
		t.Errorf("view head = %q, want %q", view.Head, m.authority.Head().String())
	}
	if err := m.initBegin(genesis); err != errTKAAlreadyEnabled {
		t.Errorf("second initBegin = %v, want errTKAAlreadyEnabled", err)
	}

	// The bootstrap response carries the genesis AUM clients need to enable
	// TKA locally.
	gotGenesis, secret, err := m.bootstrap()
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if string(gotGenesis) != string(genesis.Serialize()) {
		t.Error("bootstrap returned a different genesis AUM")
	}
	if len(secret) != 0 {
		t.Errorf("bootstrap secret = %x, want none before a disablement", secret)
	}

	// A restart reopens the same chain.
	reopened := newTestTKAManager(t, dir, store)
	if got := reopened.view(); got != view {
		t.Errorf("view after reopen = %+v, want %+v", got, view)
	}
	if _, err := os.Stat(filepath.Join(dir, tkaSealingKeyFile)); err != nil {
		t.Errorf("sealing key: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dir, tkaSealingKeyFile)); err == nil && fi.Mode().Perm() != 0o600 {
		t.Errorf("sealing key permissions = %v, want 0600", fi.Mode().Perm())
	}
}

func TestTKAManagerSyncAndSignatures(t *testing.T) {
	dir := t.TempDir()
	m := newTestTKAManager(t, dir, state.NewMemoryStore())

	priv, genesis := newTestTKAKey(t)
	if err := m.initBegin(genesis); err != nil {
		t.Fatalf("initBegin: %v", err)
	}
	if err := m.enable(nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	// A node that just bootstrapped the genesis is up to date.
	genesisHead := genesis.Hash().String()
	controlOffer, missing, err := m.syncOffer(genesisHead, nil)
	if err != nil {
		t.Fatalf("syncOffer: %v", err)
	}
	if controlOffer.Head != m.authority.Head() {
		t.Error("sync offer head does not match the authority head")
	}
	if len(missing) != 0 {
		t.Errorf("missing AUMs for an up-to-date node = %d", len(missing))
	}

	// An empty head is malformed: upstream rejects it, so the client must
	// bootstrap before it syncs.
	if _, _, err := m.syncOffer("", nil); err == nil {
		t.Error("an offer with no head was accepted")
	}

	// Extend the chain (as `tailscale lock revoke` would) and check the new
	// AUM is what a stale node pulls.
	newKey := key.NewNLPrivate()
	updater := m.authority.NewUpdater(priv)
	if err := updater.AddKey(tka.Key{Kind: tka.Key25519, Public: newKey.Public().Verifier(), Votes: 1}); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	updates, err := updater.Finalize(m.chonk)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if err := m.authority.Inform(m.chonk, updates); err != nil {
		t.Fatalf("Inform: %v", err)
	}
	controlOffer, missing, err = m.syncOffer(genesisHead, nil)
	if err != nil {
		t.Fatalf("syncOffer(stale): %v", err)
	}
	if len(missing) != 1 {
		t.Fatalf("missing AUMs = %d, want 1", len(missing))
	}
	if missing[0].Hash() != m.authority.Head() {
		t.Error("the missing AUM is not the new head")
	}
	if err := m.syncSend([]tkatype.MarshaledAUM{missing[0].Serialize()}); err != nil {
		t.Fatalf("syncSend: %v", err)
	}
	// Applying the same AUM again is a no-op (idempotent sync).
	if err := m.syncSend([]tkatype.MarshaledAUM{missing[0].Serialize()}); err != nil {
		t.Fatalf("repeated syncSend: %v", err)
	}

	// Node-key signatures must chain back to a trusted key.
	nodeKey := key.NewNode()
	sig := signTestNodeKey(t, priv, nodeKey.Public())
	got, err := m.verifyNodeSignature(sig)
	if err != nil {
		t.Fatalf("verifyNodeSignature: %v", err)
	}
	if got != nodeKey.Public() {
		t.Error("verifyNodeSignature returned the wrong key")
	}
	if err := m.nodeKeyAuthorized(nodeKey.Public(), sig); err != nil {
		t.Errorf("nodeKeyAuthorized: %v", err)
	}

	otherKey := key.NewNode()
	if _, err := m.verifyNodeSignature(signTestNodeKey(t, priv, otherKey.Public())); err != nil {
		t.Fatalf("verifyNodeSignature(other key): %v", err)
	}
	// A signature for a different key must not authorize this one.
	if err := m.nodeKeyAuthorized(nodeKey.Public(), signTestNodeKey(t, priv, otherKey.Public())); err == nil {
		t.Error("a signature for another node key was accepted")
	}

	// A malformed signature is rejected, not silently accepted.
	var garbage tka.NodeKeySignature
	_ = garbage
	if _, err := m.verifyNodeSignature(tkatype.MarshaledSignature([]byte{0xff, 0x00})); err == nil {
		t.Error("a malformed signature was accepted")
	}
	// An untrusted signer is rejected.
	stranger := key.NewNLPrivate()
	if _, err := m.verifyNodeSignature(signTestNodeKey(t, stranger, nodeKey.Public())); err == nil {
		t.Error("a signature from an untrusted key was accepted")
	}
}

func TestTKAManagerDisableAndReinit(t *testing.T) {
	dir := t.TempDir()
	store := state.NewMemoryStore()
	m := newTestTKAManager(t, dir, store)

	_, genesis := newTestTKAKey(t)
	if err := m.initBegin(genesis); err != nil {
		t.Fatalf("initBegin: %v", err)
	}
	if err := m.enable(testDisablementSecret); err != nil {
		t.Fatalf("enable: %v", err)
	}

	if err := m.disable([]byte("wrong-secret")); err != errTKADisablement {
		t.Fatalf("disable with a wrong secret = %v, want errTKADisablement", err)
	}
	if !m.view().Enabled {
		t.Fatal("a wrong secret disabled tailnet lock")
	}

	if err := m.disable(testDisablementSecret); err != nil {
		t.Fatalf("disable: %v", err)
	}
	view := m.view()
	if view.Enabled || !view.EverEnabled {
		t.Fatalf("view after disable = %+v", view)
	}
	if err := m.disable(testDisablementSecret); err != errTKANotEnabled {
		t.Errorf("second disable = %v, want errTKANotEnabled", err)
	}
	if _, _, err := m.syncOffer("", nil); err != errTKANotEnabled {
		t.Errorf("syncOffer while disabled = %v, want errTKANotEnabled", err)
	}

	// The raw support secret is sealed on disk but handed back on bootstrap.
	sealed := store.TKAMeta().DisablementSecretSealed
	if sealed == "" || sealed == string(testDisablementSecret) {
		t.Fatalf("stored disablement secret = %q, want sealed material", sealed)
	}
	_, secret, err := m.bootstrap()
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if string(secret) != string(testDisablementSecret) {
		t.Error("bootstrap did not return the disablement secret")
	}

	// Re-initializing replaces the chain and clears the old disablement state.
	_, newGenesis := newTestTKAKey(t)
	if err := m.initBegin(newGenesis); err != nil {
		t.Fatalf("re-init: %v", err)
	}
	if got := m.view(); got.Enabled || got.Disabled || !got.EverEnabled {
		t.Fatalf("view after re-init = %+v, want a fresh unpublished chain", got)
	}
	if err := m.enable(nil); err != nil {
		t.Fatalf("enable after re-init: %v", err)
	}
	if got := m.view(); !got.Enabled || !got.EverEnabled || got.Disabled {
		t.Fatalf("view after re-init enable = %+v", got)
	}
	if _, secret, err := m.bootstrap(); err != nil || len(secret) != 0 {
		t.Errorf("bootstrap after re-init = (secret %x, err %v), want none", secret, err)
	}
	if string(store.TKAMeta().DisablementSecretSealed) != "" {
		t.Error("the previous disablement secret survived a re-initialization")
	}
}

func TestTKAManagerDisabledAuthorityRejectsWrites(t *testing.T) {
	m := newTestTKAManager(t, t.TempDir(), state.NewMemoryStore())

	_, genesis := newTestTKAKey(t)
	if err := m.initBegin(genesis); err != nil {
		t.Fatalf("initBegin: %v", err)
	}
	if err := m.enable(testDisablementSecret); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := m.disable(testDisablementSecret); err != nil {
		t.Fatalf("disable: %v", err)
	}

	nodeKey := key.NewNode()
	priv := key.NewNLPrivate()
	if _, err := m.verifyNodeSignature(signTestNodeKey(t, priv, nodeKey.Public())); err != errTKANotEnabled {
		t.Errorf("verifyNodeSignature while disabled = %v, want errTKANotEnabled", err)
	}
	if err := m.syncSend(nil); err != errTKANotEnabled {
		t.Errorf("syncSend while disabled = %v, want errTKANotEnabled", err)
	}
}
