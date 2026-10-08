package control

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/tkatype"

	"github.com/xunara-net/xunara-server/state"
)

// Tailnet lock (TKA) control plane (M11).
//
// The control plane is the tailnet's tailnet-key-authority storage: it holds
// the AUM chain, serves it to nodes over the /machine/tka/* RPCs, and publishes
// every node's node-key signature in the netmap so peers can verify node keys
// without trusting the control plane. The wire formats and RPC shapes follow
// upstream (tailcfg.TKA*, tailscale/tka); the chain itself is stored through
// upstream's tailchonk implementation so the on-disk format stays compatible.
//
// Node-key signatures live on [state.Node] (the netmap's source of truth); this
// file only owns the authority, the disablement bookkeeping and the sealing of
// the support disablement secret (AGENTS.md section 8).

// tkaSealingKeyFile holds the key that seals the support disablement secret.
const tkaSealingKeyFile = "tka_secret.key"

// tkaView is the tailnet-lock state the netmap advertises.
type tkaView struct {
	// EverEnabled is true once the tailnet was locked, even after a
	// disablement, so clients keep receiving TKAInfo and can clear local
	// state.
	EverEnabled bool
	// Enabled is true while enforcement is on: the chain was installed by
	// init/begin and every existing node was signed by init/finish.
	Enabled bool
	// Disabled is true after an explicit disablement, which clients act on by
	// fetching the disablement secret and clearing their local state.
	Disabled bool
	// Head is the current head AUM hash in MarshalText form. Empty when the
	// tailnet is not enabled.
	Head string
}

var (
	errTKANotEnabled     = errors.New("tailnet lock is not enabled")
	errTKAAlreadyEnabled = errors.New("tailnet lock is already enabled")
	errTKADisablement    = errors.New("incorrect disablement secret")
)

// tkaManager owns one tailnet's tailnet-lock state.
type tkaManager struct {
	mu sync.Mutex

	key   [32]byte
	store state.TKAStore
	log   *slog.Logger

	// meta, chonk, and authority are guarded by mu.
	meta      state.TKAMeta
	chonkDir  string
	chonk     *tka.FS
	authority *tka.Authority // nil when the tailnet has no chain
}

// newTKAManager opens (or creates) the tailnet's TKA storage under stateDir.
func newTKAManager(stateDir string, store state.TKAStore, log *slog.Logger) (*tkaManager, error) {
	key, err := loadOrCreateSealingKey(filepath.Join(stateDir, tkaSealingKeyFile))
	if err != nil {
		return nil, err
	}
	chonkDir := filepath.Join(stateDir, "tka")
	chonk, err := tka.ChonkDir(chonkDir)
	if err != nil {
		return nil, fmt.Errorf("control: opening the tailnet-lock store: %w", err)
	}

	m := &tkaManager{key: key, store: store, log: log, meta: store.TKAMeta(), chonkDir: chonkDir, chonk: chonk}
	if err := m.reloadLocked(); err != nil {
		return nil, err
	}
	return m, nil
}

// reloadLocked reopens the authority from the tailchonk. The caller holds mu.
func (m *tkaManager) reloadLocked() error {
	heads, err := m.chonk.Heads()
	if err != nil {
		return fmt.Errorf("control: reading the tailnet-lock store: %w", err)
	}
	if len(heads) == 0 {
		m.authority = nil
		return nil
	}
	authority, err := tka.Open(m.chonk)
	if err != nil {
		return fmt.Errorf("control: opening the tailnet-lock authority: %w", err)
	}
	m.authority = authority
	return nil
}

// view returns the state the netmap advertises.
func (m *tkaManager) view() tkaView {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.viewLocked()
}

func (m *tkaManager) viewLocked() tkaView {
	view := tkaView{EverEnabled: m.meta.EverEnabled}
	view.Disabled = m.meta.Disabled
	if m.meta.Enabled && m.authority != nil {
		view.Enabled = true
		view.Head = m.authority.Head().String()
	}
	return view
}

// initBegin installs a fresh authority from a client-generated genesis AUM,
// replacing any previous (disabled) chain.
func (m *tkaManager) initBegin(genesis tka.AUM) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.authority != nil && !m.meta.Disabled {
		return errTKAAlreadyEnabled
	}
	if err := m.chonk.RemoveAll(); err != nil {
		return fmt.Errorf("control: resetting the tailnet-lock store: %w", err)
	}
	// RemoveAll deletes the chonk root directory itself, so recreate it before
	// bootstrapping into it.
	if err := os.MkdirAll(m.chonkDir, 0o755); err != nil {
		return fmt.Errorf("control: recreating the tailnet-lock store: %w", err)
	}
	authority, err := tka.Bootstrap(m.chonk, genesis)
	if err != nil {
		return fmt.Errorf("control: rejecting the genesis AUM: %w", err)
	}
	meta := state.TKAMeta{EverEnabled: true}
	if err := m.store.SetTKAMeta(meta); err != nil {
		return err
	}
	m.authority = authority
	m.meta = meta
	return nil
}

// enable finishes enablement: from this point the tailnet advertises the
// chain and every peer is expected to carry a node-key signature. secret is
// the support disablement secret `tailscale lock init
// --gen-disablement-for-support` produced, if any; it is sealed before it
// touches storage.
func (m *tkaManager) enable(secret []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.authority == nil {
		return errTKANotEnabled
	}
	var sealed string
	if len(secret) > 0 {
		var err error
		sealed, err = sealSecret(m.key, base64.RawStdEncoding.EncodeToString(secret))
		if err != nil {
			return err
		}
	}
	meta := state.TKAMeta{EverEnabled: true, Enabled: true, DisablementSecretSealed: sealed}
	if err := m.store.SetTKAMeta(meta); err != nil {
		return err
	}
	m.meta = meta
	return nil
}

// disable verifies a disablement secret and records that the tailnet's key
// authority is off. The chain itself is kept: re-initializing replaces it, and
// keeping it lets the operator inspect what was locked.
func (m *tkaManager) disable(secret []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.authority == nil || !m.meta.Enabled {
		return errTKANotEnabled
	}
	if !m.authority.ValidDisablement(secret) {
		return errTKADisablement
	}
	sealed, err := sealSecret(m.key, base64.RawStdEncoding.EncodeToString(secret))
	if err != nil {
		return err
	}
	meta := m.meta
	meta.EverEnabled = true
	meta.Enabled = false
	meta.Disabled = true
	meta.DisablementSecretSealed = sealed
	if err := m.store.SetTKAMeta(meta); err != nil {
		return err
	}
	m.meta = meta
	return nil
}

// bootstrap returns what a node needs to enable or disable tailnet lock
// locally: the genesis AUM of the chain and, when the tailnet is disabled, the
// support disablement secret.
func (m *tkaManager) bootstrap() (tkatype.MarshaledAUM, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var genesis tkatype.MarshaledAUM
	if m.authority != nil {
		root, err := m.genesisLocked()
		if err != nil {
			return nil, nil, err
		}
		genesis = root.Serialize()
	}

	var secret []byte
	if m.meta.Disabled && m.meta.DisablementSecretSealed != "" {
		plaintext, err := openSecret(m.key, m.meta.DisablementSecretSealed)
		if err != nil {
			return nil, nil, err
		}
		secret, err = base64.RawStdEncoding.DecodeString(plaintext)
		if err != nil {
			return nil, nil, fmt.Errorf("control: decoding the disablement secret: %w", err)
		}
	}
	return genesis, secret, nil
}

// genesisLocked walks from the head to the root of the chain. The caller holds
// mu and the authority is non-nil.
func (m *tkaManager) genesisLocked() (tka.AUM, error) {
	aum, err := m.chonk.AUM(m.authority.Head())
	if err != nil {
		return tka.AUM{}, fmt.Errorf("control: reading the tailnet-lock head: %w", err)
	}
	for {
		parent, hasParent := aum.Parent()
		if !hasParent {
			return aum, nil
		}
		if aum, err = m.chonk.AUM(parent); err != nil {
			return tka.AUM{}, fmt.Errorf("control: reading a parent AUM: %w", err)
		}
	}
}

// syncOffer answers a node's synchronization offer, mirroring the upstream
// /machine/tka/sync/offer semantics.
func (m *tkaManager) syncOffer(head string, ancestors []string) (tka.SyncOffer, []tka.AUM, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.meta.Enabled {
		return tka.SyncOffer{}, nil, errTKANotEnabled
	}

	nodeOffer, err := tka.ToSyncOffer(head, ancestors)
	if err != nil {
		return tka.SyncOffer{}, nil, fmt.Errorf("invalid sync offer: %w", err)
	}
	controlOffer, err := m.authority.SyncOffer(m.chonk)
	if err != nil {
		return tka.SyncOffer{}, nil, fmt.Errorf("control: building the sync offer: %w", err)
	}
	missing, err := m.authority.MissingAUMs(m.chonk, nodeOffer)
	if err != nil {
		return tka.SyncOffer{}, nil, fmt.Errorf("control: computing missing AUMs: %w", err)
	}
	return controlOffer, missing, nil
}

// syncSend applies AUMs a node reported, mirroring /machine/tka/sync/send.
func (m *tkaManager) syncSend(raw []tkatype.MarshaledAUM) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.meta.Enabled {
		return errTKANotEnabled
	}

	toApply := make([]tka.AUM, len(raw))
	for i, blob := range raw {
		if err := toApply[i].Unserialize(blob); err != nil {
			return fmt.Errorf("decoding AUM %d: %w", i, err)
		}
	}
	if len(toApply) == 0 {
		return nil
	}
	if err := m.authority.Inform(m.chonk, toApply); err != nil {
		return fmt.Errorf("applying AUMs: %w", err)
	}
	return nil
}

// verifyNodeSignature checks that a node-key signature authorizes the node key
// it names, and returns that key.
func (m *tkaManager) verifyNodeSignature(sig tkatype.MarshaledSignature) (key.NodePublic, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.meta.Enabled {
		return key.NodePublic{}, errTKANotEnabled
	}
	return m.verifyNodeSignatureLocked(sig)
}

// verifyNodeSignatureForInit verifies a node-key signature while the tailnet
// is being initialized: init/finish must validate the signatures it is about
// to store before enforcement is on.
func (m *tkaManager) verifyNodeSignatureForInit(sig tkatype.MarshaledSignature) (key.NodePublic, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.authority == nil {
		return key.NodePublic{}, errTKANotEnabled
	}
	return m.verifyNodeSignatureLocked(sig)
}

func (m *tkaManager) verifyNodeSignatureLocked(sig tkatype.MarshaledSignature) (key.NodePublic, error) {
	var decoded tka.NodeKeySignature
	if err := decoded.Unserialize(sig); err != nil {
		return key.NodePublic{}, fmt.Errorf("malformed signature: %w", err)
	}
	var pub key.NodePublic
	if err := pub.UnmarshalBinary(decoded.Pubkey); err != nil {
		return key.NodePublic{}, fmt.Errorf("malformed signature pubkey: %w", err)
	}
	if err := m.authority.NodeKeyAuthorized(pub, sig); err != nil {
		return key.NodePublic{}, fmt.Errorf("signature does not verify: %w", err)
	}
	return pub, nil
}

// nodeKeyAuthorized reports whether sig authorizes nodeKey, for a registration
// that carries a re-signed node-key signature.
func (m *tkaManager) nodeKeyAuthorized(nodeKey key.NodePublic, sig tkatype.MarshaledSignature) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.meta.Enabled {
		return errTKANotEnabled
	}
	return m.authority.NodeKeyAuthorized(nodeKey, sig)
}
