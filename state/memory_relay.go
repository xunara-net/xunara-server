package state

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// memoryRelayStore is the in-memory [RelayStore]. It is a sub-store of
// [MemoryStore], like the share namespace, so the map ownership stays in one
// place.
type memoryRelayStore struct {
	mu sync.RWMutex

	tokens  map[string]RelayEnrollmentToken // by token ID
	secrets map[string]string               // secret hash -> token ID

	relays     map[string]Relay  // by relay ID
	relayToken map[string]string // token hash -> relay ID
	relayNode  map[string]string // node key -> relay ID
}

func newMemoryRelayStore() *memoryRelayStore {
	return &memoryRelayStore{
		tokens:     make(map[string]RelayEnrollmentToken),
		secrets:    make(map[string]string),
		relays:     make(map[string]Relay),
		relayToken: make(map[string]string),
		relayNode:  make(map[string]string),
	}
}

var _ RelayStore = (*memoryRelayStore)(nil)

// sortRelays orders relays oldest first, with the ID breaking ties.
func sortRelays(relays []Relay) {
	sort.Slice(relays, func(i, j int) bool {
		a, b := relays[i], relays[j]
		if !a.Created.Equal(b.Created) {
			return a.Created.Before(b.Created)
		}
		return a.ID < b.ID
	})
}

// sortRelayTokens orders enrollment tokens newest first.
func sortRelayTokens(tokens []RelayEnrollmentToken) {
	sort.Slice(tokens, func(i, j int) bool {
		a, b := tokens[i], tokens[j]
		if !a.Created.Equal(b.Created) {
			return a.Created.After(b.Created)
		}
		return a.ID > b.ID
	})
}

// CreateRelayEnrollmentToken implements [RelayStore].
func (m *memoryRelayStore) CreateRelayEnrollmentToken(tok RelayEnrollmentToken, secret string) error {
	if tok.ID == "" {
		return fmt.Errorf("state: relay enrollment token id is required")
	}
	if !ValidRelayEnrollmentSecret(secret) {
		return fmt.Errorf("state: refusing to store a malformed enrollment secret")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	hash := RelaySecretHash(secret)
	if _, dup := m.secrets[hash]; dup {
		return fmt.Errorf("state: duplicate relay enrollment secret")
	}
	if _, dup := m.tokens[tok.ID]; dup {
		return fmt.Errorf("state: duplicate relay enrollment token id %q", tok.ID)
	}
	if tok.Created.IsZero() {
		tok.Created = time.Now().UTC()
	}
	m.tokens[tok.ID] = tok
	m.secrets[hash] = tok.ID
	return nil
}

// RelayEnrollmentTokenBySecret implements [RelayStore].
func (m *memoryRelayStore) RelayEnrollmentTokenBySecret(secret string) (RelayEnrollmentToken, bool) {
	if !ValidRelayEnrollmentSecret(secret) {
		return RelayEnrollmentToken{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	id, ok := m.secrets[RelaySecretHash(secret)]
	if !ok {
		return RelayEnrollmentToken{}, false
	}
	tok, ok := m.tokens[id]
	return tok, ok
}

// RelayEnrollmentTokenByID implements [RelayStore].
func (m *memoryRelayStore) RelayEnrollmentTokenByID(id string) (RelayEnrollmentToken, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tok, ok := m.tokens[id]
	return tok, ok
}

// ListRelayEnrollmentTokens implements [RelayStore].
func (m *memoryRelayStore) ListRelayEnrollmentTokens() []RelayEnrollmentToken {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]RelayEnrollmentToken, 0, len(m.tokens))
	for _, tok := range m.tokens {
		out = append(out, tok)
	}
	// Newest first, with the ID breaking ties so the order is total.
	sortRelayTokens(out)
	return out
}

// ConsumeRelayEnrollmentToken implements [RelayStore].
func (m *memoryRelayStore) ConsumeRelayEnrollmentToken(id string, at time.Time) (RelayEnrollmentToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	tok, ok := m.tokens[id]
	if !ok {
		return RelayEnrollmentToken{}, ErrRelayNotFound
	}
	if tok.Used() {
		return RelayEnrollmentToken{}, ErrRelayEnrollmentConsumed
	}
	if tok.Expired(at) {
		return RelayEnrollmentToken{}, ErrRelayEnrollmentExpired
	}
	tok.UsedAt = at.UTC()
	m.tokens[id] = tok
	return tok, nil
}

// DeleteRelayEnrollmentToken implements [RelayStore].
func (m *memoryRelayStore) DeleteRelayEnrollmentToken(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for hash, tokenID := range m.secrets {
		if tokenID == id {
			delete(m.secrets, hash)
		}
	}
	delete(m.tokens, id)
	return nil
}

// CreateRelay implements [RelayStore].
func (m *memoryRelayStore) CreateRelay(relay Relay, token string) error {
	if relay.ID == "" {
		return fmt.Errorf("state: relay id is required")
	}
	if !ValidRelayToken(token) {
		return fmt.Errorf("state: refusing to store a malformed relay token")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	hash := RelaySecretHash(token)
	if _, dup := m.relayToken[hash]; dup {
		return ErrRelayTokenExists
	}
	if _, dup := m.relays[relay.ID]; dup {
		return fmt.Errorf("state: duplicate relay id %q", relay.ID)
	}
	if relay.NodeKey != "" {
		if _, dup := m.relayNode[relay.NodeKey]; dup {
			return fmt.Errorf("state: duplicate relay node key")
		}
	}
	if relay.Created.IsZero() {
		relay.Created = time.Now().UTC()
	}
	if relay.DesiredState == "" {
		relay.DesiredState = RelayStateOnline
	}
	if relay.ConfigVersion == 0 {
		relay.ConfigVersion = 1
	}
	m.relays[relay.ID] = relay
	m.relayToken[hash] = relay.ID
	if relay.NodeKey != "" {
		m.relayNode[relay.NodeKey] = relay.ID
	}
	return nil
}

// RelayByToken implements [RelayStore].
func (m *memoryRelayStore) RelayByToken(token string) (Relay, bool) {
	if !ValidRelayToken(token) {
		return Relay{}, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	id, ok := m.relayToken[RelaySecretHash(token)]
	if !ok {
		return Relay{}, false
	}
	relay, ok := m.relays[id]
	return relay, ok
}

// RelayByID implements [RelayStore].
func (m *memoryRelayStore) RelayByID(id string) (Relay, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	relay, ok := m.relays[id]
	return relay, ok
}

// RelayByNodeKey implements [RelayStore].
func (m *memoryRelayStore) RelayByNodeKey(nodeKey string) (Relay, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id, ok := m.relayNode[nodeKey]
	if !ok {
		return Relay{}, false
	}
	relay, ok := m.relays[id]
	return relay, ok
}

// ListRelays implements [RelayStore].
func (m *memoryRelayStore) ListRelays() []Relay {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]Relay, 0, len(m.relays))
	for _, relay := range m.relays {
		out = append(out, relay)
	}
	sortRelays(out)
	return out
}

// UpdateRelayHeartbeat implements [RelayStore].
func (m *memoryRelayStore) UpdateRelayHeartbeat(id string, hb RelayHeartbeat) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	relay, ok := m.relays[id]
	if !ok {
		return ErrRelayNotFound
	}
	if hb.LastSeen.IsZero() {
		hb.LastSeen = time.Now().UTC()
	}
	relay.Healthy = hb.Healthy
	relay.UptimeSeconds = hb.UptimeSeconds
	relay.ConnectedClients = hb.ConnectedClients
	relay.BytesIn = hb.BytesIn
	relay.BytesOut = hb.BytesOut
	relay.LastSeen = hb.LastSeen.UTC()
	if hb.Version != "" {
		relay.Version = hb.Version
	}
	m.relays[id] = relay
	return nil
}

// UpdateRelayConfig implements [RelayStore].
func (m *memoryRelayStore) UpdateRelayConfig(id string, update RelayConfigUpdate) (Relay, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	relay, ok := m.relays[id]
	if !ok {
		return Relay{}, ErrRelayNotFound
	}
	relay = applyRelayConfig(relay, update)
	m.relays[id] = relay
	return relay, nil
}

// DeleteRelay implements [RelayStore].
func (m *memoryRelayStore) DeleteRelay(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	relay, ok := m.relays[id]
	if !ok {
		return nil
	}
	delete(m.relays, id)
	delete(m.relayNode, relay.NodeKey)
	for hash, relayID := range m.relayToken {
		if relayID == id {
			delete(m.relayToken, hash)
		}
	}
	return nil
}
