package state

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Relay platform state (Xunara Relay: the DERP/STUN data plane).
//
// The relay control protocol is frozen in xunara-relay/docs/relay-protocol.md:
// a relay exchanges a one-time enrollment token for a long-lived identity
// (relay_id + relay_token), then reports status on heartbeats and receives its
// desired configuration in the answer. This file is the persistence boundary
// for that protocol; validation and quota enforcement live in control, and the
// relay itself never stores user data (supplement section 92).

// The two relay credentials are distinguishable on purpose: an enrollment
// token is single-use and short-lived, a relay token is long-lived, and an
// operator reading a log or an Authorization header must be able to tell them
// apart without consulting the database.
const (
	RelayEnrollmentTokenPrefix = "xrelay-enroll-"
	RelayTokenPrefix           = "xrelay-token-"
)

// Relay visibility: who may see and use the relay (supplement sections 8-13).
const (
	RelayVisibilityPrivate      = "private"
	RelayVisibilityOrganization = "organization"
	RelayVisibilityPublic       = "public"
)

// Relay desired states: what the control plane tells a relay to do on the next
// heartbeat (supplement section 14).
const (
	RelayStateOnline      = "online"
	RelayStateMaintenance = "maintenance"
	RelayStateDisabled    = "disabled"
	RelayStateRevoked     = "revoked"
)

// Errors the relay store reports. They map to the protocol's error codes in
// control (401 RELAY_TOKEN_INVALID, 409 RELAY_ALREADY_ENROLLED, 410
// RELAY_ENROLLMENT_EXPIRED, 403 RELAY_REVOKED).
var (
	ErrRelayNotFound           = errors.New("relay: relay not found")
	ErrRelayEnrollmentConsumed = errors.New("relay: enrollment token already used")
	ErrRelayEnrollmentExpired  = errors.New("relay: enrollment token expired")
	ErrRelayTokenExists        = errors.New("relay: relay token already exists")
)

// RelayEnrollmentToken is a one-time credential an operator hands to a relay.
// The secret itself is never stored: only its SHA-256 is.
type RelayEnrollmentToken struct {
	ID string
	// Name is an operator note ("hk-1"), not the relay's final name.
	Name string
	// Visibility is what the relay may request at enrollment; empty lets the
	// relay choose.
	Visibility string
	// Expiry is the deadline after which the token is refused; the zero value
	// means it never expires.
	Expiry time.Time
	// UsedAt is when the token was consumed; zero means unused.
	UsedAt time.Time
	// Created and CreatedBy record who issued it.
	Created   time.Time
	CreatedBy string
}

// Used reports whether the token was already consumed.
func (t RelayEnrollmentToken) Used() bool { return !t.UsedAt.IsZero() }

// Expired reports whether the token is expired at the given time.
func (t RelayEnrollmentToken) Expired(at time.Time) bool {
	return !t.Expiry.IsZero() && !at.Before(t.Expiry)
}

// Relay is one enrolled relay. Telemetry fields are last-known values from
// heartbeats; they are not a metric store (supplement section 34).
type Relay struct {
	ID         string
	Name       string
	HostName   string
	RegionCode string
	RegionName string
	// NodeKey is the relay's DERP node public key ("nodekey:...").
	NodeKey string
	// Version is the relay build reported at enrollment, refreshed by
	// heartbeats.
	Version string
	// DERPPort and STUNPort are the ports the relay serves.
	DERPPort int
	STUNPort int
	// Visibility is one of the RelayVisibility* values.
	Visibility string
	// DesiredState is the state the control plane wants; it takes effect on
	// the relay's next heartbeat.
	DesiredState string
	// ConfigVersion increments whenever DesiredState, BandwidthLimit or
	// RegionName changes, so a relay can apply only changed configuration.
	ConfigVersion uint64
	// BandwidthLimit is a per-connection byte/second limit: 0 leaves the
	// relay's local setting alone, -1 removes the limit, positive sets it.
	BandwidthLimit int64

	// Telemetry from the last heartbeat.
	Healthy          bool
	UptimeSeconds    int64
	ConnectedClients int
	BytesIn          int64
	BytesOut         int64
	LastSeen         time.Time

	Created   time.Time
	CreatedBy string
}

// RelayHeartbeat is the status a relay reports on each heartbeat. A zero
// LastSeen is filled in by the store.
type RelayHeartbeat struct {
	Version          string
	Healthy          bool
	UptimeSeconds    int64
	ConnectedClients int
	BytesIn          int64
	BytesOut         int64
	LastSeen         time.Time
}

// RelayConfigUpdate is an operator's change to a relay. Nil fields keep the
// current value, so a request that only changes the desired state does not
// reset the bandwidth limit.
type RelayConfigUpdate struct {
	DesiredState   string
	BandwidthLimit *int64
	RegionName     *string
	ConfigVersion  uint64
}

// RelayStore persists the relay platform's state.
type RelayStore interface {
	// CreateRelayEnrollmentToken stores a token whose secret is the given
	// plaintext. The store keeps only a hash.
	CreateRelayEnrollmentToken(tok RelayEnrollmentToken, secret string) error
	// RelayEnrollmentTokenBySecret resolves a token by its plaintext secret.
	RelayEnrollmentTokenBySecret(secret string) (RelayEnrollmentToken, bool)
	// RelayEnrollmentTokenByID resolves a token by its identifier.
	RelayEnrollmentTokenByID(id string) (RelayEnrollmentToken, bool)
	// ListRelayEnrollmentTokens returns every token, newest first.
	ListRelayEnrollmentTokens() []RelayEnrollmentToken
	// ConsumeRelayEnrollmentToken marks a token used atomically and returns
	// its record. It reports [ErrRelayNotFound] for an unknown token,
	// [ErrRelayEnrollmentConsumed] when it was already used and
	// [ErrRelayEnrollmentExpired] when it is past its expiry.
	ConsumeRelayEnrollmentToken(id string, at time.Time) (RelayEnrollmentToken, error)
	// DeleteRelayEnrollmentToken removes a token. It is a no-op when unknown.
	DeleteRelayEnrollmentToken(id string) error

	// CreateRelay stores an enrolled relay and the hash of its token.
	CreateRelay(relay Relay, token string) error
	// RelayByToken resolves an enrolled relay by its plaintext token.
	RelayByToken(token string) (Relay, bool)
	// RelayByID resolves an enrolled relay by its identifier.
	RelayByID(id string) (Relay, bool)
	// RelayByNodeKey resolves an enrolled relay by its DERP node key.
	RelayByNodeKey(nodeKey string) (Relay, bool)
	// ListRelays returns every relay, oldest first.
	ListRelays() []Relay
	// UpdateRelayHeartbeat records a relay's status report.
	UpdateRelayHeartbeat(id string, hb RelayHeartbeat) error
	// UpdateRelayConfig applies an operator change and returns the relay's
	// new state. It reports [ErrRelayNotFound] when the relay is unknown.
	UpdateRelayConfig(id string, update RelayConfigUpdate) (Relay, error)
	// DeleteRelay removes a relay. It is a no-op when unknown.
	DeleteRelay(id string) error
}

// RelaySecretHash is the storage form of every relay credential. Tokens are
// 160 bits of randomness, so an unsalted SHA-256 is enough: there is nothing
// to guess.
func RelaySecretHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// NewRelayEnrollmentTokenSecret returns a fresh one-time enrollment secret.
func NewRelayEnrollmentTokenSecret() (string, error) {
	return newRelaySecret(RelayEnrollmentTokenPrefix)
}

// NewRelayTokenSecret returns a fresh long-lived relay token.
func NewRelayTokenSecret() (string, error) {
	return newRelaySecret(RelayTokenPrefix)
}

// NewRelayID returns a fresh relay identifier.
func NewRelayID() (string, error) {
	return newRelayID("relay")
}

// NewRelayEnrollmentTokenID returns a fresh enrollment-token identifier.
func NewRelayEnrollmentTokenID() (string, error) {
	return newRelayID("renr")
}

// newRelaySecret builds a prefix + base32(random) secret. base32 without
// padding keeps it copy-pasteable and free of characters that shells or URLs
// would mangle.
func newRelaySecret(prefix string) (string, error) {
	var raw [20]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("state: generating a relay secret: %w", err)
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return prefix + strings.ToLower(enc.EncodeToString(raw[:])), nil
}

// newRelayID builds prefix-hex(random) identifiers: short, sortable enough for
// humans and collision-free in practice.
func newRelayID(prefix string) (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("state: generating a relay id: %w", err)
	}
	return prefix + "-" + hex.EncodeToString(raw[:]), nil
}

// ValidRelayEnrollmentSecret reports whether a string is shaped like an
// enrollment secret. It is a cheap pre-check before a store lookup, not an
// authorization decision.
func ValidRelayEnrollmentSecret(secret string) bool {
	return validRelaySecret(secret, RelayEnrollmentTokenPrefix)
}

// ValidRelayToken reports whether a string is shaped like a relay token.
func ValidRelayToken(secret string) bool {
	return validRelaySecret(secret, RelayTokenPrefix)
}

func validRelaySecret(secret, prefix string) bool {
	if !strings.HasPrefix(secret, prefix) {
		return false
	}
	// 20 random bytes encode to 32 base32 characters; require the full shape
	// so a truncated token never reaches the store.
	return len(secret) == len(prefix)+32
}

// ValidRelayVisibility reports whether a visibility value is one this build
// understands. Unknown values are refused so a typo cannot create a relay that
// no surface knows how to display.
func ValidRelayVisibility(v string) bool {
	switch v {
	case RelayVisibilityPrivate, RelayVisibilityOrganization, RelayVisibilityPublic:
		return true
	}
	return false
}

// ValidRelayState reports whether a desired state is one this build
// understands.
func ValidRelayState(s string) bool {
	switch s {
	case RelayStateOnline, RelayStateMaintenance, RelayStateDisabled, RelayStateRevoked:
		return true
	}
	return false
}
