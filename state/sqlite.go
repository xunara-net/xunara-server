package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// migrations are applied in order; the applied count is tracked in
// PRAGMA user_version.
var migrations = []string{
	// v1: nodes and the counter table backing ID/address allocation.
	`
CREATE TABLE IF NOT EXISTS nodes (
	id          INTEGER PRIMARY KEY,
	stable_id   TEXT    NOT NULL UNIQUE,
	machine_key TEXT    NOT NULL,
	node_key    TEXT    NOT NULL UNIQUE,
	disco_key   TEXT    NOT NULL,
	user_id     INTEGER NOT NULL,
	hostname    TEXT    NOT NULL DEFAULT '',
	ipv4        TEXT,
	ipv6        TEXT,
	endpoints   TEXT    NOT NULL DEFAULT '[]',
	home_derp   INTEGER NOT NULL DEFAULT 0,
	cap_ver     INTEGER NOT NULL DEFAULT 0,
	hostinfo    BLOB,
	last_seen   INTEGER,
	expiry      INTEGER,
	created     INTEGER NOT NULL,
	method      TEXT    NOT NULL DEFAULT '',
	ephemeral   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_nodes_machine_key ON nodes(machine_key);

CREATE TABLE IF NOT EXISTS counters (
	name  TEXT    PRIMARY KEY,
	value INTEGER NOT NULL
);
`,

	// v2: pre-authentication keys.
	`
CREATE TABLE IF NOT EXISTS preauthkeys (
	id        INTEGER PRIMARY KEY,
	secret    TEXT    NOT NULL UNIQUE,
	user_id   INTEGER NOT NULL,
	reusable  INTEGER NOT NULL DEFAULT 0,
	ephemeral INTEGER NOT NULL DEFAULT 0,
	used      INTEGER NOT NULL DEFAULT 0,
	expiry    INTEGER,
	created   INTEGER NOT NULL,
	used_at   INTEGER
);
`,

	// v3: approved subnet routes.
	`
ALTER TABLE nodes ADD COLUMN approved_routes TEXT NOT NULL DEFAULT '[]';
`,

	// v4: MagicDNS records created through /machine/set-dns.
	`
CREATE TABLE IF NOT EXISTS dns_records (
	id      INTEGER PRIMARY KEY,
	name    TEXT    NOT NULL,
	type    TEXT    NOT NULL,
	value   TEXT    NOT NULL,
	node_id INTEGER NOT NULL DEFAULT 0,
	created INTEGER NOT NULL,
	UNIQUE(name, type, value)
);
CREATE INDEX IF NOT EXISTS idx_dns_records_name ON dns_records(name);
`,

	// v5: ACL tags carried by pre-authentication keys.
	`
ALTER TABLE preauthkeys ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';
`,

	// v6: ACL tags carried by nodes.
	`
ALTER TABLE nodes ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';
`,

	// v7: tailnet-lock node-key signatures and control-plane bookkeeping.
	`
ALTER TABLE nodes ADD COLUMN key_signature BLOB;
CREATE TABLE IF NOT EXISTS tka_meta (
	id                  INTEGER PRIMARY KEY CHECK (id = 1),
	ever_enabled        INTEGER NOT NULL DEFAULT 0,
	enabled             INTEGER NOT NULL DEFAULT 0,
	disabled            INTEGER NOT NULL DEFAULT 0,
	disablement_secret  TEXT    NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO tka_meta (id) VALUES (1);
`,

	// v8: the node's tailnet-lock public key, reported at registration and
	// needed to authorize later node-key rotations.
	`
ALTER TABLE nodes ADD COLUMN nl_key TEXT NOT NULL DEFAULT '';
`,

	// v9: device posture attributes a node reports about itself through
	// /machine/set-device-attr. Values are JSON scalars stored as JSON text so
	// the type (string, number, bool) survives a round trip. The foreign key
	// cascades: deleting a node drops its attributes.
	`
CREATE TABLE IF NOT EXISTS node_device_attrs (
	node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
	attr       TEXT    NOT NULL,
	value      TEXT    NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (node_id, attr)
);
`,

	// v10: services nodes advertise about themselves (Xunara Atlas). The name
	// is the primary key: it is unique per organization, so resolution is
	// unambiguous. The foreign key cascades: deleting a node drops its
	// services, and no other row can claim the freed name.
	`
CREATE TABLE IF NOT EXISTS node_services (
	node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
	name       TEXT    NOT NULL,
	protocol   TEXT    NOT NULL,
	port       INTEGER NOT NULL,
	metadata   TEXT    NOT NULL DEFAULT '{}',
	created    INTEGER NOT NULL,
	updated    INTEGER NOT NULL,
	PRIMARY KEY (name)
);
CREATE INDEX IF NOT EXISTS idx_node_services_node ON node_services(node_id);
`,

	// v11: Xunara Flux file transfers (section 25). Metadata only: the
	// ciphertext lives in files next to the database, keyed by transfer ID.
	// Both node references cascade, so deleting a node drops its transfers
	// (the janitor sweeps the orphaned content files).
	`
CREATE TABLE IF NOT EXISTS flux_transfers (
	id             TEXT    PRIMARY KEY,
	sender_node    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
	recipient_node INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
	name           TEXT    NOT NULL,
	size           INTEGER NOT NULL,
	sha256         TEXT    NOT NULL,
	state          TEXT    NOT NULL,
	recipient_key  BLOB,
	reason         TEXT    NOT NULL DEFAULT '',
	created_at     INTEGER NOT NULL,
	updated_at     INTEGER NOT NULL,
	expires_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flux_sender ON flux_transfers(sender_node, state);
CREATE INDEX IF NOT EXISTS idx_flux_recipient ON flux_transfers(recipient_node, state);
CREATE INDEX IF NOT EXISTS idx_flux_state ON flux_transfers(state, updated_at);
`,

	// v12: Atlas service health (section 26). Health is telemetry, not part
	// of the declaration, so it lives in its own table: a row means the
	// service opted in (the declaration's "health" flag) and carries the last
	// readiness plus the deadline after which the janitor withdraws the
	// service from discovery. The table is created rather than a column added
	// so the migration is replayable, and health rows die with their node
	// (there is deliberately no reference to node_services: a republish
	// replaces those rows, and the health state must survive it).
	`
CREATE TABLE IF NOT EXISTS node_service_health (
	node_id     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
	name        TEXT    NOT NULL,
	healthy     INTEGER NOT NULL DEFAULT 0,
	reported_at INTEGER,
	until       INTEGER,
	PRIMARY KEY (node_id, name)
);
CREATE INDEX IF NOT EXISTS idx_node_service_health_expiry ON node_service_health(healthy, until);
`,

	// v13: durable fixed-window rate limiting (section 28). Buckets are named
	// by an opaque scope string and reclaimed by age; nothing references
	// nodes, so a deleted node's buckets disappear with the prune sweep.
	`
CREATE TABLE IF NOT EXISTS rate_limits (
	scope        TEXT PRIMARY KEY,
	window_start INTEGER NOT NULL,
	count        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits(window_start);
`,

	// v14: Xunara Reach remote command sessions (section 29). The control
	// plane orchestrates sessions and relays output chunks; argv and output
	// live here, never in the audit log. Chunk rows die with their session.
	`
CREATE TABLE IF NOT EXISTS reach_sessions (
	id          TEXT    PRIMARY KEY,
	sender_node INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
	target_node INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
	state       TEXT    NOT NULL,
	argv        TEXT    NOT NULL,
	timeout_ms  INTEGER NOT NULL,
	exit_code   INTEGER,
	error       TEXT    NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL,
	expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reach_sender ON reach_sessions(sender_node, state);
CREATE INDEX IF NOT EXISTS idx_reach_target ON reach_sessions(target_node, state);
CREATE INDEX IF NOT EXISTS idx_reach_expiry ON reach_sessions(state, expires_at);
CREATE TABLE IF NOT EXISTS reach_chunks (
	session_id TEXT    NOT NULL REFERENCES reach_sessions(id) ON DELETE CASCADE,
	stream     TEXT    NOT NULL,
	seq        INTEGER NOT NULL,
	data       BLOB    NOT NULL,
	created_at INTEGER NOT NULL,
PRIMARY KEY (session_id, stream, seq)
);
`,

	// v15: the per-organization share namespace (section 38): synthetic node
	// IDs and masquerade addresses for nodes shared from another organization.
	sqliteShareMigration,

	// v16: Atlas service visibility (section 46). Like the health table, this
	// is a separate table rather than a column on node_services so the
	// migration is replayable (a republish replaces the declaration rows, and
	// the visibility must be rewritten with them). A missing row means the v1
	// default: discovery by the whole organization.
	`
CREATE TABLE IF NOT EXISTS node_service_visibility (
	node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
	name       TEXT    NOT NULL,
	visibility TEXT    NOT NULL,
	PRIMARY KEY (node_id, name)
);
`,

	// v17: cross-organization service discovery (section 47). Like the
	// visibility table, a separate table keeps the migration replayable: a
	// republish replaces the declaration rows and must rewrite the flag with
	// them. A missing row means the default: not shared.
	`
CREATE TABLE IF NOT EXISTS node_service_shared (
	node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
	name    TEXT    NOT NULL,
	PRIMARY KEY (node_id, name)
);
`,

	// v18: ACL-derived service visibility (section 48). Same replayable shape
	// as the other per-service flags: a row means "derive discovery from the
	// ACL", a missing row means the declaration uses selector visibility (or
	// the organization default).
	`
CREATE TABLE IF NOT EXISTS node_service_acl_visibility (
	node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
	name    TEXT    NOT NULL,
	PRIMARY KEY (node_id, name)
);
`,

	// v19: the relay platform (Xunara Relay). relays holds one row per enrolled
	// DERP/STUN relay with its last heartbeat telemetry and the desired
	// configuration the control plane hands back; relay_enrollment_tokens
	// holds the one-time credentials operators issue, storing only their
	// SHA-256 so a database leak cannot be replayed against the control plane.
	`
CREATE TABLE IF NOT EXISTS relays (
	id                TEXT    PRIMARY KEY,
	name              TEXT    NOT NULL DEFAULT '',
	hostname          TEXT    NOT NULL DEFAULT '',
	region_code       TEXT    NOT NULL DEFAULT '',
	region_name       TEXT    NOT NULL DEFAULT '',
	node_key          TEXT    NOT NULL DEFAULT '',
	version           TEXT    NOT NULL DEFAULT '',
	derp_port         INTEGER NOT NULL DEFAULT 0,
	stun_port         INTEGER NOT NULL DEFAULT 0,
	visibility        TEXT    NOT NULL DEFAULT 'private',
	desired_state     TEXT    NOT NULL DEFAULT 'online',
	config_version    INTEGER NOT NULL DEFAULT 1,
	bandwidth_limit   INTEGER NOT NULL DEFAULT 0,
	token_hash        TEXT    NOT NULL UNIQUE,
	healthy           INTEGER NOT NULL DEFAULT 0,
	uptime_seconds    INTEGER NOT NULL DEFAULT 0,
	connected_clients INTEGER NOT NULL DEFAULT 0,
	bytes_in          INTEGER NOT NULL DEFAULT 0,
	bytes_out         INTEGER NOT NULL DEFAULT 0,
	last_seen         INTEGER,
	created           INTEGER NOT NULL,
	created_by        TEXT    NOT NULL DEFAULT ''
);
-- A node key identifies a relay's DERP identity, so two relays must not
-- share one. The index is partial because a relay that has not reported a
-- key yet stores an empty string, and empty values must not collide.
CREATE UNIQUE INDEX IF NOT EXISTS idx_relays_node_key ON relays(node_key) WHERE node_key <> '';

CREATE TABLE IF NOT EXISTS relay_enrollment_tokens (
	id          TEXT    PRIMARY KEY,
	name        TEXT    NOT NULL DEFAULT '',
	secret_hash TEXT    NOT NULL UNIQUE,
	visibility  TEXT    NOT NULL DEFAULT 'private',
	expiry      INTEGER,
	used_at     INTEGER,
	created     INTEGER NOT NULL,
	created_by  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_relay_enrollment_created ON relay_enrollment_tokens(created);
`,

	// v20：配置头与不可变历史；旧二进制必须拒绝此版本，避免忽略已发布 ACL。
	`
ALTER TABLE dns_records ADD COLUMN revision INTEGER NOT NULL DEFAULT 1;
CREATE TABLE IF NOT EXISTS network_documents (
	kind       TEXT PRIMARY KEY,
	revision   INTEGER NOT NULL,
	content    TEXT NOT NULL,
	actor      TEXT NOT NULL,
	created    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS network_document_history (
	kind       TEXT NOT NULL,
	revision   INTEGER NOT NULL,
	content    TEXT NOT NULL,
	actor      TEXT NOT NULL,
	created    INTEGER NOT NULL,
	PRIMARY KEY (kind, revision)
);
`,
	// v21：地区 0 保留旧托管记录，不推断其证书信任或下发地区。
	`
ALTER TABLE relays ADD COLUMN region_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE relays ADD COLUMN cert_name TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_relays_region_id ON relays(region_id) WHERE region_id > 0;
`,
	// v22：旧记录执行状态未知，不能由期望版本自动补成“已执行”。
	`
ALTER TABLE relays ADD COLUMN execution_report TEXT NOT NULL DEFAULT '';
ALTER TABLE relays ADD COLUMN execution_reported_at INTEGER;
`,
}

// SQLiteStore is a durable [Store] backed by SQLite.
//
// All statements run on a single connection: SQLite allows one writer at a
// time, and serialising here keeps ID/address allocation atomic without
// sprinkling retries for SQLITE_BUSY through the call sites.
type SQLiteStore struct {
	db *sql.DB

	// mu makes "read counters, allocate, write" atomic across the two
	// statements CreateNode needs.
	mu sync.Mutex

	// ipv4Prefix and ipv6Prefix are the ranges new nodes are allocated from.
	// They default to the tailnet's well-known ranges and follow the tenant's
	// commercial network block (see prefix.go).
	ipv4Prefix netip.Prefix
	ipv6Prefix netip.Prefix
}

// OpenSQLite opens (creating if necessary) a SQLite-backed store at path and
// applies pending migrations.
func OpenSQLite(ctx context.Context, path string) (*SQLiteStore, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("state: unsupported character in database path %q", path)
	}

	dsn := "file:" + path +
		"?_txlock=immediate" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(1)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("state: opening %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)

	s := &SQLiteStore{db: db, ipv4Prefix: defaultIPv4Prefix, ipv6Prefix: defaultIPv6Prefix}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the underlying database.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// DB returns the underlying database handle.
//
// It exists so that other modules keeping their tables in the same file (the
// identity store) share one connection pool: SQLite allows a single writer, so
// one pool per process is the configuration that serialises cleanly.
func (s *SQLiteStore) DB() *sql.DB { return s.db }

func (s *SQLiteStore) migrate(ctx context.Context) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("state: reading schema version: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("state: database schema version %d is newer than this build (%d)", version, len(migrations))
	}

	for i := version; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("state: starting migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("state: migration %d: %w", i+1, err)
		}
		// PRAGMA does not accept placeholders; i+1 is a bounded loop index.
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return fmt.Errorf("state: recording migration %d: %w", i+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("state: committing migration %d: %w", i+1, err)
		}
	}
	return nil
}

var _ Store = (*SQLiteStore)(nil)

// nodeColumns is the column list every node SELECT and INSERT agrees on.
const nodeColumns = `id, stable_id, machine_key, node_key, disco_key, user_id, hostname,
	ipv4, ipv6, endpoints, home_derp, cap_ver, hostinfo, last_seen, expiry, created, method, ephemeral,
	approved_routes, tags, key_signature, nl_key`

func (s *SQLiteStore) GetNodeByID(id NodeID) (Node, bool) {
	return s.queryNode(context.Background(), "SELECT "+nodeColumns+" FROM nodes WHERE id = ?", int64(id))
}

func (s *SQLiteStore) GetNodeByNodeKey(nk key.NodePublic) (Node, bool) {
	text, err := nk.MarshalText()
	if err != nil {
		return Node{}, false
	}
	return s.queryNode(context.Background(), "SELECT "+nodeColumns+" FROM nodes WHERE node_key = ?", string(text))
}

func (s *SQLiteStore) GetNodeByStableID(id string) (Node, bool) {
	return s.queryNode(context.Background(), "SELECT "+nodeColumns+" FROM nodes WHERE stable_id = ?", id)
}

func (s *SQLiteStore) GetNodesByMachineKey(mk key.MachinePublic) []Node {
	text, err := mk.MarshalText()
	if err != nil {
		return nil
	}

	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+nodeColumns+" FROM nodes WHERE machine_key = ? ORDER BY id", string(text))
	if err != nil {
		return nil
	}
	defer rows.Close()

	return collectNodes(rows)
}

func (s *SQLiteStore) ListNodes() []Node {
	nodes, _ := s.ListNodesContext(context.Background())
	return nodes
}

func (s *SQLiteStore) ListNodesContext(ctx context.Context) ([]Node, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT "+nodeColumns+" FROM nodes ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes := make([]Node, 0)
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, rows.Err()
}

func (s *SQLiteStore) queryNode(ctx context.Context, query string, args ...any) (Node, bool) {
	row := s.db.QueryRowContext(ctx, query, args...)
	n, err := scanNode(row)
	if err != nil {
		return Node{}, false
	}
	return n, true
}

func collectNodes(rows *sql.Rows) []Node {
	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanNode(sc scanner) (Node, error) {
	var (
		id        int64
		stableID  string
		machineS  string
		nodeS     string
		discoS    string
		userID    int64
		hostname  string
		ipv4      sql.NullString
		ipv6      sql.NullString
		endpoints string
		homeDERP  int64
		capVer    int64
		hostinfo  []byte
		lastSeen  sql.NullInt64
		expiry    sql.NullInt64
		created   int64
		method    string
		ephemeral int64
		approved  string
		tags      string
		keySig    []byte
		nlKey     string
	)

	err := sc.Scan(&id, &stableID, &machineS, &nodeS, &discoS, &userID, &hostname,
		&ipv4, &ipv6, &endpoints, &homeDERP, &capVer, &hostinfo, &lastSeen, &expiry,
		&created, &method, &ephemeral, &approved, &tags, &keySig, &nlKey)
	if err != nil {
		return Node{}, err
	}

	n := Node{
		ID:        NodeID(id),
		StableID:  stableID,
		UserID:    tailcfg.UserID(userID),
		Hostname:  hostname,
		HomeDERP:  tailcfg.DERPRegionID(homeDERP),
		CapVer:    tailcfg.CapabilityVersion(capVer),
		Created:   time.Unix(0, created).UTC(),
		Method:    RegisterMethod(method),
		Ephemeral: ephemeral != 0,
	}
	if len(keySig) > 0 {
		n.KeySignature = keySig
	}
	if nlKey != "" {
		if err := n.NLKey.UnmarshalText([]byte(nlKey)); err != nil {
			return Node{}, fmt.Errorf("state: parsing network lock key: %w", err)
		}
	}

	if err := n.MachineKey.UnmarshalText([]byte(machineS)); err != nil {
		return Node{}, fmt.Errorf("state: parsing machine key: %w", err)
	}
	if err := n.NodeKey.UnmarshalText([]byte(nodeS)); err != nil {
		return Node{}, fmt.Errorf("state: parsing node key: %w", err)
	}
	if discoS != "" {
		if err := n.DiscoKey.UnmarshalText([]byte(discoS)); err != nil {
			return Node{}, fmt.Errorf("state: parsing disco key: %w", err)
		}
	}
	if ipv4.Valid {
		if n.IPv4, err = netip.ParseAddr(ipv4.String); err != nil {
			return Node{}, fmt.Errorf("state: parsing IPv4: %w", err)
		}
	}
	if ipv6.Valid {
		if n.IPv6, err = netip.ParseAddr(ipv6.String); err != nil {
			return Node{}, fmt.Errorf("state: parsing IPv6: %w", err)
		}
	}
	if lastSeen.Valid {
		t := time.Unix(0, lastSeen.Int64).UTC()
		n.LastSeen = &t
	}
	if expiry.Valid {
		n.Expiry = time.Unix(0, expiry.Int64).UTC()
	}
	if len(hostinfo) > 0 {
		var hi tailcfg.Hostinfo
		if err := json.Unmarshal(hostinfo, &hi); err != nil {
			return Node{}, fmt.Errorf("state: parsing hostinfo: %w", err)
		}
		n.Hostinfo = &hi
	}
	if err := decodeEndpoints(endpoints, &n); err != nil {
		return Node{}, err
	}
	if n.ApprovedRoutes, err = decodeRoutes(approved); err != nil {
		return Node{}, err
	}
	if err := decodeStringList(tags, &n.Tags); err != nil {
		return Node{}, err
	}

	return n, nil
}

// decodeStringList parses a NOT NULL JSON string-list column, tolerating rows
// written before the column existed (empty string means "no values").
func decodeStringList(encoded string, out *[]string) error {
	if encoded == "" || encoded == "[]" || encoded == "null" {
		return nil
	}
	if err := json.Unmarshal([]byte(encoded), out); err != nil {
		return fmt.Errorf("state: parsing string list: %w", err)
	}
	return nil
}

// encodeStringList renders a NOT NULL JSON string-list column.
func encodeStringList(values []string) (string, error) {
	if len(values) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("state: encoding string list: %w", err)
	}
	return string(b), nil
}

// decodeRoutes parses the JSON encoding of a route list.
func decodeRoutes(encoded string) ([]netip.Prefix, error) {
	if encoded == "" || encoded == "[]" {
		return nil, nil
	}

	var raw []string
	if err := json.Unmarshal([]byte(encoded), &raw); err != nil {
		return nil, fmt.Errorf("state: parsing routes: %w", err)
	}

	routes := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("state: parsing route %q: %w", s, err)
		}
		routes = append(routes, p)
	}
	return normalizeRoutes(routes), nil
}

// encodeRoutes renders a route list as JSON. It always returns valid JSON so
// that the NOT NULL column stays readable.
func encodeRoutes(routes []netip.Prefix) (string, error) {
	normalized := normalizeRoutes(routes)
	if len(normalized) == 0 {
		return "[]", nil
	}

	raw := make([]string, 0, len(normalized))
	for _, r := range normalized {
		raw = append(raw, r.String())
	}

	b, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("state: encoding routes: %w", err)
	}
	return string(b), nil
}

func decodeEndpoints(encoded string, n *Node) error {
	if encoded == "" || encoded == "[]" {
		return nil
	}

	var raw []string
	if err := json.Unmarshal([]byte(encoded), &raw); err != nil {
		return fmt.Errorf("state: parsing endpoints: %w", err)
	}

	n.Endpoints = make([]netip.AddrPort, 0, len(raw))
	for _, s := range raw {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return fmt.Errorf("state: parsing endpoint %q: %w", s, err)
		}
		n.Endpoints = append(n.Endpoints, ap)
	}
	return nil
}

func encodeEndpoints(n Node) (string, error) {
	if len(n.Endpoints) == 0 {
		return "[]", nil
	}

	raw := make([]string, 0, len(n.Endpoints))
	for _, ap := range n.Endpoints {
		raw = append(raw, ap.String())
	}

	b, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("state: encoding endpoints: %w", err)
	}
	return string(b), nil
}

func (s *SQLiteStore) CreateNode(n *Node) error {
	if n == nil {
		return fmt.Errorf("state: nil node")
	}
	if n.NodeKey.IsZero() {
		return fmt.Errorf("state: node key is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: beginning create: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	if n.StableID == "" {
		n.StableID = newStableID()
	}
	if n.Created.IsZero() {
		n.Created = time.Now().UTC()
	}

	nextID, err := nextCounter(ctx, tx, counterNextNodeID, 1)
	if err != nil {
		return err
	}
	n.ID = NodeID(nextID)

	if !n.IPv4.IsValid() {
		addr, err := nextNodeAddr(ctx, tx, counterNextIPv4Offset, s.ipv4Prefix, "IPv4", nodeHasIPv4)
		if err != nil {
			return err
		}
		n.IPv4 = addr
	}
	if !n.IPv6.IsValid() {
		addr, err := nextNodeAddr(ctx, tx, counterNextIPv6Offset, s.ipv6Prefix, "IPv6", nodeHasIPv6)
		if err != nil {
			return err
		}
		n.IPv6 = addr
	}

	endpoints, err := encodeEndpoints(*n)
	if err != nil {
		return err
	}
	approved, err := encodeRoutes(n.ApprovedRoutes)
	if err != nil {
		return err
	}
	tags, err := encodeStringList(n.Tags)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO nodes (`+nodeColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		int64(n.ID),
		n.StableID,
		textOf(n.MachineKey, ""),
		textOf(n.NodeKey, ""),
		textOf(n.DiscoKey, ""),
		int64(n.UserID),
		n.Hostname,
		nullableAddr(n.IPv4),
		nullableAddr(n.IPv6),
		endpoints,
		int64(n.HomeDERP),
		int64(n.CapVer),
		marshalHostinfo(n.Hostinfo),
		nullableTime(n.LastSeen),
		nullableTimePtr(n.Expiry),
		n.Created.UnixNano(),
		string(n.Method),
		boolToInt(n.Ephemeral),
		approved,
		tags,
		nullableBytes(n.KeySignature),
		textOf(n.NLKey, ""),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrNodeKeyExists
		}
		return fmt.Errorf("state: inserting node: %w", err)
	}

	return tx.Commit()
}

func (s *SQLiteStore) UpdateNode(n Node) error {
	endpoints, err := encodeEndpoints(n)
	if err != nil {
		return err
	}
	approved, err := encodeRoutes(n.ApprovedRoutes)
	if err != nil {
		return err
	}
	tags, err := encodeStringList(n.Tags)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(context.Background(), `UPDATE nodes SET
			stable_id = ?, machine_key = ?, node_key = ?, disco_key = ?, user_id = ?,
			hostname = ?, ipv4 = ?, ipv6 = ?, endpoints = ?, home_derp = ?,
			cap_ver = ?, hostinfo = ?, last_seen = ?, expiry = ?, created = ?,
			method = ?, ephemeral = ?, approved_routes = ?, tags = ?, key_signature = ?,
			nl_key = ?
		WHERE id = ?`,
		n.StableID,
		textOf(n.MachineKey, ""),
		textOf(n.NodeKey, ""),
		textOf(n.DiscoKey, ""),
		int64(n.UserID),
		n.Hostname,
		nullableAddr(n.IPv4),
		nullableAddr(n.IPv6),
		endpoints,
		int64(n.HomeDERP),
		int64(n.CapVer),
		marshalHostinfo(n.Hostinfo),
		nullableTime(n.LastSeen),
		nullableTimePtr(n.Expiry),
		n.Created.UnixNano(),
		string(n.Method),
		boolToInt(n.Ephemeral),
		approved,
		tags,
		nullableBytes(n.KeySignature),
		textOf(n.NLKey, ""),
		int64(n.ID),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrNodeKeyExists
		}
		return fmt.Errorf("state: updating node %d: %w", n.ID, err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("state: updating node %d: %w", n.ID, err)
	}
	if affected == 0 {
		return fmt.Errorf("state: node %d not found", n.ID)
	}
	return nil
}

func (s *SQLiteStore) DeleteNode(id NodeID) error {
	_, err := s.db.ExecContext(context.Background(), "DELETE FROM nodes WHERE id = ?", int64(id))
	if err != nil {
		return fmt.Errorf("state: deleting node %d: %w", id, err)
	}
	return nil
}

// TKAMeta implements [TKAStore].
func (s *SQLiteStore) TKAMeta() TKAMeta {
	var (
		everEnabled, enabled, disabled int64
		sealed                         string
	)
	err := s.db.QueryRowContext(context.Background(),
		`SELECT ever_enabled, enabled, disabled, disablement_secret FROM tka_meta WHERE id = 1`).
		Scan(&everEnabled, &enabled, &disabled, &sealed)
	if err != nil {
		return TKAMeta{}
	}
	return TKAMeta{
		EverEnabled:             everEnabled != 0,
		Enabled:                 enabled != 0,
		Disabled:                disabled != 0,
		DisablementSecretSealed: sealed,
	}
}

// SetTKAMeta implements [TKAStore].
func (s *SQLiteStore) SetTKAMeta(meta TKAMeta) error {
	_, err := s.db.ExecContext(context.Background(), `UPDATE tka_meta SET
			ever_enabled = ?, enabled = ?, disabled = ?, disablement_secret = ?
		WHERE id = 1`,
		boolToInt(meta.EverEnabled),
		boolToInt(meta.Enabled),
		boolToInt(meta.Disabled),
		meta.DisablementSecretSealed,
	)
	if err != nil {
		return fmt.Errorf("state: updating the tailnet-lock state: %w", err)
	}
	return nil
}

func (s *SQLiteStore) SetNodeApprovedRoutes(id NodeID, routes []netip.Prefix) error {
	encoded, err := encodeRoutes(routes)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(context.Background(),
		"UPDATE nodes SET approved_routes = ? WHERE id = ?", encoded, int64(id))
	if err != nil {
		return fmt.Errorf("state: setting approved routes for node %d: %w", id, err)
	}
	if affected, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("state: setting approved routes for node %d: %w", id, err)
	} else if affected == 0 {
		return fmt.Errorf("state: node %d not found", id)
	}
	return nil
}

// ConfigRevision returns the durable configuration revision.
func (s *SQLiteStore) ConfigRevision() uint64 {
	var value int64
	err := s.db.QueryRowContext(context.Background(),
		"SELECT value FROM counters WHERE name = ?", counterConfigRevision).Scan(&value)
	if err != nil || value < 0 {
		return 0
	}
	return uint64(value)
}

// BumpConfigRevision advances the configuration revision.
func (s *SQLiteStore) BumpConfigRevision() error {
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO counters (name, value) VALUES (?, 1)
		 ON CONFLICT(name) DO UPDATE SET value = value + 1`, counterConfigRevision)
	if err != nil {
		return fmt.Errorf("state: bumping configuration revision: %w", err)
	}
	return nil
}

// Counter names backing ID and address allocation.
const (
	counterNextNodeID     = "next_node_id"
	counterNextIPv4Offset = "next_ipv4_offset"
	counterNextIPv6Offset = "next_ipv6_offset"
	counterNextShareNode  = "next_share_node"
	// counterNextShareAddress indexes the reserved masquerade ranges.
	counterNextShareAddress = "next_share_address"

	// counterConfigRevision counts out-of-band configuration changes. It is
	// durable so that a running server notices changes made by another process
	// (the administration CLI, or a second server instance).
	counterConfigRevision = "config_revision"
)

// nextCounter returns the current value of a counter and advances it.
func nextCounter(ctx context.Context, tx *sql.Tx, name string, def int64) (int64, error) {
	var value int64
	err := tx.QueryRowContext(ctx, "SELECT value FROM counters WHERE name = ?", name).Scan(&value)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		value = def
	case err != nil:
		return 0, fmt.Errorf("state: reading counter %s: %w", name, err)
	}

	next := value + 1
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO counters (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value",
		name, next); err != nil {
		return 0, fmt.Errorf("state: writing counter %s: %w", name, err)
	}
	return value, nil
}

func textOf(m interface{ MarshalText() ([]byte, error) }, fallback string) string {
	b, err := m.MarshalText()
	if err != nil {
		return fallback
	}
	return string(b)
}

func nullableAddr(a netip.Addr) any {
	if !a.IsValid() {
		return nil
	}
	return a.String()
}

// nullableBytes stores an absent signature as SQL NULL, so "unsigned" and
// "signed with an empty blob" cannot be confused.
func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nullableTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UnixNano()
}

func nullableTimePtr(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixNano()
}

func marshalHostinfo(hi *tailcfg.Hostinfo) any {
	if hi == nil {
		return nil
	}
	b, err := json.Marshal(hi)
	if err != nil {
		return nil
	}
	return b
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
