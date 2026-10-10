package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"

	"github.com/xunara-net/xunara-server/netspace"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
)

// Tenant plans and tenant network blocks (PROJECT_SPEC section 54).
//
// A Xunara deployment sells plans; a plan is a set of quotas and feature
// switches (package plan), and this file holds the two facts a plan needs to
// become real for one tenant: which plan the tenant is on, and which address
// range its devices are allocated from.
//
// The registry is the platform layer's memory, not the control plane's: it
// lives in its own SQLite file, is keyed by organization ID, and is only
// opened when the deployment actually sells plans (multi-tenant deployments
// and single-tenant deployments that pass -plans). Without it every tenant is
// on [plan.UnlimitedPlan] and nothing changes for a self-hosted installation.
//
// 套餐记录保存当前归属；网段另有版本日志和预留，用于跨库收敛与保护旧设备地址。

// TenantPlan is one tenant's commercial state.
type TenantPlan struct {
	// OrgID is the organization (tenant) this row describes.
	OrgID string
	// PlanID names a plan in the catalog.
	PlanID string
	// NetworkPrefix is the tailnet address range devices are allocated from,
	// in canonical text form. Empty means "the deployment default".
	NetworkPrefix string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Errors the platform API and the console map to HTTP responses.
var (
	// ErrPlanUnknown is returned when an assignment names a plan the catalog
	// does not have.
	ErrPlanUnknown = errors.New("control: unknown plan")
	// ErrNetworkNotAllowed is returned when a plan forbids a custom tailnet
	// range.
	ErrNetworkNotAllowed = errors.New("control: the plan does not allow a custom network range")
	// ErrNetworkConflict is returned when a range overlaps another tenant's.
	ErrNetworkConflict = errors.New("control: the network range is already in use by another tailnet")
	// ErrNoNetworkBlock is returned when the deployment's pool is exhausted.
	ErrNoNetworkBlock = errors.New("control: the deployment has no free network block left")
)

// planRegistryMigrations are applied in order and tracked with PRAGMA
// user_version on the registry's own database file.
var planRegistryMigrations = []string{
	`
CREATE TABLE IF NOT EXISTS tenant_plans (
	org_id         TEXT    PRIMARY KEY,
	plan_id        TEXT    NOT NULL,
	network_prefix TEXT    NOT NULL DEFAULT '',
	created_at     INTEGER NOT NULL,
	updated_at     INTEGER NOT NULL
);
`,

	// v2: plans the operator created or changed through the platform API. A
	// stored row is overlaid on the deployment's catalog (file or built-in),
	// so a deployment can add a plan without shipping a new binary while the
	// file stays the baseline.
	`
CREATE TABLE IF NOT EXISTS catalog_plans (
	id         TEXT    PRIMARY KEY,
	document   TEXT    NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
`,

	// v3: platform console sessions. They are separate from tenant sessions
	// on purpose: a platform operator's browser must never hold a credential a
	// tenant accepts, and vice versa (see admin_sessions.go).
	`
CREATE TABLE IF NOT EXISTS admin_sessions (
	id           TEXT    PRIMARY KEY,
	token_hash   TEXT    NOT NULL UNIQUE,
	csrf_token   TEXT    NOT NULL,
	created_at   INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	revoked_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at);
`,
	// v4：旧设备可能保留原 IP，因此旧网段预留不能随套餐记录覆盖而释放。
	`
CREATE TABLE tenant_network_reservations (
	org_id TEXT NOT NULL,
	prefix TEXT NOT NULL,
	PRIMARY KEY (org_id, prefix)
);
INSERT INTO tenant_network_reservations SELECT org_id, network_prefix FROM tenant_plans WHERE network_prefix <> '';
CREATE TABLE tenant_network_versions (
	org_id TEXT PRIMARY KEY,
	revision INTEGER NOT NULL,
	prefix TEXT NOT NULL,
	actor TEXT NOT NULL,
	created INTEGER NOT NULL
);
INSERT INTO tenant_network_versions SELECT org_id, 1, network_prefix, 'system:import', updated_at FROM tenant_plans;
CREATE TABLE tenant_network_history (
	org_id TEXT NOT NULL,
	revision INTEGER NOT NULL,
	prefix TEXT NOT NULL,
	actor TEXT NOT NULL,
	created INTEGER NOT NULL,
	PRIMARY KEY (org_id, revision)
);
INSERT INTO tenant_network_history SELECT org_id, revision, prefix, actor, created FROM tenant_network_versions;
`,
}

// PlanRegistryConfig configures the tenant plan registry.
type PlanRegistryConfig struct {
	// Path is the SQLite database file holding assignments.
	Path string
	// Catalog is the set of sellable plans. Nil uses the built-in catalog.
	Catalog *plan.Catalog
	// Pool is the range tenant network blocks are carved from. The zero value
	// disables automatic allocation: tenants then keep the built-in default
	// range unless an operator assigns one explicitly.
	Pool netspace.Pool
	// Reserved lists ranges no tenant may be given, on top of the globally
	// reserved ranges netspace knows about. A deployment puts its internal
	// networks here.
	Reserved []netip.Prefix
}

// PlanRegistry is the durable table of tenant plan assignments.
type PlanRegistry struct {
	cfg PlanRegistryConfig
	// cat is the deployment's catalog: the configured baseline with the
	// operator's stored plans overlaid. It is swapped atomically because a
	// plan edit must be visible to running tenants on their next request.
	cat atomic.Pointer[plan.Catalog]
	db  *sql.DB
}

// OpenPlanRegistry opens (creating if necessary) the registry and applies
// pending migrations.
func OpenPlanRegistry(ctx context.Context, cfg PlanRegistryConfig) (*PlanRegistry, error) {
	if strings.TrimSpace(cfg.Path) == "" {
		return nil, errors.New("control: plan registry needs a database path")
	}
	if !cfg.Pool.Zero() {
		prefix := cfg.Pool.Prefix()
		if !prefix.Addr().Is4() || prefix.Bits() < 10 || !netip.MustParsePrefix("100.64.0.0/10").Contains(prefix.Addr()) {
			return nil, errors.New("control: official client address pools must be a subnet of 100.64.0.0/10")
		}
	}
	if strings.ContainsAny(cfg.Path, "?#") {
		return nil, fmt.Errorf("control: unsupported character in database path %q", cfg.Path)
	}
	cat := cfg.Catalog
	if cat == nil {
		cat = plan.DefaultCatalog()
	}
	if len(cat.List()) == 0 {
		return nil, errors.New("control: plan registry needs a catalog with at least one plan")
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o700); err != nil {
		return nil, fmt.Errorf("control: creating the plan registry directory: %w", err)
	}

	dsn := "file:" + cfg.Path +
		"?_txlock=immediate" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("control: opening %s: %w", cfg.Path, err)
	}
	db.SetMaxOpenConns(1)

	registry := &PlanRegistry{cfg: cfg, db: db}
	registry.cat.Store(cat)
	if err := registry.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := registry.loadStoredPlans(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return registry, nil
}

// loadStoredPlans overlays the operator's stored plans on the configured
// catalog, oldest first so the most recent edit of an ID wins.
func (g *PlanRegistry) loadStoredPlans(ctx context.Context) error {
	rows, err := g.db.QueryContext(ctx,
		"SELECT document FROM catalog_plans ORDER BY created_at, id")
	if err != nil {
		return fmt.Errorf("control: loading stored plans: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var document string
		if err := rows.Scan(&document); err != nil {
			return fmt.Errorf("control: loading stored plans: %w", err)
		}
		var p plan.Plan
		dec := json.NewDecoder(strings.NewReader(document))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return fmt.Errorf("control: stored plan is unreadable: %w", err)
		}
		next, err := g.catalog().WithPlan(p)
		if err != nil {
			return fmt.Errorf("control: stored plan %q is invalid: %w", p.ID, err)
		}
		g.cat.Store(next)
	}
	return rows.Err()
}

// catalog returns the current catalog.
func (g *PlanRegistry) catalog() *plan.Catalog {
	if cat := g.cat.Load(); cat != nil {
		return cat
	}
	return plan.DefaultCatalog()
}

func (g *PlanRegistry) migrate(ctx context.Context) error {
	var version int
	if err := g.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("control: reading plan registry schema version: %w", err)
	}
	if version > len(planRegistryMigrations) {
		return fmt.Errorf("control: plan registry schema version %d is newer than this build understands", version)
	}
	for i := version; i < len(planRegistryMigrations); i++ {
		if _, err := g.db.ExecContext(ctx, planRegistryMigrations[i]); err != nil {
			return fmt.Errorf("control: applying plan registry migration %d: %w", i+1, err)
		}
		if _, err := g.db.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			return fmt.Errorf("control: recording plan registry migration %d: %w", i+1, err)
		}
	}
	return nil
}

// Close closes the registry database.
func (g *PlanRegistry) Close() error { return g.db.Close() }

// Catalog returns the plans this deployment sells, in catalog order.
func (g *PlanRegistry) Catalog() *plan.Catalog { return g.catalog() }

// Pool returns the deployment's tenant network pool.
func (g *PlanRegistry) Pool() netspace.Pool { return g.cfg.Pool }

// Reserved returns the ranges no tenant may hold, including the deployment's
// own internal ranges.
func (g *PlanRegistry) Reserved() []netip.Prefix {
	out := netspace.Reserved()
	return append(out, g.cfg.Reserved...)
}

// List returns every tenant with an assignment, oldest first.
func (g *PlanRegistry) List(ctx context.Context) ([]TenantPlan, error) {
	rows, err := g.db.QueryContext(ctx,
		"SELECT org_id, plan_id, network_prefix, created_at, updated_at FROM tenant_plans ORDER BY created_at, org_id")
	if err != nil {
		return nil, fmt.Errorf("control: listing tenant plans: %w", err)
	}
	defer rows.Close()

	var out []TenantPlan
	for rows.Next() {
		assignment, err := scanTenantPlan(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("control: listing tenant plans: %w", err)
		}
		out = append(out, assignment)
	}
	return out, rows.Err()
}

// Get returns one tenant's assignment. An unassigned tenant reports false.
func (g *PlanRegistry) Get(ctx context.Context, orgID string) (TenantPlan, bool, error) {
	row := g.db.QueryRowContext(ctx,
		"SELECT org_id, plan_id, network_prefix, created_at, updated_at FROM tenant_plans WHERE org_id = ?", orgID)
	assignment, err := scanTenantPlan(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return TenantPlan{}, false, nil
	}
	if err != nil {
		return TenantPlan{}, false, fmt.Errorf("control: reading tenant plan %q: %w", orgID, err)
	}
	return assignment, true, nil
}

// Assignment returns a tenant's state with defaults filled in: an unassigned
// tenant is on the catalog's default plan with no explicit network block.
func (g *PlanRegistry) Assignment(ctx context.Context, orgID string) (TenantPlan, error) {
	assignment, ok, err := g.Get(ctx, orgID)
	if err != nil {
		return TenantPlan{}, err
	}
	if !ok {
		return TenantPlan{OrgID: orgID, PlanID: g.catalog().Default().ID}, nil
	}
	return assignment, nil
}

// Plan returns the plan a tenant is on. An unassigned tenant, or one whose
// assignment names a plan the catalog no longer has, falls back to the
// catalog's default: a deleted plan must not leave a tenant without rules.
func (g *PlanRegistry) Plan(ctx context.Context, orgID string) plan.Plan {
	assignment, ok, err := g.Get(ctx, orgID)
	if err != nil || !ok {
		return g.catalog().Default()
	}
	p, ok := g.catalog().Get(assignment.PlanID)
	if !ok {
		return g.catalog().Default()
	}
	return p
}

// NetworkPrefix returns the address range a tenant's devices are allocated
// from. ok is false when the tenant has no explicit block and the deployment
// default applies.
func (g *PlanRegistry) NetworkPrefix(ctx context.Context, orgID string) (netip.Prefix, bool) {
	assignment, ok, err := g.Get(ctx, orgID)
	if err != nil || !ok || assignment.NetworkPrefix == "" {
		return netip.Prefix{}, false
	}
	prefix, err := netip.ParsePrefix(assignment.NetworkPrefix)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix, true
}

// AssignPlan puts a tenant on a plan. Existing values are replaced; the
// network block is kept unless the new plan forbids the tenant's custom range,
// in which case a block is allocated from the pool again (devices keep the
// addresses they already have: a plan change never re-addresses a live
// tailnet).
func (g *PlanRegistry) AssignPlan(ctx context.Context, orgID, planID string) (TenantPlan, error) {
	next, ok := g.catalog().Get(planID)
	if !ok {
		return TenantPlan{}, fmt.Errorf("%w: %q", ErrPlanUnknown, planID)
	}
	if strings.TrimSpace(orgID) == "" {
		return TenantPlan{}, orgInvalidf("organization id is required")
	}

	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return TenantPlan{}, fmt.Errorf("control: assigning plan %q to %q: %w", planID, orgID, err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	current, ok, err := getTenantPlanTx(ctx, tx, orgID)
	if err != nil {
		return TenantPlan{}, err
	}
	now := time.Now().UTC()
	assignment := TenantPlan{OrgID: orgID, PlanID: planID, CreatedAt: now}
	if ok {
		assignment.NetworkPrefix = current.NetworkPrefix
		assignment.CreatedAt = current.CreatedAt
	}
	if assignment.NetworkPrefix != "" && !next.AllowCustomCIDR {
		// The tenant is downgrading off a custom range. Keep the range only
		// when it came from the deployment's pool (it is a pool block, so it
		// was not the tenant's choice); otherwise hand back a pool block.
		prefix, err := netip.ParsePrefix(assignment.NetworkPrefix)
		if err != nil {
			return TenantPlan{}, fmt.Errorf("control: stored network range %q of %q is not a prefix: %w", assignment.NetworkPrefix, orgID, err)
		}
		if !g.cfg.Pool.Contains(prefix) {
			block, err := g.allocateTx(ctx, tx, orgID)
			if err != nil {
				return TenantPlan{}, err
			}
			assignment.NetworkPrefix = block.String()
		}
	}
	assignment.UpdatedAt = now
	if err := upsertTenantPlanTx(ctx, tx, assignment, "system:plan-assignment"); err != nil {
		return TenantPlan{}, err
	}
	if err := tx.Commit(); err != nil {
		return TenantPlan{}, fmt.Errorf("control: assigning plan %q to %q: %w", planID, orgID, err)
	}
	return assignment, nil
}

// Allocate gives a tenant the default plan and a free block of the
// deployment's pool. It is what a hosted deployment calls when an account
// signs up. Calling it for a tenant that already has a block is a no-op for
// the network half.
func (g *PlanRegistry) Allocate(ctx context.Context, orgID string) (TenantPlan, error) {
	if strings.TrimSpace(orgID) == "" {
		return TenantPlan{}, orgInvalidf("organization id is required")
	}

	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return TenantPlan{}, fmt.Errorf("control: allocating tenant %q: %w", orgID, err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	current, ok, err := getTenantPlanTx(ctx, tx, orgID)
	if err != nil {
		return TenantPlan{}, err
	}
	now := time.Now().UTC()
	assignment := TenantPlan{OrgID: orgID, PlanID: g.catalog().Default().ID, CreatedAt: now, UpdatedAt: now}
	if ok {
		assignment = current
		if assignment.PlanID == "" {
			assignment.PlanID = g.catalog().Default().ID
		}
	}
	if assignment.NetworkPrefix == "" && !g.cfg.Pool.Zero() {
		block, err := g.allocateTx(ctx, tx, orgID)
		if err != nil {
			return TenantPlan{}, err
		}
		assignment.NetworkPrefix = block.String()
	}
	assignment.UpdatedAt = now
	if err := upsertTenantPlanTx(ctx, tx, assignment, "system:allocation"); err != nil {
		return TenantPlan{}, err
	}
	if err := tx.Commit(); err != nil {
		return TenantPlan{}, fmt.Errorf("control: allocating tenant %q: %w", orgID, err)
	}
	return assignment, nil
}

// SetNetwork assigns a tenant's tailnet address range by hand. The plan must
// allow custom ranges, the range must be legal (netspace) and it must not
// overlap another tenant's range or the network block the deployment keeps for
// itself. Passing an invalid prefix clears the custom range, which restores
// the automatically allocated block (or the deployment default).
func (g *PlanRegistry) SetNetwork(ctx context.Context, orgID string, prefix netip.Prefix) (TenantPlan, error) {
	return g.setNetwork(ctx, orgID, prefix, nil, "platform:"+orgID)
}

func (g *PlanRegistry) setNetwork(ctx context.Context, orgID string, prefix netip.Prefix, expected *uint64, actor string) (TenantPlan, error) {
	if strings.TrimSpace(orgID) == "" {
		return TenantPlan{}, orgInvalidf("organization id is required")
	}

	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return TenantPlan{}, fmt.Errorf("control: setting network range of %q: %w", orgID, err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	if expected != nil {
		version, err := readNetworkVersion(ctx, tx, orgID)
		if err != nil {
			return TenantPlan{}, err
		}
		if version.Revision != *expected {
			return TenantPlan{}, state.ErrAddressConflict
		}
	}
	current, ok, err := getTenantPlanTx(ctx, tx, orgID)
	if err != nil {
		return TenantPlan{}, err
	}
	now := time.Now().UTC()
	assignment := TenantPlan{OrgID: orgID, PlanID: g.catalog().Default().ID, CreatedAt: now}
	if ok {
		assignment = current
		if assignment.PlanID == "" {
			assignment.PlanID = g.catalog().Default().ID
		}
	}

	if !prefix.IsValid() {
		// Clearing: fall back to a pool block, or to the deployment default
		// when the deployment runs no pool.
		if !g.cfg.Pool.Zero() {
			block, err := g.allocateTx(ctx, tx, orgID)
			if err != nil {
				return TenantPlan{}, err
			}
			assignment.NetworkPrefix = block.String()
		} else {
			assignment.NetworkPrefix = ""
		}
	} else {
		tenantPlan, ok := g.catalog().Get(assignment.PlanID)
		if !ok {
			tenantPlan = g.catalog().Default()
		}
		if !tenantPlan.AllowCustomCIDR {
			return TenantPlan{}, fmt.Errorf("%w: plan %s", ErrNetworkNotAllowed, tenantPlan.ID)
		}
		normalized, err := netspace.ValidateTailnetPrefix(prefix, g.cfg.Reserved)
		if err != nil {
			return TenantPlan{}, orgInvalidf("%v", err)
		}
		used, err := g.usedNetworksTx(ctx, tx, orgID)
		if err != nil {
			return TenantPlan{}, err
		}
		if other, overlap := netspace.FirstOverlap(normalized, used); overlap {
			return TenantPlan{}, fmt.Errorf("%w (%s)", ErrNetworkConflict, other)
		}
		assignment.NetworkPrefix = normalized.String()
	}
	assignment.UpdatedAt = now
	if err := upsertTenantPlanTx(ctx, tx, assignment, actor); err != nil {
		return TenantPlan{}, err
	}
	if err := tx.Commit(); err != nil {
		return TenantPlan{}, fmt.Errorf("control: setting network range of %q: %w", orgID, err)
	}
	return assignment, nil
}

// ErrPlanBuiltIn is returned when the platform API tries to delete a plan
// that comes from the deployment's configuration: the file (or the built-in
// catalog) would bring it back on the next start, so it can only be
// overridden, never deleted.
var ErrPlanBuiltIn = errors.New("control: this plan comes from the deployment's configuration and can only be overridden")

// UpsertPlan stores a plan definition and makes it visible to every tenant on
// the plan's next request. A plan whose ID matches a configured one overrides
// it for this deployment; a new ID extends the catalog.
func (g *PlanRegistry) UpsertPlan(ctx context.Context, p plan.Plan) (plan.Plan, error) {
	p.ID = strings.TrimSpace(p.ID)
	if err := p.Validate(); err != nil {
		return plan.Plan{}, orgInvalidf("%v", err)
	}
	next, err := g.catalog().WithPlan(p)
	if err != nil {
		return plan.Plan{}, orgInvalidf("%v", err)
	}
	document, err := json.Marshal(p)
	if err != nil {
		return plan.Plan{}, fmt.Errorf("control: encoding plan %q: %w", p.ID, err)
	}

	now := time.Now().UTC()
	if _, err := g.db.ExecContext(ctx, `
		INSERT INTO catalog_plans (id, document, created_at, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET document = excluded.document, updated_at = excluded.updated_at`,
		p.ID, string(document), now.UnixNano(), now.UnixNano()); err != nil {
		return plan.Plan{}, fmt.Errorf("control: storing plan %q: %w", p.ID, err)
	}
	g.cat.Store(next)
	return p, nil
}

// DeletePlan removes an operator-created plan. A configured plan cannot be
// deleted (it would return at the next start), the default plan cannot be
// deleted (unassigned tenants follow it), and a plan tenants are on cannot be
// deleted until they are moved: deleting it would silently change their rules.
func (g *PlanRegistry) DeletePlan(ctx context.Context, id string) error {
	if _, ok := g.catalog().Get(id); !ok {
		return fmt.Errorf("%w: %q", plan.ErrPlanNotFound, id)
	}
	if g.catalog().Default().ID == id {
		return fmt.Errorf("%w: %q", plan.ErrDefaultPlan, id)
	}
	stored, err := g.storedPlan(ctx, id)
	if err != nil {
		return err
	}
	if !stored {
		return ErrPlanBuiltIn
	}
	tenants, err := g.PlanTenants(ctx, id)
	if err != nil {
		return err
	}
	if tenants > 0 {
		return orgConflictf("plan %q still has %d tenant(s); move them to another plan first", id, tenants)
	}
	next, err := g.catalog().WithoutPlan(id)
	if err != nil {
		return fmt.Errorf("%w: %v", plan.ErrPlanNotFound, err)
	}
	if _, err := g.db.ExecContext(ctx, "DELETE FROM catalog_plans WHERE id = ?", id); err != nil {
		return fmt.Errorf("control: deleting plan %q: %w", id, err)
	}
	g.cat.Store(next)
	return nil
}

// PlanTenants counts the tenants explicitly assigned to a plan.
func (g *PlanRegistry) PlanTenants(ctx context.Context, planID string) (int, error) {
	var count int
	if err := g.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM tenant_plans WHERE plan_id = ?", planID).Scan(&count); err != nil {
		return 0, fmt.Errorf("control: counting tenants on plan %q: %w", planID, err)
	}
	return count, nil
}

// storedPlan reports whether a plan comes from the registry rather than the
// deployment's configuration.
func (g *PlanRegistry) storedPlan(ctx context.Context, id string) (bool, error) {
	var one int
	err := g.db.QueryRowContext(ctx, "SELECT 1 FROM catalog_plans WHERE id = ? LIMIT 1", id).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("control: reading plan %q: %w", id, err)
	}
	return true, nil
}

// Delete drops a tenant's assignment, which returns it to the catalog default.
func (g *PlanRegistry) Delete(ctx context.Context, orgID string) error {
	transaction, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	assignment, found, err := getTenantPlanTx(ctx, transaction, orgID)
	if err != nil {
		return err
	}
	if found {
		assignment.NetworkPrefix = ""
		assignment.UpdatedAt = time.Now().UTC()
		if err := upsertTenantPlanTx(ctx, transaction, assignment, "system:assignment-removed"); err != nil {
			return err
		}
	}
	// 删除或归档组织不释放仍可能被旧设备使用的地址预留。
	if _, err := transaction.ExecContext(ctx, "DELETE FROM tenant_plans WHERE org_id = ?", orgID); err != nil {
		return fmt.Errorf("control: deleting tenant plan %q: %w", orgID, err)
	}
	return transaction.Commit()
}

// allocateTx picks the lowest free block of the pool inside a transaction.
// Running inside the writer's transaction is what makes two concurrent
// sign-ups agree on which block is free.
func (g *PlanRegistry) allocateTx(ctx context.Context, tx *sql.Tx, orgID string) (netip.Prefix, error) {
	used, err := g.usedNetworksTx(ctx, tx, orgID)
	if err != nil {
		return netip.Prefix{}, err
	}
	block, err := g.cfg.Pool.Allocate(append(g.Reserved(), netspace.ClientReserved()...), used)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: %v", ErrNoNetworkBlock, err)
	}
	return block, nil
}

// usedNetworksTx lists the network ranges other tenants hold.
func (g *PlanRegistry) usedNetworksTx(ctx context.Context, tx *sql.Tx, excludeOrg string) ([]netip.Prefix, error) {
	rows, err := tx.QueryContext(ctx,
		"SELECT network_prefix FROM tenant_plans WHERE org_id <> ? AND network_prefix <> '' UNION SELECT prefix FROM tenant_network_reservations WHERE org_id <> ?", excludeOrg, excludeOrg)
	if err != nil {
		return nil, fmt.Errorf("control: listing allocated network ranges: %w", err)
	}
	defer rows.Close()

	var out []netip.Prefix
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("control: listing allocated network ranges: %w", err)
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("control: stored network range %q is not a prefix: %w", raw, err)
		}
		out = append(out, prefix)
	}
	return out, rows.Err()
}

// getTenantPlanTx reads one assignment inside a transaction.
func getTenantPlanTx(ctx context.Context, tx *sql.Tx, orgID string) (TenantPlan, bool, error) {
	row := tx.QueryRowContext(ctx,
		"SELECT org_id, plan_id, network_prefix, created_at, updated_at FROM tenant_plans WHERE org_id = ?", orgID)
	assignment, err := scanTenantPlan(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return TenantPlan{}, false, nil
	}
	if err != nil {
		return TenantPlan{}, false, fmt.Errorf("control: reading tenant plan %q: %w", orgID, err)
	}
	return assignment, true, nil
}

// upsertTenantPlanTx writes one assignment inside a transaction.
func upsertTenantPlanTx(ctx context.Context, tx *sql.Tx, assignment TenantPlan, actor string) error {
	previous, _, err := getTenantPlanTx(ctx, tx, assignment.OrgID)
	if err != nil {
		return err
	}
	version, err := readNetworkVersion(ctx, tx, assignment.OrgID)
	if err != nil {
		return err
	}
	if version.Revision >= state.MaxAddressRevision && version.Prefix != assignment.NetworkPrefix {
		return state.ErrAddressConflict
	}
	for _, prefix := range []string{previous.NetworkPrefix, assignment.NetworkPrefix} {
		if prefix != "" {
			if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO tenant_network_reservations(org_id,prefix) VALUES (?,?)", assignment.OrgID, prefix); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO tenant_network_versions(org_id,revision,prefix,actor,created) VALUES (?,1,?,?,?)
		ON CONFLICT(org_id) DO UPDATE SET revision=revision+1,prefix=excluded.prefix,actor=excluded.actor,created=excluded.created WHERE prefix<>excluded.prefix`,
		assignment.OrgID, assignment.NetworkPrefix, actor, assignment.UpdatedAt.UnixNano()); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO tenant_network_history(org_id,revision,prefix,actor,created)
		SELECT org_id,revision,prefix,actor,created FROM tenant_network_versions WHERE org_id=?`, assignment.OrgID); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO tenant_plans (org_id, plan_id, network_prefix, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(org_id) DO UPDATE SET
			plan_id        = excluded.plan_id,
			network_prefix = excluded.network_prefix,
			updated_at     = excluded.updated_at`,
		assignment.OrgID, assignment.PlanID, assignment.NetworkPrefix,
		assignment.CreatedAt.UnixNano(), assignment.UpdatedAt.UnixNano())
	if err != nil {
		return fmt.Errorf("control: storing tenant plan %q: %w", assignment.OrgID, err)
	}
	return nil
}

// scanTenantPlan reads one row in the canonical column order.
func scanTenantPlan(scan func(...any) error) (TenantPlan, error) {
	var (
		assignment        TenantPlan
		created, modified int64
	)
	if err := scan(&assignment.OrgID, &assignment.PlanID, &assignment.NetworkPrefix, &created, &modified); err != nil {
		return TenantPlan{}, err
	}
	assignment.CreatedAt = time.Unix(0, created).UTC()
	assignment.UpdatedAt = time.Unix(0, modified).UTC()
	return assignment, nil
}
