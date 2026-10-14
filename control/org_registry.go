package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Platform-managed organizations (M7d).
//
// The organization table normally comes from the deployment's configuration
// file (`-org-config`), which means adding a tenant is a restart. This file
// adds the other half: a durable registry of organizations that the platform
// API can create, retarget and delete while the process serves.
//
// The two kinds stay separate on purpose. Configured organizations are owned by
// the deployment file and are read-only here; managed ones live in their own
// SQLite database next to the platform's state and own a state directory the
// registry chooses (never the caller: a path from an API request would be a
// directory-traversal hole).
//
// Deleting a managed organization archives its state directory instead of
// erasing it: the audit log and the identity database survive for forensics,
// and re-creating the ID starts from an empty directory rather than silently
// resurrecting old keys.

// ManagedOrg is one platform-managed organization.
type ManagedOrg struct {
	// ID is the stable identifier and the state-directory name.
	ID string
	// Name is the human-readable organization name.
	Name string
	// Domains are the request hosts routed to the organization. A managed
	// organization must declare at least one: without it there is no way to
	// route a request to it deterministically.
	Domains []string
	// ServerURL is the control-plane URL its clients are configured with. Its
	// host must be one of Domains, so clients cannot be pointed at another
	// tenant.
	ServerURL string
	// Domain is the MagicDNS domain (empty disables MagicDNS).
	Domain    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Errors the platform API maps to HTTP responses.
var (
	ErrOrgExists   = errors.New("control: organization already exists")
	ErrOrgNotFound = errors.New("control: organization not found")
)

// orgAPIError is a client mistake that is safe to return verbatim: a
// validation failure (400) or a conflict (409). It is a distinct type so an
// infrastructure failure can never be reported as a caller mistake.
type orgAPIError struct {
	status int
	msg    string
}

// Error implements error.
func (e *orgAPIError) Error() string { return e.msg }

// orgInvalidf builds a 400 for the platform API.
func orgInvalidf(format string, args ...any) error {
	return &orgAPIError{status: http.StatusBadRequest, msg: fmt.Sprintf(format, args...)}
}

// orgConflictf builds a 409 for the platform API.
func orgConflictf(format string, args ...any) error {
	return &orgAPIError{status: http.StatusConflict, msg: fmt.Sprintf(format, args...)}
}

// managedOrgIDPattern bounds an organization ID. The ID becomes a path
// component, a routing key and an audit subject, so it is restricted to
// lowercase letters, digits and dashes.
var managedOrgIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// OrgRegistryConfig configures the durable platform organization registry.
type OrgRegistryConfig struct {
	// Path is the SQLite database file holding the registry.
	Path string
	// StateRoot holds one state directory per managed organization.
	StateRoot string
	// NewServer builds the control plane for one managed organization. The
	// registry decides the state directory and passes it in.
	NewServer func(org ManagedOrg, stateDir string) (*Server, error)
}

// OrgRegistry is the durable table of platform-managed organizations.
type OrgRegistry struct {
	cfg OrgRegistryConfig
	db  *sql.DB
}

// Org registry schema versions, applied in order.
var orgRegistryMigrations = []string{
	`
CREATE TABLE IF NOT EXISTS managed_organizations (
	id         TEXT    PRIMARY KEY,
	name       TEXT    NOT NULL,
	domains    TEXT    NOT NULL DEFAULT '[]',
	server_url TEXT    NOT NULL,
	domain     TEXT    NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
`,
	// v2：公开开户名称独立于组织短名；数据库约束负责跨实例阻止重复开户。
	`
CREATE TABLE IF NOT EXISTS signup_login_claims (
	login_name TEXT NOT NULL PRIMARY KEY COLLATE NOCASE CHECK (length(login_name) BETWEEN 1 AND 128),
	org_id TEXT NOT NULL,
	completed INTEGER NOT NULL DEFAULT 0 CHECK (completed IN (0, 1)),
	created_at INTEGER NOT NULL
);
`,
	// v3：原生入口的范围绑定不是授权；机器仍必须通过自己的租户审批。
	`
CREATE TABLE native_device_bindings (
 machine_key TEXT NOT NULL,
 node_key TEXT NOT NULL,
 org_id TEXT NOT NULL,
 noise_key TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY (machine_key, node_key)
);
CREATE INDEX native_device_bindings_machine ON native_device_bindings(machine_key);
CREATE TABLE native_device_flows (
 id TEXT PRIMARY KEY,
 machine_key TEXT NOT NULL,
 node_key TEXT NOT NULL,
 registration TEXT NOT NULL,
 org_id TEXT NOT NULL DEFAULT '',
 noise_key TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 UNIQUE (machine_key, node_key)
);
CREATE INDEX native_device_flows_expiry ON native_device_flows(expires_at);
`,
}

// OpenOrgRegistry opens (creating if necessary) the registry and applies
// pending migrations.
func OpenOrgRegistry(ctx context.Context, cfg OrgRegistryConfig) (*OrgRegistry, error) {
	if cfg.Path == "" || cfg.StateRoot == "" || cfg.NewServer == nil {
		return nil, errors.New("control: organization registry needs a database path, a state root and a server factory")
	}
	if strings.ContainsAny(cfg.Path, "?#") {
		return nil, fmt.Errorf("control: unsupported character in database path %q", cfg.Path)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Path), 0o700); err != nil {
		return nil, fmt.Errorf("control: creating the registry directory: %w", err)
	}
	// The state root is where every managed organization's identity database
	// and Noise key live: private to the process owner.
	if err := os.MkdirAll(cfg.StateRoot, 0o700); err != nil {
		return nil, fmt.Errorf("control: creating the organization state root: %w", err)
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

	registry := &OrgRegistry{cfg: cfg, db: db}
	if err := registry.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return registry, nil
}

// migrate applies pending schema versions.
func (g *OrgRegistry) migrate(ctx context.Context) error {
	return migrateRegistry(ctx, g.db, orgRegistryMigrations, "organization registry")
}

// Close closes the registry database.
func (g *OrgRegistry) Close() error { return g.db.Close() }

// List returns every managed organization, oldest first.
func (g *OrgRegistry) List(ctx context.Context) ([]ManagedOrg, error) {
	rows, err := g.db.QueryContext(ctx,
		"SELECT id, name, domains, server_url, domain, created_at, updated_at FROM managed_organizations ORDER BY created_at, id")
	if err != nil {
		return nil, fmt.Errorf("control: listing managed organizations: %w", err)
	}
	defer rows.Close()

	var out []ManagedOrg
	for rows.Next() {
		org, err := scanManagedOrg(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("control: listing managed organizations: %w", err)
		}
		out = append(out, org)
	}
	return out, rows.Err()
}

// Get returns one managed organization.
func (g *OrgRegistry) Get(ctx context.Context, id string) (ManagedOrg, bool, error) {
	row := g.db.QueryRowContext(ctx,
		"SELECT id, name, domains, server_url, domain, created_at, updated_at FROM managed_organizations WHERE id = ?", id)
	org, err := scanManagedOrg(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return ManagedOrg{}, false, nil
	}
	if err != nil {
		return ManagedOrg{}, false, fmt.Errorf("control: reading managed organization %q: %w", id, err)
	}
	return org, true, nil
}

// Create validates and stores a new managed organization, assigning its
// timestamps.
func (g *OrgRegistry) Create(ctx context.Context, org ManagedOrg) (ManagedOrg, error) {
	return g.create(ctx, org, "")
}

func (g *OrgRegistry) create(ctx context.Context, org ManagedOrg, signupLogin string) (ManagedOrg, error) {
	if err := validateManagedOrg(org); err != nil {
		return ManagedOrg{}, err
	}
	if signupLogin != "" {
		canonical, err := signupLoginKey(signupLogin)
		if err != nil {
			return ManagedOrg{}, err
		}
		signupLogin = canonical
	}
	domains, err := encodeStringList(org.Domains)
	if err != nil {
		return ManagedOrg{}, err
	}

	now := time.Now().UTC()
	org.CreatedAt, org.UpdatedAt = now, now
	transaction, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return ManagedOrg{}, fmt.Errorf("control: starting organization creation: %w", err)
	}
	defer transaction.Rollback()
	if signupLogin != "" {
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO signup_login_claims (login_name, org_id, created_at) VALUES (?, ?, ?)`,
			signupLogin, org.ID, now.UnixNano()); err != nil {
			if isUniqueViolation(err) {
				return ManagedOrg{}, errSignupLoginTaken
			}
			return ManagedOrg{}, fmt.Errorf("control: reserving signup login: %w", err)
		}
	}
	// 未完成名称也保留组织 ID：旧组织移除到套餐清理之间不能被另一轮开户复用。
	var pending bool
	if err := transaction.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM signup_login_claims WHERE org_id = ? AND completed = 0 AND login_name <> ? COLLATE NOCASE)`,
		org.ID, signupLogin).Scan(&pending); err != nil {
		return ManagedOrg{}, fmt.Errorf("control: checking pending organization creation: %w", err)
	}
	if pending {
		return ManagedOrg{}, ErrOrgExists
	}
	_, err = transaction.ExecContext(ctx, `
		INSERT INTO managed_organizations (id, name, domains, server_url, domain, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		org.ID, org.Name, domains, org.ServerURL, org.Domain, now.UnixNano(), now.UnixNano())
	if err != nil {
		if isUniqueViolation(err) {
			return ManagedOrg{}, ErrOrgExists
		}
		return ManagedOrg{}, fmt.Errorf("control: creating managed organization %q: %w", org.ID, err)
	}
	if err := transaction.Commit(); err != nil {
		return ManagedOrg{}, fmt.Errorf("control: committing organization creation: %w", err)
	}
	return org, nil
}

// Update replaces the mutable fields of a managed organization. ID and
// ServerURL are immutable: clients are configured with the URL, and the ID is
// the state-directory name and routing key.
func (g *OrgRegistry) Update(ctx context.Context, org ManagedOrg) (ManagedOrg, error) {
	if err := validateManagedOrg(org); err != nil {
		return ManagedOrg{}, err
	}
	domains, err := encodeStringList(org.Domains)
	if err != nil {
		return ManagedOrg{}, err
	}

	now := time.Now().UTC()
	res, err := g.db.ExecContext(ctx, `
		UPDATE managed_organizations
		SET name = ?, domains = ?, domain = ?, updated_at = ?
		WHERE id = ?`,
		org.Name, domains, org.Domain, now.UnixNano(), org.ID)
	if err != nil {
		return ManagedOrg{}, fmt.Errorf("control: updating managed organization %q: %w", org.ID, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ManagedOrg{}, ErrOrgNotFound
	}
	updated, ok, err := g.Get(ctx, org.ID)
	if err != nil {
		return ManagedOrg{}, err
	}
	if !ok {
		return ManagedOrg{}, ErrOrgNotFound
	}
	return updated, nil
}

// Delete removes a managed organization from the registry.
func (g *OrgRegistry) Delete(ctx context.Context, id string) error {
	res, err := g.db.ExecContext(ctx, "DELETE FROM managed_organizations WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("control: deleting managed organization %q: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrOrgNotFound
	}
	return nil
}

// 只能由已经归档并关闭租户状态的路由器调用；名称释放与组织删除一起提交。
func (g *OrgRegistry) deleteArchived(ctx context.Context, id string) error {
	transaction, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	result, err := transaction.ExecContext(ctx, "DELETE FROM managed_organizations WHERE id = ?", id)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return ErrOrgNotFound
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM signup_login_claims WHERE org_id = ?", id); err != nil {
		return err
	}
	var remaining int
	if err := transaction.QueryRowContext(ctx, "SELECT count(*) FROM signup_login_claims WHERE org_id = ?", id).Scan(&remaining); err != nil {
		return err
	}
	if remaining != 0 {
		return errors.New("signup name release did not persist")
	}
	return transaction.Commit()
}

// StateDir returns the state directory of a managed organization.
func (g *OrgRegistry) StateDir(id string) string {
	return filepath.Join(g.cfg.StateRoot, id)
}

// NewServer builds an organization's control plane in its own state directory.
func (g *OrgRegistry) NewServer(org ManagedOrg) (*Server, error) {
	return g.cfg.NewServer(org, g.StateDir(org.ID))
}

// ArchiveState moves an organization's state directory aside under
// "deleted/<id>-<timestamp>" and returns the new path. A missing directory is
// not an error (nothing to archive).
func (g *OrgRegistry) ArchiveState(id string) (string, error) {
	src := g.StateDir(id)
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("control: reading organization state %s: %w", src, err)
	}

	archiveDir := filepath.Join(g.cfg.StateRoot, "deleted")
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		return "", fmt.Errorf("control: creating the archive directory: %w", err)
	}
	dst := filepath.Join(archiveDir, fmt.Sprintf("%s-%d", id, time.Now().UTC().UnixNano()))
	if err := os.Rename(src, dst); err != nil {
		return "", fmt.Errorf("control: archiving organization state: %w", err)
	}
	return dst, nil
}

// validateManagedOrg applies every rule a managed organization must satisfy.
// Messages describe the field, never a secret: the platform API returns them.
func validateManagedOrg(org ManagedOrg) error {
	if !managedOrgIDPattern.MatchString(org.ID) {
		return orgInvalidf("invalid organization id %q (lowercase letters, digits and dashes, 32 characters max)", org.ID)
	}
	if strings.TrimSpace(org.Name) == "" {
		return orgInvalidf("organization name is required")
	}
	if len(org.Name) > 128 {
		return orgInvalidf("organization name is too long")
	}
	if len(org.Domains) == 0 {
		return orgInvalidf("a managed organization needs at least one domain")
	}

	patterns, err := normalizeManagedDomains(org.Domains)
	if err != nil {
		return err
	}

	if org.Domain != "" {
		if _, err := normalizeRouterDomain(org.Domain); err != nil {
			return orgInvalidf("invalid MagicDNS domain: %v", err)
		}
		if strings.HasPrefix(org.Domain, "*.") {
			return orgInvalidf("the MagicDNS domain cannot be a wildcard")
		}
	}

	u, err := url.Parse(org.ServerURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return orgInvalidf("invalid server_url %q", org.ServerURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return orgInvalidf("invalid server_url scheme %q", u.Scheme)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return orgInvalidf("server_url must not carry credentials, a query or a fragment")
	}
	host := normalizeRouterHost(u.Host)
	routed := false
	for _, pattern := range patterns {
		if matchRouterDomain(pattern, host) {
			routed = true
			break
		}
	}
	if !routed {
		return orgInvalidf("server_url host %q is not one of the organization's domains", host)
	}
	return nil
}

// normalizeManagedDomains canonicalizes an organization's routing domains,
// rejecting duplicates that differ only by case or a trailing dot.
func normalizeManagedDomains(domains []string) ([]string, error) {
	patterns := make([]string, 0, len(domains))
	for _, domain := range domains {
		pattern, err := normalizeRouterDomain(domain)
		if err != nil {
			return nil, orgInvalidf("%v", err)
		}
		if slices.Contains(patterns, pattern) {
			return nil, orgInvalidf("duplicate domain %q", pattern)
		}
		patterns = append(patterns, pattern)
	}
	return patterns, nil
}

// scanManagedOrg reads one row in the canonical column order.
func scanManagedOrg(scan func(...any) error) (ManagedOrg, error) {
	var (
		org               ManagedOrg
		domains           string
		created, modified int64
	)
	if err := scan(&org.ID, &org.Name, &domains, &org.ServerURL, &org.Domain, &created, &modified); err != nil {
		return ManagedOrg{}, err
	}
	parsed, err := decodeStringList(domains)
	if err != nil {
		return ManagedOrg{}, err
	}
	org.Domains = parsed
	org.CreatedAt = time.Unix(0, created).UTC()
	org.UpdatedAt = time.Unix(0, modified).UTC()
	return org, nil
}

// encodeStringList renders a string slice as JSON for storage.
func encodeStringList(values []string) (string, error) {
	if len(values) == 0 {
		return "[]", nil
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("control: encoding string list: %w", err)
	}
	return string(raw), nil
}

// decodeStringList parses a stored string list.
func decodeStringList(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("control: decoding string list: %w", err)
	}
	return out, nil
}

// isUniqueViolation reports whether err is SQLite's UNIQUE constraint failure.
// The message is matched because the modernc driver does not export a typed
// constraint error.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
