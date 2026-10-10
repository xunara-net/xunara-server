package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ReplaceNodeServices implements [ServiceStore].
func (s *SQLiteStore) ReplaceNodeServices(id NodeID, services []Service) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: replacing services of node %d: %w", id, err)
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes WHERE id = ?", int64(id)).Scan(&exists); err != nil {
		return fmt.Errorf("state: looking up node %d: %w", id, err)
	}
	if exists == 0 {
		return errUnknownNode(id)
	}
	if err := checkServiceDNSNamesTx(ctx, tx, id, services); err != nil {
		return err
	}

	// Remember creation times so a purely cosmetic republish does not reset
	// them; published names are unique, so the map is unambiguous.
	created := make(map[string]time.Time)
	rows, err := tx.QueryContext(ctx, "SELECT name, created FROM node_services WHERE node_id = ?", int64(id))
	if err != nil {
		return fmt.Errorf("state: reading services of node %d: %w", id, err)
	}
	for rows.Next() {
		var name string
		var at int64
		if err := rows.Scan(&name, &at); err != nil {
			rows.Close()
			return fmt.Errorf("state: scanning service of node %d: %w", id, err)
		}
		created[name] = time.Unix(at, 0).UTC()
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("state: reading services of node %d: %w", id, err)
	}
	rows.Close()

	if _, err := tx.ExecContext(ctx, "DELETE FROM node_services WHERE node_id = ?", int64(id)); err != nil {
		return fmt.Errorf("state: clearing services of node %d: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM node_service_visibility WHERE node_id = ?", int64(id)); err != nil {
		return fmt.Errorf("state: clearing service visibility of node %d: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM node_service_shared WHERE node_id = ?", int64(id)); err != nil {
		return fmt.Errorf("state: clearing shared services of node %d: %w", id, err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM node_service_acl_visibility WHERE node_id = ?", int64(id)); err != nil {
		return fmt.Errorf("state: clearing ACL-derived visibility of node %d: %w", id, err)
	}

	seen := make(map[string]bool, len(services))
	for _, svc := range services {
		if seen[svc.Name] {
			return errServiceNameTaken(svc.Name)
		}
		seen[svc.Name] = true
	}

	now := time.Now().UTC()
	ordered := slices.Clone(services)
	slices.SortFunc(ordered, func(a, b Service) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		default:
			return 0
		}
	})
	for _, svc := range ordered {
		metadata, err := json.Marshal(svc.Metadata)
		if err != nil {
			return fmt.Errorf("state: encoding metadata of service %q: %w", svc.Name, err)
		}
		if svc.Metadata == nil {
			metadata = []byte("{}")
		}
		visibility, err := json.Marshal(svc.Visibility)
		if err != nil {
			return fmt.Errorf("state: encoding visibility of service %q: %w", svc.Name, err)
		}
		createdAt := svc.Created
		if prev, ok := created[svc.Name]; ok {
			createdAt = prev
		}
		if createdAt.IsZero() {
			createdAt = now
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO node_services (node_id, name, protocol, port, metadata, created, updated)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			int64(id), svc.Name, svc.Protocol, int(svc.Port), string(metadata),
			createdAt.Unix(), now.Unix()); err != nil {
			if isUniqueViolation(err) {
				return errServiceNameTaken(svc.Name)
			}
			return fmt.Errorf("state: storing service %q on node %d: %w", svc.Name, id, err)
		}
		if len(svc.Visibility) > 0 {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO node_service_visibility (node_id, name, visibility)
				VALUES (?, ?, ?)`,
				int64(id), svc.Name, string(visibility)); err != nil {
				return fmt.Errorf("state: storing visibility of service %q: %w", svc.Name, err)
			}
		}
		if svc.Shared {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO node_service_shared (node_id, name) VALUES (?, ?)`,
				int64(id), svc.Name); err != nil {
				return fmt.Errorf("state: storing shared flag of service %q: %w", svc.Name, err)
			}
		}
		if svc.VisibilityFromACL {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO node_service_acl_visibility (node_id, name) VALUES (?, ?)`,
				int64(id), svc.Name); err != nil {
				return fmt.Errorf("state: storing ACL-derived visibility of service %q: %w", svc.Name, err)
			}
		}
	}

	if err := replaceServiceHealth(ctx, tx, id, ordered); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("state: replacing services of node %d: %w", id, err)
	}
	return nil
}

// replaceServiceHealth aligns the health table with a freshly written
// declaration: tracking rows for services that are gone or no longer opted in
// are dropped, and newly tracked services start out not ready. Kept rows are
// left untouched, so a periodic republish never resets a standing report.
func replaceServiceHealth(ctx context.Context, tx *sql.Tx, id NodeID, services []Service) error {
	tracked := make([]any, 0, len(services))
	for _, svc := range services {
		if svc.Health {
			tracked = append(tracked, svc.Name)
		}
	}

	// Drop tracking rows for services that are gone or no longer opted in.
	if len(tracked) == 0 {
		if _, err := tx.ExecContext(ctx, "DELETE FROM node_service_health WHERE node_id = ?", int64(id)); err != nil {
			return fmt.Errorf("state: clearing service health of node %d: %w", id, err)
		}
		return nil
	}
	args := append([]any{int64(id)}, tracked...)
	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(tracked)), ", ")
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM node_service_health WHERE node_id = ? AND name NOT IN ("+placeholders+")", args...); err != nil {
		return fmt.Errorf("state: pruning service health of node %d: %w", id, err)
	}

	// Newly tracked services start out not ready; rows that survive the
	// prune keep their standing report, so a periodic republish cannot flap
	// discovery.
	for _, name := range tracked {
		if _, err := tx.ExecContext(ctx,
			"INSERT OR IGNORE INTO node_service_health (node_id, name, healthy) VALUES (?, ?, 0)",
			int64(id), name); err != nil {
			return fmt.Errorf("state: enabling service health for %q: %w", name.(string), err)
		}
	}
	return nil
}

// ListServices implements [ServiceStore].
func (s *SQLiteStore) ListServices() []Service {
	rows, err := s.db.QueryContext(context.Background(),
		serviceSelect("ORDER BY s.name"))
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []Service
	for rows.Next() {
		svc, err := scanService(rows)
		if err != nil {
			continue
		}
		out = append(out, svc)
	}
	return out
}

// ServicesForNode implements [ServiceStore].
func (s *SQLiteStore) ServicesForNode(id NodeID) ([]Service, error) {
	rows, err := s.db.QueryContext(context.Background(),
		serviceSelect("WHERE s.node_id = ? ORDER BY s.name"),
		int64(id))
	if err != nil {
		return nil, fmt.Errorf("state: reading services of node %d: %w", id, err)
	}
	defer rows.Close()

	out := []Service{}
	for rows.Next() {
		svc, err := scanService(rows)
		if err != nil {
			return nil, fmt.Errorf("state: scanning service of node %d: %w", id, err)
		}
		out = append(out, svc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("state: reading services of node %d: %w", id, err)
	}
	return out, nil
}

// GetServiceByName implements [ServiceStore].
func (s *SQLiteStore) GetServiceByName(name string) (Service, bool) {
	row := s.db.QueryRowContext(context.Background(),
		serviceSelect("WHERE s.name = ?"), name)
	svc, err := scanService(row)
	if err != nil {
		return Service{}, false
	}
	return svc, true
}

// NodeServiceCounts implements [ServiceStore].
func (s *SQLiteStore) NodeServiceCounts() (map[NodeID]int, error) {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT node_id, COUNT(*) FROM node_services GROUP BY node_id")
	if err != nil {
		return nil, fmt.Errorf("state: counting services: %w", err)
	}
	defer rows.Close()

	counts := make(map[NodeID]int)
	for rows.Next() {
		var (
			id    int64
			count int
		)
		if err := rows.Scan(&id, &count); err != nil {
			return nil, fmt.Errorf("state: scanning service counts: %w", err)
		}
		counts[NodeID(id)] = count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("state: counting services: %w", err)
	}
	return counts, nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// scanService reads one service row.
func scanService(row rowScanner) (Service, error) {
	var (
		svc        Service
		nodeID     int64
		port       int
		metadata   string
		visibility string
		shared     int
		fromACL    int
		created    int64
		updated    int64
		healthy    int
		tracked    int
		reportedAt *int64
		until      *int64
	)
	if err := row.Scan(&nodeID, &svc.Name, &svc.Protocol, &port, &metadata, &visibility,
		&created, &updated, &healthy, &reportedAt, &until, &tracked, &shared, &fromACL); err != nil {
		return Service{}, err
	}
	svc.NodeID = NodeID(nodeID)
	svc.Port = uint16(port)
	svc.Shared = shared != 0
	svc.VisibilityFromACL = fromACL != 0
	svc.Created = time.Unix(created, 0).UTC()
	svc.Updated = time.Unix(updated, 0).UTC()
	svc.Health = tracked != 0
	svc.Healthy = healthy != 0
	svc.HealthReportedAt = unixPtr(reportedAt)
	svc.HealthUntil = unixPtr(until)
	if metadata != "" {
		var meta map[string]string
		if err := json.Unmarshal([]byte(metadata), &meta); err == nil && len(meta) > 0 {
			svc.Metadata = meta
		}
	}
	if visibility != "" {
		var selectors []string
		if err := json.Unmarshal([]byte(visibility), &selectors); err == nil && len(selectors) > 0 {
			svc.Visibility = selectors
		}
	}
	return svc, nil
}

// serviceSelect builds the read query every service lookup shares: the
// declaration row joined with its optional health row. Callers append their
// own filter/order clause over the aliases.
func serviceSelect(suffix string) string {
	return `SELECT s.node_id, s.name, s.protocol, s.port, s.metadata, COALESCE(v.visibility, ''), s.created, s.updated,
			COALESCE(h.healthy, 0), h.reported_at, h.until, h.name IS NOT NULL, sh.name IS NOT NULL, a.name IS NOT NULL
		FROM node_services s
		LEFT JOIN node_service_visibility v ON v.node_id = s.node_id AND v.name = s.name
		LEFT JOIN node_service_health h ON h.node_id = s.node_id AND h.name = s.name
		LEFT JOIN node_service_shared sh ON sh.node_id = s.node_id AND sh.name = s.name
		LEFT JOIN node_service_acl_visibility a ON a.node_id = s.node_id AND a.name = s.name ` + suffix
}

// ReportServiceHealth implements [ServiceStore].
func (s *SQLiteStore) ReportServiceHealth(id NodeID, reports []ServiceHealthReport, ttl time.Duration) ([]ServiceHealthChange, error) {
	if ttl <= 0 {
		return nil, fmt.Errorf("state: service health TTL must be positive")
	}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("state: reporting service health of node %d: %w", id, err)
	}
	defer tx.Rollback()

	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes WHERE id = ?", int64(id)).Scan(&exists); err != nil {
		return nil, fmt.Errorf("state: looking up node %d: %w", id, err)
	}
	if exists == 0 {
		return nil, errUnknownNode(id)
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT h.name, h.healthy, s.protocol, s.port
		FROM node_service_health h
		JOIN node_services s ON s.node_id = h.node_id AND s.name = h.name
		WHERE h.node_id = ? ORDER BY h.name`, int64(id))
	if err != nil {
		return nil, fmt.Errorf("state: reading service health of node %d: %w", id, err)
	}
	type tracked struct {
		protocol string
		port     uint16
		healthy  bool
	}
	byName := make(map[string]tracked)
	names := make([]string, 0, 8)
	for rows.Next() {
		var (
			name     string
			healthy  int
			protocol string
			port     int
		)
		if err := rows.Scan(&name, &healthy, &protocol, &port); err != nil {
			rows.Close()
			return nil, fmt.Errorf("state: scanning service health of node %d: %w", id, err)
		}
		byName[name] = tracked{protocol: protocol, port: uint16(port), healthy: healthy != 0}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("state: reading service health of node %d: %w", id, err)
	}
	rows.Close()

	ready := make(map[string]bool, len(reports))
	for _, report := range reports {
		if _, ok := byName[report.Name]; !ok {
			return nil, errServiceHealthUnknown(report.Name)
		}
		if _, duplicate := ready[report.Name]; duplicate {
			return nil, fmt.Errorf("state: duplicate health report for service %q", report.Name)
		}
		ready[report.Name] = report.Ready
	}

	now := time.Now().UTC()
	until := now.Add(ttl)
	var changes []ServiceHealthChange
	for _, name := range names {
		entry := byName[name]
		want := ready[name]
		if _, err := tx.ExecContext(ctx, `
			UPDATE node_service_health SET healthy = ?, reported_at = ?, until = ?
			WHERE node_id = ? AND name = ?`,
			boolInt(want), now.Unix(), until.Unix(), int64(id), name); err != nil {
			return nil, fmt.Errorf("state: storing health of service %q: %w", name, err)
		}
		if entry.healthy != want {
			changes = append(changes, ServiceHealthChange{
				NodeID:   id,
				Name:     name,
				Protocol: entry.protocol,
				Port:     entry.port,
				Healthy:  want,
				Reason:   ServiceHealthReasonReported,
			})
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("state: reporting service health of node %d: %w", id, err)
	}
	sortHealthChanges(changes)
	return changes, nil
}

// ExpireServiceHealth implements [ServiceStore].
func (s *SQLiteStore) ExpireServiceHealth(now time.Time) ([]ServiceHealthChange, error) {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("state: expiring service health: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT h.node_id, h.name, s.protocol, s.port
		FROM node_service_health h
		JOIN node_services s ON s.node_id = h.node_id AND s.name = h.name
		WHERE h.healthy = 1 AND h.until IS NOT NULL AND h.until < ?
		ORDER BY h.node_id, h.name`, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("state: reading expired service health: %w", err)
	}

	var changes []ServiceHealthChange
	for rows.Next() {
		var (
			nodeID   int64
			name     string
			protocol string
			port     int
		)
		if err := rows.Scan(&nodeID, &name, &protocol, &port); err != nil {
			rows.Close()
			return nil, fmt.Errorf("state: scanning expired service health: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE node_service_health SET healthy = 0, until = NULL
			WHERE node_id = ? AND name = ? AND healthy = 1`,
			nodeID, name); err != nil {
			rows.Close()
			return nil, fmt.Errorf("state: expiring health of service %q: %w", name, err)
		}
		changes = append(changes, ServiceHealthChange{
			NodeID:   NodeID(nodeID),
			Name:     name,
			Protocol: protocol,
			Port:     uint16(port),
			Reason:   ServiceHealthReasonExpired,
		})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("state: reading expired service health: %w", err)
	}
	rows.Close()

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("state: expiring service health: %w", err)
	}
	sortHealthChanges(changes)
	return changes, nil
}

// sortHealthChanges orders changes by node and name so audit output and tests
// are deterministic (the maps iterated above are not).
func sortHealthChanges(changes []ServiceHealthChange) {
	slices.SortFunc(changes, func(a, b ServiceHealthChange) int {
		switch {
		case a.NodeID != b.NodeID:
			if a.NodeID < b.NodeID {
				return -1
			}
			return 1
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		default:
			return 0
		}
	})
}

// unixPtr converts an optional Unix timestamp to a time; nil reads as zero.
func unixPtr(at *int64) time.Time {
	if at == nil {
		return time.Time{}
	}
	return time.Unix(*at, 0).UTC()
}

// boolInt renders a bool for a SQLite INTEGER column.
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
