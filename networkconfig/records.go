package networkconfig

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

var (
	ErrRecordProtected = errors.New("DNS record is managed by a device or certificate workflow")
	ErrRecordLimit     = errors.New("DNS record limit reached")
)

type Record struct {
	ID       uint64    `json:"id"`
	Revision uint64    `json:"revision"`
	Name     string    `json:"name"`
	Type     string    `json:"type"`
	Value    string    `json:"value"`
	NodeID   uint64    `json:"node_id"`
	Created  time.Time `json:"created"`
}

func (record Record) Protected() bool {
	return record.NodeID != 0 || strings.HasPrefix(record.Name, "_acme-challenge.") || record.Type != "A" && record.Type != "AAAA"
}

const recordColumns = "id, revision, name, type, value, node_id, created"

func scanRecord(row interface{ Scan(...any) error }) (Record, error) {
	var record Record
	var created int64
	err := row.Scan(&record.ID, &record.Revision, &record.Name, &record.Type, &record.Value, &record.NodeID, &created)
	record.Created = time.Unix(0, created).UTC()
	return record, err
}

func (store *SQLiteStore) Records(ctx context.Context) ([]Record, error) {
	rows, err := store.db.QueryContext(ctx, "SELECT "+recordColumns+" FROM dns_records ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]Record, 0)
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (store *SQLiteStore) PutRecord(ctx context.Context, record Record, expected uint64, writer Writer, domain string) (Record, error) {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if err := identity.CheckNetworkWriter(ctx, tx, writer.UserID, writer.SessionID, writer.APIKeyID, now); err != nil {
		return Record{}, err
	}
	if record.Protected() {
		return Record{}, ErrRecordProtected
	}
	if err := checkDeviceRecordName(ctx, tx, record.Name, domain); err != nil {
		return Record{}, err
	}
	var serviceCount int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM node_services WHERE name || '.' || ? = ?", domain, record.Name).Scan(&serviceCount); err != nil {
		return Record{}, err
	}
	if serviceCount != 0 {
		return Record{}, ErrConflict
	}
	if record.ID != 0 {
		previous, err := scanRecord(tx.QueryRowContext(ctx, "SELECT "+recordColumns+" FROM dns_records WHERE id = ?", record.ID))
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrNotFound
		}
		if err != nil {
			return Record{}, err
		}
		if previous.Protected() {
			return Record{}, ErrRecordProtected
		}
		if expected == 0 || previous.Revision != expected {
			return Record{}, ErrConflict
		}
		record.Created = previous.Created
		record.Revision = previous.Revision + 1
	} else {
		var count, maxID uint64
		if err := tx.QueryRowContext(ctx, "SELECT count(*), coalesce(max(id), 0) FROM dns_records").Scan(&count, &maxID); err != nil {
			return Record{}, err
		}
		if count >= 512 {
			return Record{}, ErrRecordLimit
		}
		var nextID uint64
		err := tx.QueryRowContext(ctx, "SELECT value FROM counters WHERE name = 'next_dnsrecord_id'").Scan(&nextID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return Record{}, err
		}
		record.ID = max(nextID, maxID+1)
		record.Created, record.Revision = now, 1
		if _, err := tx.ExecContext(ctx, `INSERT INTO counters (name, value) VALUES ('next_dnsrecord_id', ?)
			ON CONFLICT(name) DO UPDATE SET value=excluded.value`, record.ID+1); err != nil {
			return Record{}, err
		}
	}
	var conflicts int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM dns_records WHERE name = ? AND id != ?
		AND (node_id != 0 OR type NOT IN ('A', 'AAAA') OR (type = ? AND value = ?))`,
		record.Name, record.ID, record.Type, record.Value).Scan(&conflicts); err != nil {
		return Record{}, err
	}
	if conflicts != 0 {
		return Record{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO dns_records (`+recordColumns+`) VALUES (?, ?, ?, ?, ?, 0, ?)
		ON CONFLICT(id) DO UPDATE SET revision=excluded.revision, name=excluded.name, type=excluded.type, value=excluded.value`,
		record.ID, record.Revision, record.Name, record.Type, record.Value, record.Created.UnixNano()); err != nil {
		return Record{}, err
	}
	if err := commitChange(ctx, tx, writer.Actor(), "dns.record.saved", fmt.Sprintf("dns-record:%d", record.ID), "saved address record", now); err != nil {
		return Record{}, err
	}
	return record, tx.Commit()
}

// 在同一个写事务内检查设备名，不能将读取故障当成“没有重名设备”。
func checkDeviceRecordName(ctx context.Context, tx *sql.Tx, name, domain string) error {
	rows, err := tx.QueryContext(ctx, "SELECT id, hostname FROM nodes")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var node state.Node
		if err := rows.Scan(&node.ID, &node.Hostname); err != nil {
			return err
		}
		if name == strings.TrimSuffix(node.FQDN(domain), ".") {
			return ErrRecordProtected
		}
	}
	return rows.Err()
}

func (store *SQLiteStore) DeleteRecord(ctx context.Context, recordID, expected uint64, writer Writer) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	if err := identity.CheckNetworkWriter(ctx, tx, writer.UserID, writer.SessionID, writer.APIKeyID, now); err != nil {
		return err
	}
	record, err := scanRecord(tx.QueryRowContext(ctx, "SELECT "+recordColumns+" FROM dns_records WHERE id = ?", recordID))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if record.Protected() {
		return ErrRecordProtected
	}
	if expected != 0 && record.Revision != expected {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM dns_records WHERE id = ?", recordID); err != nil {
		return err
	}
	if err := commitChange(ctx, tx, writer.Actor(), identity.AuditDNSRecordDeleted, fmt.Sprintf("dns-record:%d", record.ID), "deleted address record", now); err != nil {
		return err
	}
	return tx.Commit()
}
