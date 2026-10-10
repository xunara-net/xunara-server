package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// counterNextDNSRecordID backs DNS record identifier allocation.
const counterNextDNSRecordID = "next_dnsrecord_id"

const dnsRecordColumns = "id, name, type, value, node_id, created"

// UpsertDNSRecord implements [DNSRecordStore].
func (s *SQLiteStore) UpsertDNSRecord(r *DNSRecord) error {
	if r == nil || r.Name == "" {
		return errDNSRecordNameRequired
	}
	original := r
	record := *r
	var err error
	record.Name, err = NormalizeDNSRecordName(record.Name)
	if err != nil {
		return err
	}
	record.Type, err = NormalizeDNSRecordType(record.Type)
	if err != nil {
		return err
	}
	r = &record

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("state: beginning DNS record upsert: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op
	domain, _, err := dnsDomainTx(ctx, tx)
	if err != nil {
		return err
	}
	if err := CheckDNSRecordNameTx(ctx, tx, r.Name, domain); err != nil {
		return err
	}

	var (
		existingID      int64
		existingCreated int64
	)
	err = tx.QueryRowContext(ctx,
		"SELECT id, created FROM dns_records WHERE name = ? AND type = ? AND value = ?",
		r.Name, r.Type, r.Value).Scan(&existingID, &existingCreated)
	switch {
	case err == nil:
		r.ID = uint64(existingID)
		r.Created = time.Unix(0, existingCreated).UTC()
		if err := tx.Commit(); err != nil {
			return err
		}
		*original = record
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("state: looking up DNS record: %w", err)
	}

	id, err := nextCounter(ctx, tx, counterNextDNSRecordID, 1)
	if err != nil {
		return err
	}
	r.ID = uint64(id)
	if r.Created.IsZero() {
		r.Created = time.Now().UTC()
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO dns_records (`+dnsRecordColumns+`)
		VALUES (?, ?, ?, ?, ?, ?)`,
		int64(r.ID), r.Name, r.Type, r.Value, int64(r.NodeID), r.Created.UnixNano())
	if err != nil {
		return fmt.Errorf("state: inserting DNS record: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	*original = record
	return nil
}

// ListDNSRecords implements [DNSRecordStore].
func (s *SQLiteStore) ListDNSRecords() []DNSRecord {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+dnsRecordColumns+" FROM dns_records ORDER BY id")
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []DNSRecord
	for rows.Next() {
		r, err := scanDNSRecord(rows)
		if err != nil {
			return nil
		}
		out = append(out, r)
	}
	return out
}

// DeleteDNSRecord implements [DNSRecordStore].
func (s *SQLiteStore) DeleteDNSRecord(id uint64) error {
	_, err := s.db.ExecContext(context.Background(), "DELETE FROM dns_records WHERE id = ?", int64(id))
	if err != nil {
		return fmt.Errorf("state: deleting DNS record %d: %w", id, err)
	}
	return nil
}

func scanDNSRecord(sc scanner) (DNSRecord, error) {
	var (
		id      int64
		name    string
		typ     string
		value   string
		nodeID  int64
		created int64
	)

	if err := sc.Scan(&id, &name, &typ, &value, &nodeID, &created); err != nil {
		return DNSRecord{}, err
	}

	return DNSRecord{
		ID:      uint64(id),
		Name:    name,
		Type:    typ,
		Value:   value,
		NodeID:  NodeID(nodeID),
		Created: time.Unix(0, created).UTC(),
	}, nil
}
