package identity

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// AppendAudit implements [AuditStore].
func (s *SQLiteStore) AppendAudit(e *AuditEvent) error {
	if e == nil || e.Action == "" {
		return fmt.Errorf("identity: audit event needs an action")
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}

	res, err := s.db.ExecContext(context.Background(),
		"INSERT INTO audit_events (ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
		e.Time.UnixNano(), e.Actor, e.Action, e.Target, e.Detail)
	if err != nil {
		return fmt.Errorf("identity: appending audit event: %w", err)
	}
	// SQLite 触发器可以忽略 INSERT；没有落盘的审计不能被报告为成功。
	if affected, err := res.RowsAffected(); err != nil || affected != 1 {
		return fmt.Errorf("identity: audit event was not stored")
	}

	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("identity: reading audit event ID: %w", err)
	}
	e.ID = uint64(id)
	return nil
}

// ListAudit implements [AuditStore].
func (s *SQLiteStore) ListAudit(limit int) []AuditEvent {
	query := "SELECT id, ts, actor, action, target, detail FROM audit_events ORDER BY id"
	args := []any{}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := s.db.QueryContext(context.Background(), query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []AuditEvent
	for rows.Next() {
		var (
			id     int64
			ts     int64
			actor  string
			action string
			target string
			detail string
		)
		if err := rows.Scan(&id, &ts, &actor, &action, &target, &detail); err != nil {
			return nil
		}
		out = append(out, AuditEvent{
			ID:     uint64(id),
			Time:   time.Unix(0, ts).UTC(),
			Actor:  actor,
			Action: action,
			Target: target,
			Detail: detail,
		})
	}
	return out
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
