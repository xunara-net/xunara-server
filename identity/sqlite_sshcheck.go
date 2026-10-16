package identity

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

const sshCheckColumns = "id, src_node_id, dst_node_id, local_user, verdict, decided_by, decided_at, " +
	"consumed_at, created_at, expires_at"

// CreateSSHCheckSession implements [SSHCheckStore].
func (s *SQLiteStore) CreateSSHCheckSession(opts NewSSHCheckOptions) (SSHCheckSession, error) {
	if opts.SrcNodeID <= 0 || opts.DstNodeID <= 0 {
		return SSHCheckSession{}, fmt.Errorf("identity: ssh check needs a source and destination node")
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultSSHCheckTTL
	}

	id := opts.ID
	if id == "" {
		var err error
		id, err = newSecret()
		if err != nil {
			return SSHCheckSession{}, err
		}
	}

	now := time.Now().UTC()
	sess := SSHCheckSession{
		ID:        id,
		SrcNodeID: opts.SrcNodeID,
		DstNodeID: opts.DstNodeID,
		LocalUser: opts.LocalUser,
		Verdict:   SSHCheckPending,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	if _, err := s.db.ExecContext(context.Background(),
		`INSERT INTO ssh_check_sessions (`+sshCheckColumns+`)
		 VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)`,
		sess.ID, sess.SrcNodeID, sess.DstNodeID, sess.LocalUser, string(sess.Verdict),
		sess.CreatedAt.UnixNano(), sess.ExpiresAt.UnixNano()); err != nil {
		return SSHCheckSession{}, fmt.Errorf("identity: creating ssh check session: %w", err)
	}
	return sess, nil
}

// GetSSHCheckSession implements [SSHCheckStore].
func (s *SQLiteStore) GetSSHCheckSession(id string) (SSHCheckSession, bool) {
	session, err := s.LookupSSHCheckSession(context.Background(), id)
	return session, err == nil
}

// LookupSSHCheckSession preserves database and cancellation failures for the browser API.
func (s *SQLiteStore) LookupSSHCheckSession(ctx context.Context, id string) (SSHCheckSession, error) {
	row := s.db.QueryRowContext(ctx, "SELECT "+sshCheckColumns+" FROM ssh_check_sessions WHERE id = ?", id)
	session, err := scanSSHCheckSession(row)
	if err == sql.ErrNoRows {
		return SSHCheckSession{}, ErrSSHCheckNotFound
	}
	if err != nil {
		return SSHCheckSession{}, fmt.Errorf("identity: reading SSH check session: %w", err)
	}
	return session, nil
}

// ListSSHCheckSessions implements [SSHCheckStore].
func (s *SQLiteStore) ListSSHCheckSessions(limit int) ([]SSHCheckSession, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+sshCheckColumns+` FROM ssh_check_sessions
		 ORDER BY created_at DESC, id ASC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("identity: listing ssh check sessions: %w", err)
	}
	defer rows.Close()

	out := make([]SSHCheckSession, 0, min(limit, 64))
	for rows.Next() {
		sess, err := scanSSHCheckSession(rows)
		if err != nil {
			return nil, fmt.Errorf("identity: scanning ssh check session: %w", err)
		}
		out = append(out, sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: listing ssh check sessions: %w", err)
	}
	return out, nil
}

// GetPendingSSHCheckSession implements [SSHCheckStore].
func (s *SQLiteStore) GetPendingSSHCheckSession(srcNodeID, dstNodeID int64, localUser string, now time.Time) (SSHCheckSession, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+sshCheckColumns+` FROM ssh_check_sessions
		 WHERE src_node_id = ? AND dst_node_id = ? AND local_user = ?
		   AND verdict = ? AND expires_at > ?
		 ORDER BY created_at DESC LIMIT 1`,
		srcNodeID, dstNodeID, localUser, string(SSHCheckPending), now.UnixNano())
	sess, err := scanSSHCheckSession(row)
	if err != nil {
		return SSHCheckSession{}, false
	}
	return sess, true
}

// DecideSSHCheckSession implements [SSHCheckStore].
func (s *SQLiteStore) DecideSSHCheckSession(id string, verdict SSHCheckVerdict, by tailcfg.UserID, now time.Time) (SSHCheckSession, error) {
	if verdict != SSHCheckAccepted && verdict != SSHCheckRejected {
		return SSHCheckSession{}, ErrSSHCheckVerdict
	}

	res, err := s.db.ExecContext(context.Background(),
		`UPDATE ssh_check_sessions SET verdict = ?, decided_by = ?, decided_at = ?
		 WHERE id = ? AND verdict = ? AND expires_at > ?`,
		string(verdict), int64(by), now.UnixNano(), id, string(SSHCheckPending), now.UnixNano())
	if err != nil {
		return SSHCheckSession{}, fmt.Errorf("identity: deciding ssh check session: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return SSHCheckSession{}, fmt.Errorf("identity: deciding ssh check session: %w", err)
	}
	if affected == 0 {
		return SSHCheckSession{}, s.sshCheckDecisionError(id, now)
	}

	sess, ok := s.GetSSHCheckSession(id)
	if !ok {
		return SSHCheckSession{}, ErrSSHCheckNotFound
	}
	return sess, nil
}

// sshCheckDecisionError explains why a conditional decision update matched no
// row.
func (s *SQLiteStore) sshCheckDecisionError(id string, now time.Time) error {
	sess, ok := s.GetSSHCheckSession(id)
	switch {
	case !ok:
		return ErrSSHCheckNotFound
	case !sess.Pending():
		return ErrSSHCheckDecided
	case sess.Expired(now):
		return ErrSSHCheckExpired
	default:
		return ErrSSHCheckDecided
	}
}

// ConsumeSSHCheckVerdict implements [SSHCheckStore].
func (s *SQLiteStore) ConsumeSSHCheckVerdict(id string, now time.Time) (SSHCheckSession, error) {
	res, err := s.db.ExecContext(context.Background(),
		`UPDATE ssh_check_sessions SET consumed_at = ?
		 WHERE id = ? AND verdict != ? AND consumed_at IS NULL AND expires_at > ?`,
		now.UnixNano(), id, string(SSHCheckPending), now.UnixNano())
	if err != nil {
		return SSHCheckSession{}, fmt.Errorf("identity: consuming ssh check verdict: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return SSHCheckSession{}, fmt.Errorf("identity: consuming ssh check verdict: %w", err)
	}
	if affected == 1 {
		sess, ok := s.GetSSHCheckSession(id)
		if !ok {
			return SSHCheckSession{}, ErrSSHCheckNotFound
		}
		return sess, nil
	}

	// Nothing was handed out: explain why so the caller can re-delegate.
	sess, ok := s.GetSSHCheckSession(id)
	switch {
	case !ok:
		return SSHCheckSession{}, ErrSSHCheckNotFound
	case sess.Pending():
		return SSHCheckSession{}, ErrSSHCheckPending
	case sess.Expired(now):
		return SSHCheckSession{}, ErrSSHCheckExpired
	default:
		return SSHCheckSession{}, ErrSSHCheckConsumed
	}
}

// RecordSSHCheckAuth implements [SSHCheckStore].
func (s *SQLiteStore) RecordSSHCheckAuth(srcNodeID, dstNodeID int64, at time.Time) error {
	if _, err := s.db.ExecContext(context.Background(),
		`INSERT INTO ssh_check_auth (src_node_id, dst_node_id, authed_at) VALUES (?, ?, ?)
		 ON CONFLICT(src_node_id, dst_node_id) DO UPDATE SET authed_at = excluded.authed_at`,
		srcNodeID, dstNodeID, at.UnixNano()); err != nil {
		return fmt.Errorf("identity: recording ssh check auth: %w", err)
	}
	return nil
}

// SSHCheckAuth implements [SSHCheckStore].
func (s *SQLiteStore) SSHCheckAuth(srcNodeID, dstNodeID int64) (time.Time, bool) {
	var nanos int64
	err := s.db.QueryRowContext(context.Background(),
		"SELECT authed_at FROM ssh_check_auth WHERE src_node_id = ? AND dst_node_id = ?",
		srcNodeID, dstNodeID).Scan(&nanos)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, nanos).UTC(), true
}

// ClearSSHCheckAuth implements [SSHCheckStore].
func (s *SQLiteStore) ClearSSHCheckAuth() error {
	if _, err := s.db.ExecContext(context.Background(), "DELETE FROM ssh_check_auth"); err != nil {
		return fmt.Errorf("identity: clearing ssh check auth: %w", err)
	}
	return nil
}

// DeleteExpiredSSHCheckSessions implements [SSHCheckStore].
func (s *SQLiteStore) DeleteExpiredSSHCheckSessions(now time.Time) (int64, error) {
	res, err := s.db.ExecContext(context.Background(),
		"DELETE FROM ssh_check_sessions WHERE expires_at <= ?", now.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("identity: deleting expired ssh check sessions: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("identity: deleting expired ssh check sessions: %w", err)
	}
	return affected, nil
}

// scanSSHCheckSession reads one row in sshCheckColumns order.
func scanSSHCheckSession(row interface{ Scan(...any) error }) (SSHCheckSession, error) {
	var (
		sess                  SSHCheckSession
		verdict               string
		decidedBy             sql.NullInt64
		decidedAt, consumedAt sql.NullInt64
		createdAt, expiresAt  int64
	)
	if err := row.Scan(&sess.ID, &sess.SrcNodeID, &sess.DstNodeID, &sess.LocalUser, &verdict,
		&decidedBy, &decidedAt, &consumedAt, &createdAt, &expiresAt); err != nil {
		return SSHCheckSession{}, err
	}
	return finishSSHCheckSession(sess, verdict, decidedBy, decidedAt, consumedAt, createdAt, expiresAt), nil
}

func finishSSHCheckSession(sess SSHCheckSession, verdict string, decidedBy, decidedAt, consumedAt sql.NullInt64, createdAt, expiresAt int64) SSHCheckSession {
	sess.Verdict = SSHCheckVerdict(verdict)
	if decidedBy.Valid {
		sess.DecidedBy = tailcfg.UserID(decidedBy.Int64)
	}
	if decidedAt.Valid {
		sess.DecidedAt = time.Unix(0, decidedAt.Int64).UTC()
	}
	if consumedAt.Valid {
		sess.ConsumedAt = time.Unix(0, consumedAt.Int64).UTC()
	}
	sess.CreatedAt = time.Unix(0, createdAt).UTC()
	sess.ExpiresAt = time.Unix(0, expiresAt).UTC()
	return sess
}
