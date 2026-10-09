package identity

import (
	"context"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

func (store *SQLiteStore) ListAccountSessions(ctx context.Context, userID tailcfg.UserID) ([]Session, error) {
	rows, err := store.db.QueryContext(ctx,
		"SELECT "+sessionColumns+" FROM sessions WHERE user_id = ? ORDER BY created_at DESC, id", int64(userID))
	if err != nil {
		return nil, fmt.Errorf("identity: listing account sessions: %w", err)
	}
	defer rows.Close()

	sessions := make([]Session, 0)
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("identity: reading account session: %w", err)
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: reading account sessions: %w", err)
	}
	return sessions, nil
}

func (store *SQLiteStore) RevokeAccountSessions(ctx context.Context, userID tailcfg.UserID, initiatingID string, selection SessionRevocation) (int64, error) {
	if !selection.valid() {
		return 0, ErrInvalidSessionRevocation
	}
	if userID == 0 || initiatingID == "" {
		return 0, ErrSessionRevoked
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("identity: starting account session revocation: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	if err := lockAccountSession(ctx, tx, userID, initiatingID, now); err != nil {
		return 0, err
	}

	// 只撤销事务执行时仍活动的会话；重复操作不重写已失效记录的原因和时间。
	query := "UPDATE sessions SET revoked_at = ?, revoked_reason = ? WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?"
	reason := "signed out all sessions"
	var filter []any
	switch selection.Mode {
	case RevokeOtherSessions:
		query += " AND id != ?"
		filter = append(filter, initiatingID)
		reason = "signed out other sessions"
	case RevokeSingleSession:
		var found bool
		if err := tx.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM sessions WHERE id = ? AND user_id = ?)", selection.SessionID, int64(userID)).Scan(&found); err != nil {
			return 0, fmt.Errorf("identity: checking target session: %w", err)
		}
		if !found {
			return 0, ErrSessionNotFound
		}
		query += " AND id = ?"
		filter = append(filter, selection.SessionID)
		reason = "signed out one session"
	}
	arguments := append([]any{now.UnixNano(), reason, int64(userID), now.UnixNano()}, filter...)
	result, err := tx.ExecContext(ctx, query, arguments...)
	if err != nil {
		return 0, fmt.Errorf("identity: revoking account sessions: %w", err)
	}
	revoked, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("identity: checking account session revocation count: %w", err)
	}
	detail := fmt.Sprintf("self-service %s; revoked %d sessions", reason, revoked)
	if selection.Mode == RevokeSingleSession {
		detail += "; session:" + selection.SessionID
	}
	if err := insertAccountAudit(ctx, tx, userID, AuditSessionRevoked, detail, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("identity: committing account session revocation: %w", err)
	}
	return revoked, nil
}
