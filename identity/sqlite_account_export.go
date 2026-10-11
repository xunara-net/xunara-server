package identity

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

func (store *SQLiteStore) PrepareAccountExport(ctx context.Context, userID tailcfg.UserID, sessionID string, options AccountExportOptions) (AccountExportSnapshot, error) {
	if err := options.validate(); err != nil {
		return AccountExportSnapshot{}, err
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return AccountExportSnapshot{}, fmt.Errorf("identity: starting account export: %w", err)
	}
	defer transaction.Rollback()
	// 条件锁将撤销 / 禁用与导出串行化；后续所有读取必须使用这个事务。
	if err := lockAccountSession(ctx, transaction, userID, sessionID, time.Now().UTC()); err != nil {
		return AccountExportSnapshot{}, err
	}
	// 非即时事务也可能等待写锁；取得锁后再次用当前时间确认有效期。
	now := time.Now().UTC()
	var active bool
	if err := transaction.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM sessions WHERE id = ? AND user_id = ? AND expires_at > ?)", sessionID, int64(userID), now.UnixNano()).Scan(&active); err != nil {
		return AccountExportSnapshot{}, fmt.Errorf("identity: checking export session expiry: %w", err)
	}
	if !active {
		return AccountExportSnapshot{}, ErrSessionRevoked
	}
	snapshot := AccountExportSnapshot{GeneratedAt: now, Options: options}
	remaining := MaxAccountExportTextBytes
	query := "SELECT " + accountLoginRecordColumns + " FROM account_login_records WHERE user_id = ?"
	arguments := []any{int64(userID)}
	if !options.From.IsZero() {
		query += " AND created_at >= ?"
		arguments = append(arguments, options.From.UnixNano())
	}
	if !options.Until.IsZero() {
		query += " AND created_at < ?"
		arguments = append(arguments, options.Until.UnixNano())
	}
	query += " ORDER BY created_at DESC, id DESC LIMIT ?"
	arguments = append(arguments, MaxAccountExportRows+1)
	snapshot.LoginHistory, err = readExportLoginRecords(ctx, transaction, userID, &remaining, query, arguments...)
	if err != nil {
		return AccountExportSnapshot{}, err
	}
	if options.Scope == AccountSecurityExportScope {
		if err := readAccountExportMetadata(ctx, transaction, userID, &snapshot, &remaining); err != nil {
			return AccountExportSnapshot{}, err
		}
	}
	// 只审计准备成功及数量，绝不记录导出内容；不声明客户端已经收到文件。
	detail := fmt.Sprintf("%s snapshot prepared; history=%d sessions=%d identities=%d passkeys=%d",
		options.Scope, len(snapshot.LoginHistory), len(snapshot.Sessions), len(snapshot.Identities), len(snapshot.Passkeys))
	if err := insertAccountAudit(ctx, transaction, userID, AuditAccountExportPrepared, detail, now); err != nil {
		return AccountExportSnapshot{}, err
	}
	if err := transaction.Commit(); err != nil {
		return AccountExportSnapshot{}, fmt.Errorf("identity: committing account export: %w", err)
	}
	return snapshot, nil
}

func readExportLoginRecords(ctx context.Context, transaction *sql.Tx, userID tailcfg.UserID, remaining *int, query string, arguments ...any) ([]LoginRecord, error) {
	rows, err := transaction.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("identity: querying account export records: %w", err)
	}
	defer rows.Close()
	records := make([]LoginRecord, 0)
	for rows.Next() {
		if len(records) == MaxAccountExportRows {
			return nil, ErrAccountExportTooLarge
		}
		record, err := scanAccountLoginRecord(rows, userID)
		if err != nil {
			return nil, fmt.Errorf("identity: reading account export record: %w", err)
		}
		if err := consumeAccountExportText(remaining, record.ID, record.AuthMethod, record.Kind, record.RevokedReason, record.ClientInfo.IP, record.ClientInfo.UserAgent); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: reading account export rows: %w", err)
	}
	return records, nil
}

func readAccountExportMetadata(ctx context.Context, transaction *sql.Tx, userID tailcfg.UserID, snapshot *AccountExportSnapshot, remaining *int) error {
	user, err := scanUser(transaction.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id = ?", int64(userID)))
	if err != nil {
		return fmt.Errorf("identity: reading account export profile: %w", err)
	}
	snapshot.User = user
	if err := consumeAccountExportText(remaining, user.LoginName, user.DisplayName, user.Email, string(user.Role)); err != nil {
		return err
	}
	if err := transaction.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM local_credentials WHERE user_id = ?)", int64(userID)).Scan(&snapshot.LocalPasswordConfigured); err != nil {
		return fmt.Errorf("identity: reading account export login methods: %w", err)
	}
	records, err := readExportLoginRecords(ctx, transaction, userID, remaining, `SELECT id, auth_method, 'login', created_at, expires_at,
		last_seen_at, revoked_at, revoked_reason, client_ip, user_agent FROM sessions
		WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY created_at DESC, id DESC LIMIT ?`,
		int64(userID), snapshot.GeneratedAt.UnixNano(), MaxAccountExportRows+1)
	if err != nil {
		return err
	}
	snapshot.Sessions = make([]Session, 0, len(records))
	for _, record := range records {
		snapshot.Sessions = append(snapshot.Sessions, record.Session)
	}
	if err := readAccountExportIdentities(ctx, transaction, userID, snapshot, remaining); err != nil {
		return err
	}
	return readAccountExportPasskeys(ctx, transaction, userID, snapshot, remaining)
}

func readAccountExportIdentities(ctx context.Context, transaction *sql.Tx, userID tailcfg.UserID, snapshot *AccountExportSnapshot, remaining *int) error {
	rows, err := transaction.QueryContext(ctx, `SELECT provider_id, display_name, email, created_at, updated_at FROM external_identities
		WHERE user_id = ? AND provider_id != ? ORDER BY provider_id, created_at LIMIT ?`, int64(userID), LocalProviderID, MaxAccountExportRows+1)
	if err != nil {
		return fmt.Errorf("identity: querying account export bindings: %w", err)
	}
	defer rows.Close()
	snapshot.Identities = make([]AccountExportIdentity, 0)
	for rows.Next() {
		if len(snapshot.Identities) == MaxAccountExportRows {
			return ErrAccountExportTooLarge
		}
		var item AccountExportIdentity
		var createdAt, updatedAt int64
		if err := rows.Scan(&item.ProviderID, &item.DisplayName, &item.Email, &createdAt, &updatedAt); err != nil {
			return fmt.Errorf("identity: reading account export binding: %w", err)
		}
		item.CreatedAt, item.UpdatedAt = time.Unix(0, createdAt).UTC(), time.Unix(0, updatedAt).UTC()
		if err := consumeAccountExportText(remaining, item.ProviderID, item.DisplayName, item.Email); err != nil {
			return err
		}
		snapshot.Identities = append(snapshot.Identities, item)
	}
	return rows.Err()
}

func readAccountExportPasskeys(ctx context.Context, transaction *sql.Tx, userID tailcfg.UserID, snapshot *AccountExportSnapshot, remaining *int) error {
	rows, err := transaction.QueryContext(ctx, `SELECT id, name, created_at, last_used_at FROM webauthn_credentials
		WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`, int64(userID), MaxAccountExportRows+1)
	if err != nil {
		return fmt.Errorf("identity: querying account export passkeys: %w", err)
	}
	defer rows.Close()
	snapshot.Passkeys = make([]AccountExportPasskey, 0)
	for rows.Next() {
		if len(snapshot.Passkeys) == MaxAccountExportRows {
			return ErrAccountExportTooLarge
		}
		var item AccountExportPasskey
		var createdAt int64
		var lastUsedAt sql.NullInt64
		if err := rows.Scan(&item.ID, &item.Name, &createdAt, &lastUsedAt); err != nil {
			return fmt.Errorf("identity: reading account export passkey: %w", err)
		}
		item.CreatedAt = time.Unix(0, createdAt).UTC()
		if lastUsedAt.Valid && lastUsedAt.Int64 != 0 {
			item.LastUsedAt = time.Unix(0, lastUsedAt.Int64).UTC()
		}
		if err := consumeAccountExportText(remaining, item.ID, item.Name); err != nil {
			return err
		}
		snapshot.Passkeys = append(snapshot.Passkeys, item)
	}
	return rows.Err()
}
