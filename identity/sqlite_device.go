package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"tailscale.com/tailcfg"
)

const deviceAuthorizationColumns = "id, machine_key, node_key, user_id, approved_by, state, requested_action, " +
	"client_metadata, created_at, expires_at, approved_at, denied_at"

// 精确机器/节点对复用尚未过期的待审批记录；刷新和多实例不会生成孤立申请。
func (store *SQLiteStore) CreatePendingDeviceAuthorization(ctx context.Context, opts NewDeviceAuthorizationOptions) (DeviceAuthorization, error) {
	if opts.MachineKey == "" || opts.NodeKey == "" {
		return DeviceAuthorization{}, errors.New("device authorization needs both keys")
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, "UPDATE device_authorizations SET state = state WHERE machine_key = ? AND node_key = ? AND state = ?",
		opts.MachineKey, opts.NodeKey, string(DevicePending)); err != nil {
		return DeviceAuthorization{}, err
	}
	now := time.Now().UTC()
	current, err := scanDeviceAuthorization(transaction.QueryRowContext(ctx, "SELECT "+deviceAuthorizationColumns+
		" FROM device_authorizations WHERE machine_key = ? AND node_key = ? AND state = ? AND expires_at > ? ORDER BY created_at DESC, id DESC LIMIT 1",
		opts.MachineKey, opts.NodeKey, string(DevicePending), now.UnixNano()))
	if err == nil {
		return current, transaction.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return DeviceAuthorization{}, err
	}
	if opts.ID == "" {
		opts.ID, err = newSecret()
		if err != nil {
			return DeviceAuthorization{}, err
		}
	}
	if opts.TTL <= 0 {
		opts.TTL = DefaultDeviceAuthorizationTTL
	}
	authorization := DeviceAuthorization{ID: opts.ID, MachineKey: opts.MachineKey, NodeKey: opts.NodeKey,
		State: DevicePending, RequestedAction: opts.RequestedAction, ClientMetadata: opts.ClientMetadata,
		CreatedAt: now, ExpiresAt: now.Add(opts.TTL)}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO device_authorizations (`+deviceAuthorizationColumns+`)
		VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, NULL, NULL)`, authorization.ID, authorization.MachineKey,
		authorization.NodeKey, string(authorization.State), authorization.RequestedAction, authorization.ClientMetadata,
		authorization.CreatedAt.UnixNano(), authorization.ExpiresAt.UnixNano()); err != nil {
		return DeviceAuthorization{}, err
	}
	return authorization, transaction.Commit()
}

// CreateDeviceAuthorization implements [DeviceAuthorizationStore].
func (s *SQLiteStore) CreateDeviceAuthorization(opts NewDeviceAuthorizationOptions) (DeviceAuthorization, error) {
	if opts.MachineKey == "" || opts.NodeKey == "" {
		return DeviceAuthorization{}, fmt.Errorf("identity: device authorization needs a machine key and a node key")
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultDeviceAuthorizationTTL
	}

	id := opts.ID
	if id == "" {
		var err error
		id, err = newSecret()
		if err != nil {
			return DeviceAuthorization{}, err
		}
	}

	now := time.Now().UTC()
	da := DeviceAuthorization{
		ID:              id,
		MachineKey:      opts.MachineKey,
		NodeKey:         opts.NodeKey,
		State:           DevicePending,
		RequestedAction: opts.RequestedAction,
		ClientMetadata:  opts.ClientMetadata,
		CreatedAt:       now,
		ExpiresAt:       now.Add(ttl),
	}

	if _, err := s.db.ExecContext(context.Background(),
		`INSERT INTO device_authorizations (`+deviceAuthorizationColumns+`)
		 VALUES (?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, NULL, NULL)`,
		da.ID, da.MachineKey, da.NodeKey, string(da.State), da.RequestedAction, da.ClientMetadata,
		da.CreatedAt.UnixNano(), da.ExpiresAt.UnixNano()); err != nil {
		return DeviceAuthorization{}, fmt.Errorf("identity: creating device authorization: %w", err)
	}
	return da, nil
}

// GetDeviceAuthorization implements [DeviceAuthorizationStore].
func (s *SQLiteStore) GetDeviceAuthorization(id string) (DeviceAuthorization, bool) {
	authorization, err := s.LookupDeviceAuthorization(context.Background(), id)
	return authorization, err == nil
}

func (store *SQLiteStore) LookupDeviceAuthorization(ctx context.Context, id string) (DeviceAuthorization, error) {
	return DeviceAuthorizationTx(ctx, store.db, id)
}

func (store *SQLiteStore) LookupDeviceAuthorizationByKeys(ctx context.Context, machineKey, nodeKey string) (DeviceAuthorization, error) {
	authorization, err := scanDeviceAuthorization(store.db.QueryRowContext(ctx, "SELECT "+deviceAuthorizationColumns+
		" FROM device_authorizations WHERE machine_key = ? AND node_key = ? ORDER BY created_at DESC, id DESC LIMIT 1", machineKey, nodeKey))
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceAuthorization{}, ErrDeviceNotFound
	}
	return authorization, err
}

// 审批事务读取同一行真实状态，不能把查询故障当成不存在。
func DeviceAuthorizationTx(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id string) (DeviceAuthorization, error) {
	authorization, err := scanDeviceAuthorization(query.QueryRowContext(ctx,
		"SELECT "+deviceAuthorizationColumns+" FROM device_authorizations WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceAuthorization{}, ErrDeviceNotFound
	}
	return authorization, err
}

func DecideDeviceAuthorizationTx(ctx context.Context, transaction *sql.Tx, observed DeviceAuthorization, userID tailcfg.UserID, approve bool, now time.Time) (DeviceAuthorization, error) {
	state := DeviceDenied
	if approve {
		state = DeviceApproved
	}
	var decisionUser any
	if approve {
		decisionUser = int64(userID)
	}
	result, err := transaction.ExecContext(ctx, `UPDATE device_authorizations SET state = ?, user_id = ?, approved_by = ?,
		approved_at = ?, denied_at = ? WHERE id = ? AND machine_key = ? AND node_key = ? AND state = ? AND expires_at > ?`,
		string(state), decisionUser, decisionUser, nullableDeviceTime(now, approve), nullableDeviceTime(now, !approve),
		observed.ID, observed.MachineKey, observed.NodeKey, string(DevicePending), now.UnixNano())
	if err != nil {
		return DeviceAuthorization{}, err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return DeviceAuthorization{}, errors.New("device authorization decision did not persist")
	}
	return DeviceAuthorizationTx(ctx, transaction, observed.ID)
}

func nullableDeviceTime(now time.Time, present bool) any {
	if present {
		return now.UnixNano()
	}
	return nil
}

// GetDeviceAuthorizationByNodeKey implements [DeviceAuthorizationStore].
func (s *SQLiteStore) GetDeviceAuthorizationByNodeKey(nodeKey string) (DeviceAuthorization, bool) {
	row := s.db.QueryRowContext(context.Background(),
		"SELECT "+deviceAuthorizationColumns+
			" FROM device_authorizations WHERE node_key = ? ORDER BY created_at DESC LIMIT 1", nodeKey)
	da, err := scanDeviceAuthorization(row)
	if err != nil {
		return DeviceAuthorization{}, false
	}
	return da, true
}

// ListPendingDeviceAuthorizations implements [DeviceAuthorizationStore].
func (s *SQLiteStore) ListPendingDeviceAuthorizations(now time.Time) []DeviceAuthorization {
	rows, err := s.db.QueryContext(context.Background(),
		"SELECT "+deviceAuthorizationColumns+
			" FROM device_authorizations WHERE state = ? AND expires_at > ? ORDER BY created_at DESC",
		string(DevicePending), now.UnixNano())
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []DeviceAuthorization
	for rows.Next() {
		da, err := scanDeviceAuthorization(rows)
		if err != nil {
			return nil
		}
		out = append(out, da)
	}
	return out
}

// ApproveDeviceAuthorization implements [DeviceAuthorizationStore].
//
// The UPDATE is conditional on the row still being pending and unexpired, so
// two concurrent approvals cannot both write: the second observes the first.
func (s *SQLiteStore) ApproveDeviceAuthorization(id string, userID tailcfg.UserID) (DeviceAuthorization, error) {
	now := time.Now().UTC()

	res, err := s.db.ExecContext(context.Background(),
		`UPDATE device_authorizations
		 SET state = ?, user_id = ?, approved_by = ?, approved_at = ?
		 WHERE id = ? AND state = ? AND expires_at > ?`,
		string(DeviceApproved), int64(userID), int64(userID), now.UnixNano(),
		id, string(DevicePending), now.UnixNano())
	if err != nil {
		return DeviceAuthorization{}, fmt.Errorf("identity: approving device authorization: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return DeviceAuthorization{}, fmt.Errorf("identity: approving device authorization: %w", err)
	}

	da, ok := s.GetDeviceAuthorization(id)
	switch {
	case affected == 1:
		if !ok {
			return DeviceAuthorization{}, ErrDeviceNotFound
		}
		return da, nil
	case !ok:
		return DeviceAuthorization{}, ErrDeviceNotFound
	case da.Expired(now):
		return da, ErrDeviceExpired
	case da.State == DeviceApproved && da.ApprovedBy == userID:
		// A double-click or a retried request is not a new decision.
		return da, nil
	default:
		return da, ErrDeviceDecided
	}
}

// DenyDeviceAuthorization implements [DeviceAuthorizationStore].
func (s *SQLiteStore) DenyDeviceAuthorization(id string, userID tailcfg.UserID) (DeviceAuthorization, error) {
	now := time.Now().UTC()

	res, err := s.db.ExecContext(context.Background(),
		`UPDATE device_authorizations
		 SET state = ?, denied_at = ?
		 WHERE id = ? AND state = ? AND expires_at > ?`,
		string(DeviceDenied), now.UnixNano(), id, string(DevicePending), now.UnixNano())
	if err != nil {
		return DeviceAuthorization{}, fmt.Errorf("identity: denying device authorization: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return DeviceAuthorization{}, fmt.Errorf("identity: denying device authorization: %w", err)
	}

	da, ok := s.GetDeviceAuthorization(id)
	switch {
	case affected == 1:
		if !ok {
			return DeviceAuthorization{}, ErrDeviceNotFound
		}
		return da, nil
	case !ok:
		return DeviceAuthorization{}, ErrDeviceNotFound
	case da.Expired(now):
		return da, ErrDeviceExpired
	case da.State == DeviceDenied:
		return da, nil
	default:
		return da, ErrDeviceDecided
	}
}

// DeleteExpiredDeviceAuthorizations implements [DeviceAuthorizationStore].
func (s *SQLiteStore) DeleteExpiredDeviceAuthorizations(now time.Time) (int64, error) {
	res, err := s.db.ExecContext(context.Background(),
		"DELETE FROM device_authorizations WHERE expires_at <= ? AND state = ?",
		now.UnixNano(), string(DevicePending))
	if err != nil {
		return 0, fmt.Errorf("identity: deleting expired device authorizations: %w", err)
	}
	return res.RowsAffected()
}

func scanDeviceAuthorization(sc rowScanner) (DeviceAuthorization, error) {
	var (
		da         DeviceAuthorization
		state      string
		userID     sql.NullInt64
		approvedBy sql.NullInt64
		createdAt  int64
		expiresAt  int64
		approvedAt sql.NullInt64
		deniedAt   sql.NullInt64
	)
	if err := sc.Scan(&da.ID, &da.MachineKey, &da.NodeKey, &userID, &approvedBy, &state,
		&da.RequestedAction, &da.ClientMetadata, &createdAt, &expiresAt, &approvedAt, &deniedAt); err != nil {
		return DeviceAuthorization{}, err
	}
	da.State = DeviceAuthorizationState(state)
	if userID.Valid {
		da.UserID = tailcfg.UserID(userID.Int64)
	}
	if approvedBy.Valid {
		da.ApprovedBy = tailcfg.UserID(approvedBy.Int64)
	}
	da.CreatedAt = time.Unix(0, createdAt).UTC()
	da.ExpiresAt = time.Unix(0, expiresAt).UTC()
	if approvedAt.Valid {
		da.ApprovedAt = time.Unix(0, approvedAt.Int64).UTC()
	}
	if deniedAt.Valid {
		da.DeniedAt = time.Unix(0, deniedAt.Int64).UTC()
	}
	return da, nil
}
