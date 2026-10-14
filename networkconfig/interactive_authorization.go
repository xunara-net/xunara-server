package networkconfig

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type DeviceDecision struct {
	UserID         tailcfg.UserID
	Actor          string
	Writer         *Writer
	Node           state.Node
	Approve        bool
	DeviceLimit    int
	PolicyRevision uint64
}

func (store *SQLiteStore) NodeByKey(ctx context.Context, nodeKey key.NodePublic) (state.Node, error) {
	return state.ReadNodeByKey(ctx, store.db, nodeKey)
}

func (store *SQLiteStore) AcceptsRegistrationKey(ctx context.Context, secret string, machine key.MachinePublic, nodeKey key.NodePublic) (bool, error) {
	authorization, err := state.ReadPreAuthKey(ctx, store.db, secret)
	if errors.Is(err, state.ErrPreAuthKeyNotUsable) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	now := time.Now().UTC()
	if authorization.Usable(now) {
		return true, nil
	}
	// 一次性 Token 已成功消耗后，丢包重试只能恢复同一机器、节点与所属用户。
	// 它不能接入另一台设备，也不能把失效 Token 退回默认租户。
	if !authorization.Used || (!authorization.Expiry.IsZero() && !authorization.Expiry.After(now)) {
		return false, nil
	}
	node, err := store.NodeByKey(ctx, nodeKey)
	if errors.Is(err, state.ErrRouteNodeNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return node.MachineKey == machine && node.UserID == authorization.UserID, nil
}

// 浏览器/服务请求复核实际凭据；私有内嵌管理入口也不能替禁用或只读用户操作。
func checkDeviceDecisionActor(ctx context.Context, transaction *sql.Tx, decision DeviceDecision, now time.Time) error {
	if decision.UserID == 0 {
		return identity.ErrNetworkWriterForbidden
	}
	if decision.Writer != nil {
		if decision.Writer.UserID != decision.UserID {
			return identity.ErrNetworkWriterForbidden
		}
		return identity.CheckNetworkWriter(ctx, transaction, decision.UserID, decision.Writer.SessionID, decision.Writer.APIKeyID, now)
	}
	var role string
	var disabled, passwordChange bool
	if err := transaction.QueryRowContext(ctx, "SELECT role, disabled_at IS NOT NULL, password_change_required FROM users WHERE id = ?", int64(decision.UserID)).Scan(&role, &disabled, &passwordChange); err != nil {
		return err
	}
	if disabled || passwordChange || !identity.Role(role).CanWrite() {
		return identity.ErrNetworkWriterForbidden
	}
	return nil
}

// 节点、决定、必需审计与通知版本一同提交，任何零行更新或故障都不能留下授权。
func (store *SQLiteStore) DecideDevice(ctx context.Context, observed identity.DeviceAuthorization, decision DeviceDecision) (identity.DeviceAuthorization, state.Node, error) {
	transaction, err := store.deviceWriteTransaction(ctx)
	if err != nil {
		return identity.DeviceAuthorization{}, state.Node{}, err
	}
	defer transaction.Rollback()
	now := time.Now().UTC()
	if err := checkDeviceDecisionActor(ctx, transaction, decision, now); err != nil {
		return identity.DeviceAuthorization{}, state.Node{}, err
	}
	current, err := identity.DeviceAuthorizationTx(ctx, transaction, observed.ID)
	if err != nil {
		return current, state.Node{}, err
	}
	if !current.ExpiresAt.After(now) {
		return current, state.Node{}, identity.ErrDeviceExpired
	}
	if current.MachineKey != observed.MachineKey || current.NodeKey != observed.NodeKey || current.ClientMetadata != observed.ClientMetadata {
		return current, state.Node{}, state.ErrDeviceChanged
	}
	if current.State != identity.DevicePending {
		if decision.Approve && current.State == identity.DeviceApproved && current.UserID == decision.UserID && current.ApprovedBy == decision.UserID || !decision.Approve && current.State == identity.DeviceDenied {
			return current, state.Node{}, transaction.Commit()
		}
		return current, state.Node{}, identity.ErrDeviceDecided
	}
	var node state.Node
	if decision.Approve {
		if decision.Node.MachineKey.String() != current.MachineKey || decision.Node.NodeKey.String() != current.NodeKey || decision.Node.UserID != decision.UserID {
			return current, state.Node{}, state.ErrDeviceChanged
		}
		if len(decision.Node.Tags) > 0 {
			var revision uint64
			err := transaction.QueryRowContext(ctx, "SELECT revision FROM network_documents WHERE kind = ?", Policy).Scan(&revision)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return current, state.Node{}, err
			}
			if revision != decision.PolicyRevision {
				return current, state.Node{}, ErrConflict
			}
		}
		var rotated bool
		node, rotated, err = state.AuthorizeInteractiveNodeTx(ctx, transaction, decision.Node, decision.DeviceLimit)
		if err != nil {
			return current, state.Node{}, err
		}
		if rotated {
			if err := commitChange(ctx, transaction, decision.Actor, identity.AuditNodeKeyRotated, "node:"+node.StableID,
				"interactive reauthorization; machine identity unchanged", now); err != nil {
				return current, state.Node{}, err
			}
		}
	}
	current, err = identity.DecideDeviceAuthorizationTx(ctx, transaction, current, decision.UserID, decision.Approve, now)
	if err != nil {
		return current, state.Node{}, err
	}
	action, target, detail := identity.AuditDeviceDenied, "device:"+observed.ID, "device registration denied"
	if decision.Approve {
		action, target, detail = identity.AuditNodeApproved, "node:"+node.StableID, "device registration approved"
	}
	if err := commitChange(ctx, transaction, decision.Actor, action, target, detail, now); err != nil {
		return current, state.Node{}, err
	}
	if err := transaction.Commit(); err != nil {
		return identity.DeviceAuthorization{}, state.Node{}, errors.New("device decision could not be committed")
	}
	return current, node, nil
}
