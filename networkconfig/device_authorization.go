package networkconfig

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// 先获得数据库写锁再读，避免跨实例基于旧快照放行一次性密钥或额度。
func (store *SQLiteStore) deviceWriteTransaction(ctx context.Context) (*sql.Tx, error) {
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE counters SET value = value WHERE name = 'config_revision'"); err != nil {
		transaction.Rollback()
		return nil, err
	}
	return transaction, nil
}

func (store *SQLiteStore) ExpireNode(ctx context.Context, reference, revision string, writer Writer) (state.Node, error) {
	transaction, err := store.deviceWriteTransaction(ctx)
	if err != nil {
		return state.Node{}, err
	}
	defer transaction.Rollback()
	now := time.Now().UTC()
	if err := identity.CheckNetworkWriter(ctx, transaction, writer.UserID, writer.SessionID, writer.APIKeyID, now); err != nil {
		return state.Node{}, err
	}
	node, changed, err := state.ExpireNodeTx(ctx, transaction, reference, revision, now)
	if err != nil {
		return state.Node{}, err
	}
	if changed {
		if err := commitChange(ctx, transaction, writer.Actor(), identity.AuditNodeExpired, "node:"+node.StableID, "device key expired by administrator", now); err != nil {
			return state.Node{}, err
		}
	}
	return node, transaction.Commit()
}

func (store *SQLiteStore) AuthKeyUsage(ctx context.Context) (int, error) {
	return state.UsablePreAuthKeyCount(ctx, store.db, time.Now().UTC())
}

func (store *SQLiteStore) ShortenNodeExpiry(ctx context.Context, observed state.Node, requested time.Time) (state.Node, error) {
	transaction, err := store.deviceWriteTransaction(ctx)
	if err != nil {
		return state.Node{}, err
	}
	defer transaction.Rollback()
	now := time.Now().UTC()
	node, err := state.ShortenNodeExpiryTx(ctx, transaction, observed, requested, now)
	if err != nil {
		return state.Node{}, err
	}
	if err := commitChange(ctx, transaction, "node:"+node.StableID, identity.AuditNodeExpiryShortened, "node:"+node.StableID,
		"node key expiry shortened to "+requested.UTC().Format(time.RFC3339), now); err != nil {
		return state.Node{}, err
	}
	return node, transaction.Commit()
}

func (store *SQLiteStore) RegistrationKeys(ctx context.Context, machine key.MachinePublic, nodeKey key.NodePublic,
	lockKey key.NLPublic, signature []byte) (state.Node, bool, error) {
	transaction, err := store.deviceWriteTransaction(ctx)
	if err != nil {
		return state.Node{}, false, err
	}
	defer transaction.Rollback()
	node, changed, signed, err := state.ApplyRegistrationKeysTx(ctx, transaction, machine, nodeKey, lockKey, signature)
	if err != nil {
		return state.Node{}, false, err
	}
	if signed {
		if err := commitChange(ctx, transaction, "node:"+node.StableID, identity.AuditTailnetLockNodeSigned, "node:"+node.StableID,
			"node key signed at registration", time.Now().UTC()); err != nil {
			return state.Node{}, false, err
		}
	}
	return node, changed, transaction.Commit()
}

func (store *SQLiteStore) CreateAuthKey(ctx context.Context, authorization state.PreAuthKey, limit int, writer Writer) (state.PreAuthKey, error) {
	transaction, err := store.deviceWriteTransaction(ctx)
	if err != nil {
		return state.PreAuthKey{}, err
	}
	defer transaction.Rollback()
	now := time.Now().UTC()
	if err := identity.CheckNetworkWriter(ctx, transaction, writer.UserID, writer.SessionID, writer.APIKeyID, now); err != nil {
		return state.PreAuthKey{}, err
	}
	var available int
	if err := transaction.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE id = ? AND disabled_at IS NULL", int64(authorization.UserID)).Scan(&available); err != nil {
		return state.PreAuthKey{}, err
	}
	if available != 1 {
		return state.PreAuthKey{}, identity.ErrUserNotFound
	}
	if err := state.CreatePreAuthKeyTx(ctx, transaction, &authorization, limit, now); err != nil {
		return state.PreAuthKey{}, err
	}
	if err := commitChange(ctx, transaction, writer.Actor(), identity.AuditPreAuthKeyCreated, fmt.Sprintf("preauthkey:%d", authorization.ID), "device authorization key created", now); err != nil {
		return state.PreAuthKey{}, err
	}
	return authorization, transaction.Commit()
}

func (store *SQLiteStore) DeleteAuthKey(ctx context.Context, identifier uint64, writer Writer) error {
	transaction, err := store.deviceWriteTransaction(ctx)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	now := time.Now().UTC()
	if err := identity.CheckNetworkWriter(ctx, transaction, writer.UserID, writer.SessionID, writer.APIKeyID, now); err != nil {
		return err
	}
	result, err := transaction.ExecContext(ctx, "DELETE FROM preauthkeys WHERE id = ?", identifier)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrNotFound
	}
	if err := commitChange(ctx, transaction, writer.Actor(), identity.AuditPreAuthKeyDeleted, fmt.Sprintf("preauthkey:%d", identifier), "device authorization key revoked", now); err != nil {
		return err
	}
	return transaction.Commit()
}

// 此入口用机器预授权凭据，而非 Human Session；身份边界不能互相推导。
func (store *SQLiteStore) EnrollAuthKey(ctx context.Context, secret string, want state.Node, limit int,
	prepare func(*state.Node, time.Time)) (state.Node, error) {
	transaction, err := store.deviceWriteTransaction(ctx)
	if err != nil {
		return state.Node{}, err
	}
	defer transaction.Rollback()
	now := time.Now().UTC()
	node, identifier, rotated, err := state.EnrollPreAuthKeyTx(ctx, transaction, secret, want, limit, now, prepare)
	if err != nil {
		return state.Node{}, err
	}
	action, detail := identity.AuditNodeRegistered, "authorized with a pre-auth key"
	if rotated {
		action, detail = identity.AuditNodeKeyRotated, "node key rotated in place; machine identity unchanged"
	}
	actor := fmt.Sprintf("preauthkey:%d", identifier)
	if err := commitChange(ctx, transaction, actor, action, "node:"+node.StableID, detail, now); err != nil {
		return state.Node{}, err
	}
	if len(want.KeySignature) > 0 {
		if err := commitChange(ctx, transaction, actor, identity.AuditTailnetLockNodeSigned, "node:"+node.StableID, "node key signed at registration", now); err != nil {
			return state.Node{}, err
		}
	}
	if err := transaction.Commit(); err != nil {
		return state.Node{}, errors.New("device enrollment could not be committed")
	}
	return node, nil
}
