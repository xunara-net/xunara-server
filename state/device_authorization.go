package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"tailscale.com/types/key"
)

var (
	ErrPreAuthKeyNotUsable = errors.New("pre-auth key is invalid, expired or already used")
	ErrAuthKeyLimit        = errors.New("auth key limit reached")
	ErrDeviceLimit         = errors.New("device limit reached")
	ErrAmbiguousMachine    = errors.New("machine key is bound to multiple nodes")
	ErrDeviceChanged       = errors.New("device identity or expiry changed")
	ErrExpiryNotEarlier    = errors.New("node key expiry may only be shortened")
)

func requireSingleRow(result sql.Result) error {
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("state: required write did not persist")
	}
	return nil
}

func CheckDeviceLimitTx(ctx context.Context, tx *sql.Tx, limit int) error {
	if limit < 0 {
		return nil
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM nodes").Scan(&count); err != nil {
		return err
	}
	if count >= limit {
		return ErrDeviceLimit
	}
	return nil
}

// NodeExpiryRevision 绑定设备身份和有效期，在线活动或重命名不会产生假冲突。
func NodeExpiryRevision(node Node) string {
	facts := struct {
		ID                            NodeID
		StableID, MachineKey, NodeKey string
		UserID                        uint64
		Expiry                        time.Time
	}{node.ID, node.StableID, node.MachineKey.String(), node.NodeKey.String(), uint64(node.UserID), node.Expiry.UTC()}
	encoded, _ := json.Marshal(facts)
	digest := sha256.Sum256(append([]byte("xunara.device-expiry.v1\x00"), encoded...))
	return hex.EncodeToString(digest[:])
}

// ExpireNodeTx 只使节点密钥到期，不删除地址、路由、机器身份或人类会话。
func ExpireNodeTx(ctx context.Context, tx *sql.Tx, reference, revision string, now time.Time) (Node, bool, error) {
	node, err := ReadRouteNode(ctx, tx, reference)
	if err != nil {
		return Node{}, false, err
	}
	if NodeExpiryRevision(node) != revision {
		return Node{}, false, ErrDeviceChanged
	}
	if node.Expired(now) {
		return node, false, nil
	}
	result, err := tx.ExecContext(ctx, "UPDATE nodes SET expiry = ? WHERE id = ?", now.UnixNano(), int64(node.ID))
	if err != nil {
		return Node{}, false, err
	}
	if err := requireSingleRow(result); err != nil {
		return Node{}, false, err
	}
	node.Expiry = now
	return node, true, nil
}

// RotatedNode 保留稳定身份及网络事实，授权密钥只更新它被允许更新的字段。
func RotatedNode(existing, want Node, applyTags bool) Node {
	updated := existing
	updated.NodeKey, updated.Method = want.NodeKey, want.Method
	updated.KeySignature = slices.Clone(want.KeySignature)
	if !want.NLKey.IsZero() {
		updated.NLKey = want.NLKey
	}
	if want.Hostname != "" {
		updated.Hostname = want.Hostname
	}
	if want.Hostinfo != nil {
		updated.Hostinfo = want.Hostinfo
	}
	updated.Expiry = want.Expiry
	updated.Ephemeral = existing.Ephemeral || want.Ephemeral
	if applyTags || len(want.Tags) > 0 {
		updated.Tags = slices.Clone(want.Tags)
		updated.UserID = want.UserID
	}
	return updated
}

func ShortenNodeExpiryTx(ctx context.Context, tx *sql.Tx, observed Node, requested, now time.Time) (Node, error) {
	node, err := ReadRouteNode(ctx, tx, observed.StableID)
	if err != nil {
		return Node{}, err
	}
	if node.NodeKey != observed.NodeKey || node.MachineKey != observed.MachineKey {
		return Node{}, ErrDeviceChanged
	}
	if !requested.After(now) || node.Expiry.IsZero() || !requested.Before(node.Expiry) {
		return Node{}, ErrExpiryNotEarlier
	}
	result, err := tx.ExecContext(ctx, "UPDATE nodes SET expiry = ? WHERE id = ?", requested.UnixNano(), int64(node.ID))
	if err != nil {
		return Node{}, err
	}
	if err := requireSingleRow(result); err != nil {
		return Node{}, err
	}
	node.Expiry = requested.UTC()
	return node, nil
}

// 注册补充公钥只改公钥字段，不能从旧快照恢复已过期的设备或覆盖管理员路由。
func ApplyRegistrationKeysTx(ctx context.Context, tx *sql.Tx, machine key.MachinePublic, nodeKey key.NodePublic,
	lockKey key.NLPublic, signature []byte) (Node, bool, bool, error) {
	node, err := scanNode(tx.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM nodes WHERE node_key = ?", textOf(nodeKey, "")))
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, false, false, ErrRouteNodeNotFound
	}
	if err != nil {
		return Node{}, false, false, err
	}
	if node.MachineKey != machine {
		return Node{}, false, false, ErrDeviceChanged
	}
	signed := len(signature) > 0 && !slices.Equal(node.KeySignature, signature)
	changed := signed || (!lockKey.IsZero() && node.NLKey != lockKey)
	if !changed {
		return node, false, false, nil
	}
	if !lockKey.IsZero() {
		node.NLKey = lockKey
	}
	if signed {
		node.KeySignature = slices.Clone(signature)
	}
	result, err := tx.ExecContext(ctx, "UPDATE nodes SET nl_key = ?, key_signature = ? WHERE id = ?", textOf(node.NLKey, ""), nullableBytes(node.KeySignature), int64(node.ID))
	if err != nil {
		return Node{}, false, false, err
	}
	return node, true, signed, requireSingleRow(result)
}

// EnrollPreAuthKeyTx 必须在取得租户写锁后调用；节点写入与密钥消费不能分开提交。
func EnrollPreAuthKeyTx(ctx context.Context, tx *sql.Tx, secret string, want Node, limit int, now time.Time,
	prepare func(*Node, time.Time)) (Node, uint64, bool, error) {
	if want.MachineKey.IsZero() || want.NodeKey.IsZero() {
		return Node{}, 0, false, ErrPreAuthKeyNotUsable
	}
	authorization, err := scanPreAuthKey(tx.QueryRowContext(ctx, "SELECT "+preAuthKeyColumns+" FROM preauthkeys WHERE secret = ?", secret))
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, 0, false, ErrPreAuthKeyNotUsable
	}
	if err != nil {
		return Node{}, 0, false, err
	}
	if !authorization.Usable(now) || (!authorization.Expiry.IsZero() && !authorization.Expiry.After(now)) {
		return Node{}, 0, false, ErrPreAuthKeyNotUsable
	}
	want.UserID = authorization.UserID
	if want.UserID == 0 {
		want.UserID = DefaultUserID
	}
	want.Tags, err = NormalizeTags(authorization.Tags)
	if err != nil {
		return Node{}, 0, false, ErrPreAuthKeyNotUsable
	}
	want.Method = RegisterMethodAuthKey
	want.Ephemeral = want.Ephemeral || authorization.Ephemeral
	if prepare != nil {
		prepare(&want, now)
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+nodeColumns+" FROM nodes WHERE machine_key = ?", textOf(want.MachineKey, ""))
	if err != nil {
		return Node{}, 0, false, err
	}
	candidates := []Node{}
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			rows.Close()
			return Node{}, 0, false, err
		}
		if len(want.Tags) > 0 || len(node.Tags) > 0 || node.UserID == want.UserID {
			candidates = append(candidates, node)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Node{}, 0, false, err
	}
	if len(candidates) > 1 {
		return Node{}, 0, false, ErrAmbiguousMachine
	}
	rotated := len(candidates) == 1
	if rotated {
		want = RotatedNode(candidates[0], want, false)
		err = UpdateNodeWithDNSTx(ctx, tx, &want)
	} else {
		if err := CheckDeviceLimitTx(ctx, tx, limit); err != nil {
			return Node{}, 0, false, err
		}
		err = CreateNodeTx(ctx, tx, &want)
	}
	if err != nil {
		return Node{}, 0, false, err
	}
	result, err := tx.ExecContext(ctx, `UPDATE preauthkeys SET used = 1, used_at = ? WHERE id = ?
		AND (reusable = 1 OR used = 0) AND (expiry IS NULL OR expiry > ?)`, now.UnixNano(), int64(authorization.ID), now.UnixNano())
	if err != nil {
		return Node{}, 0, false, err
	}
	if err := requireSingleRow(result); err != nil {
		return Node{}, 0, false, err
	}
	return want, authorization.ID, rotated, nil
}
