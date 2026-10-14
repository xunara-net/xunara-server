package state

import (
	"context"
	"database/sql"
	"errors"

	"tailscale.com/types/key"
)

func ReadNodeByKey(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, nodeKey key.NodePublic) (Node, error) {
	node, err := scanNode(query.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM nodes WHERE node_key = ?", nodeKey.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrRouteNodeNotFound
	}
	return node, err
}

// 机器和所属人都匹配才允许轮换；重复节点键不能吞错后批准另一个身份。
func AuthorizeInteractiveNodeTx(ctx context.Context, transaction *sql.Tx, want Node, limit int) (Node, bool, error) {
	if want.MachineKey.IsZero() || want.NodeKey.IsZero() || want.UserID == 0 {
		return Node{}, false, ErrDeviceChanged
	}
	existing, err := ReadNodeByKey(ctx, transaction, want.NodeKey)
	if err == nil {
		if existing.MachineKey != want.MachineKey || existing.UserID != want.UserID {
			return Node{}, false, ErrDeviceChanged
		}
		return existing, false, nil
	}
	if !errors.Is(err, ErrRouteNodeNotFound) {
		return Node{}, false, err
	}
	rows, err := transaction.QueryContext(ctx, "SELECT "+nodeColumns+" FROM nodes WHERE machine_key = ?", want.MachineKey.String())
	if err != nil {
		return Node{}, false, err
	}
	candidates := make([]Node, 0, 1)
	for rows.Next() {
		node, err := scanNode(rows)
		if err != nil {
			rows.Close()
			return Node{}, false, err
		}
		if node.UserID == want.UserID || len(node.Tags) > 0 {
			candidates = append(candidates, node)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return Node{}, false, err
	}
	if len(candidates) > 1 {
		return Node{}, false, ErrAmbiguousMachine
	}
	if len(candidates) == 1 {
		want = RotatedNode(candidates[0], want, true)
		err = UpdateNodeWithDNSTx(ctx, transaction, &want)
		return want, true, err
	}
	if err := CheckDeviceLimitTx(ctx, transaction, limit); err != nil {
		return Node{}, false, err
	}
	err = CreateNodeTx(ctx, transaction, &want)
	return want, false, err
}
