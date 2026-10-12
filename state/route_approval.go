package state

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
)

var (
	ErrRouteNodeNotFound     = errors.New("route device not found")
	ErrRouteConflict         = errors.New("route configuration changed")
	ErrRouteNotAnnounced     = errors.New("new approval is not announced")
	ErrRouteSnapshotTooLarge = errors.New("route configuration exceeds the requested snapshot bound")
)

type RouteApprovalUpdate struct {
	Revision         string
	Approve          []netip.Prefix
	Unapprove        []netip.Prefix
	RequireAnnounced bool
	SnapshotLimit    int
}

// 绑定审批相关事实，普通在线活动不制造假冲突；密钥只参与摘要，不返回。
func RouteApprovalRevision(node Node) string {
	facts := struct {
		ID                            NodeID
		StableID, MachineKey, NodeKey string
		UserID                        uint64
		Approved, Announced           []netip.Prefix
	}{node.ID, node.StableID, node.MachineKey.String(), node.NodeKey.String(), uint64(node.UserID),
		normalizeRoutes(node.ApprovedRoutes), normalizeRoutes(node.AnnouncedRoutes())}
	encoded, _ := json.Marshal(facts)
	digest := sha256.Sum256(append([]byte("xunara.route-approval.v1\x00"), encoded...))
	return hex.EncodeToString(digest[:])
}

// 读取故障必须与缺设备区分，不能把数据库故障包装成不存在。
func ReadRouteNode(ctx context.Context, query addressQuery, reference string) (Node, error) {
	column, value := "stable_id", any(reference)
	if identifier, err := strconv.ParseUint(reference, 10, 64); err == nil {
		if identifier>>63 != 0 {
			return Node{}, ErrRouteNodeNotFound
		}
		column, value = "id", identifier
	}
	node, err := scanNode(query.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM nodes WHERE "+column+" = ?", value))
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrRouteNodeNotFound
	}
	return node, err
}

// 只修改批准字段；写锁、身份复查与必需审计由调用方放在同一个事务。
func ApplyRouteApprovalTx(ctx context.Context, transaction *sql.Tx, reference string, update RouteApprovalUpdate,
	check func([]netip.Prefix) error) (Node, []netip.Prefix, []netip.Prefix, error) {
	node, err := ReadRouteNode(ctx, transaction, reference)
	if err != nil {
		return Node{}, nil, nil, err
	}
	if update.Revision != "" && update.Revision != RouteApprovalRevision(node) {
		return Node{}, nil, nil, ErrRouteConflict
	}
	after := ApplyRouteApproval(node.ApprovedRoutes, update.Approve, update.Unapprove)
	if update.SnapshotLimit > 0 && (len(after) > update.SnapshotLimit || len(node.AnnouncedRoutes()) > update.SnapshotLimit) {
		return Node{}, nil, nil, ErrRouteSnapshotTooLarge
	}
	added, removed := RouteDelta(node.ApprovedRoutes, after)
	if update.RequireAnnounced {
		for _, prefix := range added {
			if !slices.Contains(node.AnnouncedRoutes(), prefix) {
				return Node{}, nil, nil, ErrRouteNotAnnounced
			}
		}
	}
	if len(added) > 0 && check != nil {
		if err := check(after); err != nil {
			return Node{}, nil, nil, err
		}
	}
	if len(added) == 0 && len(removed) == 0 {
		return node, nil, nil, nil
	}
	encoded, err := encodeRoutes(after)
	if err != nil {
		return Node{}, nil, nil, err
	}
	result, err := transaction.ExecContext(ctx, "UPDATE nodes SET approved_routes = ? WHERE id = ?", encoded, int64(node.ID))
	if err != nil {
		return Node{}, nil, nil, err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return Node{}, nil, nil, fmt.Errorf("route update did not persist")
	}
	node.ApprovedRoutes = normalizeRoutes(after)
	return node, added, removed, nil
}
