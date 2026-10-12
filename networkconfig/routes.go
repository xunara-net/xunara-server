package networkconfig

import (
	"context"
	"net/netip"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func (store *SQLiteStore) RouteNode(ctx context.Context, reference string) (state.Node, error) {
	return state.ReadRouteNode(ctx, store.db, reference)
}

func (store *SQLiteStore) SaveNodeRoutes(ctx context.Context, reference string, update state.RouteApprovalUpdate,
	writer Writer, check func([]netip.Prefix) error) (state.Node, error) {
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return state.Node{}, err
	}
	defer transaction.Rollback()
	// 服务 key 也先取得写锁，跨连接审批不能基于旧读快照覆盖彼此。
	if _, err := transaction.ExecContext(ctx, "UPDATE counters SET value = value WHERE name = 'config_revision'"); err != nil {
		return state.Node{}, err
	}
	now := time.Now().UTC()
	if err := identity.CheckNetworkWriter(ctx, transaction, writer.UserID, writer.SessionID, writer.APIKeyID, now); err != nil {
		return state.Node{}, err
	}
	node, added, removed, err := state.ApplyRouteApprovalTx(ctx, transaction, reference, update, check)
	if err != nil {
		return state.Node{}, err
	}
	for _, change := range []struct {
		action string
		routes []netip.Prefix
	}{
		{identity.AuditRouteApproved, added}, {identity.AuditRouteUnapproved, removed},
	} {
		for _, prefix := range change.routes {
			if err := commitChange(ctx, transaction, writer.Actor(), change.action, "node:"+node.StableID, prefix.String(), now); err != nil {
				return state.Node{}, err
			}
		}
	}
	return node, transaction.Commit()
}
