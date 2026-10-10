package networkconfig

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

type AllocationUpdate struct {
	Configuration state.AddressConfiguration
	Actor         string
}

// SaveAllocation 先复查 Human/Service 写权限，再选择期望网段；实际范围、审计与通知同事务。
// 跨平台库的选择失败或最终提交失败时，调用方必须将期望与实际区分为待应用。
func (store *SQLiteStore) SaveAllocation(ctx context.Context, writer *Writer, selectUpdate func(context.Context, state.AddressConfiguration) (AllocationUpdate, error)) (state.AddressConfiguration, error) {
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return state.AddressConfiguration{}, err
	}
	defer transaction.Rollback()
	now := time.Now().UTC()
	if writer != nil {
		if err := identity.CheckNetworkWriter(ctx, transaction, writer.UserID, writer.SessionID, writer.APIKeyID, now); err != nil {
			return state.AddressConfiguration{}, err
		}
	}
	before, err := state.AddressConfigurationTx(ctx, transaction)
	if err != nil {
		return before, err
	}
	update, err := selectUpdate(ctx, before)
	if err != nil {
		return before, err
	}
	changed, err := state.ApplyAddressConfigurationTx(ctx, transaction, update.Configuration)
	if err != nil {
		return before, err
	}
	if changed {
		detail := fmt.Sprintf("IPv4 %s -> %s; source revision %d; existing device addresses retained", before.IPv4, update.Configuration.IPv4, update.Configuration.SourceRevision)
		if err := commitChange(ctx, transaction, update.Actor, "network.prefix_changed", "network", detail, now); err != nil {
			return before, err
		}
	}
	return update.Configuration, transaction.Commit()
}

func (store *SQLiteStore) SaveNodeIPv4(ctx context.Context, id state.NodeID, stableID string, expected, address netip.Addr, writer Writer) (state.Node, error) {
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return state.Node{}, err
	}
	defer transaction.Rollback()
	now := time.Now().UTC()
	if err := identity.CheckNetworkWriter(ctx, transaction, writer.UserID, writer.SessionID, writer.APIKeyID, now); err != nil {
		return state.Node{}, err
	}
	node, err := state.ChangeNodeIPv4Tx(ctx, transaction, id, stableID, expected, address)
	if err != nil {
		return state.Node{}, err
	}
	if expected != address {
		if err := commitChange(ctx, transaction, writer.Actor(), "node.ipv4_changed", "node:"+stableID, fmt.Sprintf("IPv4 %s -> %s", expected, address), now); err != nil {
			return state.Node{}, err
		}
	}
	return node, transaction.Commit()
}
