package control

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"time"

	"github.com/xunara-net/xunara-server/state"
)

type networkVersion struct {
	Revision uint64    `json:"revision"`
	Prefix   string    `json:"ipv4_cidr"`
	Actor    string    `json:"actor"`
	Created  time.Time `json:"created"`
}

type networkVersionQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readNetworkVersion(ctx context.Context, query networkVersionQuery, orgID string) (networkVersion, error) {
	var version networkVersion
	var created int64
	err := query.QueryRowContext(ctx, "SELECT revision,prefix,actor,created FROM tenant_network_versions WHERE org_id=?", orgID).Scan(&version.Revision, &version.Prefix, &version.Actor, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return networkVersion{Actor: "system:allocation"}, nil
	}
	version.Created = time.Unix(0, created).UTC()
	return version, err
}

func (registry *PlanRegistry) networkVersion(ctx context.Context, orgID string) (networkVersion, error) {
	return readNetworkVersion(ctx, registry.db, orgID)
}

// reserveLegacyAddresses 补录已有设备的历史地址，不把整片默认 /10 声称为单租户所有。
func (registry *PlanRegistry) reserveLegacyAddresses(ctx context.Context, orgID string, nodes []state.Node) error {
	transaction, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	used, err := registry.usedNetworksTx(ctx, transaction, orgID)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		if !node.IPv4.IsValid() {
			continue
		}
		prefix := netip.PrefixFrom(node.IPv4, 32)
		for _, other := range used {
			if other.Overlaps(prefix) {
				return ErrNetworkConflict
			}
		}
		if _, err := transaction.ExecContext(ctx, "INSERT OR IGNORE INTO tenant_network_reservations(org_id,prefix) VALUES (?,?)", orgID, prefix.String()); err != nil {
			return err
		}
	}
	return transaction.Commit()
}

func (registry *PlanRegistry) validateNetwork(ctx context.Context, orgID string, prefix netip.Prefix) error {
	transaction, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	used, err := registry.usedNetworksTx(ctx, transaction, orgID)
	if err != nil {
		return err
	}
	for _, other := range used {
		if prefix.Overlaps(other) {
			return ErrNetworkConflict
		}
	}
	return nil
}
