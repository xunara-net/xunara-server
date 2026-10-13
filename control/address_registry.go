package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/xunara-net/xunara-server/netspace"
	"github.com/xunara-net/xunara-server/state"
)

type networkVersion struct {
	Revision  uint64         `json:"revision"`
	Prefix    string         `json:"ipv4_cidr"`
	Actor     string         `json:"actor"`
	Created   time.Time      `json:"created"`
	ExtraIPv4 []netip.Prefix `json:"extra_ipv4_cidrs"`
}

type networkVersionQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readNetworkVersion(ctx context.Context, query networkVersionQuery, orgID string) (networkVersion, error) {
	var version networkVersion
	var created int64
	var extra string
	err := query.QueryRowContext(ctx, "SELECT revision,prefix,actor,created,extra_ipv4 FROM tenant_network_versions WHERE org_id=?", orgID).Scan(&version.Revision, &version.Prefix, &version.Actor, &created, &extra)
	if errors.Is(err, sql.ErrNoRows) {
		return networkVersion{Actor: "system:allocation"}, nil
	}
	version.Created = time.Unix(0, created).UTC()
	if err == nil {
		err = json.Unmarshal([]byte(extra), &version.ExtraIPv4)
	}
	return version, err
}

// updateAdditionalNetworksTx 保留所有历史范围，避免仍在线的旧 IP 被另一个租户重新分配。
func updateAdditionalNetworksTx(ctx context.Context, transaction *sql.Tx, orgID string, extra []netip.Prefix, actor string, now time.Time) error {
	version, err := readNetworkVersion(ctx, transaction, orgID)
	if err != nil {
		return err
	}
	if slices.Equal(version.ExtraIPv4, extra) {
		return nil
	}
	if version.Revision >= state.MaxAddressRevision {
		return state.ErrAddressConflict
	}
	for _, prefix := range append(slices.Clone(version.ExtraIPv4), extra...) {
		if _, err := transaction.ExecContext(ctx, "INSERT OR IGNORE INTO tenant_network_reservations(org_id,prefix) VALUES (?,?)", orgID, prefix.String()); err != nil {
			return err
		}
	}
	document, err := json.Marshal(extra)
	if err != nil {
		return err
	}
	result, err := transaction.ExecContext(ctx, "UPDATE tenant_network_versions SET extra_ipv4=?,revision=revision+1,actor=?,created=? WHERE org_id=?", string(document), actor, now.UnixNano(), orgID)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return state.ErrAddressConflict
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO tenant_network_history(org_id,revision,prefix,actor,created,extra_ipv4)
		SELECT org_id,revision,prefix,actor,created,extra_ipv4 FROM tenant_network_versions WHERE org_id=?`, orgID)
	return err
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
	return registry.validateNetworks(ctx, orgID, prefix, nil)
}

func (registry *PlanRegistry) validateNetworks(ctx context.Context, orgID string, prefix netip.Prefix, extra []netip.Prefix) error {
	transaction, err := registry.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	used, err := registry.usedNetworksTx(ctx, transaction, orgID)
	if err != nil {
		return err
	}
	for _, candidate := range append([]netip.Prefix{prefix}, extra...) {
		for _, other := range used {
			if candidate.Overlaps(other) {
				return ErrNetworkConflict
			}
		}
	}
	_, err = netspace.NormalizeAdditionalPrefixes(prefix, extra, registry.cfg.Reserved)
	if err != nil {
		return orgInvalidf("%v", err)
	}
	return nil
}
