package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"

	"github.com/xunara-net/xunara-server/netspace"
)

var (
	ErrAddressConflict     = errors.New("device address changed or allocation revision is stale")
	ErrAddressInUse        = errors.New("device address is already in use")
	ErrAddressInvalid      = errors.New("device address is invalid")
	ErrAddressNodeNotFound = errors.New("device address owner not found")
)

const MaxAddressRevision uint64 = 1<<53 - 1

type AddressConfiguration struct {
	IPv4           netip.Prefix
	IPv6           netip.Prefix
	SourceRevision uint64
}

type addressQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func AddressConfigurationTx(ctx context.Context, query addressQuery) (AddressConfiguration, error) {
	var configuration AddressConfiguration
	var ipv4, ipv6 string
	if err := query.QueryRowContext(ctx, "SELECT ipv4, ipv6, source_revision FROM address_configuration WHERE id=1").Scan(&ipv4, &ipv6, &configuration.SourceRevision); err != nil {
		return configuration, err
	}
	var err error
	configuration.IPv4, err = netip.ParsePrefix(ipv4)
	if err != nil || !configuration.IPv4.Addr().Is4() || configuration.IPv4 != configuration.IPv4.Masked() || configuration.IPv4.Bits() == 0 {
		return AddressConfiguration{}, errors.New("stored IPv4 allocation range is invalid")
	}
	configuration.IPv6, err = netip.ParsePrefix(ipv6)
	if err != nil || !configuration.IPv6.Addr().Is6() || configuration.IPv6 != configuration.IPv6.Masked() || configuration.IPv6.Bits() == 0 || configuration.SourceRevision > MaxAddressRevision {
		return AddressConfiguration{}, errors.New("stored IPv6 allocation range is invalid")
	}
	return configuration, nil
}

func (store *SQLiteStore) AddressConfiguration(ctx context.Context) (AddressConfiguration, error) {
	return AddressConfigurationTx(ctx, store.db)
}

// ApplyAddressConfigurationTx 不覆盖旧设备；旧版本不能将已生效的分配范围倒退。
func ApplyAddressConfigurationTx(ctx context.Context, transaction *sql.Tx, next AddressConfiguration) (bool, error) {
	current, err := AddressConfigurationTx(ctx, transaction)
	if err != nil {
		return false, err
	}
	if next.SourceRevision > MaxAddressRevision || next.SourceRevision < current.SourceRevision {
		return false, ErrAddressConflict
	}
	if current.SourceRevision > 0 && next.SourceRevision == current.SourceRevision && (next.IPv4 != current.IPv4 || next.IPv6 != current.IPv6) {
		return false, ErrAddressConflict
	}
	for _, entry := range []struct {
		prefix netip.Prefix
		family string
	}{{next.IPv4, "IPv4"}, {next.IPv6, "IPv6"}} {
		if err := validateAddressPrefix(entry.prefix, entry.family); err != nil {
			return false, err
		}
	}
	if current == next {
		return false, nil
	}
	for _, entry := range []struct {
		previous, next netip.Prefix
		counter        string
	}{
		{current.IPv4, next.IPv4, counterNextIPv4Offset}, {current.IPv6, next.IPv6, counterNextIPv6Offset},
	} {
		if entry.previous != entry.next {
			if _, err := transaction.ExecContext(ctx, "INSERT INTO counters(name,value) VALUES (?,1) ON CONFLICT(name) DO UPDATE SET value=1", entry.counter); err != nil {
				return false, err
			}
		}
	}
	_, err = transaction.ExecContext(ctx, "UPDATE address_configuration SET ipv4=?,ipv6=?,source_revision=? WHERE id=1", next.IPv4.String(), next.IPv6.String(), next.SourceRevision)
	return err == nil, err
}

// ChangeNodeIPv4Tx 只改地址列，避免覆盖同时上报的 endpoints、密钥或路由。
func ChangeNodeIPv4Tx(ctx context.Context, transaction *sql.Tx, id NodeID, stableID string, expected, address netip.Addr) (Node, error) {
	node, err := scanNode(transaction.QueryRowContext(ctx, "SELECT "+nodeColumns+" FROM nodes WHERE id=? AND stable_id=?", id, stableID))
	if errors.Is(err, sql.ErrNoRows) {
		return Node{}, ErrAddressNodeNotFound
	}
	if err != nil {
		return Node{}, err
	}
	if node.IPv4 != expected {
		return Node{}, ErrAddressConflict
	}
	configuration, err := AddressConfigurationTx(ctx, transaction)
	if err != nil {
		return Node{}, err
	}
	if err := netspace.ValidateNodeIPv4(address, configuration.IPv4); err != nil {
		return Node{}, fmt.Errorf("%w: %v", ErrAddressInvalid, err)
	}
	var occupied int
	err = transaction.QueryRowContext(ctx, "SELECT 1 FROM nodes WHERE ipv4=? AND id<>? LIMIT 1", address.String(), id).Scan(&occupied)
	if err == nil {
		return Node{}, ErrAddressInUse
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Node{}, err
	}
	if _, err := transaction.ExecContext(ctx, "UPDATE nodes SET ipv4=? WHERE id=?", address.String(), id); err != nil {
		return Node{}, err
	}
	node.IPv4 = address
	return node, nil
}
