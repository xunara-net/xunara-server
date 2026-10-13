package netspace

import (
	"errors"
	"net/netip"
	"slices"
)

const MaxAdditionalIPv4Ranges = 32

// NormalizeAdditionalPrefixes 允许多个三层地址池，但不允许池内重复/重叠分配。
// 主池仍由原校验链负责；旧默认 /10 不会因为本次升级被误判为非法。
func NormalizeAdditionalPrefixes(primary netip.Prefix, additional, reserved []netip.Prefix) ([]netip.Prefix, error) {
	if len(additional) > MaxAdditionalIPv4Ranges {
		return nil, errors.New("too many additional IPv4 ranges (maximum 32)")
	}
	result := make([]netip.Prefix, 0, len(additional))
	for _, entry := range additional {
		prefix, err := ValidateTailnetPrefix(entry, reserved)
		if err != nil {
			return nil, err
		}
		if prefix.Overlaps(primary) {
			return nil, errors.New("additional range overlaps the default range")
		}
		if _, overlap := FirstOverlap(prefix, result); overlap {
			return nil, errors.New("additional IPv4 ranges overlap")
		}
		result = append(result, prefix)
	}
	slices.SortFunc(result, func(first, second netip.Prefix) int { return first.Addr().Compare(second.Addr()) })
	return result, nil
}
