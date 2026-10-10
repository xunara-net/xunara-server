// Package netspace is the Network Allocation Service's addressing rules: which
// IPv4 ranges a tenant's tailnet may use, and how a deployment hands each
// tenant its own block (PROJECT_SPEC section 54).
//
// It is a leaf package on purpose. It holds no state and reads no
// configuration: the caller supplies the deployment's pool and its internal
// reserved ranges, so the same validation serves the console, the platform API
// and the state store's allocator.
package netspace

import (
	"errors"
	"fmt"
	"net/netip"
)

// DefaultPool is the range a deployment hands tenant blocks out of, and
// DefaultBlockBits is the size of one block (/24: 254 usable addresses, enough
// for the largest built-in plan).
var (
	DefaultPool      = netip.MustParsePrefix("100.100.0.0/16")
	DefaultBlockBits = 24
)

// ErrNoBlock reports that the pool has no free block left.
var ErrNoBlock = errors.New("netspace: no free network block left")

// reservedIPv4 lists ranges a tenant may never use. It is the global half;
// callers add their own internal ranges (share masquerade addresses, a DERP
// host's own network, ...) through [ValidateTenantPrefix].
var reservedIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),          // "this network"
	netip.MustParsePrefix("127.0.0.0/8"),        // loopback
	netip.MustParsePrefix("169.254.0.0/16"),     // link-local
	netip.MustParsePrefix("192.0.0.0/24"),       // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),       // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),      // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"),    // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),     // TEST-NET-3
	netip.MustParsePrefix("224.0.0.0/4"),        // multicast
	netip.MustParsePrefix("240.0.0.0/4"),        // reserved, includes broadcast
	netip.MustParsePrefix("255.255.255.255/32"), // limited broadcast
}

// Reserved returns the ranges that are never available to a tenant. The
// returned slice is a copy: callers may append their own ranges to it.
func Reserved() []netip.Prefix {
	out := make([]netip.Prefix, len(reservedIPv4))
	copy(out, reservedIPv4)
	return out
}

// ValidateTenantPrefix reports whether p is a well-formed, allowed tailnet
// range for one tenant. extra lists additional ranges the deployment keeps for
// itself. The returned prefix is the canonical, masked form: 192.168.50.5/24
// is accepted and normalized to 192.168.50.0/24, because that is what a human
// typing into a form means.
func ValidateTenantPrefix(p netip.Prefix, extra []netip.Prefix) (netip.Prefix, error) {
	if !p.IsValid() {
		return netip.Prefix{}, errors.New("network range is required")
	}
	if p.Addr().Is6() {
		return netip.Prefix{}, errors.New("only IPv4 tailnet ranges can be customized")
	}
	masked := p.Masked()
	if masked.Addr().IsUnspecified() {
		return netip.Prefix{}, errors.New("network range must not be the unspecified address")
	}
	for _, reserved := range Reserved() {
		if masked.Overlaps(reserved) {
			return netip.Prefix{}, fmt.Errorf("network range %s is reserved (%s)", masked, reserved)
		}
	}
	for _, used := range extra {
		if !used.IsValid() {
			continue
		}
		if masked.Overlaps(used) {
			return netip.Prefix{}, fmt.Errorf("network range %s conflicts with a reserved range (%s)", masked, used.Masked())
		}
	}
	return masked, nil
}

// FirstOverlap returns the first range in others that overlaps p, if any. It
// is how the registry detects a range another tenant already holds.
func FirstOverlap(p netip.Prefix, others []netip.Prefix) (netip.Prefix, bool) {
	for _, other := range others {
		if !other.IsValid() {
			continue
		}
		if p.Overlaps(other) {
			return other.Masked(), true
		}
	}
	return netip.Prefix{}, false
}

// Pool is a deployment's range of tenant blocks, e.g. 100.100.0.0/16 carved
// into /24s. It is a value type and holds no allocation state: allocation is
// deterministic (lowest free block) so two instances sharing a registry agree.
type Pool struct {
	prefix netip.Prefix
	bits   int
}

// NewPool validates an IPv4 pool and bounds the number of candidate blocks.
func NewPool(prefix netip.Prefix, bits int) (Pool, error) {
	if !prefix.IsValid() || prefix.Addr().Is6() {
		return Pool{}, errors.New("netspace: pool must be an IPv4 range")
	}
	masked := prefix.Masked()
	if bits < masked.Bits() {
		return Pool{}, fmt.Errorf("netspace: block size /%d does not fit in pool %s", bits, masked)
	}
	if bits > 32 {
		return Pool{}, fmt.Errorf("netspace: IPv4 block size /%d exceeds /32", bits)
	}
	if _, err := ValidateTenantPrefix(masked, nil); err != nil {
		return Pool{}, fmt.Errorf("netspace: invalid pool: %w", err)
	}
	// 限制的是自动搜索成本，不是用户自定义 CIDR；移位前检查，兼容 32 位构建。
	if bits-masked.Bits() > 16 {
		return Pool{}, fmt.Errorf("netspace: pool %s holds too many blocks to search (maximum 65536)", masked)
	}
	return Pool{prefix: masked, bits: bits}, nil
}

// Prefix returns the pool's range.
func (p Pool) Prefix() netip.Prefix { return p.prefix }

// BlockBits returns the size of one block in prefix bits.
func (p Pool) BlockBits() int { return p.bits }

// Zero reports whether the pool was not configured. Callers treat it as "no
// automatic allocation", which is what a deployment that manages addresses by
// hand wants.
func (p Pool) Zero() bool { return !p.prefix.IsValid() }

// Blocks returns the number of blocks in the pool.
func (p Pool) Blocks() int {
	if p.Zero() {
		return 0
	}
	return 1 << (p.bits - p.prefix.Bits())
}

// Block returns the i-th block of the pool.
func (p Pool) Block(i int) (netip.Prefix, bool) {
	if i < 0 || i >= p.Blocks() {
		return netip.Prefix{}, false
	}
	offset := uint32(i) << (32 - p.bits)
	addr, ok := offsetAddr(p.prefix.Masked().Addr(), offset)
	if !ok {
		return netip.Prefix{}, false
	}
	block := netip.PrefixFrom(addr, p.bits)
	if !p.prefix.Contains(block.Addr()) {
		return netip.Prefix{}, false
	}
	return block, true
}

// Allocate returns the lowest block of the pool that overlaps nothing in
// reserved or used. It reports [ErrNoBlock] when the pool is exhausted.
func (p Pool) Allocate(reserved, used []netip.Prefix) (netip.Prefix, error) {
	if p.Zero() {
		return netip.Prefix{}, errors.New("netspace: no pool configured")
	}
	for i := 0; i < p.Blocks(); i++ {
		block, ok := p.Block(i)
		if !ok {
			break
		}
		taken := false
		for _, list := range [][]netip.Prefix{reserved, used} {
			for _, other := range list {
				if other.IsValid() && block.Overlaps(other) {
					taken = true
					break
				}
			}
			if taken {
				break
			}
		}
		if !taken {
			return block, nil
		}
	}
	return netip.Prefix{}, ErrNoBlock
}

// Contains reports whether q lies inside the pool.
func (p Pool) Contains(q netip.Prefix) bool {
	if p.Zero() || !q.IsValid() {
		return false
	}
	return p.prefix.Contains(q.Masked().Addr()) && p.bits >= q.Bits()
}

// offsetAddr adds an offset to an IPv4 base address.
func offsetAddr(base netip.Addr, offset uint32) (netip.Addr, bool) {
	if !base.Is4() {
		return netip.Addr{}, false
	}
	b := base.As4()
	value := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	sum := value + offset
	if sum < value {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)}), true
}
