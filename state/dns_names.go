package state

import (
	"errors"
	"fmt"
	"strings"

	"tailscale.com/util/dnsname"
)

var (
	ErrDNSNameConflict = errors.New("DNS name is already owned by another resource")
	ErrDNSDeviceName   = errors.New("DNS name is managed by a device")
	ErrDNSDomainChange = errors.New("configured DNS domain differs from the persisted namespace")
)

func NormalizeDNSDomain(domain string) (string, error) {
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	if domain == "" {
		return "", nil
	}
	if err := dnsname.ValidHostname(domain); err != nil {
		return "", fmt.Errorf("state: invalid DNS domain: %w", err)
	}
	if len(domain) > maxDNSNameLength-2 {
		return "", fmt.Errorf("state: DNS domain leaves no room for a device label")
	}
	return domain, nil
}

func defaultDNSLabel(node Node) string {
	label := dnsname.SanitizeHostname(node.Hostname)
	if label == "" {
		label = fmt.Sprintf("node-%d", node.ID)
	}
	if len(label) > maxDNSLabelLength {
		label = strings.TrimRight(label[:maxDNSLabelLength], "-")
	}
	return label
}

func dnsLabelLimit(domain string) int {
	if domain == "" {
		return maxDNSLabelLength
	}
	return min(maxDNSLabelLength, maxDNSNameLength-len(domain)-1)
}

func validateDNSLabel(label, domain string) error {
	if err := dnsname.ValidLabel(label); err != nil {
		return fmt.Errorf("state: invalid assigned DNS label: %w", err)
	}
	if len(label) > dnsLabelLimit(domain) {
		return fmt.Errorf("state: assigned DNS name exceeds the wire name limit")
	}
	return nil
}

// 分配与归属读取必须在调用方的同一个写事务或 MemoryStore 锁内完成。
func allocateDNSLabel(node Node, domain string, owners map[string]string) (string, error) {
	base := defaultDNSLabel(node)
	limit := dnsLabelLimit(domain)
	if len(base) > limit {
		base = strings.TrimRight(base[:limit], "-")
	}
	if base == "" {
		base = "n"
	}
	if _, taken := owners[base]; !taken {
		return base, nil
	}
	for attempt := 0; attempt < 4096; attempt++ {
		suffix := fmt.Sprintf("-%d", node.ID)
		if attempt != 0 {
			suffix += fmt.Sprintf("-%d", attempt)
		}
		if len(suffix) >= limit {
			break
		}
		prefix := strings.TrimRight(base[:min(len(base), limit-len(suffix))], "-")
		if prefix == "" {
			prefix = "n"
		}
		candidate := prefix + suffix
		if _, taken := owners[candidate]; !taken {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("%w: no available device label", ErrDNSNameConflict)
}

func recordDNSLabel(name, domain string) string {
	if domain == "" {
		return ""
	}
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	label, found := strings.CutSuffix(name, "."+domain)
	if !found || label == "" || strings.Contains(label, ".") {
		return ""
	}
	return label
}

// 同一记录名可有多个 A/AAAA 或挑战值，但不同资源不能共同占用一个设备名。
func dnsNameOwners(nodes []Node, services []Service, records []DNSRecord, domain string, excludeNode, excludeServices NodeID) (map[string]string, error) {
	owners := make(map[string]string)
	claim := func(label, owner string) error {
		if previous, found := owners[label]; found && previous != owner {
			return fmt.Errorf("%w: %s", ErrDNSNameConflict, label)
		}
		owners[label] = owner
		return nil
	}
	for _, node := range nodes {
		if node.ID == excludeNode {
			continue
		}
		label := node.DNSName
		if label == "" {
			label = defaultDNSLabel(node)
		}
		if err := validateDNSLabel(label, domain); err != nil {
			return nil, err
		}
		if err := claim(label, fmt.Sprintf("node:%d", node.ID)); err != nil {
			return nil, err
		}
	}
	for _, service := range services {
		if excludeServices != 0 && service.NodeID == excludeServices {
			continue
		}
		if err := claim(strings.ToLower(service.Name), fmt.Sprintf("service:%d", service.NodeID)); err != nil {
			return nil, err
		}
	}
	for _, record := range records {
		if label := recordDNSLabel(record.Name, domain); label != "" {
			if err := claim(label, "record"); err != nil {
				return nil, err
			}
		}
	}
	return owners, nil
}

func checkRecordDNSName(name, domain string, owners map[string]string) error {
	owner := owners[recordDNSLabel(name, domain)]
	if strings.HasPrefix(owner, "node:") {
		return ErrDNSDeviceName
	}
	if strings.HasPrefix(owner, "service:") {
		return ErrDNSNameConflict
	}
	return nil
}
