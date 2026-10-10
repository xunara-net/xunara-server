package state

import "context"

func (store *MemoryStore) dnsNameOwnersLocked(excludeNode, excludeServices NodeID) (map[string]string, error) {
	var nodes []Node
	for _, node := range store.byID {
		nodes = append(nodes, node)
	}
	var services []Service
	for _, service := range store.services {
		services = append(services, service)
	}
	var records []DNSRecord
	for _, record := range store.dns {
		records = append(records, record)
	}
	return dnsNameOwners(nodes, services, records, store.dnsDomain, excludeNode, excludeServices)
}

func (store *MemoryStore) ConfigureDNSDomain(ctx context.Context, domain string) error {
	domain, err := NormalizeDNSDomain(domain)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.dnsDomain != "" && store.dnsDomain != domain {
		return ErrDNSDomainChange
	}
	previous := store.dnsDomain
	store.dnsDomain = domain
	if _, err := store.dnsNameOwnersLocked(0, 0); err != nil {
		store.dnsDomain = previous
		return err
	}
	for id, node := range store.byID {
		if node.DNSName == "" {
			node.DNSName = defaultDNSLabel(node)
			store.byID[id] = node
		}
	}
	return nil
}
