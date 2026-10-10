package control

import (
	"strings"

	"github.com/xunara-net/xunara-server/state"
)

// Xunara Share: cross-organization service discovery (PROJECT_SPEC section 47).
//
// A service whose declaration sets `shared` is projected into the MagicDNS of
// the users who accepted a share of the advertising node. The projected record
// name is "<service>-<source-org>" and the address is this organization's own
// masquerade address for the foreign node, so no source-organization address,
// ID or tag ever reaches the consumer's netmap. Discovery only: the ACL rules
// of both organizations still decide who may connect (section 38.5).

// sharedServiceDNSRecordsFor returns the MagicDNS records one node sees for
// the shared services of foreign machines. The result is empty unless this
// organization has sharing enabled, this node is not under tailnet lock, and
// the node's user accepted a share of the advertising machine.
//
// Everything here is fail-closed: an unknown organization, a source under
// tailnet lock, a machine that is gone, an unhealthy service or a name that
// collides with a local one all contribute no record - never a widened name.
func (s *Server) sharedServiceDNSRecordsFor(self state.Node) []state.DNSRecord {
	if !s.sharingEnabled() || self.Tags != nil || s.TKAStatus().Enabled {
		return nil
	}
	orgID := s.Organization().ID
	if orgID == "" {
		return nil
	}
	domain := strings.Trim(s.cfg.Domain, ".")
	if domain == "" {
		return nil
	}

	taken := s.localDNSNames(domain)
	var out []state.DNSRecord

	for _, share := range s.shares.ListShares(ShareFilter{
		TargetOrg:  orgID,
		TargetUser: int64(self.UserID),
		Statuses:   []string{ShareAccepted},
	}) {
		source := s.shareDir.Org(share.SourceOrg)
		if source == nil || source.ShareTKAEnabled() {
			continue
		}
		node, ok := source.ShareNode(state.NodeID(share.SourceNode))
		if !ok {
			continue
		}
		masqV4, masqV6, err := s.store.EnsureShareAddress(share.SourceOrg, shareNodeKey(node))
		if err != nil {
			s.log.Warn("sharing: reserving the masquerade address for shared services",
				"org", share.SourceOrg, "err", err)
			continue
		}
		// The foreign machine's own MagicDNS name outranks its services.
		taken[strings.ToLower(strings.TrimSuffix(node.FQDN(domain), "."))] = true
		for _, svc := range source.ShareServices(node.ID) {
			if !svc.Shared || svc.EffectiveHealth() == state.ServiceHealthUnhealthy {
				continue
			}
			name := strings.ToLower(shareHostname(svc.Name, share.SourceOrg) + "." + domain)
			if taken[name] {
				// A local name (or an earlier foreign service) already owns
				// this name: skip the projection, never shadow what the
				// organization resolved before.
				continue
			}
			taken[name] = true
			if masqV4.IsValid() {
				out = append(out, state.DNSRecord{Name: name, Type: "A", Value: masqV4.String()})
			}
			if masqV6.IsValid() {
				out = append(out, state.DNSRecord{Name: name, Type: "AAAA", Value: masqV6.String()})
			}
		}
	}
	return out
}

// localDNSNames collects every MagicDNS name this organization already
// resolves without sharing: node names, administrator records and Atlas
// service names. A projected foreign name that would collide with any of them
// is skipped, so cross-organization discovery can never shadow a local name.
func (s *Server) localDNSNames(domain string) map[string]bool {
	taken := make(map[string]bool)
	for _, node := range s.store.ListNodes() {
		taken[strings.ToLower(strings.TrimSuffix(node.FQDN(domain), "."))] = true
	}
	for _, record := range s.store.ListDNSRecords() {
		if isACMEChallengeName(record.Name) {
			continue
		}
		taken[strings.ToLower(strings.TrimSuffix(record.FQDN(), "."))] = true
	}
	for _, svc := range s.store.ListServices() {
		taken[strings.ToLower(svc.Name+"."+domain)] = true
	}
	return taken
}
