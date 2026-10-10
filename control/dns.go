package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// DNSProvider writes records to the tailnet's public authoritative DNS zone.
//
// It exists for ACME DNS-01: the control plane is not an authoritative
// nameserver, so the challenge record a client submits through
// /machine/set-dns has to reach the zone a public certificate authority
// resolves.
type DNSProvider interface {
	// PutTXT creates or replaces the TXT record at name.
	PutTXT(ctx context.Context, name, value string) error
	// DeleteTXT removes the TXT record at name. Removing a missing record is
	// not an error.
	DeleteTXT(ctx context.Context, name string) error
}

// acmeChallengePrefix is the label ACME DNS-01 challenges live under.
const acmeChallengePrefix = "_acme-challenge."

// certChallengeTTL is how long a DNS-01 challenge record is kept before the
// janitor removes it from the internal table and the public zone. Certificate
// authorities read the record within minutes; a day is ample slack.
const certChallengeTTL = 24 * time.Hour

// normalizeCertDomains lowercases, trims and de-duplicates configured
// certificate domains, rejecting malformed names.
func normalizeCertDomains(domains []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, d := range domains {
		d = strings.Trim(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" {
			continue
		}
		if strings.Contains(d, "_acme-challenge.") || strings.Contains(d, " ") || !strings.Contains(d, ".") {
			return nil, fmt.Errorf("control: invalid certificate domain %q", d)
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	slices.Sort(out)
	return out, nil
}

// certDomainsFor returns the DNS names a node may obtain certificates for:
// its own MagicDNS FQDN plus the operator's extra certificate domains. It
// returns nil when no DNS provider is configured, which is what makes clients
// report "certificates not supported" instead of starting an impossible
// challenge.
func (s *Server) certDomainsFor(node state.Node) []string {
	if s.cfg.DNSProvider == nil {
		return nil
	}
	var out []string
	if domain := strings.Trim(s.cfg.Domain, "."); domain != "" {
		out = append(out, strings.TrimSuffix(node.FQDN(domain), "."))
	}
	out = append(out, s.certDomains...)
	slices.Sort(out)
	return slices.Compact(out)
}

// certDomainAllowed reports whether name is the ACME challenge name of one of
// the node's certificate domains.
func (s *Server) certDomainAllowed(node state.Node, name string) bool {
	base, ok := strings.CutPrefix(name, acmeChallengePrefix)
	if !ok {
		return false
	}
	return slices.Contains(s.certDomainsFor(node), base)
}

// isACMEChallengeName reports whether name is a DNS-01 challenge record.
func isACMEChallengeName(name string) bool {
	return strings.HasPrefix(name, acmeChallengePrefix)
}

// parseResolvers turns configured resolver strings into wire resolvers.
//
// An entry is either an IP address or "IP:port"; the default port (53) is left
// implicit so that clients apply their own defaults.
func parseResolvers(entries []string) ([]*dnstype.Resolver, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	out := make([]*dnstype.Resolver, 0, len(entries))
	for _, entry := range entries {
		addr, err := parseResolverAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("control: nameserver %q: %w", entry, err)
		}
		out = append(out, &dnstype.Resolver{Addr: addr})
	}
	return out, nil
}

func parseResolverAddr(entry string) (string, error) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return "", fmt.Errorf("empty resolver")
	}

	if ap, err := netip.ParseAddrPort(entry); err == nil {
		return ap.String(), nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return "", fmt.Errorf("not an IP address or IP:port")
	}
	return addr.String(), nil
}

// parseDNSRoutes validates the split-DNS table.
func parseDNSRoutes(routes map[string][]string) (map[string][]*dnstype.Resolver, error) {
	if len(routes) == 0 {
		return nil, nil
	}

	out := make(map[string][]*dnstype.Resolver, len(routes))
	for suffix, entries := range routes {
		suffix, err := state.NormalizeDNSRecordName(suffix)
		if err != nil {
			return nil, fmt.Errorf("control: DNS route %q: %w", suffix, err)
		}
		resolvers, err := parseResolvers(entries)
		if err != nil {
			return nil, fmt.Errorf("control: DNS route %q: %w", suffix, err)
		}
		if len(resolvers) == 0 {
			// An empty resolver list means "handle this suffix with
			// MagicDNS"; that is meaningful, so keep it.
			out[suffix] = nil
			continue
		}
		out[suffix] = resolvers
	}
	return out, nil
}

// handleSetDNS implements POST /machine/set-dns inside a Noise session.
//
// Clients use it for two things:
//
//   - ACME DNS-01 challenges ("_acme-challenge.<cert domain>"), which must
//     reach the public authoritative DNS zone through the configured
//     [DNSProvider], because that is where a certificate authority looks.
//   - Ordinary records under the tailnet's MagicDNS domain, which are stored
//     and published to every client through MapResponse.DNSConfig.ExtraRecords.
func (ns *noiseServer) handleSetDNS(w http.ResponseWriter, req *http.Request) {
	var setReq tailcfg.SetDNSRequest
	if err := json.NewDecoder(req.Body).Decode(&setReq); err != nil {
		httpError(w, err)
		return
	}

	if ns.rejectUnsupported(w, setReq.Version, setReq.NodeKey) {
		return
	}

	node, err := ns.getAndValidateNode(tailcfg.MapRequest{
		NodeKey: setReq.NodeKey,
	})
	if err != nil {
		httpError(w, err)
		return
	}

	record, err := ns.server.dnsRecordFromRequest(node, setReq)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), err))
		return
	}
	if err := ns.server.checkDNSRecordBudget(record); err != nil {
		httpError(w, NewHTTPError(http.StatusTooManyRequests, err.Error(), err))
		return
	}
	if err := ns.server.store.UpsertDNSRecord(record); err != nil {
		if errors.Is(err, state.ErrDNSDeviceName) || errors.Is(err, state.ErrDNSNameConflict) {
			httpError(w, NewHTTPError(http.StatusConflict, "DNS name is managed by a device or service", nil))
			return
		}
		httpError(w, err)
		return
	}

	// An ACME challenge is only useful once the public zone carries it: fail
	// the request (the client retries) rather than pretending success.
	if isACMEChallengeName(record.Name) && ns.server.cfg.DNSProvider != nil {
		ctx, cancel := context.WithTimeout(req.Context(), 20*time.Second)
		defer cancel()
		if err := ns.server.cfg.DNSProvider.PutTXT(ctx, record.Name, record.Value); err != nil {
			ns.server.log.Error("publishing ACME challenge record",
				"node_id", int(node.ID), "name", record.Name, "err", err)
			httpError(w, NewHTTPError(http.StatusBadGateway,
				"could not publish the DNS-01 challenge to the public zone", err))
			return
		}
	}

	ns.server.log.Info("stored DNS record",
		"node_id", int(node.ID),
		"name", record.Name,
		"type", record.Type,
		"record_id", record.ID)

	// The record value is not copied into the audit log: a TXT record may
	// carry an ACME challenge secret.
	ns.server.audit(nodeActor(node), identity.AuditDNSRecordSet,
		fmt.Sprintf("dns:%s/%s", record.Name, record.Type),
		fmt.Sprintf("published record %d", record.ID))

	// The new record has to reach every connected client, not just this one.
	ns.server.notifyWatchers()

	writeJSON(w, http.StatusOK, tailcfg.SetDNSResponse{})
}

// dnsRecordFromRequest validates a client's record request against the
// tailnet's MagicDNS domain and converts it to a stored record.
func (s *Server) dnsRecordFromRequest(node state.Node, req tailcfg.SetDNSRequest) (*state.DNSRecord, error) {
	name, err := state.NormalizeDNSRecordName(req.Name)
	if err != nil {
		return nil, err
	}
	recordType, err := state.NormalizeDNSRecordType(req.Type)
	if err != nil {
		return nil, err
	}
	if len(req.Value) > maxDNSRecordValueLength {
		return nil, fmt.Errorf("control: DNS record value is longer than %d bytes", maxDNSRecordValueLength)
	}

	if isACMEChallengeName(name) {
		// A DNS-01 challenge is authority for its exact certificate domain
		// only: a node may not answer challenges for names it was not
		// offered, and the record is never published to MagicDNS.
		if !s.certDomainAllowed(node, name) {
			return nil, fmt.Errorf("control: node %d is not allowed to answer challenges for %q", node.ID, name)
		}
	} else if err := s.checkRecordNameInDomain(name); err != nil {
		// Ordinary records must stay under the tailnet's own MagicDNS
		// suffix: otherwise any node could inject records for arbitrary
		// domains into every client's resolver.
		return nil, err
	}

	return &state.DNSRecord{
		Name:   name,
		Type:   recordType,
		Value:  req.Value,
		NodeID: node.ID,
	}, nil
}

// maxDNSRecordValueLength bounds a stored record value. ACME DNS-01 challenge
// values are 43 characters; the limit leaves room for other record types while
// keeping one node from filling the database.
const maxDNSRecordValueLength = 4096

// checkRecordNameInDomain reports whether name lives under the tailnet's
// MagicDNS domain.
func (s *Server) checkRecordNameInDomain(name string) error {
	domain := strings.Trim(s.cfg.Domain, ".")
	if domain == "" {
		return fmt.Errorf("control: this tailnet has no MagicDNS domain configured")
	}
	if name != domain && !strings.HasSuffix(name, "."+domain) {
		return fmt.Errorf("control: record name %q is outside the tailnet domain %q", name, domain)
	}
	return nil
}

// maxDNSRecords bounds how many records the control plane will publish, so a
// single misbehaving client cannot make every netmap unbounded.
const maxDNSRecords = 512

// checkDNSRecordBudget reports whether another record may be published. Repeats
// of an existing record are always allowed: they cost no extra space.
func (s *Server) checkDNSRecordBudget(record *state.DNSRecord) error {
	for _, existing := range s.store.ListDNSRecords() {
		if existing.Name == record.Name && existing.Type == record.Type && existing.Value == record.Value {
			return nil
		}
	}
	if got := len(s.store.ListDNSRecords()); got >= maxDNSRecords {
		return fmt.Errorf("control: DNS record limit (%d) reached", maxDNSRecords)
	}
	return nil
}
