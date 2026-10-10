package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/policy"
	"github.com/xunara-net/xunara-server/state"
)

// This file implements Xunara Atlas service discovery: the services a node
// advertises about itself over the native client protocol
// (POST /api/agent/v1/services).
//
// The official client protocol is untouched: an official client discovers a
// service through MagicDNS (the A/AAAA records this file feeds into the
// netmap) and connects to it under the existing ACL rules. Discovery is not
// authorization: publishing a name grants nothing, and the endpoints are
// never proxied by the control plane.
//
// The node is the only writer (the same boundary as device posture
// attributes): the platform surfaces are read-only, so a compromised admin
// credential cannot make a node look like it hosts a service it does not.

const (
	// maxServicesPerNode bounds how many services one node may advertise.
	maxServicesPerNode = 32
	// maxServicesPerOrg bounds the whole registry. Every service becomes
	// MagicDNS records on every netmap, so the registry is bounded in the
	// organization, not only per node.
	maxServicesPerOrg = 512
	// maxServiceNameLen bounds a service name. Names are DNS labels: they
	// become <name>.<domain> in MagicDNS.
	maxServiceNameLen = 63
	// maxServiceMetadataEntries bounds one service's metadata map.
	maxServiceMetadataEntries = 16
	// maxServiceMetadataKeyLen bounds a metadata key (same shape as device
	// attribute names: printable ASCII without spaces).
	maxServiceMetadataKeyLen = 64
	// maxServiceMetadataValueLen bounds a metadata value.
	maxServiceMetadataValueLen = 256
	// maxServiceMetadataBytes bounds the encoded metadata of one service.
	maxServiceMetadataBytes = 2 << 10
)

// agentServicesRequest is the body of POST /api/agent/v1/services. The list is
// the node's complete set: names left out are withdrawn.
type agentServicesRequest struct {
	agentRequest
	Services []agentService `json:"services"`
}

// agentService is one advertised service as the client sends it.
type agentService struct {
	Name     string            `json:"name"`
	Protocol string            `json:"protocol"`
	Port     uint32            `json:"port"`
	Metadata map[string]string `json:"metadata,omitempty"`
	// Visibility narrows which nodes may discover the service through
	// MagicDNS (section 46): ACL source selectors resolved against the node
	// that publishes it. Empty means the whole organization.
	Visibility []string `json:"visibility,omitempty"`
	// VisibilityFromACL derives discovery from the ACL instead of the
	// selector list (section 48): a node sees the service exactly when the
	// packet filter lets it connect on this protocol and port. It cannot be
	// combined with Visibility.
	VisibilityFromACL bool `json:"visibilityFromACL,omitempty"`
	// Health opts the service into readiness reporting (section 26). Without
	// it the service is always discoverable, exactly as before health
	// reporting existed.
	Health bool `json:"health,omitempty"`
	// Shared marks the service for cross-organization discovery (section 47):
	// users who accepted a share of this node also see it, under
	// "<name>-<source-org>". Health and visibility still apply on the source
	// side, and reachability is still decided by the ACL rules alone.
	Shared bool `json:"shared,omitempty"`
}

// serviceView is the JSON shape of a stored service on every read surface.
type serviceView struct {
	Name     string            `json:"name"`
	Protocol string            `json:"protocol"`
	Port     uint16            `json:"port"`
	Metadata map[string]string `json:"metadata,omitempty"`
	// Visibility lists the selectors that may discover the service; ["*"] is
	// the default (the whole organization).
	Visibility []string `json:"visibility"`
	// VisibilityFromACL reports whether discovery follows the ACL instead of
	// the selector list.
	VisibilityFromACL bool `json:"visibilityFromACL"`
	// Shared reports whether the service is projected into the MagicDNS of
	// organizations whose users accepted a share of the advertising node.
	Shared   bool   `json:"shared"`
	NodeID   uint64 `json:"nodeId"`
	StableID string `json:"stableId"`
	Hostname string `json:"hostname"`
	// DNSName is the MagicDNS name the service is reachable under, when the
	// deployment has a domain configured.
	DNSName string `json:"dnsName,omitempty"`
	// Health is "healthy" or "unhealthy" for services whose declaration
	// enabled readiness reporting; it is omitted for untracked services,
	// which are always discoverable.
	Health string `json:"health,omitempty"`
	// HealthReportedAt is when the node last reported readiness. Zero (and
	// therefore omitted) when it never did.
	HealthReportedAt time.Time `json:"healthReportedAt,omitzero"`
	// Created and Updated mirror the store's bookkeeping.
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
}

// agentServicesResponse is the answer to a publish: the stored set.
type agentServicesResponse struct {
	Services []serviceView `json:"services"`
}

// handleAgentServices implements POST /api/agent/v1/services: a node replaces
// the set of services it advertises.
func (s *Server) handleAgentServices(w http.ResponseWriter, req *http.Request) {
	var body agentServicesRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, "invalid JSON body", nil))
		return
	}

	node, _, err := s.authenticateAgent(req, body.agentRequest)
	if err != nil {
		httpError(w, err)
		return
	}

	services, err := s.normalizeAgentServices(body.Services)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), nil))
		return
	}

	// A node's declaration is reconciled: an agent may re-publish it on a
	// timer to repair a control plane that lost the record. A publish that
	// already matches the store is therefore in effect and must not rewrite
	// rows, append an audit event or wake every netmap stream; everything
	// below this point is a real change.
	current, err := s.store.ServicesForNode(node.ID)
	if err != nil {
		s.log.Error("reading services", "node", node.StableID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	if sameServiceSet(current, services) {
		writeJSON(w, http.StatusOK, agentServicesResponse{Services: s.serviceViews(node, current)})
		return
	}

	if err := s.checkServiceBudget(node, services); err != nil {
		httpError(w, NewHTTPError(http.StatusTooManyRequests, err.Error(), nil))
		return
	}

	if err := s.store.ReplaceNodeServices(node.ID, services); err != nil {
		if errors.Is(err, state.ErrServiceNameTaken) || errors.Is(err, state.ErrDNSNameConflict) {
			// Another node claimed the name between the conflict check and the
			// write, or the store holds a name this instance did not see.
			httpError(w, NewHTTPError(http.StatusConflict, "a service name is already in use", nil))
			return
		}
		s.log.Error("storing services", "node", node.StableID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}

	s.audit(nodeActor(node), identity.AuditServicesUpdated, nodeTarget(node), servicesAuditDetail(services))
	// The service's MagicDNS records changed, so streaming sessions have a new
	// netmap to send.
	s.notifyNodePeers(node)

	stored, err := s.store.ServicesForNode(node.ID)
	if err != nil {
		s.log.Error("reading back services", "node", node.StableID, "err", err)
		stored = services
	}
	writeJSON(w, http.StatusOK, agentServicesResponse{Services: s.serviceViews(node, stored)})
}

// serviceViews renders a stored set for a response.
func (s *Server) serviceViews(node state.Node, services []state.Service) []serviceView {
	views := make([]serviceView, 0, len(services))
	for _, svc := range services {
		views = append(views, s.serviceView(svc, node))
	}
	return views
}

// visibilityOrDefault renders a stored visibility list: an empty value means
// the v1 default, the whole organization.
func visibilityOrDefault(visibility []string) []string {
	if len(visibility) == 0 {
		return []string{"*"}
	}
	return visibility
}

// sameServiceSet reports whether a declaration matches the stored set. A
// declaration is a set, not a list: order carries no meaning. Names are unique
// on both sides (the store enforces it, normalizeAgentServices enforces it),
// so comparing by name is unambiguous.
func sameServiceSet(stored, declared []state.Service) bool {
	if len(stored) != len(declared) {
		return false
	}
	byName := make(map[string]state.Service, len(stored))
	for _, svc := range stored {
		byName[svc.Name] = svc
	}
	for _, svc := range declared {
		other, ok := byName[svc.Name]
		if !ok {
			return false
		}
		if svc.Protocol != other.Protocol || svc.Port != other.Port || svc.Health != other.Health {
			return false
		}
		if svc.Shared != other.Shared {
			return false
		}
		if svc.VisibilityFromACL != other.VisibilityFromACL {
			return false
		}
		if !slices.Equal(svc.Visibility, other.Visibility) {
			return false
		}
		if !maps.Equal(svc.Metadata, other.Metadata) {
			return false
		}
	}
	return true
}

// normalizeAgentServices validates a published set and converts it to store
// records. Every rule is fail-closed: the whole publish fails rather than
// dropping or rewriting a service the node meant to advertise.
//
// Visibility selectors are checked against the policy document that is
// currently loaded, so a declaration naming an undeclared group or tag is
// refused instead of silently hiding the service. A deployment without a
// policy document has no groups or tags to name, so only the default (no
// selectors) is accepted there.
func (s *Server) normalizeAgentServices(services []agentService) ([]state.Service, error) {
	if len(services) > maxServicesPerNode {
		return nil, fmt.Errorf("at most %d services may be advertised per node", maxServicesPerNode)
	}

	engine := s.policy.Load()
	out := make([]state.Service, 0, len(services))
	seen := make(map[string]bool, len(services))
	for _, svc := range services {
		if err := validateServiceName(svc.Name); err != nil {
			return nil, err
		}
		if seen[svc.Name] {
			return nil, fmt.Errorf("service name %q is listed twice", svc.Name)
		}
		seen[svc.Name] = true

		protocol := strings.ToLower(strings.TrimSpace(svc.Protocol))
		if protocol != "tcp" && protocol != "udp" {
			return nil, fmt.Errorf("service %q has an unsupported protocol %q", svc.Name, svc.Protocol)
		}
		if svc.Port == 0 || svc.Port > 65535 {
			return nil, fmt.Errorf("service %q has an invalid port", svc.Name)
		}
		metadata, err := validateServiceMetadata(svc.Metadata)
		if err != nil {
			return nil, fmt.Errorf("service %q: %w", svc.Name, err)
		}
		visibility, err := policy.NormalizeServiceVisibility(svc.Visibility)
		if err != nil {
			return nil, fmt.Errorf("service %q: %w", svc.Name, err)
		}
		if len(visibility) > 0 {
			if engine == nil {
				return nil, fmt.Errorf("service %q: visibility selectors require a policy document", svc.Name)
			}
			if err := engine.ValidateServiceVisibility(visibility); err != nil {
				return nil, fmt.Errorf("service %q: %w", svc.Name, err)
			}
		}
		if svc.VisibilityFromACL && len(visibility) > 0 {
			return nil, fmt.Errorf("service %q: visibilityFromACL cannot be combined with visibility selectors", svc.Name)
		}

		out = append(out, state.Service{
			Name:              svc.Name,
			Protocol:          protocol,
			Port:              uint16(svc.Port),
			Visibility:        visibility,
			VisibilityFromACL: svc.VisibilityFromACL,
			Shared:            svc.Shared,
			Metadata:          metadata,
			Health:            svc.Health,
		})
	}
	return out, nil
}

// validateServiceName enforces the DNS label shape a service name must have.
// The name becomes a DNS name (<name>.<domain>), so anything that could not be
// resolved — uppercase, underscores, a leading digit-free label — is refused
// rather than silently sanitized into a different name.
func validateServiceName(name string) error {
	if name == "" {
		return fmt.Errorf("service name is empty")
	}
	if len(name) > maxServiceNameLen {
		return fmt.Errorf("service name is longer than %d bytes", maxServiceNameLen)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if i == 0 || i == len(name)-1 {
				return fmt.Errorf("service name %q must not start or end with a hyphen", name)
			}
		default:
			return fmt.Errorf("service name %q must be a lowercase DNS label", name)
		}
	}
	return nil
}

// validateServiceMetadata bounds and cleans one service's metadata. Keys and
// values are printable (no control characters), so the console and terminal
// surfaces cannot be made to render escape sequences.
func validateServiceMetadata(metadata map[string]string) (map[string]string, error) {
	if len(metadata) == 0 {
		return nil, nil
	}
	if len(metadata) > maxServiceMetadataEntries {
		return nil, fmt.Errorf("metadata has more than %d entries", maxServiceMetadataEntries)
	}

	out := make(map[string]string, len(metadata))
	for key, value := range metadata {
		if key == "" || len(key) > maxServiceMetadataKeyLen || !printableASCII(key, false) {
			return nil, fmt.Errorf("metadata key %q is invalid", sanitizeServiceName(key))
		}
		if len(value) > maxServiceMetadataValueLen || !printableASCII(value, true) {
			return nil, fmt.Errorf("metadata value of %q is invalid", sanitizeServiceName(key))
		}
		out[key] = value
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("metadata cannot be encoded")
	}
	if len(encoded) > maxServiceMetadataBytes {
		return nil, fmt.Errorf("metadata is larger than %d bytes", maxServiceMetadataBytes)
	}
	return out, nil
}

// printableASCII reports whether s is printable ASCII. Space is only allowed
// when allowSpace is set (values may read as prose; keys may not).
func printableASCII(s string, allowSpace bool) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
		if allowSpace && r == ' ' {
			continue
		}
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

// sanitizeServiceName makes an untrusted name safe to echo back in an error
// message: printable ASCII only, bounded.
func sanitizeServiceName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r > unicode.MaxASCII || (r < 0x21 && r != ' ') || r == 0x7f {
			continue
		}
		if b.Len() >= 64 {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// checkServiceBudget bounds the organization's registry. The node's own
// current services are replaced, so only other nodes' entries and the new set
// count towards the limit.
func (s *Server) checkServiceBudget(node state.Node, services []state.Service) error {
	counts, err := s.store.NodeServiceCounts()
	if err != nil {
		return fmt.Errorf("counting services: %w", err)
	}
	other := 0
	for id, count := range counts {
		if id != node.ID {
			other += count
		}
	}
	if other+len(services) > maxServicesPerOrg {
		return fmt.Errorf("service limit (%d) reached", maxServicesPerOrg)
	}
	return nil
}

// serviceView renders one stored service for the read surfaces.
func (s *Server) serviceView(svc state.Service, node state.Node) serviceView {
	view := serviceView{
		Name:              svc.Name,
		Protocol:          svc.Protocol,
		Port:              svc.Port,
		Metadata:          svc.Metadata,
		Visibility:        visibilityOrDefault(svc.Visibility),
		VisibilityFromACL: svc.VisibilityFromACL,
		Shared:            svc.Shared,
		NodeID:            uint64(node.ID),
		StableID:          node.StableID,
		Hostname:          node.Hostname,
		Created:           svc.Created,
		Updated:           svc.Updated,
	}
	if domain := strings.Trim(s.cfg.Domain, "."); domain != "" {
		view.DNSName = svc.Name + "." + domain
	}
	if svc.Health {
		view.Health = string(svc.EffectiveHealth())
		view.HealthReportedAt = svc.HealthReportedAt
	}
	return view
}

// servicesAuditDetail describes a publish for the audit log: which services
// are advertised, never their metadata (AGENTS.md section 8: metadata can
// carry identifiers, and the audit log is exported to webhooks).
func servicesAuditDetail(services []state.Service) string {
	if len(services) == 0 {
		return "withdrew all services"
	}
	names := make([]string, 0, len(services))
	for _, svc := range services {
		names = append(names, fmt.Sprintf("%s/%s:%d", svc.Name, svc.Protocol, svc.Port))
	}
	sort.Strings(names)
	return truncateClean("advertised "+strings.Join(names, ", "), maxAuditDetailsLen)
}

// serviceDNSRecordsFor renders the advertised services one node may discover
// as MagicDNS A/AAAA records pointing at the node that advertises them.
// Discovery through DNS is what makes a service usable by an official client,
// which resolves the name and connects under the existing ACL rules.
func (s *Server) serviceDNSRecordsFor(self state.Node) []state.DNSRecord {
	domain := strings.Trim(s.cfg.Domain, ".")
	if domain == "" {
		return nil
	}

	services := s.store.ListServices()
	visible := s.visibleServiceNames(self, services)
	s.filterACLDerivedServices(self, services, visible)
	var out []state.DNSRecord
	for _, svc := range services {
		if !visible[svc.Name] {
			continue
		}
		// A health-tracked service that is not (or no longer) ready is
		// withdrawn from discovery: no record, so clients stop resolving it.
		// This is discovery only; ACLs still decide who may connect.
		if svc.EffectiveHealth() == state.ServiceHealthUnhealthy {
			continue
		}
		node, ok := s.store.GetNodeByID(svc.NodeID)
		if !ok {
			// The node was deleted; the store cascade already dropped the
			// service, so this is a stale read.
			continue
		}
		name := svc.Name + "." + domain
		if node.IPv4.IsValid() {
			out = append(out, state.DNSRecord{Name: name, Type: "A", Value: node.IPv4.String(), NodeID: node.ID})
		}
		if node.IPv6.IsValid() {
			out = append(out, state.DNSRecord{Name: name, Type: "AAAA", Value: node.IPv6.String(), NodeID: node.ID})
		}
	}
	return out
}

// visibleServiceNames returns the advertised services self may discover
// (section 46). A node always discovers its own services, and a service that
// declared no selectors keeps the v1 default: the whole organization.
//
// Restricted services resolve through the policy document that is loaded
// now. Without a document there is nothing to resolve, so they stay visible
// only to their publisher (fail closed) rather than silently widening again.
func (s *Server) visibleServiceNames(self state.Node, services []state.Service) map[string]bool {
	engine := s.policy.Load()
	var nodes []state.Node

	out := make(map[string]bool, len(services))
	for _, svc := range services {
		switch {
		case svc.NodeID == self.ID, len(svc.Visibility) == 0:
			out[svc.Name] = true
		case engine == nil:
			// Fail closed: the selectors cannot be resolved.
		default:
			publisher, ok := s.store.GetNodeByID(svc.NodeID)
			if !ok {
				continue
			}
			if nodes == nil {
				nodes = s.store.ListNodes()
			}
			if engine.ServiceVisibility(nodes, publisher, svc.Visibility)[self.ID] {
				out[svc.Name] = true
			}
		}
	}
	return out
}

// agentServiceHealthRequest is the body of POST /api/agent/v1/services/health.
// The list is the node's complete readiness report for its health-tracked
// services: a tracked service left out is not ready (section 26).
type agentServiceHealthRequest struct {
	agentRequest
	Services []agentServiceHealth `json:"services"`
}

// agentServiceHealth is one service's reported readiness.
type agentServiceHealth struct {
	Name  string `json:"name"`
	Ready bool   `json:"ready"`
}

// handleAgentServiceHealth implements POST /api/agent/v1/services/health: a
// node reports the readiness of the services its declaration opted into
// ("health": true). The control plane never probes the endpoint itself; it
// only records what the node says and withdraws services whose reports stop.
func (s *Server) handleAgentServiceHealth(w http.ResponseWriter, req *http.Request) {
	var body agentServiceHealthRequest
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, "invalid JSON body", nil))
		return
	}

	node, _, err := s.authenticateAgent(req, body.agentRequest)
	if err != nil {
		httpError(w, err)
		return
	}

	reports, err := normalizeServiceHealth(body.Services)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), nil))
		return
	}

	changes, err := s.store.ReportServiceHealth(node.ID, reports, s.cfg.ServiceHealthTTL)
	if err != nil {
		if errors.Is(err, state.ErrServiceHealthUnknown) {
			httpError(w, NewHTTPError(http.StatusBadRequest,
				"a reported service is not advertised with health tracking enabled", nil))
			return
		}
		s.log.Error("recording service health", "node", node.StableID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	if len(changes) > 0 {
		for _, change := range changes {
			s.auditServiceHealth(change, node)
		}
		// The service's MagicDNS records appeared or disappeared, so
		// streaming sessions have a new netmap to send.
		s.notifyWatchers()
	}

	stored, err := s.store.ServicesForNode(node.ID)
	if err != nil {
		s.log.Error("reading back services", "node", node.StableID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	writeJSON(w, http.StatusOK, agentServicesResponse{Services: s.serviceViews(node, stored)})
}

// normalizeServiceHealth validates a readiness report. Like a declaration, it
// is all-or-nothing: a malformed entry fails the whole report rather than
// leaving the node half-reported.
func normalizeServiceHealth(services []agentServiceHealth) ([]state.ServiceHealthReport, error) {
	if len(services) > maxServicesPerNode {
		return nil, fmt.Errorf("at most %d services may be reported per node", maxServicesPerNode)
	}

	out := make([]state.ServiceHealthReport, 0, len(services))
	seen := make(map[string]bool, len(services))
	for _, svc := range services {
		if err := validateServiceName(svc.Name); err != nil {
			return nil, err
		}
		if seen[svc.Name] {
			return nil, fmt.Errorf("service name %q is listed twice", svc.Name)
		}
		seen[svc.Name] = true
		out = append(out, state.ServiceHealthReport{Name: svc.Name, Ready: svc.Ready})
	}
	return out, nil
}

// auditServiceHealth records one health transition. Only transitions reach
// here, so a node repeating "ready" produces no audit noise; for the same
// reason the detail is built from stored fields and fixed strings, never from
// request text.
func (s *Server) auditServiceHealth(change state.ServiceHealthChange, node state.Node) {
	action := identity.AuditServiceUnhealthy
	verdict := "is not ready"
	if change.Healthy {
		action = identity.AuditServiceHealthy
		verdict = "is ready"
	}
	actor := "system"
	if change.Reason == state.ServiceHealthReasonReported {
		actor = nodeActor(node)
	}
	detail := fmt.Sprintf("%s/%s:%d %s (%s)", change.Name, change.Protocol, change.Port, verdict, change.Reason)
	s.audit(actor, action, nodeTarget(node), truncateClean(detail, maxAuditDetailsLen))
}
