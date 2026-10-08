// Package catalog imports local service catalogs into Xunara Atlas
// declarations (PROJECT_SPEC section 23). Importers run on the node: the
// control plane never sees the catalog or its credentials, and the node stays
// the only writer of its own services.
package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/client/protocol"
)

// DefaultConsulAddress is where the local Consul agent serves its HTTP API.
const DefaultConsulAddress = "http://127.0.0.1:8500"

// Consul Meta keys that carry a declaration instead of metadata (spec
// section 49). Consul validates meta keys against ^[a-zA-Z0-9_-]+$ and 128
// bytes (agent/structs.validateMetaPair), so the keys use hyphens where the
// Kubernetes annotations use slashes. Values are JSON exactly like
// services.json; Consul itself caps a meta value at 512 bytes.
const (
	// ConsulVisibilityMetaKey carries the visibility selectors as a JSON
	// array of strings.
	ConsulVisibilityMetaKey = "xunara-visibility"
	// ConsulSharedMetaKey enables cross-organization sharing.
	ConsulSharedMetaKey = "xunara-shared"
	// ConsulVisibilityFromACLMetaKey enables ACL-derived visibility.
	ConsulVisibilityFromACLMetaKey = "xunara-visibility-from-acl"
)

const (
	// consulTimeout bounds one catalog request.
	consulTimeout = 30 * time.Second
	// maxConsulResponseBytes bounds the catalog response.
	maxConsulResponseBytes = 8 << 20
	// maxConsulErrorBytes bounds the error text read from a failed response.
	maxConsulErrorBytes = 4 << 10
	// maxConsulDeclarationBytes defensively bounds one declaration value;
	// Consul already rejects values over 512 bytes at registration.
	maxConsulDeclarationBytes = 4 << 10
)

// ConsulConfig configures the Consul importer.
type ConsulConfig struct {
	// Address is the *local* Consul agent's HTTP(S) base URL; empty uses
	// [DefaultConsulAddress]. Pointing it at a remote agent would advertise
	// that machine's services as this node's.
	Address string
	// Token is the Consul ACL token. It is sent in the X-Consul-Token header
	// and never in a URL (AGENTS.md section 8). Empty uses the agent's
	// default token.
	Token string
	// HTTP overrides the client; a client with a per-request timeout is used
	// otherwise.
	HTTP *http.Client
}

// ConsulServices reads the services registered on the local Consul agent and
// maps them to a Xunara Atlas declaration. The returned warnings explain what
// was skipped and never contain metadata values; the declaration itself is
// validated and sorted by name.
//
// Skipped on purpose (spec 23.1): Connect proxies and gateways, unix-socket
// services, services imported from a Consul peer, and anything that cannot be
// represented faithfully (illegal DNS name, port 0 or out of range, metadata
// outside the declaration limits). Registrations that share a name must agree
// on protocol, port and the declared visibility/sharing; a disagreement skips
// the whole name rather than guessing. The Meta keys
// [ConsulVisibilityMetaKey], [ConsulSharedMetaKey] and
// [ConsulVisibilityFromACLMetaKey] carry declaration fields (spec section 49)
// instead of metadata and are validated like services.json entries.
func ConsulServices(ctx context.Context, cfg ConsulConfig) ([]protocol.Service, []string, error) {
	address := normalizeAddress(cfg.Address)
	client := cfg.HTTP
	if client == nil {
		client = &http.Client{Timeout: consulTimeout}
	}

	ctx, cancel := context.WithTimeout(ctx, consulTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address+"/v1/agent/services", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("catalog: building the Consul request: %w", err)
	}
	req.Header.Set("User-Agent", "xunara-agent")
	if cfg.Token != "" {
		req.Header.Set("X-Consul-Token", cfg.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("catalog: reading the Consul agent: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxConsulErrorBytes))
		message := strings.TrimSpace(string(body))
		if message == "" {
			return nil, nil, fmt.Errorf("catalog: Consul agent returned %s", resp.Status)
		}
		return nil, nil, fmt.Errorf("catalog: Consul agent returned %s: %s", resp.Status, message)
	}

	var services map[string]consulAgentService
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxConsulResponseBytes)).Decode(&services); err != nil {
		return nil, nil, fmt.Errorf("catalog: decoding the Consul services: %w", err)
	}
	return mapConsulServices(services)
}

// consulAgentService mirrors the fields of Consul's api.AgentService the
// importer reads. The JSON keys and the port rule are verified against
// hashicorp/consul api/agent.go (AgentService, AgentService.DefaultPort).
type consulAgentService struct {
	Kind       string              `json:"Kind"`
	ID         string              `json:"ID"`
	Service    string              `json:"Service"`
	Tags       []string            `json:"Tags"`
	Meta       map[string]string   `json:"Meta"`
	Port       int                 `json:"Port"`
	Ports      []consulServicePort `json:"Ports"`
	SocketPath string              `json:"SocketPath"`
	PeerName   string              `json:"PeerName"`
}

// consulServicePort is one entry of a multi-port service registration.
type consulServicePort struct {
	Name    string `json:"Name"`
	Port    int    `json:"Port"`
	Default bool   `json:"Default"`
}

// defaultPort mirrors api.AgentService.DefaultPort: the port marked default,
// falling back to the legacy single Port field.
func (s consulAgentService) defaultPort() int {
	for _, port := range s.Ports {
		if port.Default {
			return port.Port
		}
	}
	return s.Port
}

// mapConsulServices converts a catalog response into a declaration. It is a
// pure function so the mapping rules can be tested without a Consul agent.
func mapConsulServices(catalog map[string]consulAgentService) ([]protocol.Service, []string, error) {
	ids := make([]string, 0, len(catalog))
	for id := range catalog {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var warnings []string
	byName := make(map[string]protocol.Service, len(ids))
	ambiguous := make(map[string]bool)

	for _, id := range ids {
		svc := catalog[id]

		var reason string
		switch {
		case svc.Service == "":
			reason = "it has no service name"
		case svc.Kind != "":
			reason = fmt.Sprintf("Consul kind %q is not an application service", svc.Kind)
		case svc.SocketPath != "":
			reason = "it is registered on a unix socket"
		case svc.PeerName != "":
			reason = fmt.Sprintf("it is imported from peer %q, not hosted on this node", svc.PeerName)
		}
		if reason != "" {
			warnings = append(warnings, skipWarning(svc, id, reason))
			continue
		}
		if ambiguous[svc.Service] {
			continue
		}

		visibility, reason := consulVisibility(svc.Meta)
		fromACL, shared := false, false
		if reason == "" {
			fromACL, reason = consulDeclarationBool(svc.Meta, ConsulVisibilityFromACLMetaKey)
		}
		if reason == "" {
			shared, reason = consulDeclarationBool(svc.Meta, ConsulSharedMetaKey)
		}
		if reason != "" {
			warnings = append(warnings, skipWarning(svc, id, reason))
			continue
		}

		candidate := protocol.Service{
			Name:              svc.Service,
			Protocol:          consulProtocol(svc.Tags),
			Port:              uint32(svc.defaultPort()),
			Metadata:          consulMetadata(svc.Meta),
			Visibility:        visibility,
			VisibilityFromACL: fromACL,
			Shared:            shared,
		}
		validated, err := protocol.ValidateServices([]protocol.Service{candidate})
		if err != nil {
			warnings = append(warnings, skipWarning(svc, id, err.Error()))
			continue
		}
		candidate = validated[0]

		previous, seen := byName[candidate.Name]
		switch {
		case !seen:
			byName[candidate.Name] = candidate
		case consulSameDeclaration(previous, candidate):
			// The same service registered under two IDs: one declaration.
		default:
			delete(byName, candidate.Name)
			ambiguous[candidate.Name] = true
			warnings = append(warnings, fmt.Sprintf(
				"skipping Consul service %q: registrations disagree on protocol/port or on the visibility/shared declaration",
				candidate.Name))
		}
	}

	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]protocol.Service, 0, len(names))
	for _, name := range names {
		out = append(out, byName[name])
	}
	if len(out) > protocol.MaxServicesPerNode {
		return nil, warnings, fmt.Errorf(
			"catalog: the local Consul agent advertises %d services; at most %d can be published per node",
			len(out), protocol.MaxServicesPerNode)
	}
	return out, warnings, nil
}

// consulProtocol maps Consul's "udp" tag to a UDP service; Consul services are
// TCP unless tagged otherwise.
func consulProtocol(tags []string) string {
	for _, tag := range tags {
		if strings.EqualFold(tag, "udp") {
			return "udp"
		}
	}
	return "tcp"
}

// consulVisibility decodes the visibility declaration from Consul Meta. The
// reason string fits the skip-warning shape and never contains the value.
func consulVisibility(meta map[string]string) ([]string, string) {
	selectors, err := parseDeclarationVisibility(meta[ConsulVisibilityMetaKey], maxConsulDeclarationBytes)
	if err != nil {
		return nil, fmt.Sprintf("Meta key %s %s", ConsulVisibilityMetaKey, err)
	}
	return selectors, ""
}

// consulDeclarationBool decodes one boolean declaration from Consul Meta.
func consulDeclarationBool(meta map[string]string, key string) (bool, string) {
	value, err := parseDeclarationBool(meta[key])
	if err != nil {
		return false, fmt.Sprintf("Meta key %s %s", key, err)
	}
	return value, ""
}

// consulMetadata copies Meta without the declaration keys: those are importer
// directives, not service metadata. Metadata comes from Consul's Meta map, not
// from tags: tags are free-form identity hints and can change meaning per
// service.
func consulMetadata(meta map[string]string) map[string]string {
	if len(meta) == 0 {
		return nil
	}
	out := make(map[string]string, len(meta))
	for key, value := range meta {
		switch key {
		case ConsulVisibilityMetaKey, ConsulSharedMetaKey, ConsulVisibilityFromACLMetaKey:
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// consulSameDeclaration reports whether two registrations of one name describe
// the same declaration: everything except metadata must match, because the
// import is a whole-name replacement and metadata differences were already
// tolerated before this rule (the first registration wins).
func consulSameDeclaration(a, b protocol.Service) bool {
	return a.Protocol == b.Protocol &&
		a.Port == b.Port &&
		a.VisibilityFromACL == b.VisibilityFromACL &&
		a.Shared == b.Shared &&
		slices.Equal(a.Visibility, b.Visibility)
}

// skipWarning names the skipped registration without echoing metadata values.
func skipWarning(svc consulAgentService, id, reason string) string {
	name := svc.Service
	if name == "" {
		name = svc.ID
	}
	return fmt.Sprintf("skipping Consul service %q (%s): %s", name, id, reason)
}

// normalizeAddress accepts "host:port" as well as a full URL.
func normalizeAddress(address string) string {
	address = strings.TrimSpace(strings.TrimRight(address, "/"))
	if address == "" {
		return DefaultConsulAddress
	}
	if !strings.Contains(address, "://") {
		address = "http://" + address
	}
	return address
}
