package catalog

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/client/protocol"
)

// Kubernetes importer constants (spec section 27). The annotation and label
// names are the operator-facing contract.
const (
	// KubernetesAdvertiseAnnotation opts a Service in. Anything else is
	// ignored silently: not opting in is not an error.
	KubernetesAdvertiseAnnotation = "xunara.io/advertise"
	// KubernetesPortAnnotation selects one port of a multi-port Service by
	// EndpointSlice port name. Without it a multi-port Service is skipped.
	KubernetesPortAnnotation = "xunara.io/port"
	// KubernetesMetadataAnnotation carries the declaration metadata as a JSON
	// object of strings. Labels and other annotations are never imported:
	// they routinely hold credentials (AGENTS section 8).
	KubernetesMetadataAnnotation = "xunara.io/metadata"
	// KubernetesVisibilityAnnotation carries the visibility selectors as a
	// JSON array of strings (spec sections 46, 49). Absent means the whole
	// organization.
	KubernetesVisibilityAnnotation = "xunara.io/visibility"
	// KubernetesVisibilityFromACLAnnotation is "true" to derive discovery
	// from the ACL instead of the selector list (spec sections 48, 49); it
	// cannot be combined with KubernetesVisibilityAnnotation.
	KubernetesVisibilityFromACLAnnotation = "xunara.io/visibility-from-acl"
	// KubernetesSharedAnnotation is "true" to project the service into the
	// MagicDNS of organizations sharing this node (spec sections 47, 49).
	KubernetesSharedAnnotation = "xunara.io/shared"
	// KubernetesServiceNameLabel links an EndpointSlice to its Service.
	KubernetesServiceNameLabel = "kubernetes.io/service-name"

	// InClusterTokenFile, InClusterCAFile and InClusterNamespaceFile are the
	// service-account paths every Kubernetes client uses.
	InClusterTokenFile     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	InClusterCAFile        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	InClusterNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

const (
	kubernetesPageLimit        = 200
	kubernetesMaxPages         = 50
	kubernetesMaxItems         = 5000
	kubernetesTimeout          = 30 * time.Second
	kubernetesMaxResponseBytes = 16 << 20
	kubernetesMaxErrorBytes    = 4 << 10
	kubernetesMaxMetadataBytes = 8 << 10
	// kubernetesMaxDeclarationBytes bounds one declaration annotation value
	// before decoding; services.json has the same limits enforced at publish.
	kubernetesMaxDeclarationBytes = 4 << 10
)

// KubernetesConfig configures the Kubernetes importer. The zero value reads
// in-cluster defaults; Node is always required (in a pod the hostname is the
// pod name, so it cannot be derived).
type KubernetesConfig struct {
	// Address is the API server base URL; empty uses
	// https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT. Only https,
	// or loopback http, is accepted: the token travels in a header.
	Address string
	// TokenFile holds the bearer token; empty uses the in-cluster service
	// account token. The token never comes from argv or the environment.
	TokenFile string
	// CAFile is the API server CA bundle; empty uses the in-cluster ca.crt
	// when it exists, else the system roots.
	CAFile string
	// Namespace scopes the import; empty uses the in-cluster namespace file,
	// else "default".
	Namespace string
	// Node is the Kubernetes node this agent runs on, matched against
	// EndpointSlice endpoints[].nodeName.
	Node string
	// HTTP overrides the client; tests use this to trust a local server.
	HTTP *http.Client
}

// KubernetesServices reads the Services a node provides in one namespace and
// maps them to a Xunara Atlas declaration, following spec sections 27 and 49.
// The returned warnings explain what was skipped and never contain annotation
// or label values; the declaration is validated and sorted by name.
func KubernetesServices(ctx context.Context, cfg KubernetesConfig) ([]protocol.Service, []string, error) {
	conn, err := newKubernetesConnection(cfg)
	if err != nil {
		return nil, nil, err
	}
	node := strings.TrimSpace(cfg.Node)

	ctx, cancel := context.WithTimeout(ctx, kubernetesTimeout)
	defer cancel()

	base := "/api/v1/namespaces/" + url.PathEscape(conn.namespace)
	services, err := kubernetesList[kubernetesService](ctx, conn, base+"/services")
	if err != nil {
		return nil, nil, err
	}
	slices, err := kubernetesList[kubernetesEndpointSlice](ctx, conn, "/apis/discovery.k8s.io/v1/namespaces/"+url.PathEscape(conn.namespace)+"/endpointslices")
	if err != nil {
		return nil, nil, err
	}
	return mapKubernetesServices(services, slices, node)
}

// kubernetesConnection is the resolved, validated connection.
type kubernetesConnection struct {
	address   string
	token     string
	namespace string
	client    *http.Client
}

// newKubernetesConnection resolves the configuration and fails closed on
// anything that cannot be trusted: a missing node name, a missing token, a
// plaintext address that is not loopback, or a malformed namespace.
func newKubernetesConnection(cfg KubernetesConfig) (*kubernetesConnection, error) {
	node := strings.TrimSpace(cfg.Node)
	if node == "" {
		return nil, errors.New("catalog: the Kubernetes node name is required (-k8s-node or NODE_NAME); the pod hostname is not the node name")
	}

	address := strings.TrimSpace(cfg.Address)
	tokenFile := strings.TrimSpace(cfg.TokenFile)
	caFile := strings.TrimSpace(cfg.CAFile)
	caExplicit := caFile != ""
	if address == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, errors.New("catalog: no Kubernetes API address: set -k8s-api or run with KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT")
		}
		address = "https://" + net.JoinHostPort(host, port)
		if tokenFile == "" {
			tokenFile = InClusterTokenFile
		}
		if caFile == "" {
			caFile = InClusterCAFile
		}
	}
	address, err := validateKubernetesAddress(address)
	if err != nil {
		return nil, err
	}

	if tokenFile == "" {
		return nil, errors.New("catalog: no Kubernetes bearer token file: set -k8s-token-file or run in-cluster")
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("catalog: reading the Kubernetes token: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return nil, fmt.Errorf("catalog: the Kubernetes token file %s is empty", tokenFile)
	}

	namespace := strings.TrimSpace(cfg.Namespace)
	if namespace == "" {
		if raw, err := os.ReadFile(InClusterNamespaceFile); err == nil {
			namespace = strings.TrimSpace(string(raw))
		}
	}
	if namespace == "" {
		namespace = "default"
	}
	if !validKubernetesName(namespace, 63) {
		return nil, fmt.Errorf("catalog: %q is not a valid Kubernetes namespace", namespace)
	}

	client := cfg.HTTP
	if client == nil {
		client, err = kubernetesHTTPClient(caFile, caExplicit)
		if err != nil {
			return nil, err
		}
	}
	return &kubernetesConnection{address: address, token: token, namespace: namespace, client: client}, nil
}

// validateKubernetesAddress accepts https anywhere and http only on loopback.
func validateKubernetesAddress(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("catalog: %q is not a valid Kubernetes API address", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", fmt.Errorf("catalog: refusing to send the Kubernetes token to the plaintext address %q; use https or loopback", raw)
		}
	default:
		return "", fmt.Errorf("catalog: the Kubernetes API address must be https (or loopback http), got %q", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("catalog: the Kubernetes API address must not carry credentials, a query or a fragment")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// validKubernetesName checks the DNS-1123 label/subdomain charset Kubernetes
// itself enforces; it also keeps user input out of URL path surprises.
func validKubernetesName(name string, max int) bool {
	if name == "" || len(name) > max || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

// kubernetesHTTPClient builds the client: a custom CA when one is configured
// or present in-cluster, the system roots otherwise.
func kubernetesHTTPClient(caFile string, caExplicit bool) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		switch {
		case err != nil && caExplicit:
			return nil, fmt.Errorf("catalog: reading the Kubernetes CA: %w", err)
		case err != nil:
			// The in-cluster CA is optional (client-go behaves the same):
			// fall back to the system roots.
		default:
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				if caExplicit {
					return nil, fmt.Errorf("catalog: %s holds no PEM certificates", caFile)
				}
			} else {
				tlsConfig.RootCAs = pool
			}
		}
	}
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: kubernetesTimeout, Transport: transport}, nil
}

// kubernetesListMeta carries the pagination cursor.
type kubernetesListMeta struct {
	Continue string `json:"continue"`
}

// kubernetesObjectMeta is the slice of ObjectMeta the importer reads.
type kubernetesObjectMeta struct {
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// kubernetesService mirrors the fields of a core/v1 Service the importer
// reads (verified against k8s.io/api/core/v1 types.go).
type kubernetesService struct {
	Metadata kubernetesObjectMeta `json:"metadata"`
}

// kubernetesEndpointSlice mirrors discovery.k8s.io/v1 EndpointSlice
// (verified against k8s.io/api/discovery/v1 types.go).
type kubernetesEndpointSlice struct {
	Metadata  kubernetesObjectMeta     `json:"metadata"`
	Endpoints []kubernetesEndpoint     `json:"endpoints"`
	Ports     []kubernetesEndpointPort `json:"ports"`
}

// kubernetesEndpoint is one EndpointSlice endpoint.
type kubernetesEndpoint struct {
	Conditions kubernetesEndpointConditions `json:"conditions"`
	NodeName   *string                      `json:"nodeName"`
}

// kubernetesEndpointConditions carries the readiness pointer; nil means
// unknown, which upstream consumers interpret as ready.
type kubernetesEndpointConditions struct {
	Ready *bool `json:"ready"`
}

// kubernetesEndpointPort is one EndpointSlice port.
type kubernetesEndpointPort struct {
	Name     *string `json:"name"`
	Protocol *string `json:"protocol"`
	Port     *int32  `json:"port"`
}

// kubernetesList reads one paginated list endpoint, following continue
// tokens with a bounded page and item count.
func kubernetesList[T any](ctx context.Context, conn *kubernetesConnection, path string) ([]T, error) {
	var out []T
	next := ""
	for page := 0; ; page++ {
		if page >= kubernetesMaxPages {
			return nil, fmt.Errorf("catalog: listing %s: more than %d pages", path, kubernetesMaxPages)
		}
		query := url.Values{"limit": {strconv.Itoa(kubernetesPageLimit)}}
		if next != "" {
			query.Set("continue", next)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, conn.address+path+"?"+query.Encode(), nil)
		if err != nil {
			return nil, fmt.Errorf("catalog: building the Kubernetes request: %w", err)
		}
		req.Header.Set("User-Agent", "xunara-agent")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+conn.token)

		resp, err := conn.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("catalog: reading %s from the Kubernetes API: %w", path, err)
		}
		func() {
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, kubernetesMaxErrorBytes))
				message := strings.TrimSpace(string(body))
				if message == "" {
					err = fmt.Errorf("catalog: the Kubernetes API returned %s", resp.Status)
				} else {
					err = fmt.Errorf("catalog: the Kubernetes API returned %s: %s", resp.Status, message)
				}
				return
			}
			var list struct {
				Metadata kubernetesListMeta `json:"metadata"`
				Items    []T                `json:"items"`
			}
			if decErr := json.NewDecoder(io.LimitReader(resp.Body, kubernetesMaxResponseBytes)).Decode(&list); decErr != nil {
				err = fmt.Errorf("catalog: decoding %s: %w", path, decErr)
				return
			}
			out = append(out, list.Items...)
			next = list.Metadata.Continue
		}()
		if err != nil {
			return nil, err
		}
		if len(out) > kubernetesMaxItems {
			return nil, fmt.Errorf("catalog: listing %s returned more than %d objects", path, kubernetesMaxItems)
		}
		if next == "" {
			return out, nil
		}
	}
}

// kubernetesPort is one usable port of a Service's local endpoints.
type kubernetesPort struct {
	name     string
	protocol string
	number   int32
}

// mapKubernetesServices converts the two list responses into a declaration.
// It is a pure function so the mapping rules can be tested without a cluster.
func mapKubernetesServices(services []kubernetesService, slices []kubernetesEndpointSlice, node string) ([]protocol.Service, []string, error) {
	byService := make(map[string][]kubernetesEndpointSlice, len(slices))
	for _, slice := range slices {
		name := slice.Metadata.Labels[KubernetesServiceNameLabel]
		if name == "" {
			continue
		}
		byService[name] = append(byService[name], slice)
	}

	var warnings []string
	byName := make(map[string]protocol.Service, len(services))
	for _, svc := range services {
		name := svc.Metadata.Name
		if svc.Metadata.Annotations[KubernetesAdvertiseAnnotation] != "true" {
			continue
		}
		if name == "" {
			continue
		}

		ports := kubernetesLocalPorts(byService[name], node)
		if len(ports) == 0 {
			warnings = append(warnings, fmt.Sprintf(
				"skipping Kubernetes service %q: it has no ready endpoints on node %q", name, node))
			continue
		}
		port, reason := selectKubernetesPort(ports, svc.Metadata.Annotations[KubernetesPortAnnotation])
		if reason != "" {
			warnings = append(warnings, fmt.Sprintf("skipping Kubernetes service %q: %s", name, reason))
			continue
		}
		metadata, reason := kubernetesMetadata(svc.Metadata.Annotations[KubernetesMetadataAnnotation])
		if reason != "" {
			warnings = append(warnings, fmt.Sprintf("skipping Kubernetes service %q: %s", name, reason))
			continue
		}
		visibility, reason := kubernetesVisibility(svc.Metadata.Annotations[KubernetesVisibilityAnnotation])
		if reason != "" {
			warnings = append(warnings, fmt.Sprintf("skipping Kubernetes service %q: %s", name, reason))
			continue
		}
		visibilityFromACL, reason := kubernetesDeclarationBool(
			svc.Metadata.Annotations[KubernetesVisibilityFromACLAnnotation], KubernetesVisibilityFromACLAnnotation)
		if reason != "" {
			warnings = append(warnings, fmt.Sprintf("skipping Kubernetes service %q: %s", name, reason))
			continue
		}
		shared, reason := kubernetesDeclarationBool(
			svc.Metadata.Annotations[KubernetesSharedAnnotation], KubernetesSharedAnnotation)
		if reason != "" {
			warnings = append(warnings, fmt.Sprintf("skipping Kubernetes service %q: %s", name, reason))
			continue
		}

		candidate := protocol.Service{
			Name:              name,
			Protocol:          port.protocol,
			Port:              uint32(port.number),
			Metadata:          metadata,
			Visibility:        visibility,
			VisibilityFromACL: visibilityFromACL,
			Shared:            shared,
		}
		validated, err := protocol.ValidateServices([]protocol.Service{candidate})
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skipping Kubernetes service %q: %s", name, err))
			continue
		}
		byName[name] = validated[0]
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
			"catalog: the Kubernetes namespace exposes %d node-local services; at most %d can be published per node",
			len(out), protocol.MaxServicesPerNode)
	}
	return out, warnings, nil
}

// kubernetesLocalPorts collects the usable ports of the slices that have at
// least one ready endpoint on this node.
func kubernetesLocalPorts(slices []kubernetesEndpointSlice, node string) []kubernetesPort {
	set := make(map[kubernetesPort]bool)
	for _, slice := range slices {
		local := false
		for _, endpoint := range slice.Endpoints {
			if endpoint.NodeName == nil || *endpoint.NodeName != node {
				continue
			}
			if endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready {
				local = true
				break
			}
		}
		if !local {
			continue
		}
		for _, port := range slice.Ports {
			if port.Port == nil || *port.Port <= 0 || *port.Port > 65535 {
				continue
			}
			protocolName := "tcp"
			if port.Protocol != nil {
				protocolName = strings.ToLower(string(*port.Protocol))
			}
			if protocolName != "tcp" && protocolName != "udp" {
				continue
			}
			name := ""
			if port.Name != nil {
				name = *port.Name
			}
			set[kubernetesPort{name: name, protocol: protocolName, number: *port.Port}] = true
		}
	}
	out := make([]kubernetesPort, 0, len(set))
	for port := range set {
		out = append(out, port)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		if out[i].protocol != out[j].protocol {
			return out[i].protocol < out[j].protocol
		}
		return out[i].number < out[j].number
	})
	return out
}

// selectKubernetesPort picks the one port to declare; a reason string means
// the Service is skipped rather than guessed.
func selectKubernetesPort(ports []kubernetesPort, want string) (kubernetesPort, string) {
	if want == "" {
		if len(ports) == 1 {
			return ports[0], ""
		}
		return kubernetesPort{}, fmt.Sprintf(
			"it exposes %d ports; set annotation %s to one port name", len(ports), KubernetesPortAnnotation)
	}
	var matches []kubernetesPort
	for _, port := range ports {
		if port.name == want {
			matches = append(matches, port)
		}
	}
	switch len(matches) {
	case 0:
		return kubernetesPort{}, fmt.Sprintf("annotation %s names a port that no local endpoint exposes", KubernetesPortAnnotation)
	case 1:
		return matches[0], ""
	default:
		return kubernetesPort{}, fmt.Sprintf("annotation %s matches %d distinct ports", KubernetesPortAnnotation, len(matches))
	}
}

// kubernetesMetadata decodes the opt-in metadata annotation. Labels and other
// annotations are deliberately never imported (spec 27.2).
func kubernetesMetadata(raw string) (map[string]string, string) {
	if strings.TrimSpace(raw) == "" {
		return nil, ""
	}
	if len(raw) > kubernetesMaxMetadataBytes {
		return nil, fmt.Sprintf("annotation %s is larger than %d bytes", KubernetesMetadataAnnotation, kubernetesMaxMetadataBytes)
	}
	var metadata map[string]string
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		return nil, fmt.Sprintf("annotation %s is not a JSON object of strings", KubernetesMetadataAnnotation)
	}
	return metadata, ""
}

// kubernetesVisibility decodes the visibility annotation (spec section 49).
// The reason string fits the skip-warning shape and never contains the value.
func kubernetesVisibility(raw string) ([]string, string) {
	selectors, err := parseDeclarationVisibility(raw, kubernetesMaxDeclarationBytes)
	if err != nil {
		return nil, fmt.Sprintf("annotation %s %s", KubernetesVisibilityAnnotation, err)
	}
	return selectors, ""
}

// kubernetesDeclarationBool decodes one boolean declaration annotation. Only
// "true" and "false" are accepted: a typo must skip the Service with a
// warning instead of silently dropping a declaration the operator wrote.
func kubernetesDeclarationBool(raw, annotation string) (bool, string) {
	value, err := parseDeclarationBool(raw)
	if err != nil {
		return false, fmt.Sprintf("annotation %s %s", annotation, err)
	}
	return value, ""
}
