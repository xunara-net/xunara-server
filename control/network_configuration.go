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

	"tailscale.com/types/dnstype"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/networkconfig"
	"github.com/xunara-net/xunara-server/state"
)

type dnsSettings struct {
	MagicDNS      bool                `json:"magic_dns"`
	Nameservers   []string            `json:"nameservers"`
	SearchDomains []string            `json:"search_domains"`
	SplitDNS      map[string][]string `json:"split_dns"`
}

type dnsRuntimeConfig struct {
	Revision  uint64
	Settings  dnsSettings
	Resolvers []*dnstype.Resolver
	Routes    map[string][]*dnstype.Resolver
}

func (server *Server) validateDNSSettings(settings dnsSettings) (*dnsRuntimeConfig, error) {
	if len(settings.Nameservers) > 8 || len(settings.SearchDomains) > 16 || len(settings.SplitDNS) > 32 {
		return nil, errors.New("too many DNS servers, search domains or split DNS entries")
	}
	if settings.MagicDNS && server.cfg.Domain == "" {
		return nil, errors.New("the deployment has not configured a network domain")
	}
	settings.Nameservers = slices.Clone(settings.Nameservers)
	settings.SearchDomains = slices.Clone(settings.SearchDomains)
	routes := make(map[string][]string, len(settings.SplitDNS))
	for suffix, entries := range settings.SplitDNS {
		name, err := normalizeSearchDomain(suffix)
		if err != nil {
			return nil, err
		}
		if name == strings.Trim(server.cfg.Domain, ".") || strings.HasSuffix(name, "."+strings.Trim(server.cfg.Domain, ".")) {
			return nil, errors.New("split DNS cannot replace the managed network domain")
		}
		if _, exists := routes[name]; exists || len(entries) == 0 || len(entries) > 8 {
			return nil, errors.New("split DNS needs a unique domain and one to eight resolvers")
		}
		routes[name] = slices.Clone(entries)
	}
	settings.SplitDNS = routes
	for index, suffix := range settings.SearchDomains {
		name, err := normalizeSearchDomain(suffix)
		if err != nil {
			return nil, err
		}
		settings.SearchDomains[index] = name
	}
	settings.SearchDomains = uniqueStrings(settings.SearchDomains)
	resolvers, err := parseResolvers(settings.Nameservers)
	if err != nil {
		return nil, err
	}
	for index, resolver := range resolvers {
		if err := validateManagedResolver(resolver.Addr); err != nil {
			return nil, err
		}
		settings.Nameservers[index] = resolver.Addr
	}
	parsedRoutes, err := parseDNSRoutes(settings.SplitDNS)
	if err != nil {
		return nil, err
	}
	for suffix, entries := range parsedRoutes {
		for index, resolver := range entries {
			if err := validateManagedResolver(resolver.Addr); err != nil {
				return nil, err
			}
			settings.SplitDNS[suffix][index] = resolver.Addr
		}
	}
	if settings.Nameservers == nil {
		settings.Nameservers = []string{}
	}
	if settings.SearchDomains == nil {
		settings.SearchDomains = []string{}
	}
	return &dnsRuntimeConfig{Settings: settings, Resolvers: resolvers, Routes: parsedRoutes}, nil
}

func validateManagedResolver(value string) error {
	address, err := netip.ParseAddr(value)
	if err != nil {
		endpoint, parseErr := netip.ParseAddrPort(value)
		if parseErr != nil || endpoint.Port() == 0 {
			return errors.New("DNS server must be an IP address with an optional nonzero port")
		}
		address = endpoint.Addr()
	}
	if address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
		return errors.New("DNS server address is not usable")
	}
	return nil
}

func normalizeSearchDomain(value string) (string, error) {
	name, err := state.NormalizeDNSRecordName(value)
	if err != nil || strings.Contains(name, "_") {
		return "", errors.New("DNS domain must be a fully-qualified hostname")
	}
	return name, nil
}

func uniqueStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !slices.Contains(out, value) {
			out = append(out, value)
		}
	}
	return out
}

// loadDNSConfiguration 只替换完整快照；配置故障不能把客户端 DNS 清空或伪装默认值。
func (server *Server) loadDNSConfiguration(ctx context.Context) error {
	document, found, err := server.networkConfig.Get(ctx, networkconfig.DNS)
	if err != nil {
		return err
	}
	if !found {
		if current := server.dnsConfig.Load(); current != nil {
			if current.Revision != 0 {
				return networkconfig.ErrNotFound
			}
			return nil
		}
		server.dnsConfig.Store(&dnsRuntimeConfig{
			Settings:  dnsSettings{MagicDNS: server.cfg.Domain != "", Nameservers: stringsOrEmpty(server.cfg.Nameservers), SearchDomains: []string{}, SplitDNS: server.cfg.DNSRoutes},
			Resolvers: server.resolvers, Routes: server.dnsRoutes,
		})
		return nil
	}
	if current := server.dnsConfig.Load(); current != nil && current.Revision == document.Revision {
		return nil
	}
	var settings dnsSettings
	if err := json.Unmarshal([]byte(document.Content), &settings); err != nil {
		return err
	}
	runtime, err := server.validateDNSSettings(settings)
	if err != nil {
		return err
	}
	runtime.Revision = document.Revision
	server.dnsConfig.Store(runtime)
	return nil
}

func (server *Server) requireNetworkWriter(writer http.ResponseWriter, request *http.Request) (apiPrincipal, bool) {
	writer.Header().Set("Cache-Control", "no-store")
	principal, ok := server.requireScope(writer, request, identity.ScopeWrite)
	if !ok {
		return apiPrincipal{}, false
	}
	if principal.Kind == "session" && !checkCSRFHeader(request, server.accountSessionToken(request)) {
		writeAPIError(writer, http.StatusForbidden, "CSRF_INVALID: reload the page and try again")
		return apiPrincipal{}, false
	}
	if principal.Kind == "api_key" && !server.Plan().AllowAPI {
		writeAPIError(writer, http.StatusForbidden, MsgAPIKeysDisabled)
		return apiPrincipal{}, false
	}
	return principal, true
}

func networkWriter(principal apiPrincipal) networkconfig.Writer {
	return networkconfig.Writer{UserID: principal.UserID, SessionID: principal.Session.ID, APIKeyID: principal.APIKey.ID}
}

func (server *Server) networkNodes(ctx context.Context) ([]state.Node, error) {
	store, ok := server.store.(interface {
		ListNodesContext(context.Context) ([]state.Node, error)
	})
	if !ok {
		return nil, errors.New("network management requires a durable device store")
	}
	return store.ListNodesContext(ctx)
}

func (server *Server) writeNetworkError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, networkconfig.ErrConflict):
		writeAPIError(writer, http.StatusConflict, "CONFIG_CHANGED: another administrator has changed this configuration; reload before publishing")
	case errors.Is(err, networkconfig.ErrNotFound):
		writeAPIError(writer, http.StatusNotFound, "CONFIG_NOT_FOUND: configuration version not found")
	case errors.Is(err, identity.ErrSessionRevoked), errors.Is(err, identity.ErrNetworkWriterForbidden):
		writeAPIError(writer, http.StatusForbidden, "NETWORK_WRITE_FORBIDDEN: session or administrator permissions have changed")
	default:
		server.log.Error("network configuration operation failed", "err", err)
		writeAPIError(writer, http.StatusServiceUnavailable, "NETWORK_CONFIG_UNAVAILABLE: configuration could not be read or committed; retry later")
	}
}

func (server *Server) handleAPIV2DNSConfiguration(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireScope(writer, request, identity.ScopeRead); !ok {
		return
	}
	server.networkMu.Lock()
	defer server.networkMu.Unlock()
	if err := server.loadDNSConfiguration(request.Context()); err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	runtime := server.dnsConfig.Load()
	settings := runtime.Settings
	if settings.SplitDNS == nil {
		settings.SplitDNS = map[string][]string{}
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, map[string]any{
		"domain": server.cfg.Domain, "revision": runtime.Revision, "settings": settings,
		"base_hash":  dnsSettingsHash(runtime.Settings),
		"can_edit":   server.Plan().AllowCustomDNS,
		"csrf_token": csrfTokenFor(server.accountSessionToken(request)),
	})
}

func (server *Server) handleAPIV2SaveDNSConfiguration(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireNetworkWriter(writer, request)
	if !ok {
		return
	}
	if !server.Plan().AllowCustomDNS {
		writeAPIError(writer, http.StatusForbidden, "PLAN_FEATURE_DISABLED: custom DNS is not included in this plan")
		return
	}
	var body struct {
		Revision *uint64     `json:"revision"`
		BaseHash string      `json:"base_hash"`
		Settings dnsSettings `json:"settings"`
	}
	if !decodeAPIBody(writer, request, &body) {
		return
	}
	if body.Revision == nil {
		writeAPIError(writer, http.StatusBadRequest, "CONFIG_INVALID: expected revision is required")
		return
	}
	runtime, err := server.validateDNSSettings(body.Settings)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "CONFIG_INVALID: "+err.Error())
		return
	}
	server.networkMu.Lock()
	defer server.networkMu.Unlock()
	if err := server.loadDNSConfiguration(request.Context()); err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	content, _ := json.Marshal(runtime.Settings)
	if body.BaseHash != dnsSettingsHash(server.dnsConfig.Load().Settings) {
		server.writeNetworkError(writer, networkconfig.ErrConflict)
		return
	}
	initial, _ := json.Marshal(server.dnsConfig.Load().Settings)
	document, err := server.networkConfig.Save(request.Context(), networkconfig.DNS, string(content), string(initial), *body.Revision, networkWriter(principal))
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	runtime.Revision = document.Revision
	server.dnsConfig.Store(runtime)
	server.notifyWatchers()
	writeJSON(writer, http.StatusOK, map[string]any{"revision": document.Revision, "settings": runtime.Settings, "base_hash": dnsSettingsHash(runtime.Settings)})
}

func dnsSettingsHash(settings dnsSettings) string {
	content, _ := json.Marshal(settings)
	return contentHash(string(content))
}

func formatPolicyError(err error) string { return fmt.Sprintf("POLICY_INVALID: %s", err) }
