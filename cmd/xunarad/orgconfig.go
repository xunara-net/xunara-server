package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/control"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/webhook"
)

// This file loads the multi-tenant organization table. One xunarad process can
// host several organizations; each gets its own state directory, policy, DNS
// domain and identity store, and requests are routed to it by Host. Tenant
// isolation therefore does not depend on query filters (AGENTS.md section 12).

// orgConfigFile is the JSON document accepted by -org-config.
type orgConfigFile struct {
	Organizations []orgConfig `json:"organizations"`
	// SelfService, when present, turns the named organization's hosts into
	// the deployment's sign-up desk: every account created there gets its own
	// organization (self-service registration, spec section 54).
	SelfService *orgSelfServiceConfig `json:"self_service"`
}

// orgSelfServiceConfig is the -org-config half of control.SelfServiceConfig.
// It lives in the config file rather than on the command line because it
// describes the tenant model, which only a multi-tenant deployment has.
type orgSelfServiceConfig struct {
	Site         string `json:"site"`
	DomainSuffix string `json:"domain_suffix"`
	Scheme       string `json:"scheme"`
	Port         string `json:"port"`
	CookieDomain string `json:"cookie_domain"`
	Plan         string `json:"plan"`
}

// orgConfig describes one organization. Secrets are never read from the file:
// each secret field names the environment variable that holds it (AGENTS.md
// section 8).
type orgConfig struct {
	ID                  string              `json:"id"`
	Name                string              `json:"name"`
	Domains             []string            `json:"domains"`
	ServerURL           string              `json:"server_url"`
	StateDir            string              `json:"state_dir"`
	Domain              string              `json:"domain"`
	Policy              string              `json:"policy"`
	Nameservers         []string            `json:"nameservers"`
	DNSRoutes           map[string][]string `json:"dns_routes"`
	DERPMapFile         string              `json:"derp_map"`
	DERPPolicy          *orgDERPPolicy      `json:"derp_policy"`
	LatestClientVersion string              `json:"client_version"`
	ClientVersionURL    string              `json:"client_version_url"`
	NodeKeyExpiry       string              `json:"node_key_expiry"`
	ServiceHealthTTL    string              `json:"service_health_ttl"`
	IDTokenRateLimit    int                 `json:"id_token_rate_limit"`
	ReachEnabled        bool                `json:"reach_enabled"`
	FluxEnabled         bool                `json:"flux_enabled"`
	FluxDir             string              `json:"flux_dir"`
	FluxMaxSize         int64               `json:"flux_max_size"`
	FluxTTL             string              `json:"flux_ttl"`
	CertDomains         []string            `json:"cert_domains"`
	DNS                 *orgDNSConfig       `json:"dns"`
	OIDC                *orgOIDCConfig      `json:"oidc"`
	Webhooks            []orgWebhookConfig  `json:"webhooks"`
	AllowLocalLogin     bool                `json:"allow_local_login"`
	Registration        string              `json:"registration"`
}

// orgDERPPolicy restricts the DERP regions this organization serves. Mode is
// "" (serve derp_map as-is), "none" or "regions"; regions lists the allowed
// DERP region IDs for mode "regions".
type orgDERPPolicy struct {
	Mode    string `json:"mode"`
	Regions []int  `json:"regions"`
}

// orgWebhookConfig names one audit-event receiver. SecretEnv defaults to
// XUNARA_WEBHOOK_SECRET.
type orgWebhookConfig struct {
	ID        string   `json:"id"`
	URL       string   `json:"url"`
	SecretEnv string   `json:"secret_env"`
	Events    []string `json:"events"`
}

// orgDNSConfig names the public-zone writer for ACME DNS-01.
type orgDNSConfig struct {
	WebhookURL         string `json:"webhook_url"`
	WebhookTokenEnv    string `json:"webhook_token_env"`
	CloudflareZone     string `json:"cloudflare_zone"`
	CloudflareTokenEnv string `json:"cloudflare_token_env"`
}

// orgOIDCConfig names the organization's OIDC provider. ClientSecretEnv
// defaults to XUNARA_OIDC_CLIENT_SECRET.
type orgOIDCConfig struct {
	ID              string   `json:"id"`
	DisplayName     string   `json:"display_name"`
	Issuer          string   `json:"issuer"`
	ClientID        string   `json:"client_id"`
	ClientSecretEnv string   `json:"client_secret_env"`
	RedirectURL     string   `json:"redirect_url"`
	Scopes          []string `json:"scopes"`
}

// loadOrgSites parses the organization table and builds one control-plane
// server per organization. Any partly built server is closed when a later one
// fails, so a broken row cannot leak resources.
func loadOrgSites(path string, logger *slog.Logger) ([]control.OrgSite, error) {
	sites, _, err := loadOrgConfig(path, logger)
	return sites, err
}

// loadOrgConfig parses the organization table and returns the deployment-wide
// settings that sit next to it.
func loadOrgConfig(path string, logger *slog.Logger) ([]control.OrgSite, *control.SelfServiceConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var doc orgConfigFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(doc.Organizations) == 0 {
		return nil, nil, fmt.Errorf("%s lists no organizations", path)
	}

	var selfService *control.SelfServiceConfig
	if doc.SelfService != nil {
		selfService = &control.SelfServiceConfig{
			Site:         doc.SelfService.Site,
			DomainSuffix: doc.SelfService.DomainSuffix,
			Scheme:       doc.SelfService.Scheme,
			Port:         doc.SelfService.Port,
			CookieDomain: doc.SelfService.CookieDomain,
			Plan:         doc.SelfService.Plan,
		}
	}

	sites := make([]control.OrgSite, 0, len(doc.Organizations))
	stateDirs := make(map[string]string, len(doc.Organizations))
	closeAll := func() {
		for _, site := range sites {
			_ = site.Server.Close()
		}
	}

	for i, org := range doc.Organizations {
		// Two organizations sharing a state directory would share the same
		// SQLite database and Noise key: a tenant-boundary violation by
		// configuration. Refuse it.
		if other, dup := stateDirs[org.StateDir]; dup {
			closeAll()
			return nil, nil, fmt.Errorf("%s: organizations[%d] (%s): state_dir %q is already used by organization %q",
				path, i, org.ID, org.StateDir, other)
		}
		stateDirs[org.StateDir] = org.ID

		cfg, err := org.controlConfig(logger)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("%s: organizations[%d] (%s): %w", path, i, org.ID, err)
		}
		server, err := control.New(cfg)
		if err != nil {
			closeAll()
			return nil, nil, fmt.Errorf("%s: organizations[%d] (%s): %w", path, i, org.ID, err)
		}
		sites = append(sites, control.OrgSite{
			ID:      org.ID,
			Name:    org.Name,
			Domains: org.Domains,
			Server:  server,
		})
	}
	return sites, selfService, nil
}

// controlConfig turns one organization row into a [control.Config].
func (o orgConfig) controlConfig(logger *slog.Logger) (control.Config, error) {
	if strings.TrimSpace(o.ID) == "" {
		return control.Config{}, fmt.Errorf("id is required")
	}
	if o.StateDir == "" {
		return control.Config{}, fmt.Errorf("state_dir is required (organizations must not share state)")
	}
	if o.ServerURL == "" {
		return control.Config{}, fmt.Errorf("server_url is required (it is what clients are configured with)")
	}

	derpMap, err := loadDERPMap(o.DERPMapFile)
	if err != nil {
		return control.Config{}, err
	}

	var derpPolicy control.DERPPolicy
	if o.DERPPolicy != nil {
		derpPolicy = control.DERPPolicy{
			Mode:    control.DERPPolicyMode(o.DERPPolicy.Mode),
			Regions: o.DERPPolicy.Regions,
		}
		// Validate against the map now so the error names the organization.
		if _, err := derpPolicy.Apply(derpMap); err != nil {
			return control.Config{}, err
		}
	}

	nodeKeyExpiry, err := parseNodeKeyExpiry(o.NodeKeyExpiry)
	if err != nil {
		return control.Config{}, err
	}

	serviceHealthTTL, err := parseServiceHealthTTL(o.ServiceHealthTTL)
	if err != nil {
		return control.Config{}, err
	}
	if o.IDTokenRateLimit < 0 {
		return control.Config{}, fmt.Errorf("id_token_rate_limit %d must not be negative", o.IDTokenRateLimit)
	}

	fluxTTL, err := parseFluxTTL(o.FluxTTL)
	if err != nil {
		return control.Config{}, err
	}

	registration, err := control.ParseRegistrationMode(o.Registration)
	if err != nil {
		return control.Config{}, err
	}
	fluxCfg, err := fluxConfigFor(o.FluxEnabled, o.FluxDir, o.FluxMaxSize, fluxTTL)
	if err != nil {
		return control.Config{}, err
	}

	var dnsProvider control.DNSProvider
	if o.DNS != nil {
		webhookTokenEnv := o.DNS.WebhookTokenEnv
		if webhookTokenEnv == "" {
			webhookTokenEnv = "XUNARA_DNS_WEBHOOK_TOKEN"
		}
		cfTokenEnv := o.DNS.CloudflareTokenEnv
		if cfTokenEnv == "" {
			cfTokenEnv = "XUNARA_CLOUDFLARE_API_TOKEN"
		}
		dnsProvider, err = buildDNSProvider(o.DNS.WebhookURL, webhookTokenEnv, o.DNS.CloudflareZone, cfTokenEnv)
		if err != nil {
			return control.Config{}, err
		}
	}

	var oidcProviders []identity.OIDCConfig
	if o.OIDC != nil {
		secretEnv := o.OIDC.ClientSecretEnv
		if secretEnv == "" {
			secretEnv = "XUNARA_OIDC_CLIENT_SECRET"
		}
		oidcProviders = append(oidcProviders, identity.OIDCConfig{
			ID:           o.OIDC.ID,
			DisplayName:  o.OIDC.DisplayName,
			Issuer:       o.OIDC.Issuer,
			ClientID:     o.OIDC.ClientID,
			ClientSecret: os.Getenv(secretEnv),
			RedirectURL:  o.OIDC.RedirectURL,
			Scopes:       o.OIDC.Scopes,
		})
	}

	var webhooks []webhook.Endpoint
	for _, wh := range o.Webhooks {
		secretEnv := wh.SecretEnv
		if secretEnv == "" {
			secretEnv = "XUNARA_WEBHOOK_SECRET"
		}
		secret := os.Getenv(secretEnv)
		if secret == "" {
			return control.Config{}, fmt.Errorf("webhook %q: environment variable %s is empty", wh.ID, secretEnv)
		}
		webhooks = append(webhooks, webhook.Endpoint{
			ID:     wh.ID,
			URL:    wh.URL,
			Secret: secret,
			Events: wh.Events,
		})
	}

	return control.Config{
		ServerURL:           o.ServerURL,
		StateDir:            o.StateDir,
		Domain:              o.Domain,
		Nameservers:         o.Nameservers,
		DNSRoutes:           o.DNSRoutes,
		PolicyPath:          o.Policy,
		DERPMap:             derpMap,
		DERPPolicy:          derpPolicy,
		LatestClientVersion: o.LatestClientVersion,
		ClientVersionURL:    o.ClientVersionURL,
		NodeKeyExpiry:       nodeKeyExpiry,
		ServiceHealthTTL:    serviceHealthTTL,
		IDTokenRateLimit:    o.IDTokenRateLimit,
		ReachEnabled:        o.ReachEnabled,
		Flux:                fluxCfg,
		CertDomains:         o.CertDomains,
		DNSProvider:         dnsProvider,
		OIDCProviders:       oidcProviders,
		Webhooks:            webhooks,
		AllowLocalLogin:     o.AllowLocalLogin,
		Registration:        registration,
		// Each organization is served from its own server_url, so passkey
		// sign-in is derived per organization. A URL that cannot be a
		// relying party leaves the feature off rather than failing the
		// organization at startup.
		Passkeys: derivePasskeyConfig(o.ServerURL),
		Logger:   logger,
	}, nil
}

// parseFluxTTL parses an organization's Flux transfer TTL. The zero value
// keeps the server default; the range check happens in control.New, so the
// error names the deployment rather than this file.
func parseFluxTTL(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid flux_ttl %q", raw)
	}
	return ttl, nil
}

// parseServiceHealthTTL parses an organization's health-report TTL. The zero
// value keeps the server default; the range check happens in control.New, so
// the error names the deployment rather than this file.
func parseServiceHealthTTL(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid service_health_ttl %q", raw)
	}
	return ttl, nil
}

// parseNodeKeyExpiry accepts a Go duration ("4320h") or a day count ("180d").
func parseNodeKeyExpiry(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(raw, "d"); ok {
		n, err := time.ParseDuration(days + "h")
		if err != nil {
			return 0, fmt.Errorf("invalid node_key_expiry %q", raw)
		}
		n *= 24
		if n < 0 {
			return 0, fmt.Errorf("invalid node_key_expiry %q: must not be negative", raw)
		}
		return n, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid node_key_expiry %q: %w", raw, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("invalid node_key_expiry %q: must not be negative", raw)
	}
	return d, nil
}
