// Command xunarad is the Xunara control plane server.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/control"
	"github.com/xunara-net/xunara-server/dnsprovider"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/netspace"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
	"github.com/xunara-net/xunara-server/webhook"
)

func main() {
	var (
		showVersion     = flag.Bool("version", false, "print the build version and exit")
		listen          = flag.String("listen", "0.0.0.0:8080", "address to listen on")
		stateDir        = flag.String("state-dir", "data", "directory for persistent state")
		serverURL       = flag.String("server-url", "", "externally reachable base URL (defaults to http://<listen>)")
		domain          = flag.String("domain", "", "tailnet MagicDNS domain (empty disables MagicDNS)")
		derpMapPath     = flag.String("derp-map", "", "path to a tailcfg.DERPMap JSON file to advertise to clients")
		derpPolicy      = flag.String("derp-policy", "", "DERP policy: empty serves -derp-map, none disables DERP, regions serves only -derp-regions")
		derpRegions     = flag.String("derp-regions", "", "comma-separated DERP region IDs served when -derp-policy=regions")
		clientVer       = flag.String("client-version", "", "latest client version to advertise to clients (e.g. 1.88.3); empty disables the advisory")
		clientVerURL    = flag.String("client-version-url", "", "URL opened by the client's update notification (optional)")
		policyPath      = flag.String("policy", "", "path to an ACL policy document (HuJSON); empty allows everything")
		logLevel        = flag.String("log-level", "info", "log level: debug|info|warn|error")
		consoleTimezone = flag.String("console-timezone", "Asia/Shanghai",
			"IANA timezone the web console prints timestamps in; empty or unknown falls back to UTC")
		oidcIssuer   = flag.String("oidc-issuer", "", "OIDC issuer URL; enables OIDC login when set")
		oidcID       = flag.String("oidc-id", "oidc", "provider ID for the OIDC issuer")
		oidcClient   = flag.String("oidc-client-id", "", "OIDC client ID")
		oidcRedirect = flag.String("oidc-redirect-url", "",
			"OIDC redirect URL (default <server-url>/oidc/callback/<oidc-id>)")
		oidcScopes = flag.String("oidc-scopes", "",
			"comma-separated OIDC scopes (default openid,profile,email)")
		allowLocalLogin = flag.Bool("allow-local-login", false,
			"offer the built-in local login even when OIDC is configured")
		trustedProxy = flag.Bool("trusted-proxy", false,
			"trust the reverse proxy in front of this service (nginx in the shipped units) and take the client address from the last X-Forwarded-For hop for rate limiting; keep it off when the control plane is reachable directly")
		registration = flag.String("registration", string(control.DefaultRegistrationMode),
			"self-service sign-up policy: closed (administrators only), invite (single-use invitation, default) or open (anyone, subject to the plan's member quota)")
		passkey = flag.Bool("passkey", true,
			"enable passkey (WebAuthn) sign-in; RP ID and origin default to -server-url")
		passkeyRPID = flag.String("passkey-rpid", "",
			"WebAuthn relying party ID (bare domain, e.g. login.example.com); empty derives it from -server-url")
		passkeyDisplayName = flag.String("passkey-display-name", "",
			"relying party name authenticators show (defaults to the RP ID)")
		dnsWebhook = flag.String("dns-webhook-url", "",
			"HTTPS endpoint that applies DNS record changes for ACME DNS-01 (enables certificates)")
		dnsWebhookTokenEnv = flag.String("dns-webhook-token-env", "XUNARA_DNS_WEBHOOK_TOKEN",
			"environment variable holding the DNS webhook bearer token")
		cfZone     = flag.String("dns-cloudflare-zone", "", "Cloudflare zone for ACME DNS-01 (enables certificates)")
		cfTokenEnv = flag.String("dns-cloudflare-token-env", "XUNARA_CLOUDFLARE_API_TOKEN",
			"environment variable holding the Cloudflare API token")
		orgConfigPath = flag.String("org-config", "",
			"JSON file listing organizations to host (multi-tenant mode; mutually exclusive with the per-organization flags)")
		platformTokenEnv = flag.String("platform-token-env", "XUNARA_PLATFORM_ADMIN_TOKEN",
			"environment variable holding the /api/platform bearer token (multi-tenant mode)")
		grpcListen = flag.String("grpc-listen", "",
			"address for the platform gRPC API (xunara.v2); empty disables gRPC")
		platformStateDir = flag.String("platform-state-dir", "",
			"directory holding the platform registry and platform-managed organizations; empty disables runtime organization CRUD")
		plansFile = flag.String("plans", "",
			"JSON file with the plans this deployment sells, or 'builtin' for the shipped free/pro/business catalog; empty disables plan quotas")
		networkPool = flag.String("network-pool", "100.100.0.0/16",
			"range tenant tailnet blocks are allocated from, carved into /24s; 'none' disables automatic allocation")
		webhookURL = flag.String("webhook-url", "",
			"HTTPS endpoint that receives audit events (enables webhook delivery)")
		webhookSecretEnv = flag.String("webhook-secret-env", "XUNARA_WEBHOOK_SECRET",
			"environment variable holding the webhook HMAC signing secret")
		serviceHealthTTL = flag.Duration("services-health-ttl", control.DefaultServiceHealthTTL,
			"how long a service readiness report stays valid before the service is withdrawn from discovery")
		idTokenRateLimit = flag.Int("id-token-rate-limit", control.DefaultIDTokenRateLimit,
			"identity tokens one node may obtain per audience per minute (0 uses the default)")
		reachEnabled = flag.Bool("reach", false,
			"enable Xunara Reach remote command execution (agents must be re-run with -reach too)")
		fluxEnabled = flag.Bool("flux", false,
			"enable Xunara Flux file transfers between agents (ciphertext is stored under -state-dir)")
		fluxDir = flag.String("flux-dir", "",
			"directory for Flux ciphertext (default <state-dir>/flux)")
		fluxMaxSize = flag.Int64("flux-max-size", 0,
			"Flux plaintext size limit per transfer in bytes (default 8 MiB, hard cap 64 MiB)")
		fluxTTL = flag.Duration("flux-ttl", 0,
			"how long a Flux transfer may stay active (default 1h, max 24h)")
		webhookEvents = flag.String("webhook-events", "",
			"comma-separated audit action globs to deliver (default all events)")
	)
	var (
		nameservers    stringListFlag
		dnsRoutes      stringListFlag
		certDomains    stringListFlag
		passkeyOrigins stringListFlag
	)
	flag.Var(&nameservers, "nameserver", "global DNS resolver (IP or IP:port); repeatable")
	flag.Var(&dnsRoutes, "dns-route", "split-DNS entry suffix=resolver[,resolver]; repeatable")
	flag.Var(&certDomains, "cert-domain", "extra DNS name clients may obtain TLS certificates for; repeatable")
	flag.Var(&passkeyOrigins, "passkey-origin", "allowed WebAuthn origin (repeatable); empty derives it from -server-url")
	flag.Parse()

	// Packaging and install scripts need the version without starting the
	// server, so answer it before any configuration is validated.
	if *showVersion {
		fmt.Println("xunarad " + control.Version)
		return
	}

	logger := newLogger(*logLevel)

	// Multi-tenant mode routes by Host and takes every organization-level
	// setting from the config file, so mixing in the single-tenant flags would
	// be ambiguous. Refuse instead of guessing.
	if *orgConfigPath != "" {
		if err := rejectOrgScopedFlags(); err != nil {
			logger.Error("invalid configuration", "err", err)
			os.Exit(1)
		}
		runRouter(routerOptions{
			path:             *orgConfigPath,
			listen:           *listen,
			grpcListen:       *grpcListen,
			platformTokenEnv: *platformTokenEnv,
			platformStateDir: *platformStateDir,
			trustedProxy:     *trustedProxy,
			consoleTimezone:  *consoleTimezone,
			plansFile:        *plansFile,
			networkPool:      *networkPool,
		}, logger)
		return
	}
	if *platformStateDir != "" {
		logger.Error("-platform-state-dir requires -org-config (platform-managed organizations are a multi-tenant feature)")
		os.Exit(1)
	}

	if *serverURL == "" {
		*serverURL = "http://" + *listen
	}

	derpMap, err := loadDERPMap(*derpMapPath)
	if err != nil {
		logger.Error("loading DERP map", "err", err)
		os.Exit(1)
	}

	routes, err := parseDNSRouteFlags(dnsRoutes)
	if err != nil {
		logger.Error("parsing -dns-route", "err", err)
		os.Exit(1)
	}

	dnsProvider, err := buildDNSProvider(*dnsWebhook, *dnsWebhookTokenEnv, *cfZone, *cfTokenEnv)
	if err != nil {
		logger.Error("configuring the DNS provider", "err", err)
		os.Exit(1)
	}

	// The client secret is read from the environment, never from a flag:
	// process arguments are visible to every user on the host.
	var oidcProviders []identity.OIDCConfig
	if *oidcIssuer != "" {
		oidcProviders = append(oidcProviders, identity.OIDCConfig{
			ID:          *oidcID,
			DisplayName: *oidcID,
			Issuer:      *oidcIssuer,
			ClientID:    *oidcClient,
			// XUNARA_OIDC_CLIENT_SECRET keeps the secret out of argv.
			ClientSecret: os.Getenv("XUNARA_OIDC_CLIENT_SECRET"),
			RedirectURL:  *oidcRedirect,
			Scopes:       splitCSV(*oidcScopes),
		})
	}

	var webhooks []webhook.Endpoint
	if *webhookURL != "" {
		secret := os.Getenv(*webhookSecretEnv)
		if secret == "" {
			logger.Error("webhook delivery needs a signing secret", "env", *webhookSecretEnv)
			os.Exit(1)
		}
		webhooks = append(webhooks, webhook.Endpoint{
			ID:     "default",
			URL:    *webhookURL,
			Secret: secret,
			Events: splitCSV(*webhookEvents),
		})
	}

	derpPolicyValue, err := control.ParseDERPPolicy(*derpPolicy, *derpRegions)
	if err != nil {
		logger.Error("parsing the DERP policy", "err", err)
		os.Exit(1)
	}

	passkeyCfg, err := buildPasskeyConfig(*passkey, *serverURL, *passkeyRPID, *passkeyDisplayName, passkeyOrigins)
	if err != nil {
		logger.Error("invalid passkey configuration", "err", err)
		os.Exit(1)
	}
	if *passkey && passkeyCfg == nil {
		logger.Warn("passkey sign-in is disabled: -server-url cannot serve as a WebAuthn relying party (use -passkey-rpid/-passkey-origin, or -passkey=false to silence this)")
	}

	fluxCfg, err := fluxConfigFor(*fluxEnabled, *fluxDir, *fluxMaxSize, *fluxTTL)
	if err != nil {
		logger.Error("invalid flux configuration", "err", err)
		os.Exit(1)
	}

	registrationMode, err := control.ParseRegistrationMode(*registration)
	if err != nil {
		logger.Error("invalid configuration", "err", err)
		os.Exit(1)
	}

	// Self-hosted deployments do not sell plans, so the commercial layer stays
	// off unless the operator asks for it with -plans. When it is on, the
	// single tenant is the deployment itself ("default").
	var plans *control.PlanRegistry
	if *plansFile != "" {
		plans, err = loadPlanRegistry(context.Background(), filepath.Join(*stateDir, "plans.db"), *plansFile, *networkPool)
		if err != nil {
			logger.Error("opening the tenant plan registry", "err", err)
			os.Exit(1)
		}
		defer plans.Close()
	}

	srv, err := control.New(control.Config{
		ServerURL:           *serverURL,
		ListenAddr:          *listen,
		GRPCListenAddr:      *grpcListen,
		StateDir:            *stateDir,
		Domain:              *domain,
		Nameservers:         nameservers,
		DNSRoutes:           routes,
		PolicyPath:          *policyPath,
		DERPMap:             derpMap,
		DERPPolicy:          derpPolicyValue,
		LatestClientVersion: *clientVer,
		ClientVersionURL:    *clientVerURL,
		ConsoleTimezone:     *consoleTimezone,
		OIDCProviders:       oidcProviders,
		AllowLocalLogin:     *allowLocalLogin,
		Registration:        registrationMode,
		TrustedProxy:        *trustedProxy,
		Passkeys:            passkeyCfg,
		CertDomains:         certDomains,
		DNSProvider:         dnsProvider,
		ServiceHealthTTL:    *serviceHealthTTL,
		IDTokenRateLimit:    *idTokenRateLimit,
		ReachEnabled:        *reachEnabled,
		Flux:                fluxCfg,
		Webhooks:            webhooks,
		PlanSource:          planSourceFor(plans),
		Logger:              logger,
	})
	if err != nil {
		logger.Error("initializing server", "err", err)
		os.Exit(1)
	}
	defer srv.Close()

	if plans != nil {
		if prefix, ok := plans.NetworkPrefix(context.Background(), srv.TenantID()); ok {
			if err := srv.SetAddressPrefix(prefix); err != nil {
				logger.Error("applying the tenant network range", "err", err)
				os.Exit(1)
			}
		}
		logger.Info("commercial plans enabled",
			"default", plans.Catalog().Default().ID, "pool", plans.Pool().Prefix().String())
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// A single-tenant deployment that configures a platform token also gets
	// the platform API and the /admin entry point. Without the router those
	// routes exist only in multi-tenant mode, which would leave a self-hosted
	// installation unable to use the administrator console at all.
	if platformToken := os.Getenv(*platformTokenEnv); platformToken != "" {
		if err := serveSingleTenantPlatform(srv, plans, platformToken, *listen, *grpcListen, *domain, logger, ctx); err != nil {
			logger.Error("server error", "err", err)
			os.Exit(1)
		}
		return
	}

	if err := srv.Serve(ctx); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}

// serveSingleTenantPlatform serves one organization through a [control.Router]
// so that /api/platform/v1 and /admin exist. The router owns the site from
// here on: it starts its background workers and closes it when serving stops.
func serveSingleTenantPlatform(srv *control.Server, plans *control.PlanRegistry, platformToken, listen, grpcListen, domain string, logger *slog.Logger, ctx context.Context) error {
	name := strings.TrimSpace(domain)
	if name == "" {
		name = srv.TenantID()
	}
	router, err := control.NewRouter(control.RouterConfig{
		ListenAddr:     listen,
		GRPCListenAddr: grpcListen,
		// A single site without domains becomes the fallback for every host,
		// which is exactly how a single-tenant deployment is addressed.
		Orgs:               []control.OrgSite{{ID: srv.TenantID(), Name: name, Server: srv}},
		PlatformAdminToken: platformToken,
		Plans:              plans,
		Logger:             logger,
	})
	if err != nil {
		return err
	}
	logger.Info("platform API enabled for the single-tenant deployment",
		"tenant", srv.TenantID(), "admin", "/admin", "platform_api", "/api/platform/v1")
	return router.Serve(ctx)
}

// orgScopedFlags are the flags that describe a single organization. They are
// rejected in -org-config mode, where the config file owns them.
var orgScopedFlags = []string{
	"state-dir", "server-url", "domain", "policy", "nameserver", "dns-route",
	"derp-map", "derp-policy", "derp-regions", "client-version", "client-version-url",
	"oidc-issuer", "oidc-id", "oidc-client-id", "oidc-redirect-url", "oidc-scopes",
	"allow-local-login", "registration", "cert-domain",
	"passkey", "passkey-rpid", "passkey-origin", "passkey-display-name",
	"services-health-ttl", "id-token-rate-limit", "reach",
	"flux", "flux-dir", "flux-max-size", "flux-ttl",
	"dns-webhook-url", "dns-webhook-token-env",
	"dns-cloudflare-zone", "dns-cloudflare-token-env",
	"webhook-url", "webhook-secret-env", "webhook-events",
}

// rejectOrgScopedFlags fails when the operator combined -org-config with a
// flag that belongs to the single-organization configuration.
func rejectOrgScopedFlags() error {
	var visited []string
	flag.Visit(func(f *flag.Flag) { visited = append(visited, f.Name) })
	return checkOrgScopedFlags(visited)
}

// checkOrgScopedFlags is the pure part of [rejectOrgScopedFlags].
func checkOrgScopedFlags(visited []string) error {
	var offending []string
	for _, name := range visited {
		for _, scoped := range orgScopedFlags {
			if name == scoped {
				offending = append(offending, "-"+name)
			}
		}
	}
	if len(offending) == 0 {
		return nil
	}
	return fmt.Errorf("-org-config cannot be combined with %s; move them into the config file",
		strings.Join(offending, ", "))
}

// runRouter serves a multi-tenant deployment until the process is signalled.
// When platformStateDir is set, the platform API may also create and delete
// organizations at runtime; their control planes live under that directory.
// routerOptions are the multi-tenant deployment's process-level settings.
type routerOptions struct {
	path             string
	listen           string
	grpcListen       string
	platformTokenEnv string
	platformStateDir string
	trustedProxy     bool
	consoleTimezone  string
	plansFile        string
	networkPool      string
}

// planSourceFor turns a plan registry into the control plane's plan source.
// A nil registry keeps the deployment on the unlimited plan.
func planSourceFor(registry *control.PlanRegistry) func(tenantID string) plan.Plan {
	if registry == nil {
		return nil
	}
	return func(tenantID string) plan.Plan {
		return registry.Plan(context.Background(), tenantID)
	}
}

// loadPlanRegistry opens the tenant plan registry (spec section 54). It also
// returns the catalog the deployment sells: the file when -plans names one,
// the built-in catalog otherwise. It returns (nil, nil) when the deployment
// does not sell plans, which is the self-hosted default.
func loadPlanRegistry(ctx context.Context, dbPath, plansFile, networkPool string) (*control.PlanRegistry, error) {
	catalog := plan.DefaultCatalog()
	if plansFile != "" && !strings.EqualFold(strings.TrimSpace(plansFile), "builtin") {
		raw, err := os.ReadFile(plansFile)
		if err != nil {
			return nil, err
		}
		catalog, err = plan.ParseCatalog(raw)
		if err != nil {
			return nil, err
		}
	}

	var pool netspace.Pool
	if !strings.EqualFold(strings.TrimSpace(networkPool), "none") && strings.TrimSpace(networkPool) != "" {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(networkPool))
		if err != nil {
			return nil, fmt.Errorf("-network-pool: %w", err)
		}
		if pool, err = netspace.NewPool(prefix, netspace.DefaultBlockBits); err != nil {
			return nil, err
		}
	}

	return control.OpenPlanRegistry(ctx, control.PlanRegistryConfig{
		Path:     dbPath,
		Catalog:  catalog,
		Pool:     pool,
		Reserved: []netip.Prefix{state.ShareMasqIPv4Prefix, state.ShareMasqIPv6Prefix},
	})
}

func runRouter(opts routerOptions, logger *slog.Logger) {
	path, listen, grpcListen, platformTokenEnv, platformStateDir, consoleTimezone, plansFile, networkPool :=
		opts.path, opts.listen, opts.grpcListen, opts.platformTokenEnv, opts.platformStateDir, opts.consoleTimezone, opts.plansFile, opts.networkPool
	sites, selfService, err := loadOrgConfig(path, logger, opts.trustedProxy)
	if err != nil {
		logger.Error("loading the organization table", "err", err)
		os.Exit(1)
	}

	platformToken := os.Getenv(platformTokenEnv)
	if platformToken == "" {
		logger.Warn("platform API disabled: environment variable is empty",
			"env", platformTokenEnv)
	}

	var registry *control.OrgRegistry
	var shares *control.ShareRegistry
	var plans *control.PlanRegistry
	if plansFile != "" && platformStateDir == "" {
		logger.Error("-plans needs -platform-state-dir in multi-tenant mode: the registry holds the assignments")
		os.Exit(1)
	}
	if platformStateDir != "" {
		plans, err = loadPlanRegistry(context.Background(), filepath.Join(platformStateDir, "plans.db"), plansFile, networkPool)
		if err != nil {
			for _, site := range sites {
				_ = site.Server.Close()
			}
			logger.Error("opening the tenant plan registry", "err", err)
			os.Exit(1)
		}
		if platformToken == "" {
			logger.Error("platform-managed organizations need a platform token",
				"env", platformTokenEnv)
			os.Exit(1)
		}
		registry, err = control.OpenOrgRegistry(context.Background(), control.OrgRegistryConfig{
			Path:      filepath.Join(platformStateDir, "platform.db"),
			StateRoot: filepath.Join(platformStateDir, "orgs"),
			// Managed organizations inherit the deployment's process-level
			// settings (the logger and nothing that carries a secret).
			NewServer: func(org control.ManagedOrg, stateDir string) (*control.Server, error) {
				return control.New(control.Config{
					ServerURL:       org.ServerURL,
					Domain:          org.Domain,
					StateDir:        stateDir,
					ConsoleTimezone: consoleTimezone,
					TrustedProxy:    opts.trustedProxy,
					Logger:          logger,
				})
			},
		})
		if err != nil {
			logger.Error("opening the platform organization registry", "err", err)
			os.Exit(1)
		}
		// The share registry is platform-scoped, like the organization table:
		// one authoritative place to see every cross-organization share
		// (PROJECT_SPEC section 38.2). Its presence is what enables sharing.
		shares, err = control.OpenShareRegistry(context.Background(), control.ShareRegistryConfig{
			Path: filepath.Join(platformStateDir, "shares.db"),
		})
		if err != nil {
			_ = registry.Close()
			logger.Error("opening the platform share registry", "err", err)
			os.Exit(1)
		}
	}

	router, err := control.NewRouter(control.RouterConfig{
		ListenAddr:         listen,
		GRPCListenAddr:     grpcListen,
		Orgs:               sites,
		PlatformAdminToken: platformToken,
		Registry:           registry,
		Shares:             shares,
		Plans:              plans,
		SelfService:        selfService,
		Logger:             logger,
	})
	if err != nil {
		for _, site := range sites {
			_ = site.Server.Close()
		}
		if registry != nil {
			_ = registry.Close()
		}
		if shares != nil {
			_ = shares.Close()
		}
		if plans != nil {
			_ = plans.Close()
		}
		logger.Error("initializing the organization router", "err", err)
		os.Exit(1)
	}
	defer router.Close()

	for _, site := range sites {
		logger.Info("organization hosted",
			"id", site.ID, "name", site.Name, "domains", strings.Join(site.Domains, ","))
	}
	if plans != nil {
		ids := make([]string, 0, len(plans.Catalog().List()))
		for _, p := range plans.Catalog().List() {
			ids = append(ids, p.ID)
		}
		logger.Info("commercial plans enabled",
			"default", plans.Catalog().Default().ID, "plans", strings.Join(ids, ","),
			"pool", plans.Pool().Prefix().String())
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := router.Serve(ctx); err != nil {
		logger.Error("server error", "err", err)
		os.Exit(1)
	}
}

// buildDNSProvider assembles the external DNS writer for ACME DNS-01 from
// flags. API tokens are read from the environment: process arguments are
// visible to every user on the host (AGENTS.md section 8).
func buildDNSProvider(webhookURL, webhookTokenEnv, cfZone, cfTokenEnv string) (control.DNSProvider, error) {
	switch {
	case webhookURL != "" && cfZone != "":
		return nil, fmt.Errorf("configure either -dns-webhook-url or -dns-cloudflare-zone, not both")
	case webhookURL != "":
		return dnsprovider.NewWebhook(webhookURL, os.Getenv(webhookTokenEnv))
	case cfZone != "":
		token := os.Getenv(cfTokenEnv)
		if token == "" {
			return nil, fmt.Errorf("dnsprovider: set %s to the Cloudflare API token", cfTokenEnv)
		}
		return dnsprovider.NewCloudflare(cfZone, token)
	}
	return nil, nil
}

// stringListFlag collects a repeatable string flag.
type stringListFlag []string

func (f *stringListFlag) String() string { return strings.Join(*f, ",") }

func (f *stringListFlag) Set(v string) error {
	*f = append(*f, v)
	return nil
}

// parseDNSRouteFlags turns "suffix=resolver[,resolver]" entries into the map
// control.Config expects.
func parseDNSRouteFlags(entries []string) (map[string][]string, error) {
	if len(entries) == 0 {
		return nil, nil
	}

	out := make(map[string][]string, len(entries))
	for _, entry := range entries {
		suffix, resolvers, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("%q is not of the form suffix=resolver[,resolver]", entry)
		}
		suffix = strings.TrimSpace(suffix)
		if suffix == "" {
			return nil, fmt.Errorf("%q has an empty suffix", entry)
		}

		var list []string
		for _, r := range strings.Split(resolvers, ",") {
			if r = strings.TrimSpace(r); r != "" {
				list = append(list, r)
			}
		}
		out[suffix] = list
	}
	return out, nil
}

// loadDERPMap reads a tailcfg.DERPMap JSON document, returning nil when no path
// is configured.
func loadDERPMap(path string) (*tailcfg.DERPMap, error) {
	if path == "" {
		return nil, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var m tailcfg.DERPMap
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &m, nil
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

// splitCSV splits a comma-separated flag value, dropping empty entries.
func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
