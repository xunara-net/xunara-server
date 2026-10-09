package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"google.golang.org/grpc"
	"tailscale.com/tailcfg"
)

// This file hosts several organizations on one listener. Each organization is
// a full [Server] with its own state store, policy, DNS provider and identity
// store, so tenant isolation is by construction instead of by query filters
// (AGENTS.md section 12). Requests are dispatched by Host: the DNS name a
// client was configured with decides the organization, mirroring how a
// Tailscale login server is per-tailnet.

// OrgSite is one organization hosted by a [Router].
type OrgSite struct {
	// ID is the stable organization identifier, e.g. "acme".
	ID string
	// Name is the human-readable organization name.
	Name string
	// Domains are the request hosts routed to this organization. Entries are
	// exact hosts ("login.acme.example.com") or single-label wildcards
	// ("*.acme.example.com"). Empty is only allowed when the deployment has
	// exactly one site, which then becomes the fallback for every host.
	Domains []string
	// Server is the organization's control plane.
	Server *Server
}

// RouterConfig configures a [Router].
type RouterConfig struct {
	// ListenAddr is the address the HTTP server binds to.
	ListenAddr string
	// GRPCListenAddr is the address the platform gRPC API binds to. The
	// organization is chosen by the gRPC authority, mirroring HTTP Host
	// routing, so one listener serves every organization. Empty disables the
	// gRPC surface.
	GRPCListenAddr string
	// Orgs are the organizations to serve. At least one is required.
	Orgs []OrgSite
	// PlatformAdminToken authorizes /api/platform/*. It is compared in
	// constant time with the request's bearer token. Empty disables the
	// platform API (fail closed).
	PlatformAdminToken string
	// Registry, when non-nil, enables platform-managed organizations: the
	// platform API can create, retarget and delete organizations at runtime,
	// and the registry's rows are served alongside the configured ones.
	// Managed organizations must declare domains, so enabling the registry
	// requires every configured organization to declare domains too.
	Registry *OrgRegistry
	// Shares, when non-nil, enables Xunara Share: a machine can be shared with
	// a user in another organization hosted by this router (spec section 38).
	Shares *ShareRegistry
	// SelfService, when non-nil, turns the deployment's front door into a
	// sign-up desk: POST /api/self-service/v1/signup on the named
	// organization's hosts creates a brand-new organization per account, the
	// tenant model of a hosted deployment (selfservice.go).
	SelfService *SelfServiceConfig
	// Plans, when non-nil, turns on the commercial layer (spec section 54):
	// every organization is on a plan from the registry's catalog, quotas are
	// enforced by its control plane, and each tenant's devices are allocated
	// from the network block the registry holds for it.
	Plans         *PlanRegistry
	SharedDERPMap *tailcfg.DERPMap
	// Logger receives router logs. Defaults to slog.Default.
	Logger *slog.Logger
}

// Router dispatches requests to organizations by Host.
type Router struct {
	cfg RouterConfig
	log *slog.Logger

	// mu guards the organization table below. Requests read it on every
	// dispatch, so platform CRUD takes it for writing.
	mu sync.RWMutex
	// orgs are the served organizations: configured ones first, then managed
	// ones in registry order.
	orgs []*routerOrg

	// fallback is set when exactly one organization exists and declares no
	// domains; it receives every request regardless of Host, preserving
	// single-organization deployments (and tests that use a synthetic host).
	fallback *routerOrg

	// startCtx is the context [Router.Start] received; organizations created
	// while the router serves are started with it.
	startCtx context.Context
	started  bool

	// selfService is the deployment's sign-up desk, or nil when it has none.
	// It is written once, before the router serves, and read per request.
	selfService atomic.Pointer[selfService]

	// platformTokenHash is the SHA-256 of the platform admin token; hashing
	// equalizes lengths so the constant-time comparison does not leak the
	// token's length.
	platformTokenHash [32]byte

	startOnce sync.Once
}

// routerOrg is an [OrgSite] with its routing state precomputed.
type routerOrg struct {
	site     OrgSite
	patterns []string
	handler  http.Handler
	// managed marks an organization created through the platform API, which
	// may be updated or deleted at runtime; configured ones may not.
	managed bool
	// record is the registry row of a managed organization; the zero value
	// for configured ones.
	record ManagedOrg
}

// Errors the platform CRUD maps to HTTP responses.
var (
	errManagedOrgsDisabled = errors.New("platform-managed organizations are disabled")
	errOrgConfigured       = errors.New("this organization is configured at startup")
)

// NewRouter validates the organization table and prepares the per-site
// handlers.
func NewRouter(cfg RouterConfig) (*Router, error) {
	cfg.SharedDERPMap = cfg.SharedDERPMap.Clone()
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:8080"
	}
	if len(cfg.Orgs) == 0 {
		return nil, errors.New("control: router needs at least one organization")
	}

	r := &Router{cfg: cfg, log: cfg.Logger}
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, site := range cfg.Orgs {
		if err := r.register(site, false); err != nil {
			return nil, err
		}
	}

	if len(r.orgs) == 1 && len(r.orgs[0].patterns) == 0 {
		r.fallback = r.orgs[0]
	}
	for _, org := range r.orgs {
		if len(org.patterns) == 0 && org != r.fallback {
			return nil, fmt.Errorf("control: organization %q has no domains and is not the only organization", org.site.ID)
		}
	}

	if cfg.Registry != nil {
		if r.fallback != nil {
			return nil, errors.New("control: platform-managed organizations require every configured organization to declare domains")
		}
		if err := r.loadManagedOrgs(); err != nil {
			return nil, err
		}
	}

	if cfg.PlatformAdminToken != "" {
		r.platformTokenHash = sha256Sum(cfg.PlatformAdminToken)
	}

	if cfg.SelfService != nil {
		// mu is still held here: the desk is attached to the organization
		// table the caller just built.
		if err := r.enableSelfServiceLocked(); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// register adds one organization to the routing table. The caller holds mu.
func (r *Router) register(site OrgSite, managed bool) error {
	if site.ID == "" {
		return errors.New("control: organization ID is required")
	}
	if site.Server == nil {
		return fmt.Errorf("control: organization %q has no server", site.ID)
	}
	if r.orgByIDLocked(site.ID) != nil {
		return fmt.Errorf("control: duplicate organization ID %q", site.ID)
	}

	org := &routerOrg{site: site, handler: site.Server.Handler(), managed: managed}
	if r.cfg.Shares != nil {
		site.Server.enableSharing(r.cfg.Shares, r)
	}
	if err := r.applyPlans(org); err != nil {
		return err
	}
	// Host routing is the authority on which organization a request belongs
	// to, so the server learns its own identity from the site it serves
	// (spec section 30).
	site.Server.setOrganization(OrgIdentity{
		ID:      site.ID,
		Name:    site.Name,
		Domains: site.Domains,
		Managed: managed,
	})
	for _, domain := range site.Domains {
		pattern, err := normalizeRouterDomain(domain)
		if err != nil {
			return fmt.Errorf("control: organization %q: %w", site.ID, err)
		}
		if other := r.domainOwner(pattern); other != "" {
			return fmt.Errorf("control: domain %q is claimed by organizations %q and %q",
				pattern, other, site.ID)
		}
		org.patterns = append(org.patterns, pattern)
	}
	if managed && len(org.patterns) == 0 {
		return fmt.Errorf("control: managed organization %q has no domains", site.ID)
	}

	r.orgs = append(r.orgs, org)
	return nil
}

// domainOwner returns the organization that already claims a routing pattern.
// The caller holds mu.
func (r *Router) domainOwner(pattern string) string {
	for _, org := range r.orgs {
		if slices.Contains(org.patterns, pattern) {
			return org.site.ID
		}
	}
	return ""
}

// loadManagedOrgs builds the control plane of every registered organization.
// The caller holds mu.
func (r *Router) loadManagedOrgs() error {
	records, err := r.cfg.Registry.List(context.Background())
	if err != nil {
		return err
	}
	for _, record := range records {
		server, err := r.cfg.Registry.NewServer(record)
		if err != nil {
			return fmt.Errorf("control: starting managed organization %q: %w", record.ID, err)
		}
		if err := r.register(OrgSite{
			ID:      record.ID,
			Name:    record.Name,
			Domains: record.Domains,
			Server:  server,
		}, true); err != nil {
			_ = server.Close()
			return err
		}
		r.orgs[len(r.orgs)-1].record = record
	}
	return nil
}

// orgByIDLocked returns the organization with this ID, or nil. The caller
// holds mu.
func (r *Router) orgByIDLocked(id string) *routerOrg {
	for _, org := range r.orgs {
		if org.site.ID == id {
			return org
		}
	}
	return nil
}

// orgByID returns the organization with this ID, or nil.
func (r *Router) orgByID(id string) *routerOrg {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.orgByIDLocked(id)
}

// orgSnapshot copies the served organization list for read-only iteration.
func (r *Router) orgSnapshot() []*routerOrg {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]*routerOrg(nil), r.orgs...)
}

// CreateManagedOrg persists, builds and serves a new platform-managed
// organization. The registry row is written first and rolled back if the
// control plane cannot start, so a failure never claims the ID.
func (r *Router) CreateManagedOrg(ctx context.Context, org ManagedOrg) (OrgSite, error) {
	registry := r.cfg.Registry
	if registry == nil {
		return OrgSite{}, errManagedOrgsDisabled
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := validateManagedOrg(org); err != nil {
		return OrgSite{}, err
	}
	if r.orgByIDLocked(org.ID) != nil {
		return OrgSite{}, orgConflictf("organization %q already exists", org.ID)
	}
	patterns, err := normalizeManagedDomains(org.Domains)
	if err != nil {
		return OrgSite{}, err
	}
	for _, pattern := range patterns {
		if other := r.domainOwner(pattern); other != "" {
			return OrgSite{}, orgConflictf("domain %q is already used by organization %q", pattern, other)
		}
	}

	record, err := registry.Create(ctx, org)
	if err != nil {
		return OrgSite{}, err
	}

	server, err := registry.NewServer(record)
	if err != nil {
		r.rollbackManagedOrg(ctx, record.ID, nil)
		return OrgSite{}, err
	}
	site := OrgSite{ID: record.ID, Name: record.Name, Domains: record.Domains, Server: server}
	if err := r.register(site, true); err != nil {
		r.rollbackManagedOrg(ctx, record.ID, server)
		return OrgSite{}, err
	}
	r.orgs[len(r.orgs)-1].record = record

	// A router that already serves starts the new organization's background
	// workers; one that has not started yet does so in Start.
	if r.started {
		server.Start(r.startCtx)
	}
	return site, nil
}

// UpdateManagedOrg changes the mutable fields of a managed organization: its
// name and its routing domains. ID, server URL and MagicDNS domain stay fixed —
// clients are configured with the URL, and the ID names the state directory.
// The changes are persisted before any request is rerouted.
func (r *Router) UpdateManagedOrg(ctx context.Context, id string, name *string, domains []string) (OrgSite, error) {
	registry := r.cfg.Registry
	if registry == nil {
		return OrgSite{}, errManagedOrgsDisabled
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	org := r.orgByIDLocked(id)
	if org == nil {
		return OrgSite{}, ErrOrgNotFound
	}
	if !org.managed {
		return OrgSite{}, errOrgConfigured
	}

	updated := org.record
	if name != nil {
		updated.Name = *name
	}
	if domains != nil {
		updated.Domains = domains
	}
	if err := validateManagedOrg(updated); err != nil {
		return OrgSite{}, err
	}
	patterns, err := normalizeManagedDomains(updated.Domains)
	if err != nil {
		return OrgSite{}, err
	}
	for _, pattern := range patterns {
		if other := r.domainOwner(pattern); other != "" && other != id {
			return OrgSite{}, orgConflictf("domain %q is already used by organization %q", pattern, other)
		}
	}

	record, err := registry.Update(ctx, updated)
	if err != nil {
		return OrgSite{}, err
	}
	org.site.Name = record.Name
	org.site.Domains = append([]string(nil), record.Domains...)
	org.patterns = patterns
	org.record = record
	org.site.Server.setOrganization(OrgIdentity{
		ID:      org.site.ID,
		Name:    org.site.Name,
		Domains: org.site.Domains,
		Managed: true,
	})
	return org.site, nil
}

// DeleteManagedOrg stops serving an organization and archives its state
// directory. The directory is moved aside before anything else changes, so a
// re-created ID starts from an empty directory rather than inheriting the old
// identity database and Noise key.
func (r *Router) DeleteManagedOrg(ctx context.Context, id string) (string, error) {
	registry := r.cfg.Registry
	if registry == nil {
		return "", errManagedOrgsDisabled
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	org := r.orgByIDLocked(id)
	if org == nil {
		return "", ErrOrgNotFound
	}
	if !org.managed {
		return "", errOrgConfigured
	}

	archived, err := registry.ArchiveState(id)
	if err != nil {
		return "", err
	}

	r.removeOrgLocked(org)
	if err := org.site.Server.Close(); err != nil {
		r.log.Warn("closing a deleted organization", "organization", id, "err", err)
	}
	if err := registry.Delete(ctx, id); err != nil {
		return archived, err
	}
	return archived, nil
}

// removeOrgLocked drops one organization from the routing table. The caller
// holds mu.
func (r *Router) removeOrgLocked(target *routerOrg) {
	kept := r.orgs[:0]
	for _, org := range r.orgs {
		if org != target {
			kept = append(kept, org)
		}
	}
	r.orgs = kept
}

// rollbackManagedOrg undoes a partially created managed organization: the
// control plane is closed (when one was built) and the registry row removed.
// The caller holds mu.
func (r *Router) rollbackManagedOrg(ctx context.Context, id string, server *Server) {
	if server != nil {
		_ = server.Close()
	}
	if err := r.cfg.Registry.Delete(ctx, id); err != nil && !errors.Is(err, ErrOrgNotFound) {
		r.log.Error("rolling back a managed organization row", "organization", id, "err", err)
	}
}

// Close releases every organization's durable resources.
func (r *Router) Close() error {
	r.mu.Lock()
	orgs := r.orgs
	r.orgs = nil
	r.fallback = nil
	registry := r.cfg.Registry
	shares := r.cfg.Shares
	plans := r.cfg.Plans
	r.mu.Unlock()

	var errs []error
	for _, org := range orgs {
		if err := org.site.Server.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", org.site.ID, err))
		}
	}
	if registry != nil {
		if err := registry.Close(); err != nil {
			errs = append(errs, fmt.Errorf("platform registry: %w", err))
		}
	}
	if shares != nil {
		if err := shares.Close(); err != nil {
			errs = append(errs, fmt.Errorf("share registry: %w", err))
		}
	}
	if plans != nil {
		if err := plans.Close(); err != nil {
			errs = append(errs, fmt.Errorf("plan registry: %w", err))
		}
	}
	return errors.Join(errs...)
}

// Start launches every organization's background workers.
func (r *Router) Start(ctx context.Context) {
	r.startOnce.Do(func() {
		r.mu.Lock()
		r.startCtx = ctx
		r.started = true
		orgs := append([]*routerOrg(nil), r.orgs...)
		r.mu.Unlock()

		for _, org := range orgs {
			org.site.Server.Start(ctx)
		}
	})
}

// Serve runs the HTTP server until ctx is cancelled.
func (r *Router) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              r.cfg.ListenAddr,
		Handler:           r.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	r.Start(ctx)

	// The platform gRPC API is optional; when enabled it runs on its own
	// listener with the HTTP server's lifecycle.
	grpcSrv, grpcLis, err := r.startPlatformGRPC()
	if err != nil {
		return err
	}

	errCh := make(chan error, 2)
	go func() {
		r.log.Info("control server listening",
			"addr", r.cfg.ListenAddr, "organizations", len(r.orgSnapshot()))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	if grpcSrv != nil {
		go func() {
			r.log.Info("platform gRPC listening", "addr", r.cfg.GRPCListenAddr)
			if err := grpcSrv.Serve(grpcLis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				errCh <- err
				return
			}
			errCh <- nil
		}()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		r.log.Info("control server shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpErr := srv.Shutdown(shutdownCtx)
		stopPlatformGRPC(grpcSrv)
		return httpErr
	}
}

// Handler returns the router's public HTTP handler.
func (r *Router) Handler() http.Handler {
	mux := chi.NewRouter()
	mux.Use(middleware.Recoverer)

	// Health and version describe the process, not an organization, so they
	// are answered here rather than leaking through a host-specific site.
	mux.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "pass"})
	})
	mux.Get("/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"version":  Version,
			"mine":     "xunara",
			"protocol": "ts2021",
		})
	})

	mux.Route("/api/platform", func(pr chi.Router) {
		r.mountPlatform(pr)
	})

	// The platform console lives at /admin on every host, next to the
	// process-level endpoints: it is not a tenant surface, so no host's
	// routing decides whether it exists (spec section 54).
	r.mountAdmin(mux)
	if r.cfg.SharedDERPMap != nil {
		mux.Post(relayAdmissionPath, r.handleSharedDERPAdmit)
	}

	// The sign-up desk is platform-level like the console, but it answers
	// only on its own site's hosts: everywhere else the request belongs to
	// that organization and falls through to its handler.
	if r.selfService.Load() != nil {
		mux.Post(selfServiceSignupPath, r.handleSelfServiceSignup)
	}

	mux.NotFound(func(w http.ResponseWriter, req *http.Request) {
		org := r.orgForHost(req.Host)
		if org == nil {
			// Do not enumerate organizations on an unknown host.
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "unknown organization", http.StatusNotFound)
			return
		}
		org.handler.ServeHTTP(w, req)
	})

	return mux
}

// orgForHost returns the organization a request host belongs to.
func (r *Router) orgForHost(hostport string) *routerOrg {
	host := normalizeRouterHost(hostport)
	r.mu.RLock()
	defer r.mu.RUnlock()

	if host != "" {
		var best *routerOrg
		bestLen := -1
		for _, org := range r.orgs {
			for _, pattern := range org.patterns {
				if !matchRouterDomain(pattern, host) {
					continue
				}
				// Prefer the most specific (longest) matching pattern so
				// "login.acme.example.com" beats "*.example.com".
				if len(pattern) > bestLen {
					best, bestLen = org, len(pattern)
				}
			}
		}
		if best != nil {
			return best
		}
	}
	return r.fallback
}

// normalizeRouterHost lowercases a Host header value and strips the port and
// any brackets around an IPv6 literal.
func normalizeRouterHost(hostport string) string {
	host := strings.TrimSpace(hostport)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// normalizeRouterDomain validates and canonicalizes one routing domain.
func normalizeRouterDomain(domain string) (string, error) {
	pattern := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if pattern == "" {
		return "", errors.New("empty routing domain")
	}
	if strings.ContainsAny(pattern, " \t\r\n/\\@:") {
		return "", fmt.Errorf("invalid routing domain %q", domain)
	}
	wildcard := strings.HasPrefix(pattern, "*.")
	base := pattern
	if wildcard {
		base = strings.TrimPrefix(pattern, "*.")
		if base == "" {
			return "", fmt.Errorf("invalid routing domain %q", domain)
		}
	}
	if strings.Contains(base, "*") || !strings.Contains(base, ".") {
		return "", fmt.Errorf("invalid routing domain %q", domain)
	}
	return pattern, nil
}

// matchRouterDomain reports whether a canonical host matches a routing domain
// pattern. A "*.example.com" pattern matches exactly one label in front of the
// suffix, matching DNS wildcard semantics.
func matchRouterDomain(pattern, host string) bool {
	if pattern == host {
		return true
	}
	suffix, ok := strings.CutPrefix(pattern, "*.")
	if !ok {
		return false
	}
	rest, ok := strings.CutSuffix(host, "."+suffix)
	if !ok || rest == "" {
		return false
	}
	return !strings.Contains(rest, ".")
}
