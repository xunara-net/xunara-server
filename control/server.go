package control

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"google.golang.org/grpc"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/idtoken"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/policy"
	"github.com/xunara-net/xunara-server/state"
	"github.com/xunara-net/xunara-server/webhook"
)

// Version is the Xunara server version reported by /version and shown in the
// console footer. A release build overrides it with
// -ldflags "-X github.com/xunara-net/xunara-server/control.Version=<version>"; the
// default keeps a source build honest about being a development snapshot.
var Version = "0.0.0-dev"

// Config configures a [Server].
type Config struct {
	// ServerURL is the externally reachable base URL of this control server,
	// used to build login URLs handed to clients (e.g.
	// "https://login.example.com"). It has no trailing slash.
	ServerURL string
	// ListenAddr is the address the HTTP server binds to.
	ListenAddr string
	// GRPCListenAddr is the address the platform gRPC API binds to. The API
	// speaks the same xunara.v2 service as /api/v2 with the same credentials
	// and scopes; a separate port keeps HTTP/2 cleartext policy explicit.
	// Like ListenAddr it serves cleartext, so deployments must terminate TLS
	// in front of it. Empty disables the gRPC surface.
	GRPCListenAddr string
	// StateDir is the directory holding persistent server state.
	StateDir string
	// DBPath is the SQLite database file. It defaults to <StateDir>/state.db.
	DBPath string
	// Domain is the tailnet's MagicDNS domain, without a trailing dot. Empty
	// disables MagicDNS.
	Domain string
	// Nameservers are the tailnet's global DNS resolvers, in preference order.
	// Entries are IP addresses or "IP:port" pairs; an empty port uses 53.
	Nameservers []string
	// DNSRoutes is the split-DNS table: DNS suffix (without a leading dot) to
	// the resolvers that answer it.
	DNSRoutes map[string][]string
	// DERPMap is advertised to clients when non-nil.
	DERPMap *tailcfg.DERPMap
	// DERPPolicy restricts which DERP regions this organization serves and
	// admits. The zero value inherits DERPMap unchanged.
	DERPPolicy DERPPolicy
	// LatestClientVersion is the newest client version to advertise to clients
	// through MapResponse.ClientVersion, as a short version like "1.88.3".
	// Empty disables the advisory.
	LatestClientVersion string
	// ClientVersionURL, when LatestClientVersion is set, is the URL a client
	// opens when acting on the update notification. Optional.
	ClientVersionURL string
	// NodeKeyExpiry is the lifetime granted to node keys at registration. Zero
	// means keys never expire.
	NodeKeyExpiry time.Duration
	// EphemeralInactivityTimeout is how long an ephemeral node may stay offline
	// before it is reaped. Zero uses the default.
	EphemeralInactivityTimeout time.Duration
	// ServiceHealthTTL bounds how long a service readiness report stays valid
	// (Xunara Atlas, spec section 26). A node that stops reporting has its
	// health-tracked services withdrawn from discovery once the deadline
	// passes. Zero uses [DefaultServiceHealthTTL].
	ServiceHealthTTL time.Duration
	// IDTokenRateLimit is how many identity tokens one node may obtain per
	// audience per minute (spec section 28). Zero uses
	// [DefaultIDTokenRateLimit]; negative is rejected at startup.
	IDTokenRateLimit int
	// ConsoleTimezone is the IANA name the web console prints timestamps in,
	// so operators read audit and expiry times in their own zone instead of
	// UTC. Empty or unknown falls back to UTC; the CLI is unaffected.
	ConsoleTimezone string
	// PolicyPath is the ACL policy document (HuJSON). Empty means the tailnet
	// has no policy and everything is allowed, which is what the official
	// service does for a tailnet without a policy.
	PolicyPath string
	// OIDCProviders configures external OpenID Connect identity providers.
	// Each provider gets its own callback path
	// <ServerURL>/oidc/callback/<provider-id> unless RedirectURL says
	// otherwise.
	OIDCProviders []identity.OIDCConfig
	// Providers are additional identity providers registered as-is (custom
	// adapters and tests). Prefer OIDCProviders for OIDC issuers.
	Providers []identity.IdentityProvider
	// Passkeys enables passkey (WebAuthn) sign-in and console credential
	// management. Nil disables the feature: the endpoints answer 404 and the
	// sign-in page offers no passkey button.
	Passkeys *identity.PasskeyConfig
	// Flux configures Xunara Flux file transfers. Nil (or
	// FluxConfig.Disabled) keeps the feature off and its endpoints answer
	// 404; a non-nil value enables it, with zero fields using the defaults.
	// Like Reach it is opt-in: storing files on behalf of agents must be
	// asked for.
	Flux *FluxConfig
	// ReachEnabled turns on Xunara Reach remote command execution (spec
	// section 29). It is opt-in: running commands on nodes is powerful enough
	// that a deployment must ask for it (agent endpoints answer 404 when off).
	ReachEnabled bool
	// CertDomains are extra DNS names for which clients may obtain TLS
	// certificates, on top of each node's own MagicDNS FQDN. They only take
	// effect when DNSProvider is set: cert issuance needs a public zone the
	// control plane can write ACME DNS-01 challenges to.
	CertDomains []string
	// DNSProvider writes ACME DNS-01 challenge records to the tailnet's
	// public authoritative DNS zone. Nil disables certificate issuance.
	DNSProvider DNSProvider
	// SessionTTL bounds browser sessions. Zero uses identity.DefaultSessionTTL.
	SessionTTL time.Duration
	// AllowLocalLogin enables the built-in local provider even when external
	// providers are configured. It is enabled automatically when no external
	// provider is configured at all.
	AllowLocalLogin bool
	// Registration decides how accounts come into existence (registration.go).
	// Empty means [DefaultRegistrationMode]: self-service sign-up needs an
	// invitation from an administrator.
	Registration RegistrationMode
	// PlanSource reports the commercial plan of a tenant, by tenant ID, when
	// the deployment sells plans (spec section 54). Nil means "no plans":
	// the server runs on plan.UnlimitedPlan and every quota gate is a no-op.
	// Multi-tenant deployments get this from the router's PlanRegistry.
	PlanSource func(tenantID string) plan.Plan
	// Webhooks deliver audit events to operator-configured receivers. Empty
	// disables webhook delivery.
	Webhooks []webhook.Endpoint
	// Logger receives server logs. Defaults to slog.Default.
	Logger *slog.Logger
}

// DefaultEphemeralInactivityTimeout is how long an ephemeral node may stay
// offline before it is deleted.
const DefaultEphemeralInactivityTimeout = 30 * time.Minute

// Service health reporting (spec section 26). The TTL must comfortably exceed
// a sensible reporting interval: the default pairs with the agent's 30s
// cadence, giving three missed reports before a service is withdrawn.
const (
	// DefaultServiceHealthTTL is how long a readiness report stays valid.
	DefaultServiceHealthTTL = 90 * time.Second
	// MinServiceHealthTTL and MaxServiceHealthTTL bound a configured TTL.
	MinServiceHealthTTL = 30 * time.Second
	MaxServiceHealthTTL = 15 * time.Minute
	// serviceHealthSweepInterval is how often the janitor withdraws services
	// whose report expired. It is deliberately shorter than the general
	// janitor cadence: withdrawal is the user-visible half of this feature.
	serviceHealthSweepInterval = 15 * time.Second

	// DefaultIDTokenRateLimit is how many workload identity tokens one node
	// may obtain per audience in [idTokenRateWindow] (spec section 28). It is
	// far above any sane client's refresh cadence and far below what a
	// compromised node would need to exhaust the signing key or annoy a
	// relying party.
	DefaultIDTokenRateLimit = 30
	// idTokenRateWindow is the fixed window of the identity token limiter.
	idTokenRateWindow = time.Minute
	// rateLimitPruneAge is how long an idle bucket is kept before the janitor
	// deletes it. It only needs to exceed the longest window.
	rateLimitPruneAge = time.Hour
)

// ephemeralReapInterval is how often the janitor looks for reaped nodes.
const ephemeralReapInterval = 1 * time.Minute

// Server is the Xunara control plane server.
type Server struct {
	cfg      Config
	log      *slog.Logger
	noiseKey key.MachinePrivate
	store    state.Store
	closer   io.Closer

	// identity is the trust plane: users, external identities and the audit
	// log. It shares the control plane's database.
	identity identity.Store

	// providers is the registry of configured identity providers, and
	// providerRedirects maps a provider to its registered callback URL.
	providers         *identity.Registry
	providerRedirects map[string]string

	// passkeys performs WebAuthn registration and login, or nil when the
	// feature is not configured.
	passkeys *identity.PasskeyService

	// flux holds the normalized Xunara Flux configuration and content
	// directory, or nil when file transfer is disabled.
	flux *fluxServer

	// org is the identity of the organization this server serves when the
	// deployment has an organization table (spec section 30). The router sets
	// it from the registered OrgSite; updates are atomic because the platform
	// API renames organizations while requests read.
	org atomic.Pointer[OrgIdentity]

	// selfService marks this organization as the deployment's sign-up desk
	// (selfservice.go): the console offers "create your own tailnet" only
	// where that is what signing up does.
	selfService atomic.Pointer[SelfServiceInfo]

	// planSource reports the tenant's commercial plan, or nil when the
	// deployment sells none. It is a function rather than a value because a
	// platform operator changes a tenant's plan while the process serves.
	planSource func(tenantID string) plan.Plan

	// consoleLoc is the timezone the web console prints timestamps in. It is
	// loaded once at startup so a broken zone name never fails a request.
	consoleLoc *time.Location

	// secureCookies marks cookies Secure; sessionTTL bounds browser sessions;
	// authTTL bounds pending login transactions.
	secureCookies bool
	sessionTTL    time.Duration
	authTTL       time.Duration

	// localLogin reports whether the built-in password sign-in is offered,
	// and formKey signs the CSRF tokens of the anonymous forms (sign in,
	// first-run setup, registration).
	localLogin bool
	formKey    []byte
	// registration is the normalized self-service registration policy; every
	// sign-up entry point reads it so the HTML page and the JSON API cannot
	// disagree.
	registration RegistrationMode

	// approveMu serialises device approvals so an approval is applied exactly
	// once even under concurrent requests.
	approveMu sync.Mutex

	// resolvers and dnsRoutes are the parsed forms of cfg.Nameservers and
	// cfg.DNSRoutes; parsing happens once, at construction, so a bad
	// configuration fails fast instead of on every netmap build.
	resolvers []*dnstype.Resolver
	dnsRoutes map[string][]*dnstype.Resolver

	// mu guards the registration maps below.
	mu            sync.Mutex
	pending       map[string]*pendingRegistration
	pendingByNode map[key.NodePublic]string

	// policy holds the compiled ACL policy, or nil when the tailnet has none.
	policy atomic.Pointer[policy.Engine]

	// webhooks delivers audit events, or nil when no endpoint is configured.
	webhooks *webhook.Dispatcher

	// tka owns the tailnet's tailnet-lock (TKA) state: the AUM chain and the
	// sealed support disablement secret.
	tka *tkaManager

	// tokens holds the signing keys for the OIDC identity tokens nodes fetch
	// from /machine/id-token, and for the public JWKS a relying party reads. It
	// is nil when no issuer URL is configured: without one there is nothing a
	// relying party could trust, so the endpoint answers 501 instead of
	// minting a token with an empty issuer.
	tokens *idtoken.Keyring

	// certDomains are the extra certificate names from cfg, normalised at
	// construction. Empty when no DNS provider is configured.
	certDomains []string

	// webhookKey seals operator-managed webhook signing secrets at rest. It
	// is generated on first use next to the server's other state.
	webhookKey [32]byte

	// shares is the platform-level cross-organization share registry, and
	// shareDir resolves the other organizations of this router. Both are nil
	// unless the deployment enables Xunara Share (spec section 38).
	shares   *ShareRegistry
	shareDir ShareDirectory

	// aclIngress memoizes per-destination ingress filters for services whose
	// visibility is derived from the ACL (spec section 48).
	aclIngress aclIngressCache

	// derpMap is the DERP map served to this organization's clients after
	// DERPPolicy is applied; nil when there is no map to advertise.
	derpMap *tailcfg.DERPMap

	// derpPolicy is the validated configuration policy used by the DERP
	// admission controller.
	derpPolicy DERPPolicy

	// startOnce guards the background workers started by [Server.Start].
	startOnce sync.Once

	// sessMu guards control-session bookkeeping and netmap change watchers.
	sessMu        sync.Mutex
	online        map[state.NodeID]int
	agentSeen     map[state.NodeID]time.Time
	watchers      map[uint64]chan struct{}
	nextWatcherID uint64
}

// New builds a Server from cfg, creating the state directory and loading (or
// creating) the server's Noise key.
func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:8080"
	}
	if cfg.StateDir == "" {
		cfg.StateDir = "data"
	}
	cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")

	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	if cfg.DBPath == "" {
		cfg.DBPath = filepath.Join(cfg.StateDir, "state.db")
	}
	if cfg.EphemeralInactivityTimeout == 0 {
		cfg.EphemeralInactivityTimeout = DefaultEphemeralInactivityTimeout
	}
	if cfg.ServiceHealthTTL == 0 {
		cfg.ServiceHealthTTL = DefaultServiceHealthTTL
	}
	if cfg.ServiceHealthTTL < MinServiceHealthTTL || cfg.ServiceHealthTTL > MaxServiceHealthTTL {
		return nil, fmt.Errorf("control: service health TTL %v is outside %v..%v",
			cfg.ServiceHealthTTL, MinServiceHealthTTL, MaxServiceHealthTTL)
	}
	if cfg.IDTokenRateLimit == 0 {
		cfg.IDTokenRateLimit = DefaultIDTokenRateLimit
	}
	if cfg.IDTokenRateLimit < 0 {
		return nil, fmt.Errorf("control: identity token rate limit %d must not be negative", cfg.IDTokenRateLimit)
	}
	consoleLoc, err := loadConsoleTimezone(cfg.ConsoleTimezone)
	if err != nil {
		cfg.Logger.Warn("unknown console timezone; the console prints UTC", "timezone", cfg.ConsoleTimezone)
	}

	noiseKey, err := loadOrCreateNoiseKey(cfg.StateDir)
	if err != nil {
		return nil, err
	}

	store, err := state.OpenSQLite(context.Background(), cfg.DBPath)
	if err != nil {
		return nil, err
	}

	identityStore, err := newIdentityStore(store)
	if err != nil {
		store.Close()
		return nil, err
	}

	providers := identity.NewRegistry()
	redirects := make(map[string]string)

	// The built-in local provider is the single-user mode's login method; it
	// is offered by default when no external provider exists. It never
	// authenticates anyone by itself: the password is checked against the
	// local credential store, and a deployment without one has to be set up
	// first (see initSetupToken).
	registration, err := ParseRegistrationMode(string(cfg.Registration))
	if err != nil {
		return nil, err
	}

	localLogin := len(cfg.OIDCProviders) == 0 && len(cfg.Providers) == 0 || cfg.AllowLocalLogin
	// A deployment that cannot sign anyone in cannot sign anyone up either:
	// an account created here would have no way to authenticate. Closing
	// registration is the honest answer, not a 500 on the sign-up page.
	if !localLogin {
		registration = RegistrationClosed
	}
	if localLogin {
		local := identity.LocalLogin{}
		providers.Register(local)
	}
	for _, p := range cfg.Providers {
		if p == nil {
			store.Close()
			return nil, fmt.Errorf("control: nil identity provider")
		}
		providers.Register(p)
		if rp, ok := p.(interface{ RedirectURL() string }); ok {
			redirects[p.ID()] = rp.RedirectURL()
		}
	}
	for _, oc := range cfg.OIDCProviders {
		if oc.ID == "" {
			oc.ID = "oidc"
		}
		if oc.RedirectURL == "" && cfg.ServerURL != "" {
			oc.RedirectURL = cfg.ServerURL + "/oidc/callback/" + oc.ID
		}
		provider, err := identity.NewOIDCProvider(oc)
		if err != nil {
			store.Close()
			return nil, fmt.Errorf("control: %w", err)
		}
		providers.Register(provider)
		redirects[provider.ID()] = provider.RedirectURL()
	}
	if len(providers.IDs()) == 0 {
		store.Close()
		return nil, fmt.Errorf("control: no identity provider configured")
	}

	sessionTTL := cfg.SessionTTL
	if sessionTTL <= 0 {
		sessionTTL = identity.DefaultSessionTTL
	}

	// A passkey configuration that cannot serve ceremonies must stop the
	// server: silently disabling the feature would leave operators guessing
	// why no browser can register.
	var passkeys *identity.PasskeyService
	if cfg.Passkeys != nil {
		passkeys, err = identity.NewPasskeyService(identityStore, *cfg.Passkeys)
		if err != nil {
			store.Close()
			return nil, fmt.Errorf("control: passkey sign-in: %w", err)
		}
	}

	// Xunara Flux: a configuration that cannot work stops the server too.
	flux, err := newFluxServer(cfg.StateDir, cfg.Flux)
	if err != nil {
		store.Close()
		return nil, err
	}

	resolvers, err := parseResolvers(cfg.Nameservers)
	if err != nil {
		store.Close()
		return nil, err
	}

	certDomains, err := normalizeCertDomains(cfg.CertDomains)
	if err != nil {
		store.Close()
		return nil, err
	}
	if cfg.DNSProvider == nil {
		if len(certDomains) > 0 {
			cfg.Logger.Warn("certificate domains configured without a DNS provider; clients will not be offered TLS certificates")
		}
		// Without a public zone writer a DNS-01 challenge could never be
		// validated, so the client must not be told to start one.
		certDomains = nil
	}
	dnsRoutes, err := parseDNSRoutes(cfg.DNSRoutes)
	if err != nil {
		store.Close()
		return nil, err
	}

	formKey, err := loadOrCreateFormKey(cfg.StateDir)
	if err != nil {
		store.Close()
		return nil, fmt.Errorf("control: loading the form signing key: %w", err)
	}

	srv := &Server{
		cfg:               cfg,
		log:               cfg.Logger,
		consoleLoc:        consoleLoc,
		noiseKey:          noiseKey,
		store:             store,
		closer:            store,
		identity:          identityStore,
		providers:         providers,
		providerRedirects: redirects,
		passkeys:          passkeys,
		flux:              flux,
		planSource:        cfg.PlanSource,
		secureCookies:     strings.HasPrefix(strings.ToLower(cfg.ServerURL), "https://"),
		sessionTTL:        sessionTTL,
		authTTL:           identity.DefaultAuthTransactionTTL,
		localLogin:        localLogin,
		registration:      registration,
		formKey:           formKey,
		resolvers:         resolvers,
		dnsRoutes:         dnsRoutes,
		certDomains:       certDomains,
		pending:           make(map[string]*pendingRegistration),
		pendingByNode:     make(map[key.NodePublic]string),
		online:            make(map[state.NodeID]int),
		watchers:          make(map[uint64]chan struct{}),
	}

	if cfg.ServerURL != "" {
		srv.tokens = idtoken.NewKeyring(cfg.StateDir, cfg.Logger)
		cfg.Logger.Info("identity-token issuer enabled", "issuer", idtoken.TrimIssuer(cfg.ServerURL))
	}

	if passkeys != nil {
		cfg.Logger.Info("passkey sign-in enabled", "rp_id", cfg.Passkeys.RPID)
	}
	// Arm the first-run setup token before anything can serve a request.
	srv.initSetupToken()
	if flux != nil {
		cfg.Logger.Info("flux file transfer enabled",
			"dir", flux.dir, "max_size", flux.maxSize, "ttl", flux.ttl)
	}

	// The DERP policy decides what clients are served; a policy that names a
	// region the map does not contain must stop the server rather than
	// silently serve a different tailnet.
	derpMap, err := cfg.DERPPolicy.Apply(cfg.DERPMap)
	if err != nil {
		store.Close()
		return nil, err
	}
	srv.derpMap = derpMap
	srv.derpPolicy = cfg.DERPPolicy

	// A broken policy file must stop the server from starting: falling back to
	// allow-all would silently open the tailnet.
	if err := srv.loadPolicy(); err != nil {
		store.Close()
		return nil, fmt.Errorf("control: loading policy %s: %w", cfg.PolicyPath, err)
	}

	// Webhook endpoints come from two places: deployment configuration
	// (flags/environment, secrets never stored) and runtime management
	// (sealed secrets in the database). They share one dispatcher, so leases
	// and cursors stay per endpoint ID.
	if err := srv.initWebhooks(cfg); err != nil {
		store.Close()
		return nil, err
	}

	// Tailnet lock state lives next to the database; opening it can fail on
	// corrupt or incompatible on-disk state, which must stop the server.
	if srv.tka, err = newTKAManager(cfg.StateDir, store, cfg.Logger); err != nil {
		store.Close()
		return nil, err
	}

	return srv, nil
}

// initWebhooks merges deployment-configured and managed webhook endpoints and
// builds the dispatcher.
func (s *Server) initWebhooks(cfg Config) error {
	key, err := loadOrCreateWebhookSecretKey(cfg.StateDir)
	if err != nil {
		return err
	}
	s.webhookKey = key

	endpoints := make([]webhook.Endpoint, 0, len(cfg.Webhooks)+4)
	configured := make(map[string]bool, len(cfg.Webhooks))
	for _, ep := range cfg.Webhooks {
		configured[ep.ID] = true
		endpoints = append(endpoints, ep)
	}

	for _, managed := range s.identity.ListWebhookEndpoints() {
		if configured[managed.ID] {
			return fmt.Errorf("control: webhook endpoint %q is both configured and managed", managed.ID)
		}
		if !managed.Enabled {
			continue
		}
		secret, err := openWebhookSecret(key, managed.Secret)
		if err != nil {
			return fmt.Errorf("control: webhook endpoint %q: %w", managed.ID, err)
		}
		endpoints = append(endpoints, webhook.Endpoint{
			ID:     managed.ID,
			URL:    managed.URL,
			Secret: secret,
			Events: managed.Events,
		})
	}

	dispatcher, err := webhook.New(webhook.Config{
		Endpoints: endpoints,
		Store:     s.identity,
		Logger:    cfg.Logger,
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	s.webhooks = dispatcher
	return nil
}

// Close releases the server's durable resources.
func (s *Server) Close() error {
	if s.closer == nil {
		return nil
	}
	return s.closer.Close()
}

// markOnline records that a node holds a control session.
func (s *Server) markOnline(node state.Node) {
	s.sessMu.Lock()
	s.online[node.ID]++
	s.sessMu.Unlock()
	s.notifyNodePeers(node)
}

// markOffline releases a control session and records the node's last-seen time.
func (s *Server) markOffline(node state.Node) {
	s.sessMu.Lock()
	if n := s.online[node.ID]; n > 1 {
		s.online[node.ID] = n - 1
	} else {
		delete(s.online, node.ID)
	}
	s.sessMu.Unlock()

	if stored, ok := s.store.GetNodeByID(node.ID); ok {
		now := time.Now().UTC()
		stored.LastSeen = &now
		if err := s.store.UpdateNode(stored); err != nil {
			s.log.Warn("recording last seen", "node_id", int(node.ID), "err", err)
		}
		node = stored
	}

	s.notifyNodePeers(node)
}

// isOnline reports whether a node currently holds a control session.
func (s *Server) isOnline(id state.NodeID) bool {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if s.online[id] > 0 {
		return true
	}
	// Native clients (Xunara Agent) do not hold a Noise session; a recent
	// heartbeat is the equivalent liveness signal.
	return s.agentHeartbeatFreshLocked(id, time.Now())
}

// IsNodeOnline reports whether a node currently holds a control session or a
// recent native-client heartbeat. It is the liveness view the platform API and
// console present.
func (s *Server) IsNodeOnline(id state.NodeID) bool { return s.isOnline(id) }

// agentHeartbeatFreshLocked reports whether the node heartbeat recently. The
// caller must hold sessMu. Stale entries are pruned here, which bounds the map
// by the number of nodes the netmap is built for.
func (s *Server) agentHeartbeatFreshLocked(id state.NodeID, now time.Time) bool {
	seen, ok := s.agentSeen[id]
	if !ok {
		return false
	}
	if now.Sub(seen) > agentHeartbeatTTL {
		delete(s.agentSeen, id)
		return false
	}
	return true
}

// watch registers a netmap change listener. The returned cancel function must
// be called when the listener stops.
func (s *Server) watch() (<-chan struct{}, func()) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	id := s.nextWatcherID
	s.nextWatcherID++

	ch := make(chan struct{}, 1)
	s.watchers[id] = ch

	return ch, func() {
		s.sessMu.Lock()
		defer s.sessMu.Unlock()
		delete(s.watchers, id)
	}
}

// notifyWatchers wakes every netmap change listener. Sends are non-blocking:
// a listener that has not drained its previous notification does not need
// another one.
func (s *Server) notifyWatchers() {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()

	for _, ch := range s.watchers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Store returns the tailnet store backing the server.
func (s *Server) Store() state.Store { return s.store }

// Identity returns the trust plane backing the server.
func (s *Server) Identity() identity.Store { return s.identity }

// UserProfile describes a user to clients. Unknown users fall back to the
// single-user default so that a netmap can always be built.
func (s *Server) UserProfile(id tailcfg.UserID) tailcfg.UserProfile {
	if u, ok := s.identity.GetUser(id); ok {
		return tailcfg.UserProfile{
			ID:          u.ID,
			LoginName:   u.LoginName,
			DisplayName: u.DisplayName,
		}
	}
	return state.DefaultUserProfile(id)
}

// audit records an audit event, logging (but not failing on) write errors: the
// audit log must never take the control plane down.
func (s *Server) audit(actor, action, target, detail string) {
	event := identity.AuditEvent{Actor: actor, Action: action, Target: target, Detail: detail}
	if err := s.identity.AppendAudit(&event); err != nil {
		s.log.Error("appending audit event", "action", action, "target", target, "err", err)
	}
}

// NoisePublicKey returns the server's TS2021 Noise public key.
func (s *Server) NoisePublicKey() key.MachinePublic { return s.noiseKey.Public() }

// DERPMap returns the DERP map served to this organization's clients, after
// the organization's DERP policy is applied. It is nil when there is nothing
// to advertise.
func (s *Server) DERPMap() *tailcfg.DERPMap { return s.derpMap }

// Handler returns the public HTTP router: the endpoints reachable before a
// Noise session exists.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	// TS2021 accepts both the native client's HTTP POST upgrade and the
	// browser/WASM client's WebSocket GET upgrade; the handler dispatches on the
	// Upgrade header, so both methods must reach it.
	r.Get(ts2021UpgradePath, s.handleNoiseUpgrade)
	r.Post(ts2021UpgradePath, s.handleNoiseUpgrade)

	r.Get("/key", s.handleKey)
	r.Get("/health", s.handleHealth)
	r.Get("/version", s.handleVersion)
	r.Get("/.well-known/jwks.json", s.handleJWKS)
	r.Get("/.well-known/openid-configuration", s.handleOpenIDConfiguration)
	r.Get("/login", s.handleLogin)
	r.Post("/login", s.handlePasswordLogin)
	r.Get("/setup", s.handleSetupPage)
	r.Post("/setup", s.handleSetupSubmit)
	r.Get("/signup", s.handleSignupPage)
	r.Post("/signup", s.handleSignupSubmit)
	r.Post("/logout", s.handleLogout)
	if s.passkeys != nil {
		r.Post("/passkey/login/begin", s.handlePasskeyLoginBegin)
		r.Post("/passkey/login/finish", s.handlePasskeyLoginFinish)
	}
	r.Get("/oidc/callback/{providerID}", s.handleCallback)
	r.Get("/register/{authID}", s.handleRegisterPage)
	r.Post("/register/{authID}/approve", s.handleApproveDevice)
	r.Post("/register/{authID}/deny", s.handleDenyDevice)
	r.Get("/ssh/check/{authID}", s.handleSSHCheckPage)
	r.Post("/ssh/check/{authID}/approve", s.handleSSHCheckApprove)
	r.Post("/ssh/check/{authID}/deny", s.handleSSHCheckDeny)
	r.Post("/derp/admit", s.handleDERPAdmit)

	// The relay control protocol: relays are service identities, so they
	// authenticate with their own credential instead of a session
	// (xunara-relay/docs/relay-protocol.md).
	r.Post(relayEnrollPath, s.handleRelayEnroll)
	r.Post(relayHeartbeatPath, s.handleRelayHeartbeat)
	r.Mount("/api/agent/v1", s.agentRouter())
	r.Mount("/api/v1", s.apiRouter())
	r.Mount("/api/v2", s.apiV2Router())
	r.Mount("/console", s.consoleRouter())
	r.Get("/", s.handleRoot)
	r.NotFound(s.handleNotFound)

	return r
}

// Start launches the server's background workers: the ephemeral-node janitor
// and the out-of-band configuration watcher. They run until ctx is cancelled.
//
// Serve calls Start itself; call it directly when the HTTP handler is served by
// something else (tests, or an embedding process).
func (s *Server) Start(ctx context.Context) {
	s.startOnce.Do(func() {
		go s.runJanitor(ctx)
		go s.runConfigWatcher(ctx)
		go s.runPolicyWatcher(ctx)
		if s.webhooks != nil {
			go s.webhooks.Run(ctx)
		}
	})
}

// Serve runs the HTTP server until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	s.Start(ctx)

	// The platform gRPC API is optional; when enabled it runs on its own
	// listener with the HTTP server's lifecycle.
	grpcSrv, grpcLis, err := s.startPlatformGRPC()
	if err != nil {
		return err
	}

	errCh := make(chan error, 2)
	go func() {
		s.log.Info("control server listening", "addr", s.cfg.ListenAddr, "url", s.cfg.ServerURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	if grpcSrv != nil {
		go func() {
			s.log.Info("platform gRPC listening", "addr", s.cfg.GRPCListenAddr)
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
		s.log.Info("control server shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpErr := srv.Shutdown(shutdownCtx)
		stopPlatformGRPC(grpcSrv)
		return httpErr
	}
}

// handleKey implements GET /key, returning the server's Noise public key to
// clients at or above the supported capability floor.
func (s *Server) handleKey(w http.ResponseWriter, req *http.Request) {
	capVer, err := parseCapabilityVersion(req)
	if err != nil {
		httpError(w, err)
		return
	}
	if !isSupportedVersion(capVer) {
		httpError(w, NewHTTPError(
			http.StatusBadRequest,
			"unsupported client version",
			errUnsupportedClientVersion,
		))
		return
	}

	writeJSON(w, http.StatusOK, tailcfg.OverTLSPublicKeyResponse{
		PublicKey: s.noiseKey.Public(),
	})
}

// userCanWrite reports whether a user's role may change tailnet state.
func (s *Server) userCanWrite(userID tailcfg.UserID) bool {
	user, ok := s.identity.GetUser(userID)
	return ok && user.Role.CanWrite()
}

// otherOwnerExists reports whether any owner other than excludeID exists.
func (s *Server) otherOwnerExists(excludeID tailcfg.UserID) bool {
	for _, u := range s.identity.ListUsers() {
		if u.ID != excludeID && u.Role.IsOwner() {
			return true
		}
	}
	return false
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "pass"})
}

func (s *Server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"version":  Version,
		"mine":     "xunara",
		"protocol": "ts2021",
	})
}

// handleRoot implements GET /. A browser gets the landing page: what this
// deployment is, how to sign in, and the command that points a device at it.
// Callers that do not ask for HTML (scripts, health probes) keep the short
// machine-readable description, so the endpoint stays useful to both.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Accept"), "text/html") {
		writeJSON(w, http.StatusOK, map[string]string{
			"name":    "Xunara",
			"version": Version,
			"message": "Tailscale-compatible control plane. Point clients at this URL with `tailscale up --login-server=<url>`.",
			"console": "/console/",
		})
		return
	}
	s.renderPublicPage(w, r, landingPageTemplate, map[string]any{
		"Title": "Home",
	})
}
