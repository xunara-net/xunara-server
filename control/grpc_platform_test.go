package control

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"tailscale.com/types/key"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"github.com/xunara-net/xunara-server/webhook"
)

// startGRPCConn serves register on a loopback port and returns a client
// connection. Extra dial options let a test pin the authority, which is how the
// router selects an organization.
func startGRPCConn(t *testing.T, register func(grpc.ServiceRegistrar), opts ...grpc.DialOption) *grpc.ClientConn {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	dialOpts := append([]grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, opts...)
	conn, err := grpc.NewClient("passthrough:///"+lis.Addr().String(), dialOpts...)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// startGRPCTestServer serves register and returns the organization-scoped
// client.
func startGRPCTestServer(t *testing.T, register func(grpc.ServiceRegistrar), opts ...grpc.DialOption) xunarav2.PlatformServiceClient {
	t.Helper()
	return xunarav2.NewPlatformServiceClient(startGRPCConn(t, register, opts...))
}

// registerPlatformGRPCServices registers both platform surfaces of a router,
// exactly like [Router.Start] does on its own listener.
func registerPlatformGRPCServices(reg grpc.ServiceRegistrar, router *Router) {
	router.RegisterPlatformGRPC(reg)
	router.RegisterPlatformAdminGRPC(reg)
}

// grpcCtx attaches a bearer credential the same way a real client would.
func grpcCtx(token string) context.Context {
	if token == "" {
		return context.Background()
	}
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token)
}

func TestPlatformGRPCRequiresAuthentication(t *testing.T) {
	s := newTestServer(t)
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	if _, err := client.GetMeta(grpcCtx(""), &xunarav2.GetMetaRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("anonymous GetMeta error = %v, want Unauthenticated", err)
	}
	if _, err := client.GetMeta(grpcCtx("xunara_nope"), &xunarav2.GetMetaRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("bad credential error = %v, want Unauthenticated", err)
	}
	// A session token is not an API key; it must not be accepted by accident
	// through a different lookup path.
	if _, err := client.GetMeta(grpcCtx("not-a-bearer-token"), &xunarav2.GetMetaRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("unknown credential error = %v, want Unauthenticated", err)
	}
}

func TestPlatformGRPCMeta(t *testing.T) {
	s := newServerWithConfig(t, Config{
		Domain:         "example.com",
		CertDomains:    []string{"extra.example.com"},
		DNSProvider:    &fakeDNSProvider{},
		Webhooks:       []webhook.Endpoint{{ID: "cfg", URL: "https://hooks.example.com/x", Secret: "s3cret"}},
		ListenAddr:     "127.0.0.1:0",
		ServerURL:      "https://login.example.com",
		GRPCListenAddr: "127.0.0.1:0",
	})
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)
	_, token := seedAPIKey(t, s, identity.ScopeRead)

	meta, err := client.GetMeta(grpcCtx(token), &xunarav2.GetMetaRequest{})
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if meta.GetVersion() != Version {
		t.Errorf("version = %q, want %q", meta.GetVersion(), Version)
	}
	if meta.GetDomain() != "example.com" || meta.GetServerUrl() != "https://login.example.com" {
		t.Errorf("meta identity = %+v", meta)
	}
	if meta.GetMaxPageSize() != uint32(apiV2MaxPageSize) {
		t.Errorf("max page size = %d, want %d", meta.GetMaxPageSize(), apiV2MaxPageSize)
	}
	if meta.GetAgentProtocolVersion() != uint32(agentProtocolVersion) {
		t.Errorf("agent protocol version = %d", meta.GetAgentProtocolVersion())
	}
	if meta.GetCapabilityVersion() == 0 || meta.GetMinCapabilityVersion() == 0 {
		t.Errorf("capability versions missing: %+v", meta)
	}
	if len(meta.GetCertDomains()) != 1 || meta.GetCertDomains()[0] != "extra.example.com" {
		t.Errorf("cert domains = %v", meta.GetCertDomains())
	}
	if !meta.GetWebhooksEnabled() || !meta.GetDnsProviderConfigured() {
		t.Errorf("feature flags = %+v", meta)
	}
	if meta.GetReachEnabled() || meta.GetFluxEnabled() || meta.GetPasskeysEnabled() || meta.GetSharingEnabled() {
		t.Errorf("optional features = %+v, want disabled", meta)
	}
}

// TestPlatformGRPCMetaFeatureFlags checks that gRPC meta mirrors the HTTP
// discovery document for the optional features and managed webhooks.
func TestPlatformGRPCMetaFeatureFlags(t *testing.T) {
	s := newServerWithConfig(t, Config{
		ReachEnabled: true,
		Flux:         &FluxConfig{},
		Passkeys:     testPasskeyConfig(),
	})
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)
	_, token := seedAPIKey(t, s, identity.ScopeRead)

	// A local receiver: the dispatcher delivers real audit events to enabled
	// endpoints, and a test must not talk to the outside world.
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(receiver.Close)

	if _, err := s.storeManagedWebhook(webhook.Endpoint{ID: "ops", URL: receiver.URL, Secret: "s3cret"}, true); err != nil {
		t.Fatalf("storeManagedWebhook: %v", err)
	}

	meta, err := client.GetMeta(grpcCtx(token), &xunarav2.GetMetaRequest{})
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if !meta.GetReachEnabled() || !meta.GetFluxEnabled() || !meta.GetPasskeysEnabled() {
		t.Errorf("optional features = %+v, want enabled", meta)
	}
	if !meta.GetWebhooksEnabled() {
		t.Errorf("webhooksEnabled with a managed endpoint = false, want true")
	}

	// The paused endpoint must not count.
	if _, err := s.storeManagedWebhook(webhook.Endpoint{ID: "paused", URL: "https://hooks.example.com/p", Secret: "s3cret"}, false); err != nil {
		t.Fatalf("storeManagedWebhook: %v", err)
	}
	if err := s.deleteManagedWebhook("ops"); err != nil {
		t.Fatalf("deleteManagedWebhook: %v", err)
	}
	meta, err = client.GetMeta(grpcCtx(token), &xunarav2.GetMetaRequest{})
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if meta.GetWebhooksEnabled() {
		t.Errorf("webhooksEnabled with only a paused endpoint = true, want false")
	}
}

func TestPlatformGRPCListMachinesPaginationAndFilters(t *testing.T) {
	s := newTestServer(t)
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	seeded := []state.Node{
		seedAPIMachine(t, s, "one", nil),
		seedAPIMachine(t, s, "two", []string{"tag:server"}),
		seedAPIMachine(t, s, "three", nil),
	}
	_, token := seedAPIKey(t, s, identity.ScopeRead)
	ctx := grpcCtx(token)

	first, err := client.ListMachines(ctx, &xunarav2.ListMachinesRequest{PageSize: 2})
	if err != nil {
		t.Fatalf("ListMachines page 1: %v", err)
	}
	if len(first.GetMachines()) != 2 || first.GetNextPageToken() == "" {
		t.Fatalf("page 1 = %d machines, next %q", len(first.GetMachines()), first.GetNextPageToken())
	}
	if first.GetMachines()[0].GetId() != uint64(seeded[0].ID) || first.GetMachines()[1].GetId() != uint64(seeded[1].ID) {
		t.Errorf("page 1 ids = %d, %d", first.GetMachines()[0].GetId(), first.GetMachines()[1].GetId())
	}

	second, err := client.ListMachines(ctx, &xunarav2.ListMachinesRequest{PageSize: 2, PageToken: first.GetNextPageToken()})
	if err != nil {
		t.Fatalf("ListMachines page 2: %v", err)
	}
	if len(second.GetMachines()) != 1 || second.GetNextPageToken() != "" {
		t.Fatalf("page 2 = %d machines, next %q", len(second.GetMachines()), second.GetNextPageToken())
	}
	if id := second.GetMachines()[0].GetId(); id != uint64(seeded[2].ID) {
		t.Errorf("page 2 id = %d, want %d", id, seeded[2].ID)
	}

	tagged, err := client.ListMachines(ctx, &xunarav2.ListMachinesRequest{Tag: "tag:server"})
	if err != nil {
		t.Fatalf("ListMachines tag filter: %v", err)
	}
	if len(tagged.GetMachines()) != 1 || tagged.GetMachines()[0].GetHostname() != "two" {
		t.Errorf("tag filter = %+v", tagged.GetMachines())
	}

	// An unknown user matches nothing instead of silently returning everyone.
	unknown, err := client.ListMachines(ctx, &xunarav2.ListMachinesRequest{User: "nobody@example.com"})
	if err != nil {
		t.Fatalf("ListMachines user filter: %v", err)
	}
	if len(unknown.GetMachines()) != 0 {
		t.Errorf("unknown user matched %d machines", len(unknown.GetMachines()))
	}
	// "0" is not a user ID: it must match nothing, never mean "no filter".
	zeroUser, err := client.ListMachines(ctx, &xunarav2.ListMachinesRequest{User: "0"})
	if err != nil {
		t.Fatalf("ListMachines user=0: %v", err)
	}
	if len(zeroUser.GetMachines()) != 0 {
		t.Errorf("user=0 matched %d machines", len(zeroUser.GetMachines()))
	}

	byID, err := client.ListMachines(ctx, &xunarav2.ListMachinesRequest{User: itoa64(uint64(seeded[1].UserID))})
	if err != nil {
		t.Fatalf("ListMachines id filter: %v", err)
	}
	if len(byID.GetMachines()) != 3 {
		t.Errorf("user id filter = %d machines", len(byID.GetMachines()))
	}

	if _, err := client.ListMachines(ctx, &xunarav2.ListMachinesRequest{State: "fresh"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad state error = %v, want InvalidArgument", err)
	}
	if _, err := client.ListMachines(ctx, &xunarav2.ListMachinesRequest{PageToken: "%%%"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad page token error = %v, want InvalidArgument", err)
	}
	if _, err := client.ListMachines(ctx, &xunarav2.ListMachinesRequest{PageToken: apiV2EncodeCursor("audit", "3")}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("wrong cursor kind error = %v, want InvalidArgument", err)
	}
}

func TestPlatformGRPCListAuditFilters(t *testing.T) {
	s := newTestServer(t)
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	s.audit("tester", "node.approved", "node:1", "first")
	s.audit("tester", "user.created", "user:2", "second")
	s.audit("robot", "node.approved", "node:3", "third")

	_, token := seedAPIKey(t, s, identity.ScopeRead)
	ctx := grpcCtx(token)

	page, err := client.ListAudit(ctx, &xunarav2.ListAuditRequest{PageSize: 2})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(page.GetEvents()) != 2 {
		t.Fatalf("audit page = %d events", len(page.GetEvents()))
	}
	if page.GetEvents()[0].GetId() >= page.GetEvents()[1].GetId() {
		t.Error("audit events are not oldest first")
	}
	if page.GetEvents()[0].GetTime() == nil || page.GetEvents()[0].GetAction() == "" {
		t.Errorf("audit event lacks time/action: %+v", page.GetEvents()[0])
	}
	if page.GetNextPageToken() == "" {
		t.Fatal("audit page 2 cursor missing")
	}

	all, err := client.ListAudit(ctx, &xunarav2.ListAuditRequest{PageSize: 100})
	if err != nil {
		t.Fatalf("ListAudit all: %v", err)
	}
	rest, err := client.ListAudit(ctx, &xunarav2.ListAuditRequest{PageSize: 2, PageToken: page.GetNextPageToken()})
	if err != nil {
		t.Fatalf("ListAudit page 2: %v", err)
	}
	if got, want := len(page.GetEvents())+len(rest.GetEvents()), len(all.GetEvents()); got != want {
		t.Errorf("paged audit = %d events, want %d", got, want)
	}
	if rest.GetEvents()[0].GetId() <= page.GetEvents()[1].GetId() {
		t.Error("audit page 2 did not continue after the cursor")
	}

	filtered, err := client.ListAudit(ctx, &xunarav2.ListAuditRequest{Actor: "tester", Action: "node.approved"})
	if err != nil {
		t.Fatalf("ListAudit filters: %v", err)
	}
	if len(filtered.GetEvents()) != 1 || filtered.GetEvents()[0].GetTarget() != "node:1" {
		t.Errorf("filtered audit = %+v", filtered.GetEvents())
	}

	prefixed, err := client.ListAudit(ctx, &xunarav2.ListAuditRequest{Target: "node:"})
	if err != nil {
		t.Fatalf("ListAudit target filter: %v", err)
	}
	if len(prefixed.GetEvents()) != 2 {
		t.Errorf("target prefix = %d events", len(prefixed.GetEvents()))
	}

	if _, err := client.ListAudit(ctx, &xunarav2.ListAuditRequest{PageToken: "%%%"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad audit cursor error = %v, want InvalidArgument", err)
	}
}

func TestPlatformGRPCListWebhooks(t *testing.T) {
	s := newServerWithConfig(t, Config{
		Webhooks: []webhook.Endpoint{{
			ID: "cfg", URL: "https://hooks.example.com/config", Secret: "cfg-secret",
			Events: []string{"node.*"},
		}},
	})
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	// A managed endpoint goes through the same sealing path as the HTTP API.
	if err := s.identity.CreateWebhookEndpoint(&identity.WebhookEndpoint{
		ID: "managed", URL: "https://hooks.example.com/managed", Secret: "sealed",
		Events: []string{"user.*"}, Enabled: true,
	}); err != nil {
		t.Fatalf("CreateWebhookEndpoint: %v", err)
	}

	_, token := seedAPIKey(t, s, identity.ScopeRead)
	resp, err := client.ListWebhooks(grpcCtx(token), &xunarav2.ListWebhooksRequest{})
	if err != nil {
		t.Fatalf("ListWebhooks: %v", err)
	}
	if len(resp.GetWebhooks()) != 2 {
		t.Fatalf("webhooks = %d, want 2", len(resp.GetWebhooks()))
	}
	byID := map[string]*xunarav2.Webhook{}
	for _, endpoint := range resp.GetWebhooks() {
		byID[endpoint.GetId()] = endpoint
	}
	config := byID["cfg"]
	if config == nil || config.GetSource() != "config" || !config.GetEnabled() || config.GetUrl() != "https://hooks.example.com/config" {
		t.Errorf("config webhook = %+v", config)
	}
	managed := byID["managed"]
	if managed == nil || managed.GetSource() != "managed" || managed.GetCreatedAt() == nil {
		t.Errorf("managed webhook = %+v", managed)
	}
}

func TestPlatformGRPCRevokeAgentToken(t *testing.T) {
	s := newTestServer(t)
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	token, _, err := s.Identity().CreateAgentToken(identity.NewAgentTokenOptions{
		NodeID:     7,
		MachineKey: key.NewMachine().Public().String(),
		NodeKey:    key.NewNode().Public().String(),
	})
	if err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}

	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s)

	if _, err := client.RevokeAgentToken(grpcCtx(readToken), &xunarav2.RevokeAgentTokenRequest{Id: token.ID}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("read-only revoke error = %v, want PermissionDenied", err)
	}
	if _, err := client.RevokeAgentToken(grpcCtx(writeToken), &xunarav2.RevokeAgentTokenRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing id error = %v, want InvalidArgument", err)
	}
	if _, err := client.RevokeAgentToken(grpcCtx(writeToken), &xunarav2.RevokeAgentTokenRequest{Id: "xunara_agenttoken_missing"}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown token error = %v, want NotFound", err)
	}

	resp, err := client.RevokeAgentToken(grpcCtx(writeToken), &xunarav2.RevokeAgentTokenRequest{Id: token.ID})
	if err != nil {
		t.Fatalf("RevokeAgentToken: %v", err)
	}
	if resp.GetId() != token.ID || !resp.GetRevoked() {
		t.Errorf("revoke response = %+v", resp)
	}
	// Idempotent retry.
	if _, err := client.RevokeAgentToken(grpcCtx(writeToken), &xunarav2.RevokeAgentTokenRequest{Id: token.ID}); err != nil {
		t.Errorf("repeated revoke: %v", err)
	}
	if event, ok := findAudit(t, s, identity.AuditAgentTokenRevoked); !ok || event.Target != "agenttoken:"+token.ID {
		t.Errorf("revocation audit = %+v (found %v)", event, ok)
	}
}

func TestPlatformGRPCAuthoritySelectsOrganization(t *testing.T) {
	acme := newServerWithConfig(t, Config{Domain: "acme.example.com"})
	globex := newServerWithConfig(t, Config{Domain: "globex.example.com"})
	router := newTestRouter(t, RouterConfig{Orgs: []OrgSite{
		{ID: "acme", Name: "Acme", Domains: []string{"login.acme.example.com"}, Server: acme},
		{ID: "globex", Name: "Globex", Domains: []string{"login.globex.example.com"}, Server: globex},
	}})

	_, acmeToken := seedAPIKey(t, acme, identity.ScopeRead)
	_, globexToken := seedAPIKey(t, globex, identity.ScopeRead)

	acmeClient := startGRPCTestServer(t, router.RegisterPlatformGRPC, grpc.WithAuthority("login.acme.example.com"))
	meta, err := acmeClient.GetMeta(grpcCtx(acmeToken), &xunarav2.GetMetaRequest{})
	if err != nil {
		t.Fatalf("acme GetMeta: %v", err)
	}
	if meta.GetDomain() != "acme.example.com" {
		t.Errorf("acme domain = %q", meta.GetDomain())
	}

	// The same connection, a credential from the other organization: tenant
	// boundaries hold even though both keys are valid API keys.
	if _, err := acmeClient.GetMeta(grpcCtx(globexToken), &xunarav2.GetMetaRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("cross-organization credential error = %v, want Unauthenticated", err)
	}

	globexClient := startGRPCTestServer(t, router.RegisterPlatformGRPC, grpc.WithAuthority("login.globex.example.com"))
	if _, err := globexClient.GetMeta(grpcCtx(globexToken), &xunarav2.GetMetaRequest{}); err != nil {
		t.Errorf("globex GetMeta: %v", err)
	}

	// An authority that names no organization is NOT_FOUND, not a fallback.
	unknownClient := startGRPCTestServer(t, router.RegisterPlatformGRPC, grpc.WithAuthority("login.unknown.example.com"))
	if _, err := unknownClient.GetMeta(grpcCtx(acmeToken), &xunarav2.GetMetaRequest{}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown authority error = %v, want NotFound", err)
	}
}

func TestServePlatformGRPCLifecycle(t *testing.T) {
	// Reserve a loopback port for the gRPC surface so the test can dial it.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()

	s := newServerWithConfig(t, Config{
		ListenAddr:     "127.0.0.1:0",
		GRPCListenAddr: addr,
	})
	_, token := seedAPIKey(t, s, identity.ScopeRead)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()

	conn, err := grpc.NewClient("passthrough:///"+addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()
	client := xunarav2.NewPlatformServiceClient(conn)

	deadline := time.Now().Add(10 * time.Second)
	for {
		callCtx, callCancel := context.WithTimeout(grpcCtx(token), time.Second)
		_, err = client.GetMeta(callCtx, &xunarav2.GetMetaRequest{})
		callCancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("gRPC surface did not come up: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not stop after cancel")
	}
}

func TestServeRejectsBadGRPCAddress(t *testing.T) {
	s := newServerWithConfig(t, Config{
		ListenAddr:     "127.0.0.1:0",
		GRPCListenAddr: "127.0.0.1:not-a-port",
	})
	if err := s.Serve(context.Background()); err == nil {
		t.Fatal("Serve accepted an unbindable gRPC address")
	}
}

func TestRouterServeRejectsBadGRPCAddress(t *testing.T) {
	org := newTestServer(t)
	router := newTestRouter(t, RouterConfig{
		ListenAddr:     "127.0.0.1:0",
		GRPCListenAddr: "127.0.0.1:not-a-port",
		Orgs:           []OrgSite{{ID: "default", Name: "Default", Server: org}},
	})
	if err := router.Serve(context.Background()); err == nil {
		t.Fatal("Router.Serve accepted an unbindable gRPC address")
	}
}

// TestPlatformGRPCTailnetLock checks the gRPC tailnet-lock status: read scope
// only, same values as GET /api/v2/tka, and nothing from the chain beyond the
// head hash.
func TestPlatformGRPCTailnetLock(t *testing.T) {
	s := newTestServer(t)
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)

	if _, err := client.GetTailnetLock(grpcCtx(""), &xunarav2.GetTailnetLockRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("anonymous GetTailnetLock error = %v, want Unauthenticated", err)
	}
	if _, err := client.GetTailnetLock(grpcCtx(writeToken), &xunarav2.GetTailnetLockRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("write-only GetTailnetLock error = %v, want PermissionDenied", err)
	}

	signed := seedAPIMachine(t, s, "signed", nil)
	seedAPIMachine(t, s, "unsigned", nil)

	status, err := client.GetTailnetLock(grpcCtx(readToken), &xunarav2.GetTailnetLockRequest{})
	if err != nil {
		t.Fatalf("GetTailnetLock: %v", err)
	}
	if status.GetEverEnabled() || status.GetEnabled() || status.GetDisabled() || status.GetHead() != "" {
		t.Errorf("status before enablement = %+v, want an untouched tailnet", status)
	}
	if status.GetNodes().GetTotal() != 2 || status.GetNodes().GetUnsigned() != 2 {
		t.Errorf("node counts = %+v, want 2 unsigned nodes", status.GetNodes())
	}

	adminKey, genesis := newTestTKAKey(t)
	if err := s.tka.initBegin(genesis); err != nil {
		t.Fatalf("initBegin: %v", err)
	}
	signed = storedNode(t, s, signed.NodeKey)
	signed.KeySignature = signTestNodeKey(t, adminKey, signed.NodeKey)
	if err := s.store.UpdateNode(signed); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	if err := s.tka.enable(nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	status, err = client.GetTailnetLock(grpcCtx(readToken), &xunarav2.GetTailnetLockRequest{})
	if err != nil {
		t.Fatalf("GetTailnetLock after enablement: %v", err)
	}
	if !status.GetEnabled() || status.GetDisabled() {
		t.Errorf("status after enablement = %+v, want enabled", status)
	}
	if status.GetHead() != genesis.Hash().String() {
		t.Errorf("head = %q, want %q", status.GetHead(), genesis.Hash().String())
	}
	if status.GetNodes().GetSigned() != 1 || status.GetNodes().GetTotal() != 2 {
		t.Errorf("node counts = %+v, want one of two nodes signed", status.GetNodes())
	}
}

// TestPlatformGRPCIDTokenIssuer checks the gRPC identity-token issuer status:
// read scope only, and the same public state as GET /api/v2/id-token.
func TestPlatformGRPCIDTokenIssuer(t *testing.T) {
	s := newServerWithConfig(t, Config{ServerURL: "https://login.example.com", Domain: "example.com"})
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)

	if _, err := client.GetIDTokenIssuer(grpcCtx(""), &xunarav2.GetIDTokenIssuerRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("anonymous GetIDTokenIssuer error = %v, want Unauthenticated", err)
	}
	if _, err := client.GetIDTokenIssuer(grpcCtx(writeToken), &xunarav2.GetIDTokenIssuerRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("write-only GetIDTokenIssuer error = %v, want PermissionDenied", err)
	}

	issuer, err := client.GetIDTokenIssuer(grpcCtx(readToken), &xunarav2.GetIDTokenIssuerRequest{})
	if err != nil {
		t.Fatalf("GetIDTokenIssuer: %v", err)
	}

	want, err := s.IDTokenStatus()
	if err != nil {
		t.Fatalf("IDTokenStatus: %v", err)
	}
	if !issuer.GetEnabled() || issuer.GetIssuer() != want.Issuer || issuer.GetJwksUrl() != want.JWKSURL {
		t.Errorf("issuer = %+v, want enabled with issuer %q and jwks %q", issuer, want.Issuer, want.JWKSURL)
	}
	if issuer.GetAlgorithm() != want.Algorithm || issuer.GetTokenTtlSeconds() != int64(want.TokenTTLSeconds) {
		t.Errorf("algorithm/ttl = %q/%d, want %q/%d", issuer.GetAlgorithm(), issuer.GetTokenTtlSeconds(), want.Algorithm, want.TokenTTLSeconds)
	}
	if len(issuer.GetKeys()) != len(want.Keys) || issuer.GetActiveKeyId() != want.ActiveKeyID {
		t.Fatalf("keys = %+v (active %q), want %+v (active %q)", issuer.GetKeys(), issuer.GetActiveKeyId(), want.Keys, want.ActiveKeyID)
	}
	key := issuer.GetKeys()[0]
	if key.GetKid() != want.ActiveKeyID || key.GetRetired() != nil || key.GetCreated() == nil {
		t.Errorf("key = %+v, want the active key %q with a creation time", key, want.ActiveKeyID)
	}

	// The feature is advertised through Meta as well.
	meta, err := client.GetMeta(grpcCtx(readToken), &xunarav2.GetMetaRequest{})
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if !meta.GetIdentityTokensEnabled() {
		t.Error("meta does not advertise identity tokens")
	}
}

// TestPlatformGRPCIDTokenIssuerWithoutIssuer checks the disabled shape over
// gRPC: enabled=false and no keys, matching HTTP.
func TestPlatformGRPCIDTokenIssuerWithoutIssuer(t *testing.T) {
	s := newServerWithoutIssuer(t)
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)
	_, token := seedAPIKey(t, s, identity.ScopeRead)

	issuer, err := client.GetIDTokenIssuer(grpcCtx(token), &xunarav2.GetIDTokenIssuerRequest{})
	if err != nil {
		t.Fatalf("GetIDTokenIssuer: %v", err)
	}
	if issuer.GetEnabled() || issuer.GetIssuer() != "" || issuer.GetActiveKeyId() != "" || len(issuer.GetKeys()) != 0 {
		t.Errorf("issuer without an issuer URL = %+v, want disabled and empty", issuer)
	}

	meta, err := client.GetMeta(grpcCtx(token), &xunarav2.GetMetaRequest{})
	if err != nil {
		t.Fatalf("GetMeta: %v", err)
	}
	if meta.GetIdentityTokensEnabled() {
		t.Error("meta advertises identity tokens without an issuer URL")
	}
}

// TestPlatformGRPCDeviceAttrs checks the read-only posture view over gRPC: read
// scope only, the JSON scalars the node reported, and the per-machine count in
// ListMachines.
func TestPlatformGRPCDeviceAttrs(t *testing.T) {
	s := newTestServer(t)
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	reporter := seedAPIMachine(t, s, "reporter", nil)
	quiet := seedAPIMachine(t, s, "quiet", nil)
	if err := s.store.SetNodeDeviceAttrs(reporter.ID, map[string]any{
		"os_version": "15.2",
		"encrypted":  true,
		"score":      float64(7.5),
	}); err != nil {
		t.Fatalf("SetNodeDeviceAttrs: %v", err)
	}

	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)

	if _, err := client.GetMachineDeviceAttrs(grpcCtx(""), &xunarav2.GetMachineDeviceAttrsRequest{MachineId: uint64(reporter.ID)}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("anonymous error = %v, want Unauthenticated", err)
	}
	if _, err := client.GetMachineDeviceAttrs(grpcCtx(writeToken), &xunarav2.GetMachineDeviceAttrsRequest{MachineId: uint64(reporter.ID)}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("write-only error = %v, want PermissionDenied", err)
	}
	if _, err := client.GetMachineDeviceAttrs(grpcCtx(readToken), &xunarav2.GetMachineDeviceAttrsRequest{MachineId: 9999}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown machine error = %v, want NotFound", err)
	}

	got, err := client.GetMachineDeviceAttrs(grpcCtx(readToken), &xunarav2.GetMachineDeviceAttrsRequest{MachineId: uint64(reporter.ID)})
	if err != nil {
		t.Fatalf("GetMachineDeviceAttrs: %v", err)
	}
	if got.GetMachineId() != uint64(reporter.ID) || got.GetStableId() != reporter.StableID {
		t.Errorf("identity = %d/%q, want %d/%q", got.GetMachineId(), got.GetStableId(), reporter.ID, reporter.StableID)
	}
	attrs := got.GetAttrs()
	if len(attrs) != 3 {
		t.Fatalf("attrs = %v, want 3", attrs)
	}
	if attrs["os_version"].GetStringValue() != "15.2" || !attrs["encrypted"].GetBoolValue() || attrs["score"].GetNumberValue() != 7.5 {
		t.Errorf("attrs = %v", attrs)
	}

	// A machine without attributes answers without any entries. An empty map
	// and a nil map are indistinguishable on the wire, so only the length is
	// meaningful here.
	empty, err := client.GetMachineDeviceAttrs(grpcCtx(readToken), &xunarav2.GetMachineDeviceAttrsRequest{MachineId: uint64(quiet.ID)})
	if err != nil {
		t.Fatalf("GetMachineDeviceAttrs quiet: %v", err)
	}
	if len(empty.GetAttrs()) != 0 {
		t.Errorf("attrs without any = %v, want no entries", empty.GetAttrs())
	}

	list, err := client.ListMachines(grpcCtx(readToken), &xunarav2.ListMachinesRequest{})
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	seen := 0
	for _, m := range list.GetMachines() {
		switch m.GetStableId() {
		case reporter.StableID:
			seen++
			if m.GetDeviceAttrCount() != 3 {
				t.Errorf("reporter deviceAttrCount = %d, want 3", m.GetDeviceAttrCount())
			}
		case quiet.StableID:
			seen++
			if m.GetDeviceAttrCount() != 0 {
				t.Errorf("quiet deviceAttrCount = %d, want 0", m.GetDeviceAttrCount())
			}
		}
	}
	if seen != 2 {
		t.Errorf("ListMachines covered %d machines, want 2", seen)
	}
}

// TestPlatformGRPCListServices checks the read-only service registry over
// gRPC: scopes, filters, pagination and the same values the HTTP API returns.
func TestPlatformGRPCListServices(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com"})
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	web := seedAPIMachine(t, s, "web", nil)
	seedAPIMachine(t, s, "quiet", nil)
	if err := s.store.ReplaceNodeServices(web.ID, []state.Service{
		{Name: "api", Protocol: "tcp", Port: 8080, Metadata: map[string]string{"version": "2"}, Visibility: []string{"tag:app"}, Shared: true},
		{Name: "metrics", Protocol: "udp", Port: 9090, VisibilityFromACL: true},
	}); err != nil {
		t.Fatalf("ReplaceNodeServices: %v", err)
	}

	_, readToken := seedAPIKey(t, s, identity.ScopeRead)
	_, writeToken := seedAPIKey(t, s, identity.ScopeWrite)

	if _, err := client.ListServices(grpcCtx(""), &xunarav2.ListServicesRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("anonymous error = %v, want Unauthenticated", err)
	}
	if _, err := client.ListServices(grpcCtx(writeToken), &xunarav2.ListServicesRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("write-only error = %v, want PermissionDenied", err)
	}

	list, err := client.ListServices(grpcCtx(readToken), &xunarav2.ListServicesRequest{})
	if err != nil {
		t.Fatalf("ListServices: %v", err)
	}
	if len(list.GetServices()) != 2 {
		t.Fatalf("services = %+v, want two", list.GetServices())
	}
	first := list.GetServices()[0]
	if first.GetName() != "api" || first.GetProtocol() != "tcp" || first.GetPort() != 8080 {
		t.Errorf("first service = %+v", first)
	}
	if first.GetMachineId() != uint64(web.ID) || first.GetStableId() != web.StableID || first.GetHostname() != "web" {
		t.Errorf("first service identity = %+v", first)
	}
	if first.GetDnsName() != "api.example.com" || first.GetMetadata()["version"] != "2" {
		t.Errorf("first service dns/metadata = %+v", first)
	}
	if !slices.Equal(first.GetVisibility(), []string{"tag:app"}) {
		t.Errorf("first service visibility = %v, want tag:app", first.GetVisibility())
	}
	if len(list.GetServices()[1].GetVisibility()) != 1 || list.GetServices()[1].GetVisibility()[0] != "*" {
		t.Errorf("default visibility = %v, want [*]", list.GetServices()[1].GetVisibility())
	}
	if !first.GetShared() {
		t.Error("first service shared = false, want true")
	}
	if list.GetServices()[1].GetShared() {
		t.Error("default shared = true, want false")
	}
	if first.GetVisibilityFromAcl() {
		t.Error("api visibilityFromAcl = true, want false")
	}
	if !list.GetServices()[1].GetVisibilityFromAcl() {
		t.Error("metrics visibilityFromAcl = false, want true")
	}
	if first.GetCreated() == nil || first.GetUpdated() == nil {
		t.Errorf("first service has no timestamps: %+v", first)
	}

	byNode, err := client.ListServices(grpcCtx(readToken), &xunarav2.ListServicesRequest{NodeId: proto.Uint64(uint64(web.ID))})
	if err != nil {
		t.Fatalf("ListServices node filter: %v", err)
	}
	if len(byNode.GetServices()) != 2 {
		t.Errorf("node filter = %+v", byNode.GetServices())
	}
	byName, err := client.ListServices(grpcCtx(readToken), &xunarav2.ListServicesRequest{Name: "metrics"})
	if err != nil {
		t.Fatalf("ListServices name filter: %v", err)
	}
	if len(byName.GetServices()) != 1 || byName.GetServices()[0].GetProtocol() != "udp" {
		t.Errorf("name filter = %+v", byName.GetServices())
	}
	unknown, err := client.ListServices(grpcCtx(readToken), &xunarav2.ListServicesRequest{NodeId: proto.Uint64(9999)})
	if err != nil {
		t.Fatalf("ListServices unknown node: %v", err)
	}
	if len(unknown.GetServices()) != 0 {
		t.Errorf("unknown node filter = %+v, want none", unknown.GetServices())
	}
	// A present 0 is not a node ID and must match nothing; an absent one
	// still lists every machine.
	zeroNode, err := client.ListServices(grpcCtx(readToken), &xunarav2.ListServicesRequest{NodeId: proto.Uint64(0)})
	if err != nil {
		t.Fatalf("ListServices node_id=0: %v", err)
	}
	if len(zeroNode.GetServices()) != 0 {
		t.Errorf("node_id=0 filter = %+v, want none", zeroNode.GetServices())
	}
	unset, err := client.ListServices(grpcCtx(readToken), &xunarav2.ListServicesRequest{})
	if err != nil {
		t.Fatalf("ListServices without a node filter: %v", err)
	}
	if len(unset.GetServices()) == 0 {
		t.Error("an absent node_id must not filter anything out")
	}

	page, err := client.ListServices(grpcCtx(readToken), &xunarav2.ListServicesRequest{PageSize: 1})
	if err != nil {
		t.Fatalf("ListServices page 1: %v", err)
	}
	if len(page.GetServices()) != 1 || page.GetNextPageToken() == "" {
		t.Fatalf("page 1 = %+v, next %q", page.GetServices(), page.GetNextPageToken())
	}
	page2, err := client.ListServices(grpcCtx(readToken), &xunarav2.ListServicesRequest{PageSize: 1, PageToken: page.GetNextPageToken()})
	if err != nil {
		t.Fatalf("ListServices page 2: %v", err)
	}
	if len(page2.GetServices()) != 1 || page2.GetServices()[0].GetName() != "metrics" || page2.GetNextPageToken() != "" {
		t.Errorf("page 2 = %+v, next %q", page2.GetServices(), page2.GetNextPageToken())
	}
	if _, err := client.ListServices(grpcCtx(readToken), &xunarav2.ListServicesRequest{PageToken: apiV2EncodeCursor("machines", "1")}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("wrong cursor kind error = %v, want InvalidArgument", err)
	}

	// The machine list carries the per-machine count.
	machines, err := client.ListMachines(grpcCtx(readToken), &xunarav2.ListMachinesRequest{})
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	for _, m := range machines.GetMachines() {
		switch m.GetStableId() {
		case web.StableID:
			if m.GetServiceCount() != 2 {
				t.Errorf("web service_count = %d, want 2", m.GetServiceCount())
			}
		default:
			if m.GetServiceCount() != 0 {
				t.Errorf("%s service_count = %d, want 0", m.GetHostname(), m.GetServiceCount())
			}
		}
	}
}
