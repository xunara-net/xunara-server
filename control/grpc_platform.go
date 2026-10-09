package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"tailscale.com/tailcfg"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// Platform API v2 over gRPC (M8d).
//
// The gRPC surface mirrors the read-mostly /api/v2 endpoints so automation can
// use a typed protocol; the credentials, scopes, role rules and pagination
// cursors are exactly the HTTP ones. Nothing here touches the Tailscale
// compatibility core: TS2021, Noise, MapRequest and the node/machine key rules
// are unchanged.
//
// One service implementation serves both deployment shapes: a single
// organization registers [Server.RegisterPlatformGRPC], a multi-tenant router
// registers [Router.RegisterPlatformGRPC] and resolves the organization from
// the gRPC authority, which is the HTTP/2 equivalent of the Host header.

// grpcPlatformServer implements xunarav2.PlatformServiceServer. The organization
// is resolved per call, so one registration can serve many organizations.
type grpcPlatformServer struct {
	xunarav2.UnimplementedPlatformServiceServer

	// lookup resolves the organization a call addresses. It returns a gRPC
	// status error when the authority names no organization.
	lookup func(ctx context.Context) (*Server, error)
}

// RegisterPlatformGRPC registers the platform service for this organization.
func (s *Server) RegisterPlatformGRPC(reg grpc.ServiceRegistrar) {
	xunarav2.RegisterPlatformServiceServer(reg, &grpcPlatformServer{
		lookup: func(context.Context) (*Server, error) { return s, nil },
	})
}

// RegisterPlatformGRPC registers the platform service for every organization
// this router serves. The organization is chosen by the gRPC authority
// (":authority"), mirroring HTTP Host routing; an unknown authority is
// reported as NOT_FOUND without listing the hosted organizations.
func (r *Router) RegisterPlatformGRPC(reg grpc.ServiceRegistrar) {
	xunarav2.RegisterPlatformServiceServer(reg, &grpcPlatformServer{
		lookup: func(ctx context.Context) (*Server, error) {
			org := r.orgForHost(grpcAuthority(ctx))
			if org == nil {
				return nil, status.Error(codes.NotFound, "unknown organization")
			}
			return org.site.Server, nil
		},
	})
}

// startPlatformGRPC binds the optional platform gRPC listener for a single
// organization. A disabled surface (no address) returns nil values.
func (s *Server) startPlatformGRPC() (*grpc.Server, net.Listener, error) {
	return startPlatformGRPCOn(s.cfg.GRPCListenAddr, s.RegisterPlatformGRPC)
}

// startPlatformGRPC binds the optional platform gRPC listener for a router.
// Both surfaces are registered on it: the organization-scoped service and the
// deployment-level admin service.
func (r *Router) startPlatformGRPC() (*grpc.Server, net.Listener, error) {
	return startPlatformGRPCOn(r.cfg.GRPCListenAddr, func(reg grpc.ServiceRegistrar) {
		r.RegisterPlatformGRPC(reg)
		r.RegisterPlatformAdminGRPC(reg)
	})
}

// startPlatformGRPCOn binds addr and registers the platform service on it. A
// disabled surface (no address) returns nil values.
func startPlatformGRPCOn(addr string, register func(grpc.ServiceRegistrar)) (*grpc.Server, net.Listener, error) {
	if addr == "" {
		return nil, nil, nil
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("platform gRPC: %w", err)
	}
	srv := grpc.NewServer()
	register(srv)
	return srv, lis, nil
}

// stopPlatformGRPC stops the gRPC server, giving in-flight calls a grace period
// before the hard stop. A nil server is a no-op.
func stopPlatformGRPC(srv *grpc.Server) {
	if srv == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		srv.Stop()
	}
}

// grpcAuthority returns the ":authority" the client addressed, falling back to
// a "host" metadata entry for proxies that rewrite one into the other.
func grpcAuthority(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, key := range []string{":authority", "host"} {
		if values := md.Get(key); len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// grpcBearerToken reads the bearer token from the authorization metadata. Only
// the Bearer scheme is accepted, matching the HTTP API.
func grpcBearerToken(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	for _, value := range md.Get("authorization") {
		scheme, token, ok := strings.Cut(value, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			continue
		}
		if token = strings.TrimSpace(token); token != "" {
			return token, true
		}
	}
	return "", false
}

// authorize resolves the organization and the caller for one call. It applies
// the same credential, scope and role rules as the HTTP API.
func (g *grpcPlatformServer) authorize(ctx context.Context, scope string) (*Server, apiPrincipal, error) {
	server, err := g.lookup(ctx)
	if err != nil {
		return nil, apiPrincipal{}, err
	}

	token, ok := grpcBearerToken(ctx)
	if !ok {
		return nil, apiPrincipal{}, status.Error(codes.Unauthenticated, "authorization metadata with a Bearer token is required")
	}
	principal, err := server.principalForToken(ctx, token)
	if err != nil {
		if isAuthenticationRequired(err) {
			return nil, apiPrincipal{}, status.Error(codes.Unauthenticated, "invalid credential")
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, apiPrincipal{}, status.FromContextError(err).Err()
		}
		return nil, apiPrincipal{}, status.Error(codes.Unavailable, "authentication temporarily unavailable")
	}
	if err := authorizeScope(principal, scope); err != nil {
		return nil, apiPrincipal{}, status.Error(codes.PermissionDenied, err.Error())
	}
	return server, principal, nil
}

// GetMeta implements PlatformService.GetMeta.
func (g *grpcPlatformServer) GetMeta(ctx context.Context, _ *xunarav2.GetMetaRequest) (*xunarav2.Meta, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	return &xunarav2.Meta{
		Version:               Version,
		ServerUrl:             s.cfg.ServerURL,
		Domain:                s.cfg.Domain,
		CapabilityVersion:     uint64(tailcfg.CurrentCapabilityVersion),
		MinCapabilityVersion:  uint64(MinSupportedCapabilityVersion),
		MaxPageSize:           uint32(apiV2MaxPageSize),
		IdentityProviders:     s.providers.IDs(),
		AgentProtocolVersion:  uint32(agentProtocolVersion),
		WebhooksEnabled:       s.webhooksEnabled(),
		DnsProviderConfigured: s.cfg.DNSProvider != nil,
		CertDomains:           slices.Clone(s.certDomains),
		DerpMapConfigured:     s.DERPMap() != nil,
		DerpPolicy:            string(s.cfg.DERPPolicy.Mode),
		DerpRegionsServed:     uint32(s.derpRegionsServed()),
		IdentityTokensEnabled: s.tokens != nil,
		ReachEnabled:          s.cfg.ReachEnabled,
		FluxEnabled:           s.flux != nil,
		PasskeysEnabled:       s.passkeys != nil,
		SharingEnabled:        s.sharingEnabled(),
	}, nil
}

// GetOrganizationIdentity implements PlatformService.GetOrganizationIdentity:
// the same read-only identity as GET /api/v2/organization. The organization is
// the one the call's authority routed to; the request cannot name another.
func (g *grpcPlatformServer) GetOrganizationIdentity(ctx context.Context, _ *xunarav2.GetOrganizationIdentityRequest) (*xunarav2.OrganizationIdentity, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	org := s.Organization()
	domains := org.Domains
	if domains == nil {
		domains = []string{}
	}
	return &xunarav2.OrganizationIdentity{
		Id:             org.ID,
		Name:           org.Name,
		Domains:        domains,
		Managed:        org.Managed,
		MagicDnsDomain: s.cfg.Domain,
		ServerUrl:      s.cfg.ServerURL,
	}, nil
}

// GetIDTokenIssuer implements PlatformService.GetIDTokenIssuer: the same
// read-only issuer state as GET /api/v2/id-token. Only public key material
// (the JWKS content) and bookkeeping are reported; the private keys never
// leave the server.
func (g *grpcPlatformServer) GetIDTokenIssuer(ctx context.Context, _ *xunarav2.GetIDTokenIssuerRequest) (*xunarav2.IDTokenIssuerStatus, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	view, err := s.IDTokenStatus()
	if err != nil {
		s.log.Error("reading the identity-token issuer state", "err", err)
		return nil, status.Error(codes.Internal, "identity-token issuer state is unavailable")
	}

	out := &xunarav2.IDTokenIssuerStatus{
		Enabled:         view.Enabled,
		Issuer:          view.Issuer,
		JwksUrl:         view.JWKSURL,
		Algorithm:       view.Algorithm,
		TokenTtlSeconds: int64(view.TokenTTLSeconds),
		ActiveKeyId:     view.ActiveKeyID,
		Keys:            make([]*xunarav2.IDTokenSigningKey, 0, len(view.Keys)),
	}
	for _, key := range view.Keys {
		entry := &xunarav2.IDTokenSigningKey{
			Kid:     key.KID,
			Created: timestamppb.New(key.Created),
		}
		if !key.Retired.IsZero() {
			entry.Retired = timestamppb.New(key.Retired)
		}
		out.Keys = append(out.Keys, entry)
	}
	return out, nil
}

// GetMachineDeviceAttrs implements PlatformService.GetMachineDeviceAttrs: the
// same read-only device posture view as
// GET /api/v2/machines/{id}/device-attrs. Values are the JSON scalars the node
// reported; the machine must belong to the organization this call authorized
// against.
// GetDERPStatus implements PlatformService.GetDERPStatus: the same read-only
// DERP state as GET /api/v2/derp (spec section 32.1). The request carries no
// parameters: the organization follows from the authority, and the policy is
// configuration.
func (g *grpcPlatformServer) GetDERPStatus(ctx context.Context, _ *xunarav2.GetDERPStatusRequest) (*xunarav2.DERPStatus, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	view, _ := s.derpStatus()
	out := &xunarav2.DERPStatus{
		PolicyMode:            view.PolicyMode,
		PolicyRegions:         view.PolicyRegions,
		MapConfigured:         view.MapConfigured,
		RegionsServed:         uint32(view.RegionsServed),
		Regions:               make([]*xunarav2.DERPRegion, 0, len(view.Regions)),
		NodesWithoutHome:      uint32(view.NodesWithoutHome),
		NodesWithUnservedHome: uint32(view.NodesWithUnservedHome),
	}
	for _, region := range view.Regions {
		out.Regions = append(out.Regions, &xunarav2.DERPRegion{
			Id:        region.ID,
			Code:      region.Code,
			Name:      region.Name,
			Hosts:     region.Hosts,
			NodeCount: uint32(region.NodeCount),
		})
	}
	return out, nil
}

// GetPolicyStatus implements PlatformService.GetPolicyStatus: the same
// read-only policy view as GET /api/v2/policy (spec section 34.1). The request
// carries no parameters: the organization follows from the authority, and the
// document is local configuration. A document whose tests fail is data, not an
// RPC error.
func (g *grpcPlatformServer) GetPolicyStatus(ctx context.Context, _ *xunarav2.GetPolicyStatusRequest) (*xunarav2.PolicyStatus, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	view := s.policyView()
	out := &xunarav2.PolicyStatus{
		Configured:  view.Configured,
		Path:        view.Path,
		RuleCount:   uint32(view.RuleCount),
		Warnings:    view.Warnings,
		Unsupported: view.Unsupported,
		LoadError:   view.LoadError,
		Acls:        make([]*xunarav2.PolicyACLRule, 0, len(view.ACLs)),
		Grants:      make([]*xunarav2.PolicyGrant, 0, len(view.Grants)),
		Groups:      policyStringLists(view.Groups),
		Hosts:       view.Hosts,
		TagOwners:   policyStringLists(view.TagOwners),
		Ssh:         make([]*xunarav2.PolicySSHRule, 0, len(view.SSH)),
		NodeAttrs:   make([]*xunarav2.PolicyNodeAttr, 0, len(view.NodeAttrs)),
		Tests: &xunarav2.PolicyTestSummary{
			Total:   uint32(view.Tests.Total),
			Ran:     view.Tests.Ran,
			Reason:  view.Tests.Reason,
			Results: make([]*xunarav2.PolicyTestResult, 0, len(view.Tests.Results)),
		},
	}
	for _, row := range view.ACLs {
		out.Acls = append(out.Acls, &xunarav2.PolicyACLRule{
			Action: row.Action,
			Proto:  row.Proto,
			Src:    row.Src,
			Dst:    row.Dst,
			Users:  row.Users,
			Ports:  row.Ports,
		})
	}
	for _, row := range view.Grants {
		grant := &xunarav2.PolicyGrant{
			Src: row.Src,
			Dst: row.Dst,
			Ip:  row.IP,
			Via: row.Via,
			App: make(map[string]*xunarav2.StringList, len(row.App)),
		}
		for name, values := range row.App {
			encoded := make([]string, len(values))
			for i, value := range values {
				encoded[i] = string(value)
			}
			grant.App[name] = &xunarav2.StringList{Values: encoded}
		}
		out.Grants = append(out.Grants, grant)
	}
	for _, row := range view.SSH {
		out.Ssh = append(out.Ssh, &xunarav2.PolicySSHRule{
			Action:      row.Action,
			Src:         row.Src,
			Dst:         row.Dst,
			Users:       row.Users,
			AcceptEnv:   row.AcceptEnv,
			CheckPeriod: row.CheckPeriod,
		})
	}
	for _, row := range view.NodeAttrs {
		out.NodeAttrs = append(out.NodeAttrs, &xunarav2.PolicyNodeAttr{
			Target: row.Target,
			Attr:   row.Attr,
		})
	}
	for _, result := range view.Tests.Results {
		out.Tests.Results = append(out.Tests.Results, &xunarav2.PolicyTestResult{
			Index:    uint32(result.Index),
			Src:      result.Src,
			Proto:    result.Proto,
			Pass:     result.Pass,
			Failures: result.Failures,
		})
	}
	return out, nil
}

// policyStringLists converts document map values to the proto map type.
func policyStringLists(in map[string][]string) map[string]*xunarav2.StringList {
	out := make(map[string]*xunarav2.StringList, len(in))
	for name, values := range in {
		out[name] = &xunarav2.StringList{Values: values}
	}
	return out
}

func (g *grpcPlatformServer) GetMachineDeviceAttrs(ctx context.Context, req *xunarav2.GetMachineDeviceAttrsRequest) (*xunarav2.MachineDeviceAttrs, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	node, ok := s.store.GetNodeByID(state.NodeID(req.GetMachineId()))
	if !ok {
		return nil, status.Error(codes.NotFound, "machine not found")
	}

	attrs, err := s.store.NodeDeviceAttrs(node.ID)
	if err != nil {
		s.log.Error("reading device attributes", "node", node.StableID, "err", err)
		return nil, status.Error(codes.Internal, "device attributes are unavailable")
	}

	out := &xunarav2.MachineDeviceAttrs{
		MachineId: uint64(node.ID),
		StableId:  node.StableID,
		Attrs:     make(map[string]*structpb.Value, len(attrs)),
	}
	for name, value := range attrs {
		converted, err := structpb.NewValue(value)
		if err != nil {
			// A value the store cannot represent in a protobuf Value is a
			// server-side bug (ingestion only stores JSON scalars).
			return nil, status.Error(codes.Internal, "device attribute cannot be encoded")
		}
		out.Attrs[name] = converted
	}
	return out, nil
}

// GetTailnetLock implements PlatformService.GetTailnetLock: the same
// read-only tailnet-lock status as GET /api/v2/tka. The AUM chain contents,
// the trusted key material and the sealed disablement secret stay on the
// server; the head hash and node counts are what clients already receive in
// the netmap.
func (g *grpcPlatformServer) GetTailnetLock(ctx context.Context, _ *xunarav2.GetTailnetLockRequest) (*xunarav2.TailnetLockStatus, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	status := s.TKAStatus()
	return &xunarav2.TailnetLockStatus{
		EverEnabled: status.EverEnabled,
		Enabled:     status.Enabled,
		Disabled:    status.Disabled,
		Head:        status.Head,
		Nodes: &xunarav2.TailnetLockNodeCounts{
			Total:    uint32(status.Nodes.Total),
			Signed:   uint32(status.Nodes.Signed),
			Unsigned: uint32(status.Nodes.Unsigned),
		},
	}, nil
}

// ListMachines implements PlatformService.ListMachines. Filters and cursor
// semantics match GET /api/v2/machines.
func (g *grpcPlatformServer) ListMachines(ctx context.Context, req *xunarav2.ListMachinesRequest) (*xunarav2.ListMachinesResponse, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}
	if req.GetState() != "" && req.GetState() != "online" && req.GetState() != "offline" {
		return nil, status.Error(codes.InvalidArgument, "state must be \"online\", \"offline\" or empty")
	}

	limit := grpcPageSize(req.GetPageSize(), 50)
	after, ok := grpcCursorUint(req.GetPageToken(), "machines")
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid page token")
	}

	// An unknown user matches nothing instead of being ignored, exactly like
	// the HTTP filter.
	var userFilter uint64
	if raw := strings.TrimSpace(req.GetUser()); raw != "" {
		if id, err := strconv.ParseUint(raw, 10, 64); err == nil && id > 0 {
			userFilter = id
		} else if user, ok := s.identity.GetUserByLoginName(raw); ok {
			userFilter = uint64(user.ID)
		} else {
			userFilter = ^uint64(0)
		}
	}
	tagFilter := strings.TrimSpace(req.GetTag())

	nodes := s.store.ListNodes()
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	out := make([]*xunarav2.Machine, 0, limit)
	counts := s.deviceAttrCounts()
	serviceCounts := s.serviceCounts()
	var last uint64
	next := ""
	for _, n := range nodes {
		id := uint64(n.ID)
		if id <= after {
			continue
		}
		if userFilter != 0 && uint64(n.UserID) != userFilter {
			continue
		}
		if tagFilter != "" && !slices.Contains(n.Tags, tagFilter) {
			continue
		}
		online := s.isOnline(n.ID)
		if req.GetState() == "online" && !online {
			continue
		}
		if req.GetState() == "offline" && online {
			continue
		}
		if len(out) == limit {
			next = apiV2EncodeCursor("machines", strconv.FormatUint(last, 10))
			break
		}
		view := grpcMachineView(n, s)
		view.DeviceAttrCount = uint32(counts[n.ID])
		view.ServiceCount = uint32(serviceCounts[n.ID])
		out = append(out, view)
		last = id
	}

	return &xunarav2.ListMachinesResponse{Machines: out, NextPageToken: next}, nil
}

// ListServices implements PlatformService.ListServices: the same read-only
// registry as GET /api/v2/services, with the same filters and cursor.
func (g *grpcPlatformServer) ListServices(ctx context.Context, req *xunarav2.ListServicesRequest) (*xunarav2.ListServicesResponse, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	limit := grpcPageSize(req.GetPageSize(), 100)
	after, ok := grpcCursorString(req.GetPageToken(), "services")
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid page token")
	}

	// An absent node_id lists every machine; a present 0 is not a node ID and
	// matches nothing, exactly like the HTTP filter.
	var nodeFilter state.NodeID
	if req.NodeId != nil {
		nodeFilter = state.NodeID(req.GetNodeId())
		if nodeFilter == 0 {
			nodeFilter = ^state.NodeID(0)
		}
	}
	nameFilter := strings.TrimSpace(req.GetName())

	out := make([]*xunarav2.Service, 0, limit)
	var last string
	next := ""
	for _, svc := range s.store.ListServices() {
		if after != "" && svc.Name <= after {
			continue
		}
		if nodeFilter != 0 && svc.NodeID != nodeFilter {
			continue
		}
		if nameFilter != "" && svc.Name != nameFilter {
			continue
		}
		if len(out) == limit {
			next = apiV2EncodeCursor("services", last)
			break
		}
		node, ok := s.store.GetNodeByID(svc.NodeID)
		if !ok {
			continue
		}
		view := s.serviceView(svc, node)
		entry := &xunarav2.Service{
			Name:              view.Name,
			Protocol:          view.Protocol,
			Port:              uint32(view.Port),
			Metadata:          view.Metadata,
			MachineId:         view.NodeID,
			StableId:          view.StableID,
			Hostname:          view.Hostname,
			DnsName:           view.DNSName,
			Visibility:        view.Visibility,
			Shared:            view.Shared,
			VisibilityFromAcl: view.VisibilityFromACL,
			Created:           timestamppb.New(view.Created),
			Updated:           timestamppb.New(view.Updated),
			Health:            view.Health,
		}
		if !view.HealthReportedAt.IsZero() {
			entry.HealthReportedAt = timestamppb.New(view.HealthReportedAt)
		}
		out = append(out, entry)
		last = svc.Name
	}

	return &xunarav2.ListServicesResponse{Services: out, NextPageToken: next}, nil
}

// ListReachSessions implements PlatformService.ListReachSessions: the same
// read-only listing as GET /api/v2/reach/sessions, with the same filters and
// cursor. Reach must be enabled; otherwise the call is NOT_FOUND, matching the
// HTTP 404.
func (g *grpcPlatformServer) ListReachSessions(ctx context.Context, req *xunarav2.ListReachSessionsRequest) (*xunarav2.ListReachSessionsResponse, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}
	if !s.cfg.ReachEnabled {
		return nil, status.Error(codes.NotFound, "reach is not enabled")
	}

	limit := grpcPageSize(req.GetPageSize(), 100)
	afterCreated, afterID, ok := grpcCursorTime(req.GetPageToken(), "reach")
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid page token")
	}
	var stateFilter state.ReachState
	if raw := strings.TrimSpace(req.GetState()); raw != "" {
		stateFilter = state.ReachState(raw)
		if !stateFilter.Valid() {
			return nil, status.Error(codes.InvalidArgument, "invalid state filter")
		}
	}
	nodeFilter := s.apiV2NodeFilter(strings.TrimSpace(req.GetNode()))

	out := make([]*xunarav2.ReachSession, 0, limit)
	var last state.ReachSession
	next := ""
	for _, session := range s.store.ListAllReachSessions() {
		if !newestFirstAfterCursor(session.CreatedAt, session.ID, afterCreated, afterID) {
			continue
		}
		if stateFilter != "" && session.State != stateFilter {
			continue
		}
		if nodeFilter != 0 && session.Sender != nodeFilter && session.Target != nodeFilter {
			continue
		}
		if len(out) == limit {
			next = reachEncodePageCursor(last)
			break
		}
		view, ok := s.reachAdminView(session)
		if !ok {
			continue
		}
		out = append(out, grpcReachSession(view))
		last = session
	}

	return &xunarav2.ListReachSessionsResponse{Sessions: out, NextPageToken: next}, nil
}

// ListFluxTransfers implements PlatformService.ListFluxTransfers: the same
// read-only listing as GET /api/v2/flux/transfers, with the same filters and
// cursor. Flux must be enabled; otherwise the call is NOT_FOUND, matching the
// HTTP 404. No message carries content or key material.
func (g *grpcPlatformServer) ListFluxTransfers(ctx context.Context, req *xunarav2.ListFluxTransfersRequest) (*xunarav2.ListFluxTransfersResponse, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}
	if s.flux == nil {
		return nil, status.Error(codes.NotFound, "flux is not enabled")
	}

	limit := grpcPageSize(req.GetPageSize(), 100)
	afterCreated, afterID, ok := grpcCursorTime(req.GetPageToken(), "flux")
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid page token")
	}
	var stateFilter state.FluxTransferState
	if raw := strings.TrimSpace(req.GetState()); raw != "" {
		stateFilter = state.FluxTransferState(raw)
		if !stateFilter.Valid() {
			return nil, status.Error(codes.InvalidArgument, "invalid state filter")
		}
	}
	nodeFilter := s.apiV2NodeFilter(strings.TrimSpace(req.GetNode()))

	out := make([]*xunarav2.FluxTransfer, 0, limit)
	var last state.FluxTransfer
	next := ""
	for _, transfer := range s.store.ListAllFluxTransfers() {
		if !newestFirstAfterCursor(transfer.CreatedAt, transfer.ID, afterCreated, afterID) {
			continue
		}
		if stateFilter != "" && transfer.State != stateFilter {
			continue
		}
		if nodeFilter != 0 && transfer.SenderNode != nodeFilter && transfer.RecipientNode != nodeFilter {
			continue
		}
		if len(out) == limit {
			next = fluxEncodePageCursor(last)
			break
		}
		view, ok := s.fluxAdminView(transfer)
		if !ok {
			continue
		}
		out = append(out, grpcFluxTransfer(view))
		last = transfer
	}

	return &xunarav2.ListFluxTransfersResponse{Transfers: out, NextPageToken: next}, nil
}

// GetFluxTransfer implements PlatformService.GetFluxTransfer.
func (g *grpcPlatformServer) GetFluxTransfer(ctx context.Context, req *xunarav2.GetFluxTransferRequest) (*xunarav2.FluxTransfer, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}
	if s.flux == nil {
		return nil, status.Error(codes.NotFound, "flux is not enabled")
	}

	transfer, ok := s.store.GetFluxTransfer(req.GetId())
	if !ok {
		return nil, status.Error(codes.NotFound, "no such transfer")
	}
	view, ok := s.fluxAdminView(transfer)
	if !ok {
		return nil, status.Error(codes.NotFound, "no such transfer")
	}
	return grpcFluxTransfer(view), nil
}

// grpcFluxTransfer converts one management view. Content and keys have no
// field to land in.
func grpcFluxTransfer(view fluxAdminTransfer) *xunarav2.FluxTransfer {
	return &xunarav2.FluxTransfer{
		Id:        view.ID,
		State:     view.State,
		Name:      view.Name,
		Size:      view.Size,
		Sha256:    view.SHA256,
		Sender:    &xunarav2.FluxPeer{NodeId: view.Sender.NodeID, StableId: view.Sender.StableID, Hostname: view.Sender.Hostname},
		Recipient: &xunarav2.FluxPeer{NodeId: view.Recipient.NodeID, StableId: view.Recipient.StableID, Hostname: view.Recipient.Hostname},
		Reason:    view.Reason,
		CreatedAt: timestamppb.New(view.CreatedAt),
		UpdatedAt: timestamppb.New(view.UpdatedAt),
		ExpiresAt: timestamppb.New(view.ExpiresAt),
	}
}

// GetReachSession implements PlatformService.GetReachSession.
func (g *grpcPlatformServer) GetReachSession(ctx context.Context, req *xunarav2.GetReachSessionRequest) (*xunarav2.ReachSession, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}
	if !s.cfg.ReachEnabled {
		return nil, status.Error(codes.NotFound, "reach is not enabled")
	}

	session, ok := s.store.GetReachSession(req.GetId())
	if !ok {
		return nil, status.Error(codes.NotFound, "no such session")
	}
	view, ok := s.reachAdminView(session)
	if !ok {
		return nil, status.Error(codes.NotFound, "no such session")
	}
	return grpcReachSession(view), nil
}

// grpcReachSession converts one management view.
func grpcReachSession(view reachAdminSession) *xunarav2.ReachSession {
	out := &xunarav2.ReachSession{
		Id:             view.ID,
		State:          view.State,
		Sender:         &xunarav2.ReachPeer{NodeId: view.Sender.NodeID, StableId: view.Sender.StableID, Hostname: view.Sender.Hostname},
		Target:         &xunarav2.ReachPeer{NodeId: view.Target.NodeID, StableId: view.Target.StableID, Hostname: view.Target.Hostname},
		Argv:           slices.Clone(view.Argv),
		TimeoutSeconds: uint32(view.TimeoutSec),
		Error:          view.Error,
		Created:        timestamppb.New(view.CreatedAt),
		Updated:        timestamppb.New(view.UpdatedAt),
		Expires:        timestamppb.New(view.ExpiresAt),
		OutputBytes:    &xunarav2.ReachOutputBytes{Stdout: view.OutputBytes.Stdout, Stderr: view.OutputBytes.Stderr},
	}
	if view.ExitCode != nil {
		code := int32(*view.ExitCode)
		out.ExitCode = &code
	}
	return out
}

// ListSSHCheckSessions implements PlatformService.ListSSHCheckSessions: the
// same read-only listing as GET /api/v2/ssh-check/sessions (spec section
// 35.1), with the same derived states, filters and cursor. Verdicts are only
// made on the browser approval page; there is no decide RPC.
func (g *grpcPlatformServer) ListSSHCheckSessions(ctx context.Context, req *xunarav2.ListSSHCheckSessionsRequest) (*xunarav2.ListSSHCheckSessionsResponse, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	limit := grpcPageSize(req.GetPageSize(), 100)
	afterCreated, afterID, ok := grpcCursorTime(req.GetPageToken(), "sshcheck")
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid page token")
	}
	stateFilter := strings.TrimSpace(req.GetState())
	if stateFilter != "" && !sshCheckStateValid(stateFilter) {
		return nil, status.Error(codes.InvalidArgument, "invalid state filter")
	}
	nodeFilter := s.apiV2NodeFilter(strings.TrimSpace(req.GetNode()))

	items, next, err := s.sshCheckPage(stateFilter, nodeFilter, limit, afterCreated, afterID)
	if err != nil {
		return nil, status.Error(codes.Internal, "could not list ssh checks")
	}
	out := &xunarav2.ListSSHCheckSessionsResponse{
		Sessions:      make([]*xunarav2.SSHCheckSession, 0, len(items)),
		NextPageToken: next,
	}
	for _, view := range items {
		out.Sessions = append(out.Sessions, grpcSSHCheckSession(view))
	}
	return out, nil
}

// grpcSSHCheckSession converts one management view.
func grpcSSHCheckSession(view sshCheckAdminSession) *xunarav2.SSHCheckSession {
	out := &xunarav2.SSHCheckSession{
		Id:        view.ID,
		State:     view.State,
		Verdict:   view.Verdict,
		Src:       &xunarav2.SSHCheckPeer{NodeId: view.Src.NodeID, StableId: view.Src.StableID, Hostname: view.Src.Hostname},
		Dst:       &xunarav2.SSHCheckPeer{NodeId: view.Dst.NodeID, StableId: view.Dst.StableID, Hostname: view.Dst.Hostname},
		LocalUser: view.LocalUser,
		CreatedAt: timestamppb.New(view.CreatedAt),
		ExpiresAt: timestamppb.New(view.ExpiresAt),
	}
	if view.DecidedAt != nil {
		out.DecidedAt = timestamppb.New(*view.DecidedAt)
	}
	if view.DecidedBy != nil {
		out.DecidedBy = &xunarav2.SSHCheckDecider{
			UserId:    view.DecidedBy.UserID,
			LoginName: view.DecidedBy.LoginName,
		}
	}
	if view.ConsumedAt != nil {
		out.ConsumedAt = timestamppb.New(*view.ConsumedAt)
	}
	return out
}

// grpcCursorTime decodes a newest-first list page token; an empty token
// starts at the top of the list.
func grpcCursorTime(raw, want string) (time.Time, string, bool) {
	kind, parts, ok := apiV2DecodeCursor(raw)
	if !ok || (kind != "" && (kind != want || len(parts) != 2)) {
		return time.Time{}, "", false
	}
	if kind == "" {
		return time.Time{}, "", true
	}
	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, "", false
	}
	return time.Unix(0, nanos).UTC(), parts[1], true
}

// ListAudit implements PlatformService.ListAudit. Filters and cursor semantics
// match GET /api/v2/audit, including the scan bound that keeps a filtered page
// from walking the whole log.
func (g *grpcPlatformServer) ListAudit(ctx context.Context, req *xunarav2.ListAuditRequest) (*xunarav2.ListAuditResponse, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	limit := grpcPageSize(req.GetPageSize(), 100)
	after, ok := grpcCursorUint(req.GetPageToken(), "audit")
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid page token")
	}

	items := make([]*xunarav2.AuditEvent, 0, limit)
	scanned := 0
	for len(items) < limit && scanned < apiV2AuditScanMax {
		batch := s.identity.ListAuditAfter(after, 256)
		if len(batch) == 0 {
			break
		}
		for _, e := range batch {
			after = e.ID
			scanned++
			if req.GetAction() != "" && e.Action != req.GetAction() {
				continue
			}
			if req.GetActor() != "" && e.Actor != req.GetActor() {
				continue
			}
			if req.GetTarget() != "" && !strings.HasPrefix(e.Target, req.GetTarget()) {
				continue
			}
			items = append(items, &xunarav2.AuditEvent{
				Id:     e.ID,
				Time:   timestamppb.New(e.Time),
				Actor:  e.Actor,
				Action: e.Action,
				Target: e.Target,
				Detail: e.Detail,
			})
			if len(items) == limit {
				break
			}
		}
		if len(batch) < 256 {
			break
		}
	}

	next := ""
	if len(items) == limit {
		next = apiV2EncodeCursor("audit", strconv.FormatUint(items[len(items)-1].GetId(), 10))
	}
	return &xunarav2.ListAuditResponse{Events: items, NextPageToken: next}, nil
}

// ListWebhooks implements PlatformService.ListWebhooks. The signing secret is
// never returned, matching the HTTP endpoint.
func (g *grpcPlatformServer) ListWebhooks(ctx context.Context, _ *xunarav2.ListWebhooksRequest) (*xunarav2.ListWebhooksResponse, error) {
	s, _, err := g.authorize(ctx, identity.ScopeRead)
	if err != nil {
		return nil, err
	}

	views := make([]apiWebhookView, 0, len(s.cfg.Webhooks)+4)
	for _, managed := range s.identity.ListWebhookEndpoints() {
		created, updated := managed.CreatedAt, managed.UpdatedAt
		views = append(views, apiWebhookView{
			ID: managed.ID, URL: managed.URL, Events: managed.Events,
			Enabled: managed.Enabled, Source: "managed",
			CreatedAt: &created, UpdatedAt: &updated,
		})
	}
	for _, ep := range s.cfg.Webhooks {
		views = append(views, apiWebhookView{
			ID: ep.ID, URL: ep.URL, Events: ep.Events, Enabled: true, Source: "config",
		})
	}

	out := make([]*xunarav2.Webhook, 0, len(views))
	for _, view := range views {
		webhook := &xunarav2.Webhook{
			Id:      view.ID,
			Url:     view.URL,
			Events:  slices.Clone(view.Events),
			Enabled: view.Enabled,
			Source:  view.Source,
		}
		if view.CreatedAt != nil {
			webhook.CreatedAt = timestamppb.New(*view.CreatedAt)
		}
		if view.UpdatedAt != nil {
			webhook.UpdatedAt = timestamppb.New(*view.UpdatedAt)
		}
		out = append(out, webhook)
	}
	return &xunarav2.ListWebhooksResponse{Webhooks: out}, nil
}

// RevokeAgentToken implements PlatformService.RevokeAgentToken. It is
// idempotent and audited exactly like DELETE /api/v2/agent-tokens/{id}.
func (g *grpcPlatformServer) RevokeAgentToken(ctx context.Context, req *xunarav2.RevokeAgentTokenRequest) (*xunarav2.RevokeAgentTokenResponse, error) {
	s, principal, err := g.authorize(ctx, identity.ScopeWrite)
	if err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "agent token id is required")
	}
	var found *identity.AgentToken
	for _, t := range s.identity.ListAgentTokens(0) {
		if t.ID == id {
			token := t
			found = &token
			break
		}
	}
	if found == nil {
		return nil, status.Error(codes.NotFound, "agent token not found")
	}

	if err := s.identity.RevokeAgentToken(id, time.Now().UTC()); err != nil {
		s.log.Error("revoking agent token", "token", id, "err", err)
		return nil, status.Error(codes.Internal, "could not revoke the agent token")
	}
	s.audit(principal.actor(), identity.AuditAgentTokenRevoked, "agenttoken:"+id,
		fmt.Sprintf("revoked the native client credential of node %d", found.NodeID))
	return &xunarav2.RevokeAgentTokenResponse{Id: id, Revoked: true}, nil
}

// grpcPageSize applies the same page bounds as the HTTP "limit" parameter,
// including that endpoint's default.
func grpcPageSize(requested uint32, def int) int {
	limit := int(requested)
	if limit <= 0 {
		limit = def
	}
	if limit > apiV2MaxPageSize {
		limit = apiV2MaxPageSize
	}
	return limit
}

// grpcCursorUint reads a single-number cursor of the given kind, accepting the
// same opaque tokens the HTTP API returns. An invalid token is rejected rather
// than treated as "from the start".
func grpcCursorUint(raw, kind string) (uint64, bool) {
	cursorKind, parts, ok := apiV2DecodeCursor(raw)
	if !ok || (cursorKind != "" && cursorKind != kind) || len(parts) > 1 {
		return 0, false
	}
	if cursorKind == "" {
		return 0, true
	}
	id, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// grpcCursorString reads a single-string cursor of the given kind, accepting
// the same opaque tokens the HTTP API returns.
func grpcCursorString(raw, kind string) (string, bool) {
	cursorKind, parts, ok := apiV2DecodeCursor(raw)
	if !ok || (cursorKind != "" && cursorKind != kind) || len(parts) > 1 {
		return "", false
	}
	if cursorKind == "" {
		return "", true
	}
	return parts[0], true
}

// grpcMachineView builds the typed view of one node.
func grpcMachineView(n state.Node, s *Server) *xunarav2.Machine {
	view := s.apiMachineView(n)
	machine := &xunarav2.Machine{
		Id:              view.ID,
		StableId:        view.StableID,
		Hostname:        view.Hostname,
		UserId:          view.UserID,
		UserLoginName:   view.UserLoginName,
		Online:          view.Online,
		Ephemeral:       view.Ephemeral,
		Expired:         view.Expired,
		Method:          view.Method,
		Ipv4:            view.IPv4,
		Ipv6:            view.IPv6,
		Created:         timestamppb.New(view.Created),
		Tags:            slices.Clone(n.Tags),
		ApprovedRoutes:  slices.Clone(view.ApprovedRoutes),
		AnnouncedRoutes: slices.Clone(view.AnnouncedRoutes),
		ExitNode:        view.ExitNode,
	}
	if view.LastSeen != nil {
		machine.LastSeen = timestamppb.New(*view.LastSeen)
	}
	return machine
}
