package control

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
)

// Deployment-level platform API over gRPC.
//
// This service mirrors /api/platform/v1: it manages the organizations a
// multi-tenant deployment hosts. It is deliberately separate from the
// organization-scoped [xunarav2.PlatformService]: the only credential it
// accepts is the process-level platform admin token, so an organization's
// session or API key can never enumerate or change its neighbours (AGENTS.md
// section 12). When no token is configured the service fails closed, exactly
// like the HTTP handlers.

// grpcPlatformAdminServer implements xunarav2.PlatformAdminServiceServer.
type grpcPlatformAdminServer struct {
	xunarav2.UnimplementedPlatformAdminServiceServer

	router *Router
}

// RegisterPlatformAdminGRPC registers the deployment-level platform service.
// It requires [RouterConfig.PlatformAdminToken]; without one every call fails
// with PERMISSION_DENIED.
func (r *Router) RegisterPlatformAdminGRPC(reg grpc.ServiceRegistrar) {
	xunarav2.RegisterPlatformAdminServiceServer(reg, &grpcPlatformAdminServer{router: r})
}

// authorize enforces the platform admin token, fail closed.
func (g *grpcPlatformAdminServer) authorize(ctx context.Context) error {
	if g.router.cfg.PlatformAdminToken == "" {
		return status.Error(codes.PermissionDenied, "platform API is disabled")
	}
	token, ok := grpcBearerToken(ctx)
	if !ok || !constantTimeTokenEqual(g.router.platformTokenHash, token) {
		return status.Error(codes.Unauthenticated, "unauthorized")
	}
	return nil
}

// orgStatus maps an organization error to a gRPC status, mirroring the HTTP
// status codes. Validation messages come from [orgAPIError] and are safe to
// return; anything unexpected is logged and reported as INTERNAL.
func (g *grpcPlatformAdminServer) orgStatus(op string, err error) error {
	var apiErr *orgAPIError
	switch {
	case errors.As(err, &apiErr):
		// orgAPIError carries the HTTP status the HTTP handler would write;
		// translate it so callers see the same distinction between a client
		// mistake (400) and a conflict (409).
		switch apiErr.status {
		case http.StatusConflict:
			return status.Error(codes.AlreadyExists, apiErr.msg)
		case http.StatusNotFound:
			return status.Error(codes.NotFound, apiErr.msg)
		case http.StatusForbidden:
			return status.Error(codes.PermissionDenied, apiErr.msg)
		default:
			return status.Error(codes.InvalidArgument, apiErr.msg)
		}
	case errors.Is(err, ErrOrgExists):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, ErrOrgNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, errOrgConfigured):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, errManagedOrgsDisabled):
		return status.Error(codes.PermissionDenied, err.Error())
	default:
		g.router.log.Error("platform organization request failed", "op", op, "err", err)
		return status.Error(codes.Internal, "internal error")
	}
}

// ListOrganizations implements PlatformAdminService.ListOrganizations.
func (g *grpcPlatformAdminServer) ListOrganizations(ctx context.Context, _ *xunarav2.ListOrganizationsRequest) (*xunarav2.ListOrganizationsResponse, error) {
	if err := g.authorize(ctx); err != nil {
		return nil, err
	}

	snapshot := g.router.orgSnapshot()
	orgs := make([]*xunarav2.Organization, 0, len(snapshot))
	for _, org := range snapshot {
		orgs = append(orgs, g.router.grpcOrganizationView(org))
	}
	return &xunarav2.ListOrganizationsResponse{Organizations: orgs}, nil
}

// GetOrganization implements PlatformAdminService.GetOrganization.
func (g *grpcPlatformAdminServer) GetOrganization(ctx context.Context, req *xunarav2.GetOrganizationRequest) (*xunarav2.Organization, error) {
	if err := g.authorize(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "organization id is required")
	}
	org := g.router.orgByID(id)
	if org == nil {
		return nil, status.Error(codes.NotFound, "organization not found")
	}
	return g.router.grpcOrganizationView(org), nil
}

// CreateOrganization implements PlatformAdminService.CreateOrganization.
func (g *grpcPlatformAdminServer) CreateOrganization(ctx context.Context, req *xunarav2.CreateOrganizationRequest) (*xunarav2.Organization, error) {
	if err := g.authorize(ctx); err != nil {
		return nil, err
	}

	site, err := g.router.CreateManagedOrg(ctx, ManagedOrg{
		ID:        strings.TrimSpace(req.GetId()),
		Name:      strings.TrimSpace(req.GetName()),
		Domains:   req.GetDomains(),
		ServerURL: strings.TrimSpace(req.GetServerUrl()),
		Domain:    strings.TrimSpace(req.GetDomain()),
	})
	if err != nil {
		return nil, g.orgStatus("create", err)
	}
	org := g.router.orgByID(site.ID)
	if org == nil {
		// The organization was registered a moment ago; this only happens if
		// the router was closed concurrently.
		return nil, status.Error(codes.Unavailable, "organization is no longer served")
	}
	return g.router.grpcOrganizationView(org), nil
}

// UpdateOrganization implements PlatformAdminService.UpdateOrganization.
func (g *grpcPlatformAdminServer) UpdateOrganization(ctx context.Context, req *xunarav2.UpdateOrganizationRequest) (*xunarav2.Organization, error) {
	if err := g.authorize(ctx); err != nil {
		return nil, err
	}
	if req.Name == nil && req.Domains == nil {
		return nil, status.Error(codes.InvalidArgument, "nothing to update")
	}

	var name *string
	if req.Name != nil {
		trimmed := strings.TrimSpace(req.GetName())
		name = &trimmed
	}
	var domains []string
	if req.Domains != nil {
		domains = req.GetDomains().GetValues()
	}

	site, err := g.router.UpdateManagedOrg(ctx, strings.TrimSpace(req.GetId()), name, domains)
	if err != nil {
		return nil, g.orgStatus("update", err)
	}
	org := g.router.orgByID(site.ID)
	if org == nil {
		return nil, status.Error(codes.Unavailable, "organization is no longer served")
	}
	return g.router.grpcOrganizationView(org), nil
}

// DeleteOrganization implements PlatformAdminService.DeleteOrganization.
func (g *grpcPlatformAdminServer) DeleteOrganization(ctx context.Context, req *xunarav2.DeleteOrganizationRequest) (*xunarav2.DeleteOrganizationResponse, error) {
	if err := g.authorize(ctx); err != nil {
		return nil, err
	}

	id := strings.TrimSpace(req.GetId())
	archived, err := g.router.DeleteManagedOrg(ctx, id)
	if err != nil {
		return nil, g.orgStatus("delete", err)
	}
	return &xunarav2.DeleteOrganizationResponse{Id: id, Deleted: true, ArchivedAt: archived}, nil
}

// ListAudit implements PlatformAdminService.ListAudit. It mirrors
// GET /api/platform/v1/audit, including per-organization cursors and the rule
// that filtered-out events still advance a cursor.
func (g *grpcPlatformAdminServer) ListAudit(ctx context.Context, req *xunarav2.ListPlatformAuditRequest) (*xunarav2.ListPlatformAuditResponse, error) {
	if err := g.authorize(ctx); err != nil {
		return nil, err
	}

	orgs, err := g.router.selectAuditOrgs(req.GetOrgs())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	cursors, err := parseAuditCursors(req.GetCursors())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	patterns, err := parseAuditActions(req.GetActions())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// An unset protobuf limit is zero, which means "default", not "invalid".
	limit := platformAuditDefaultLimit
	if req.GetLimit() != 0 {
		parsed, err := parseAuditLimit(strconv.FormatUint(uint64(req.GetLimit()), 10))
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		limit = parsed
	}

	events := make([]*xunarav2.PlatformAuditEvent, 0, len(orgs)*8)
	next := make(map[string]uint64, len(orgs))
	hasMore := false

	for _, org := range orgs {
		after := cursors[org.site.ID]
		next[org.site.ID] = after

		batch := org.site.Server.Identity().ListAuditAfter(after, limit)
		if len(batch) == limit {
			hasMore = true
		}
		for _, event := range batch {
			next[org.site.ID] = event.ID
			if !matchesAnyAction(patterns, event.Action) {
				continue
			}
			events = append(events, &xunarav2.PlatformAuditEvent{
				Org:    org.site.ID,
				Id:     event.ID,
				Time:   timestamppb.New(event.Time),
				Actor:  event.Actor,
				Action: event.Action,
				Target: event.Target,
				Detail: event.Detail,
			})
		}
	}

	// Merge the per-organization logs into one stream ordered by time, with
	// the organization and ID breaking ties so the order is deterministic.
	slices.SortFunc(events, func(a, b *xunarav2.PlatformAuditEvent) int {
		if c := a.GetTime().AsTime().Compare(b.GetTime().AsTime()); c != 0 {
			return c
		}
		if c := strings.Compare(a.GetOrg(), b.GetOrg()); c != 0 {
			return c
		}
		return int(a.GetId()) - int(b.GetId())
	})

	return &xunarav2.ListPlatformAuditResponse{Events: events, Cursors: next, HasMore: hasMore}, nil
}

// grpcOrganizationView builds the typed view of one organization.
func (r *Router) grpcOrganizationView(org *routerOrg) *xunarav2.Organization {
	view := r.platformOrgView(org)
	return &xunarav2.Organization{
		Id:      view.ID,
		Name:    view.Name,
		Domains: slices.Clone(view.Domains),
		Managed: view.Managed,
		Stats: &xunarav2.OrganizationStats{
			Nodes:          uint64(view.Stats.Nodes),
			Online:         uint64(view.Stats.Online),
			Users:          uint64(view.Stats.Users),
			PendingDevices: uint64(view.Stats.PendingDevices),
			PolicyLoaded:   view.Stats.PolicyLoaded,
		},
	}
}
