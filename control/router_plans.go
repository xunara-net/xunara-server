package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/xunara-net/xunara-server/networkconfig"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
)

// Plans at the router (PROJECT_SPEC section 54).
//
// The router owns the platform's view of its tenants: it knows every
// organization, it starts each one's control plane, and it is the only place
// that can apply a plan change to a running server. This file is that seam —
// the registry holds the durable assignment, the router turns it into
// enforcement.

// ErrTenantNotFound is returned when a plan operation names an organization
// the router does not serve.
var ErrTenantNotFound = errors.New("control: tenant not found")

// TenantPlanRow is one tenant's plan state as the platform surfaces show it.
type TenantPlanRow struct {
	OrgID string
	// Name is the organization's display name, empty when the router only
	// knows its ID.
	Name string
	// Plan is the plan the tenant is on right now.
	Plan plan.Plan
	// Assigned reports whether the plan came from an explicit assignment
	// (false means the catalog's default).
	Assigned bool
	// NetworkPrefix is the tenant's tailsnet range, empty when the deployment
	// default applies.
	NetworkPrefix string
	// Devices is how many devices the tenant has registered.
	Devices int
	// Online is how many of them are connected.
	Online int
	// Users is how many members the tenant has.
	Users     int
	UpdatedAt time.Time
}

// Plans returns the registry that holds assignments, or nil.
func (r *Router) Plans() *PlanRegistry { return r.cfg.Plans }

// applyPlans attaches the deployment's plan registry to one organization: the
// control plane learns how to look up its plan and starts allocating device
// addresses from the tenant's block.
func (r *Router) applyPlans(org *routerOrg) error {
	return org.site.Server.attachPlanRegistry(context.Background(), r.cfg.Plans, org.site.ID)
}

// AttachPlanRegistry 让单租户与路由器部署共用持久网段、冲突检查和重试链路。
func (server *Server) AttachPlanRegistry(ctx context.Context, registry *PlanRegistry) error {
	return server.attachPlanRegistry(ctx, registry, server.TenantID())
}

func (server *Server) attachPlanRegistry(ctx context.Context, registry *PlanRegistry, orgID string) error {
	if registry == nil {
		return nil
	}
	server.setPlanSource(func(tenantID string) plan.Plan {
		return registry.Plan(context.Background(), tenantID)
	})
	nodes, err := server.networkNodes(ctx)
	if err != nil {
		return err
	}
	if err := registry.reserveLegacyAddresses(ctx, orgID, nodes); err != nil {
		return err
	}
	server.addressSource.Store(&addressSource{
		Load: func(ctx context.Context) (networkVersion, error) { return registry.networkVersion(ctx, orgID) },
		Change: func(ctx context.Context, prefix netip.Prefix, expected *uint64, actor string) (networkVersion, error) {
			if _, err := registry.setNetwork(ctx, orgID, prefix, expected, actor); err != nil {
				return networkVersion{}, err
			}
			version, err := registry.networkVersion(ctx, orgID)
			if err == nil && version.Prefix != prefix.String() {
				return networkVersion{}, state.ErrAddressConflict
			}
			return version, err
		},
		Validate: func(ctx context.Context, prefix netip.Prefix) error {
			return registry.validateNetwork(ctx, orgID, prefix)
		},
		Reserved: registry.Reserved(),
	})
	if err := server.refreshAddressAllocation(ctx); err != nil {
		return fmt.Errorf("control: applying the network range of organization %q: %w", orgID, err)
	}
	return nil
}

// TenantPlans returns every served organization with its plan, device usage
// and network block, oldest first. Organizations without an assignment report
// the catalog's default.
func (r *Router) TenantPlans(ctx context.Context) ([]TenantPlanRow, error) {
	registry := r.cfg.Plans
	if registry == nil {
		return nil, errors.New("control: this deployment does not serve plans")
	}

	rows := make([]TenantPlanRow, 0, len(r.orgSnapshot()))
	for _, org := range r.orgSnapshot() {
		row := TenantPlanRow{
			OrgID: org.site.ID,
			Name:  org.site.Name,
			Plan:  registry.Plan(ctx, org.site.ID),
		}
		assignment, ok, err := registry.Get(ctx, org.site.ID)
		if err != nil {
			return nil, err
		}
		if ok {
			row.Assigned = true
			row.NetworkPrefix = assignment.NetworkPrefix
			row.UpdatedAt = assignment.UpdatedAt
		}
		server := org.site.Server
		for _, node := range server.store.ListNodes() {
			row.Devices++
			if server.isOnline(node.ID) {
				row.Online++
			}
		}
		row.Users = len(server.identity.ListUsers())
		rows = append(rows, row)
	}
	return rows, nil
}

// TenantPlan returns one tenant's row.
func (r *Router) TenantPlan(ctx context.Context, orgID string) (TenantPlanRow, error) {
	rows, err := r.TenantPlans(ctx)
	if err != nil {
		return TenantPlanRow{}, err
	}
	for _, row := range rows {
		if row.OrgID == orgID {
			return row, nil
		}
	}
	return TenantPlanRow{}, ErrTenantNotFound
}

// SetTenantPlan puts a tenant on a plan and makes it effective immediately:
// the running control plane picks the new quotas up on its next request.
func (r *Router) SetTenantPlan(ctx context.Context, orgID, planID string) (TenantPlanRow, error) {
	registry := r.cfg.Plans
	if registry == nil {
		return TenantPlanRow{}, errors.New("control: this deployment does not serve plans")
	}
	org := r.orgByID(orgID)
	if org == nil {
		return TenantPlanRow{}, ErrTenantNotFound
	}
	if _, err := registry.AssignPlan(ctx, orgID, planID); err != nil {
		return TenantPlanRow{}, err
	}
	if err := org.site.Server.refreshAddressAllocation(ctx); err != nil {
		return TenantPlanRow{}, err
	}
	return r.TenantPlan(ctx, orgID)
}

// SetTenantNetwork assigns a tenant's tailnet address range and applies it to
// the running control plane. Devices keep the addresses they already have.
func (r *Router) SetTenantNetwork(ctx context.Context, orgID string, prefix netip.Prefix) (TenantPlanRow, error) {
	registry := r.cfg.Plans
	if registry == nil {
		return TenantPlanRow{}, errors.New("control: this deployment does not serve plans")
	}
	org := r.orgByID(orgID)
	if org == nil {
		return TenantPlanRow{}, ErrTenantNotFound
	}
	_, err := org.site.Server.networkConfig.SaveAllocation(ctx, nil, func(ctx context.Context, current state.AddressConfiguration) (networkconfig.AllocationUpdate, error) {
		if _, err := registry.SetNetwork(ctx, orgID, prefix); err != nil {
			return networkconfig.AllocationUpdate{}, err
		}
		version, err := registry.networkVersion(ctx, orgID)
		if err != nil {
			return networkconfig.AllocationUpdate{}, err
		}
		configuration, err := allocationFromVersion(current, version)
		return networkconfig.AllocationUpdate{Configuration: configuration, Actor: "platform:" + orgID}, err
	})
	if err != nil {
		return TenantPlanRow{}, err
	}
	return r.TenantPlan(ctx, orgID)
}
