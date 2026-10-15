package control

import (
	"errors"
	"net/http"
	"net/netip"

	"github.com/xunara-net/xunara-server/plan"
)

// Commercial quotas (PROJECT_SPEC section 54).
//
// A deployment that sells plans opens a [PlanRegistry]; the router hands every
// tenant's control plane a plan source, and the gates below turn that plan into
// enforcement. They live at the point where a resource is created — a device
// registers, a key is minted, a route is approved — because that is the only
// place where "the tenant has too many" can be decided for good. The state
// store, the protocol and the client never learn about plans.
//
// A server without a plan source is on [plan.UnlimitedPlan]: a self-hosted
// installation sees none of this.

// Plan returns the commercial plan this server's tenant is on. Servers without
// a plan source — every single-tenant deployment that does not sell plans —
// report the unlimited plan, so every gate below is a no-op there.
func (s *Server) Plan() plan.Plan {
	if s.planSource == nil {
		return plan.UnlimitedPlan()
	}
	p := s.planSource(s.TenantID())
	if p.ID == "" {
		// A plan without an ID is not a plan; refuse to guess.
		return plan.UnlimitedPlan()
	}
	return p
}

// TenantID returns the stable identifier of the tenant this server serves:
// the organization ID under a router, and "default" for a single-tenant
// deployment.
func (s *Server) TenantID() string {
	if org := s.Organization(); org.ID != "" {
		return org.ID
	}
	return "default"
}

// setPlanSource attaches the deployment's plan registry. The router calls it
// for every site; a single-tenant deployment sets Config.PlanSource instead.
func (s *Server) setPlanSource(source func(tenantID string) plan.Plan) {
	s.planSource = source
}

// DeviceUsage reports how many devices the tenant has and how many the plan
// allows ([plan.Unlimited] when there is no cap).
func (s *Server) DeviceUsage() (used, limit int) {
	return len(s.store.ListNodes()), s.Plan().MaxDevices
}

// PlanGateError builds the 403 a gate returns. The message starts with a
// stable code so an API caller can branch on it, and continues with a sentence
// the console can translate verbatim.
func planGateError(message string) HTTPError {
	return NewHTTPError(http.StatusForbidden, message, nil)
}

// Plan gate messages. They are constants — not built with fmt at the call
// site — so the console's translator can key on the whole string.
const (
	// MsgDeviceLimitReached is returned instead of registering an eleventh
	// device on a plan that allows ten.
	MsgDeviceLimitReached = "DEVICE_LIMIT_REACHED: this plan's device limit is reached; upgrade the plan to add more devices"
	// MsgAuthKeyLimitReached is returned when a new pre-auth key would exceed
	// the plan's key quota.
	MsgAuthKeyLimitReached = "AUTH_KEY_LIMIT_REACHED: this plan's auth key limit is reached; delete unused keys or upgrade the plan"
	// MsgUserLimitReached is returned when an invitation or sign-up would
	// exceed the plan's member quota.
	MsgUserLimitReached = "USER_LIMIT_REACHED: this plan's member limit is reached; upgrade the plan to add more members"
	// MsgRouteLimitReached is returned when approving routes would exceed the
	// plan's route quota.
	MsgRouteLimitReached = "ROUTE_LIMIT_REACHED: this plan's route limit is reached; withdraw unused routes or upgrade the plan"
	// MsgAPIKeysDisabled is returned for API key creation on a plan without
	// API access.
	MsgAPIKeysDisabled = "PLAN_FEATURE_DISABLED: API keys are not included in this plan"
	// MsgAuditLogDisabled is returned when the audit log is not part of the
	// plan.
	MsgAuditLogDisabled = "PLAN_FEATURE_DISABLED: the audit log is not included in this plan"
	// MsgExitNodeDisabled is returned when an exit node route is approved on a
	// plan without exit nodes.
	MsgExitNodeDisabled = "PLAN_FEATURE_DISABLED: exit nodes are not included in this plan"
	// MsgSubnetRouterDisabled is returned when a subnet route is approved on a
	// plan without subnet routers.
	MsgSubnetRouterDisabled = "PLAN_FEATURE_DISABLED: subnet routers are not included in this plan"
)

// assertDeviceQuota reports whether the tenant may register one more device.
// It is called on every path that creates a node: interactive approval, the
// pre-auth key path and the device-approval page.
func (s *Server) assertDeviceQuota() error {
	p := s.Plan()
	if p.AllowsDevices(len(s.store.ListNodes())) {
		return nil
	}
	return planGateError(MsgDeviceLimitReached)
}

// 开通独立租户时检查最终成员数；认领内置 owner 不会再新增一名成员。
// 普通注册和密钥额度由各自写事务复核，不能恢复“先读列表再写入”的重复门禁。
func (s *Server) assertMemberQuota(n int) error {
	p := s.Plan()
	if p.MaxUsers == plan.Unlimited || n <= p.MaxUsers {
		return nil
	}
	return planGateError(MsgUserLimitReached)
}

// assertAPIAllowed reports whether the tenant may mint API keys.
func (s *Server) assertAPIAllowed() error {
	if s.Plan().AllowAPI {
		return nil
	}
	return planGateError(MsgAPIKeysDisabled)
}

// assertAuditLogAllowed reports whether the tenant may read the audit log.
func (s *Server) assertAuditLogAllowed() error {
	if s.Plan().AllowAuditLog {
		return nil
	}
	return planGateError(MsgAuditLogDisabled)
}

// assertRouteApprovalAllowed reports whether a node may end up with the given
// approved routes: those inside the plan's route quota, without an exit node
// (0.0.0.0/0 or ::/0) unless the plan allows one, and without other routes
// unless the plan includes subnet routers.
func (s *Server) assertRouteApprovalAllowed(routes []netip.Prefix) error {
	p := s.Plan()
	if p.MaxRoutes != plan.Unlimited && len(routes) > p.MaxRoutes {
		return planGateError(MsgRouteLimitReached)
	}
	for _, route := range routes {
		if isExitRoute(route) && !p.AllowExitNode {
			return planGateError(MsgExitNodeDisabled)
		}
		if !isExitRoute(route) && !p.AllowSubnetRouter {
			return planGateError(MsgSubnetRouterDisabled)
		}
	}
	return nil
}

// isExitRoute reports whether a prefix is an exit-node default route.
func isExitRoute(prefix netip.Prefix) bool {
	return prefix.Bits() == 0
}

// planGateOrRender writes the gate's error page and reports false, or returns
// true when the action may proceed. Console handlers use it to keep the gate,
// the audit trail and the page rendering in one place.
func (s *Server) planGateOrRender(w http.ResponseWriter, r *http.Request, err error, title string) bool {
	if err == nil {
		return true
	}
	var he HTTPError
	if !errors.As(err, &he) {
		s.renderError(w, r, http.StatusInternalServerError, title, "Please try again.")
		return false
	}
	s.renderError(w, r, he.Code, title, s.translateMessage(r, he.Msg))
	return false
}

// translateMessage localizes a gate message for the request's language. The
// translator returns its input unchanged when there is no entry, so a message
// added without a translation still reaches the user.
func (s *Server) translateMessage(r *http.Request, message string) string {
	return translator(consoleLangFromRequest(r))(message)
}

// SetAddressPrefix points new device addresses at a network range. It is how
// a tenant's commercial network block reaches the store that allocates
// addresses; devices registered before the change keep their addresses.
//
// An invalid prefix is a no-op, so a tenant without an assigned block keeps
// the deployment's built-in range.
func (s *Server) SetAddressPrefix(prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return nil
	}
	if err := s.store.SetAddressPrefixes(prefix, netip.Prefix{}); err != nil {
		return err
	}
	s.log.Info("tenant network range applied",
		"tenant", s.TenantID(), "prefix", prefix.String())
	return nil
}
