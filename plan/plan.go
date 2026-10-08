// Package plan defines the commercial plans a Xunara deployment sells and the
// quotas they impose on a tenant (PROJECT_SPEC section 54).
//
// The package is deliberately inert: it holds data, validation and the
// arithmetic of "is this tenant within its quota", but it never decides who is
// on which plan and never stores anything. Assignment belongs to the platform
// layer (control.PlanRegistry), and enforcement happens where the resource is
// created. That split is what lets a deployment add a plan without touching
// program logic (AGENTS.md section 13).
package plan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Unlimited is the value of a quota that is not enforced. Any quota may carry
// it; a plan that is entirely unlimited is what a deployment without plans
// gets, so existing single-tenant installations keep working unchanged.
const Unlimited = -1

// Built-in plan identifiers. Deployments may replace the catalog wholesale
// with -plans; these are the defaults shipped in the binary.
const (
	FreeID     = "free"
	ProID      = "pro"
	BusinessID = "business"
)

// Plan is one sellable plan and the limits it imposes.
//
// Quotas are counts a tenant may have: MaxDevices is how many devices the
// tenant may register, not how many it may add on top of what it has. A quota
// of [Unlimited] disables the check; zero means "none allowed".
type Plan struct {
	// ID is the stable identifier stored in assignments, e.g. "pro".
	ID string `json:"id"`
	// Name is the human-readable name shown in the console.
	Name string `json:"name"`
	// PriceCents is the price in minor units; it is informational only, the
	// control plane never bills anyone.
	PriceCents int64 `json:"price_cents"`
	// Currency is the ISO 4217 code the price is expressed in, e.g. "CNY".
	Currency string `json:"currency"`
	// BillingCycle is "month", "year" or "" for a plan that is not sold.
	BillingCycle string `json:"billing_cycle"`

	MaxDevices  int `json:"max_devices"`
	MaxUsers    int `json:"max_users"`
	MaxRoutes   int `json:"max_routes"`
	MaxAuthKeys int `json:"max_auth_keys"`
	// MaxRelays caps the DERP/STUN relays the tenant may enroll. Relays are
	// the tenant's share of the relay platform (supplement section 49).
	MaxRelays int `json:"max_relays"`

	AllowCustomCIDR   bool `json:"allow_custom_cidr"`
	AllowExitNode     bool `json:"allow_exit_node"`
	AllowSubnetRouter bool `json:"allow_subnet_router"`
	AllowAPI          bool `json:"allow_api"`
	AllowACL          bool `json:"allow_acl"`
	AllowGrants       bool `json:"allow_grants"`
	AllowCustomDNS    bool `json:"allow_custom_dns"`
	AllowAuditLog     bool `json:"allow_audit_log"`
	AllowMultiMember  bool `json:"allow_multi_member"`
}

// Validate reports whether the plan is internally consistent. It is the single
// place that decides what a well-formed plan is, so a catalog file, a platform
// API request and a test all enforce the same rules.
func (p Plan) Validate() error {
	if strings.TrimSpace(p.ID) == "" {
		return errors.New("plan: id is required")
	}
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("plan: name is required")
	}
	if p.PriceCents < 0 {
		return fmt.Errorf("plan %s: price must not be negative", p.ID)
	}
	switch p.BillingCycle {
	case "", "month", "year":
	default:
		return fmt.Errorf("plan %s: billing cycle %q is not month, year or empty", p.ID, p.BillingCycle)
	}
	for _, quota := range []struct {
		name  string
		value int
	}{
		{"max_devices", p.MaxDevices},
		{"max_users", p.MaxUsers},
		{"max_routes", p.MaxRoutes},
		{"max_auth_keys", p.MaxAuthKeys},
		{"max_relays", p.MaxRelays},
	} {
		if quota.value < Unlimited {
			return fmt.Errorf("plan %s: %s must be %d (unlimited), zero or positive", p.ID, quota.name, Unlimited)
		}
	}
	return nil
}

// UnlimitedDevices reports whether the plan does not cap devices.
func (p Plan) UnlimitedDevices() bool { return p.MaxDevices == Unlimited }

// AllowsDevices reports whether a tenant with used devices already registered
// may register one more. current < 0 is treated as zero.
func (p Plan) AllowsDevices(used int) bool {
	if p.UnlimitedDevices() {
		return true
	}
	if used < 0 {
		used = 0
	}
	return used < p.MaxDevices
}

// DeviceAllowance renders the plan's device quota for humans: "10", or
// "unlimited" when there is no cap.
func (p Plan) DeviceAllowance() string {
	if p.UnlimitedDevices() {
		return "unlimited"
	}
	return fmt.Sprintf("%d", p.MaxDevices)
}

// UnlimitedRelays reports whether the plan does not cap relays.
func (p Plan) UnlimitedRelays() bool { return p.MaxRelays == Unlimited }

// AllowsRelays reports whether a tenant that already enrolled used relays may
// enroll one more. current < 0 is treated as zero.
func (p Plan) AllowsRelays(used int) bool {
	if p.UnlimitedRelays() {
		return true
	}
	if used < 0 {
		used = 0
	}
	return used < p.MaxRelays
}

// RelayAllowance renders the plan's relay quota for humans.
func (p Plan) RelayAllowance() string {
	if p.UnlimitedRelays() {
		return "unlimited"
	}
	return fmt.Sprintf("%d", p.MaxRelays)
}

// Catalog is an ordered set of plans. It is immutable once built.
type Catalog struct {
	plans map[string]Plan
	order []string
}

// catalogFile is the JSON document a deployment supplies with -plans.
type catalogFile struct {
	Plans []Plan `json:"plans"`
}

// NewCatalog validates plans and returns them as a catalog. The first plan is
// the default one, so a deployment's own file decides which plan new tenants
// start on.
func NewCatalog(plans ...Plan) (*Catalog, error) {
	if len(plans) == 0 {
		return nil, errors.New("plan: a catalog needs at least one plan")
	}
	c := &Catalog{plans: make(map[string]Plan, len(plans))}
	for _, p := range plans {
		if err := p.Validate(); err != nil {
			return nil, err
		}
		if _, dup := c.plans[p.ID]; dup {
			return nil, fmt.Errorf("plan: duplicate plan %q", p.ID)
		}
		c.plans[p.ID] = p
		c.order = append(c.order, p.ID)
	}
	return c, nil
}

// ParseCatalog reads the JSON document accepted by -plans. Unknown fields are
// refused so a typo in a plan file fails at startup instead of silently
// dropping a limit.
func ParseCatalog(raw []byte) (*Catalog, error) {
	var doc catalogFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("plan: parsing the catalog: %w", err)
	}
	return NewCatalog(doc.Plans...)
}

// DefaultCatalog is the catalog built into the binary: free, pro, business.
func DefaultCatalog() *Catalog {
	c, err := NewCatalog(
		Plan{
			ID: FreeID, Name: "Free", Currency: "CNY",
			MaxDevices: 10, MaxUsers: 1, MaxRoutes: 4, MaxAuthKeys: 3,
			MaxRelays:         1,
			AllowSubnetRouter: true, AllowACL: true, AllowAuditLog: true,
		},
		Plan{
			ID: ProID, Name: "Pro", PriceCents: 1990, Currency: "CNY", BillingCycle: "month",
			MaxDevices: 50, MaxUsers: 5, MaxRoutes: 32, MaxAuthKeys: 25,
			MaxRelays:       5,
			AllowCustomCIDR: true, AllowExitNode: true, AllowSubnetRouter: true,
			AllowAPI: true, AllowACL: true, AllowGrants: true, AllowCustomDNS: true,
			AllowAuditLog: true, AllowMultiMember: true,
		},
		Plan{
			ID: BusinessID, Name: "Business", PriceCents: 9900, Currency: "CNY", BillingCycle: "month",
			MaxDevices: 200, MaxUsers: 50, MaxRoutes: 128, MaxAuthKeys: 100,
			MaxRelays:       20,
			AllowCustomCIDR: true, AllowExitNode: true, AllowSubnetRouter: true,
			AllowAPI: true, AllowACL: true, AllowGrants: true, AllowCustomDNS: true,
			AllowAuditLog: true, AllowMultiMember: true,
		},
	)
	if err != nil {
		// The built-ins are constants; a failure here is a programming error.
		panic(err)
	}
	return c
}

// Errors a catalog mutation reports.
var (
	// ErrPlanNotFound is returned when a mutation names a plan the catalog
	// does not have.
	ErrPlanNotFound = errors.New("plan: no such plan")
	// ErrDefaultPlan is returned when a mutation would remove the plan new
	// tenants start on.
	ErrDefaultPlan = errors.New("plan: the default plan cannot be removed")
)

// Clone returns an independent copy of the catalog. It is how a deployment
// applies a runtime change (a plan added through the platform API) without
// mutating the catalog other goroutines are reading.
func (c *Catalog) Clone() *Catalog {
	if c == nil {
		return &Catalog{plans: make(map[string]Plan)}
	}
	out := &Catalog{plans: make(map[string]Plan, len(c.plans)), order: append([]string(nil), c.order...)}
	for id, p := range c.plans {
		out.plans[id] = p
	}
	return out
}

// WithPlan returns a new catalog with p added. A plan with the same ID is
// replaced in place, so a deployment can reprice or retune a built-in plan
// without losing its position (in particular its place as the default).
func (c *Catalog) WithPlan(p Plan) (*Catalog, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	out := c.Clone()
	if _, exists := out.plans[p.ID]; !exists {
		out.order = append(out.order, p.ID)
	}
	out.plans[p.ID] = p
	return out, nil
}

// WithoutPlan returns a new catalog without the plan. Removing the default
// plan is refused: tenants without an assignment follow the default, so
// deleting it would change their rules without anybody deciding to.
func (c *Catalog) WithoutPlan(id string) (*Catalog, error) {
	if _, ok := c.Get(id); !ok {
		return nil, fmt.Errorf("%w: %q", ErrPlanNotFound, id)
	}
	if c.Default().ID == id {
		return nil, fmt.Errorf("%w: %q", ErrDefaultPlan, id)
	}
	out := c.Clone()
	delete(out.plans, id)
	kept := out.order[:0]
	for _, existing := range out.order {
		if existing != id {
			kept = append(kept, existing)
		}
	}
	out.order = kept
	return out, nil
}

// Get returns the plan with the given ID.
func (c *Catalog) Get(id string) (Plan, bool) {
	if c == nil {
		return Plan{}, false
	}
	p, ok := c.plans[id]
	return p, ok
}

// UnlimitedPlan is the plan of a deployment that sells nothing: every quota is
// disabled. It is what a control plane without a catalog runs under, so a
// self-hosted installation keeps behaving exactly as before (AGENTS.md
// section 16).
func UnlimitedPlan() Plan {
	return Plan{
		ID: "unlimited", Name: "Unlimited",
		MaxDevices: Unlimited, MaxUsers: Unlimited, MaxRoutes: Unlimited,
		MaxAuthKeys: Unlimited, MaxRelays: Unlimited,
		AllowCustomCIDR: true, AllowExitNode: true, AllowSubnetRouter: true, AllowAPI: true,
		AllowACL: true, AllowGrants: true, AllowCustomDNS: true, AllowAuditLog: true, AllowMultiMember: true,
	}
}

// Default returns the plan a tenant starts on: the first one in the catalog.
func (c *Catalog) Default() Plan {
	if c == nil || len(c.order) == 0 {
		return UnlimitedPlan()
	}
	return c.plans[c.order[0]]
}

// List returns every plan in catalog order.
func (c *Catalog) List() []Plan {
	if c == nil {
		return nil
	}
	out := make([]Plan, 0, len(c.order))
	for _, id := range c.order {
		out = append(out, c.plans[id])
	}
	return out
}
