package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// This file compiles the document's "ssh" section into the per-destination
// tailcfg.SSHPolicy a client needs to run its Tailscale SSH server.
//
// Semantics follow reference/headscale/hscontrol/policy/v2/filter.go
// (compileSSHPolicy) and the upstream SSHRule type. "accept" rules carry an
// immediate verdict; "check" rules carry a HoldAndDelegate URL the client
// fetches over its control connection for a per-session verdict.

// SSH action names, as written in the document.
const (
	sshActionAccept = "accept"
	sshActionCheck  = "check"
)

// Check-period bounds, mirroring reference/headscale/hscontrol/policy/v2:
// a rule without checkPeriod is remembered for 12h, "always" re-checks every
// session, and a configured period may not exceed 168h.
const (
	sshCheckPeriodDefault = 12 * time.Hour
	sshCheckPeriodMax     = 7 * 24 * time.Hour
)

// compiledSSHRule is a validated "ssh" row.
type compiledSSHRule struct {
	// index is the row's position in the document, for warnings.
	index int

	src []selector
	dst []selector // host selectors only; autogroup:self is not included

	// selfOnly reports that dst named autogroup:self: the rule then applies
	// between devices of one user.
	selfOnly bool

	// users is the wire SSHUsers map ("ssh user" -> "local user").
	users map[string]string

	acceptEnv []string

	// check marks an "check" rule and checkPeriod is the window an accepted
	// session is remembered by the control plane (0 = check every session).
	check       bool
	checkPeriod time.Duration
}

// compileSSHRules validates and classifies the document's SSH rows.
func (e *Engine) compileSSHRules() error {
	for i, row := range e.doc.SSH {
		rule, err := e.compileSSHRule(i, row)
		if err != nil {
			return fmt.Errorf("policy: ssh[%d]: %w", i, err)
		}
		e.ssh = append(e.ssh, rule)
	}
	return nil
}

func (e *Engine) compileSSHRule(index int, row SSHRow) (compiledSSHRule, error) {
	rule := compiledSSHRule{index: index}

	switch row.Action {
	case sshActionAccept:
	case sshActionCheck:
		rule.check = true
	case "":
		return rule, fmt.Errorf("action is required (accept or check)")
	default:
		return rule, fmt.Errorf("unsupported action %q (only \"accept\" and \"check\" are defined)", row.Action)
	}

	if len(row.Src) == 0 {
		return rule, fmt.Errorf("src is required")
	}
	for _, s := range row.Src {
		sel, err := e.classifySource(s)
		if err != nil {
			return rule, fmt.Errorf("src: %w", err)
		}
		rule.src = append(rule.src, sel)
	}

	if len(row.Dst) == 0 {
		return rule, fmt.Errorf("dst is required")
	}
	for _, d := range row.Dst {
		sel, err := e.classifyHost(d, false)
		if err != nil {
			return rule, fmt.Errorf("dst: %w", err)
		}
		if sel.kind == selSelf {
			rule.selfOnly = true
			continue
		}
		rule.dst = append(rule.dst, sel)
	}

	if row.CheckPeriod != nil {
		if row.Action != sshActionCheck {
			return rule, fmt.Errorf("checkPeriod is only valid with action %q", sshActionCheck)
		}
		switch {
		case row.CheckPeriod.Always:
			rule.checkPeriod = 0
		case row.CheckPeriod.Duration < 0:
			return rule, fmt.Errorf("checkPeriod %s must not be negative", row.CheckPeriod.Duration)
		case row.CheckPeriod.Duration > sshCheckPeriodMax:
			return rule, fmt.Errorf("checkPeriod %s is above the max (%s)",
				row.CheckPeriod.Duration, sshCheckPeriodMax)
		default:
			rule.checkPeriod = row.CheckPeriod.Duration
		}
	} else if rule.check {
		rule.checkPeriod = sshCheckPeriodDefault
	}

	if len(row.Users) == 0 {
		return rule, fmt.Errorf("users is required")
	}
	for _, u := range row.Users {
		if !isSSHUser(u) {
			return rule, fmt.Errorf("users: %q is not a local user, \"root\" or \"autogroup:nonroot\"", u)
		}
	}
	rule.users = sshUsersMap(row.Users)

	for _, env := range row.AcceptEnv {
		if env == "" || strings.ContainsAny(env, " \t\r\n") {
			return rule, fmt.Errorf("acceptEnv: %q is not an environment variable name pattern", env)
		}
	}
	rule.acceptEnv = slices.Clone(row.AcceptEnv)

	return rule, nil
}

// isSSHUser reports whether u names a local user an SSH session may run as.
func isSSHUser(u string) bool {
	switch u {
	case "", "*":
		return false
	case "root", "autogroup:nonroot":
		return true
	}
	if strings.ContainsAny(u, ":/\\ \t\r\n") {
		return false
	}
	return true
}

// sshUsersMap converts the document's users list into the wire SSHUsers map.
//
// The map always carries a "root" entry: an empty value means "this rule does
// not match root", which is how upstream expresses "root is not allowed here".
// "autogroup:nonroot" adds the "*" entry ("=": keep the requested user name).
func sshUsersMap(users []string) map[string]string {
	const rootUser = "root"

	out := make(map[string]string, len(users)+1)
	nonRoot, root := false, false
	for _, u := range users {
		switch u {
		case "autogroup:nonroot":
			nonRoot = true
		case rootUser:
			root = true
		default:
			out[u] = u
		}
	}
	if nonRoot {
		out["*"] = "="
	}
	if root {
		out[rootUser] = rootUser
	} else {
		out[rootUser] = ""
	}
	return out
}

// sshAcceptAction is the action for an "accept" rule. The forwarding flags
// mirror the upstream defaults (reference/headscale/hscontrol/policy/v2/filter.go).
var sshAcceptAction = tailcfg.SSHAction{
	Accept:                    true,
	AllowAgentForwarding:      true,
	AllowLocalPortForwarding:  true,
	AllowRemotePortForwarding: true,
}

// sshCheckAction is the action for a "check" rule: the client holds the
// connection and fetches the URL (with $SRC_NODE_ID, $DST_NODE_ID and
// $LOCAL_USER expanded by tailscaled) for a per-session verdict. Forwarding
// stays off until the verdict arrives.
func (e *Engine) sshCheckAction() tailcfg.SSHAction {
	base := strings.TrimRight(e.opts.ServerURL, "/")
	return tailcfg.SSHAction{
		HoldAndDelegate: base +
			"/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER",
	}
}

// CompileSSHPolicy builds the SSH policy for self as the destination of an
// incoming SSH connection, or nil when no rule applies to it.
//
// The returned policy grants nothing by itself: it tells the destination's
// SSH server which sources may connect and as which local users.
func (e *Engine) CompileSSHPolicy(self state.Node, nodes []state.Node) *tailcfg.SSHPolicy {
	if len(e.ssh) == 0 {
		return nil
	}
	if self.ID == 0 {
		return nil
	}

	r := &resolution{engine: e, self: self, nodes: nodes}

	var out []*tailcfg.SSHRule
	appendRule := func(principals []*tailcfg.SSHPrincipal, rule compiledSSHRule) {
		if len(principals) == 0 {
			return
		}
		action := &sshAcceptAction
		if rule.check {
			check := e.sshCheckAction()
			action = &check
		}
		out = append(out, &tailcfg.SSHRule{
			Principals: principals,
			SSHUsers:   rule.users,
			Action:     action,
			AcceptEnv:  rule.acceptEnv,
		})
	}

	for _, rule := range e.ssh {
		// dst: autogroup:self applies between devices of one user.
		// A tagged destination has no user, so it can never match.
		if rule.selfOnly && len(self.Tags) == 0 {
			appendRule(r.sshPrincipals(rule.src, self.UserID), rule)
		}
		if len(rule.dst) > 0 && r.nodesForSelectors(rule.dst)[self.ID] {
			appendRule(r.sshPrincipals(rule.src, 0), rule)
		}
	}

	if len(out) == 0 {
		return nil
	}
	return &tailcfg.SSHPolicy{Rules: out}
}

// SSHCheckPeriod resolves the check period for a source-destination pair from
// the "check" rules: the first matching rule wins. ok is false when no check
// rule matches the pair. A zero period ("always") means every session must be
// approved again.
func (e *Engine) SSHCheckPeriod(src, dst state.Node, nodes []state.Node) (time.Duration, bool) {
	if len(e.ssh) == 0 {
		return 0, false
	}

	r := &resolution{engine: e, self: dst, nodes: nodes}
	for _, rule := range e.ssh {
		if !rule.check {
			continue
		}
		if !r.nodesForSelectors(rule.src)[src.ID] {
			continue
		}
		if rule.selfOnly {
			if len(src.Tags) == 0 && len(dst.Tags) == 0 && src.UserID == dst.UserID {
				return rule.checkPeriod, true
			}
			continue
		}
		if len(rule.dst) > 0 && r.nodesForSelectors(rule.dst)[dst.ID] {
			return rule.checkPeriod, true
		}
	}
	return 0, false
}

// SSHDestinations reports which nodes are named as the destination of at least
// one SSH rule. Those nodes advertise the tailscale.com/cap/ssh capability,
// which is what allows them to run the SSH server.
//
// A rule whose destination is autogroup:self marks every node: any device may
// be reached by another device of the same user.
func (e *Engine) SSHDestinations(nodes []state.Node) map[state.NodeID]bool {
	if len(e.ssh) == 0 {
		return nil
	}

	r := &resolution{engine: e, nodes: nodes}
	out := make(map[state.NodeID]bool)
	for _, rule := range e.ssh {
		if rule.selfOnly {
			for _, n := range nodes {
				if len(n.Tags) == 0 {
					out[n.ID] = true
				}
			}
			continue
		}
		for id := range r.nodesForSelectors(rule.dst) {
			out[id] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// nodesForSelectors resolves host selectors to the union of the nodes they
// name.
func (r *resolution) nodesForSelectors(sels []selector) map[state.NodeID]bool {
	out := make(map[state.NodeID]bool)
	for _, sel := range sels {
		for _, n := range r.nodesForSelector(sel) {
			out[n.ID] = true
		}
	}
	return out
}

// nodesForSelector is the node-level counterpart of hostIPs: where hostIPs
// produces wire strings, this returns the nodes themselves.
func (r *resolution) nodesForSelector(sel selector) []state.Node {
	switch sel.kind {
	case selWildcard:
		return r.nodes
	case selMember:
		return r.memberNodes()
	case selTagged:
		return r.taggedNodes()
	case selSelf:
		return r.selfNodes()
	case selTag:
		return r.nodesWithTag(sel.raw)
	case selGroup:
		return r.nodesForGroup(sel.raw, nil)
	case selUser:
		return r.nodesForUser(sel.raw)
	case selPrefix:
		return r.nodesInPrefix(sel.prefix)
	case selHost:
		prefix, err := parseAddrOrPrefix(sel.target)
		if err != nil {
			r.warn("policy: host alias %q resolves to %q, which is not an address", sel.raw, sel.target)
			return nil
		}
		return r.nodesInPrefix(prefix)
	default:
		return nil
	}
}

// nodesInPrefix returns the nodes whose tailnet addresses fall inside prefix.
func (r *resolution) nodesInPrefix(prefix netip.Prefix) []state.Node {
	var out []state.Node
	for _, n := range r.nodes {
		if (n.IPv4.IsValid() && prefix.Contains(n.IPv4)) || (n.IPv6.IsValid() && prefix.Contains(n.IPv6)) {
			out = append(out, n)
		}
	}
	return out
}

// sshPrincipals lists the source addresses that may open an SSH session under
// the given source selectors. When onlyUserID is non-zero, sources owned by
// another user are excluded (dst autogroup:self).
func (r *resolution) sshPrincipals(sels []selector, onlyUserID tailcfg.UserID) []*tailcfg.SSHPrincipal {
	var out []*tailcfg.SSHPrincipal
	seen := make(map[netip.Addr]bool)

	for _, sel := range sels {
		for _, n := range r.nodesForSelector(sel) {
			if onlyUserID != 0 && (n.UserID != onlyUserID || len(n.Tags) > 0) {
				continue
			}
			for _, addr := range []netip.Addr{n.IPv4, n.IPv6} {
				if !addr.IsValid() || seen[addr] {
					continue
				}
				seen[addr] = true
				out = append(out, &tailcfg.SSHPrincipal{NodeIP: addr.String()})
			}
		}
	}
	return out
}
