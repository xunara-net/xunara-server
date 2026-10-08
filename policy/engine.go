package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// Options carries the tailnet facts the compiler needs beyond the document.
type Options struct {
	// LoginName maps a user ID to the login name users are written as in ACL
	// selectors ("alice@example.com"). Nil means the default single-user
	// profile.
	LoginName func(id tailcfg.UserID) string

	// Domain is the tailnet's MagicDNS domain, without a trailing dot. It lets
	// a user selector written as "login@domain" match the profile's login name.
	Domain string

	// ServerURL is the externally reachable base URL the control plane uses
	// to build the HoldAndDelegate URL of "check" ssh rules. Empty produces a
	// path-relative URL, which keeps the rule fail-closed until a URL is set.
	ServerURL string
}

// Engine is a validated policy document ready to compile per-node filters.
type Engine struct {
	doc  *Document
	opts Options

	rules    []compiledRule
	warnings []string

	// ssh are the compiled "ssh" rows.
	ssh []compiledSSHRule

	// nodeAttrs are the compiled "nodeAttrs" rows.
	nodeAttrs []compiledNodeAttr

	// grants are the compiled "grants" rows (ACL v2).
	grants []compiledGrant
}

// compiledRule keeps selectors unresolved: user, tag and autogroup selectors
// depend on the nodes, so resolution happens per netmap build.
type compiledRule struct {
	src   []selector
	dst   []dstSelector
	proto []int
}

type dstSelector struct {
	host  selector
	ports []tailcfg.PortRange
}

// selector is a validated, classified source or destination host selector.
type selector struct {
	kind selKind
	raw  string
	// prefix is set for kind == selPrefix.
	prefix netip.Prefix
	// target is set for kind == selHost (the hosts section value).
	target string
}

type selKind int

const (
	selWildcard selKind = iota // "*"
	selSelf                    // autogroup:self
	selMember                  // autogroup:member
	selTagged                  // autogroup:tagged
	selInternet                // autogroup:internet (destinations only)
	selTag
	selGroup
	selUser
	selHost
	selPrefix
)

// NewEngine validates a document and compiles it into an Engine.
//
// Validation is independent of the current nodes, so a policy can be rejected
// at load time: unknown groups, hosts and tags, malformed prefixes or ports,
// and unsupported actions are all errors.
func NewEngine(doc *Document, opts Options) (*Engine, error) {
	if doc == nil {
		return nil, fmt.Errorf("policy: nil document")
	}
	if opts.LoginName == nil {
		opts.LoginName = func(id tailcfg.UserID) string {
			return state.DefaultUserProfile(id).LoginName
		}
	}

	e := &Engine{doc: doc, opts: opts}
	if err := e.validateGroups(); err != nil {
		return nil, err
	}
	if err := e.validateHosts(); err != nil {
		return nil, err
	}
	if err := e.validateTagOwners(); err != nil {
		return nil, err
	}
	if err := e.compileACLs(); err != nil {
		return nil, err
	}
	if err := e.compileGrants(); err != nil {
		return nil, err
	}
	if err := e.compileSSHRules(); err != nil {
		return nil, err
	}
	if err := e.compileNodeAttrs(); err != nil {
		return nil, err
	}
	for _, field := range doc.Unsupported {
		e.warnf("policy field %q is not implemented by this build and is ignored", field)
	}
	return e, nil
}

// Warnings returns the non-fatal problems found while loading the policy, such
// as selectors that currently match no node.
func (e *Engine) Warnings() []string { return slices.Clone(e.warnings) }

// Document returns a copy of the document this engine compiled. The read-only
// management surface renders it; the copy keeps a caller from mutating the
// engine the tailnet is enforcing.
func (e *Engine) Document() *Document { return e.doc.Clone() }

// RuleCount reports how many traffic rows the document declares: ACLs plus
// grants.
func (e *Engine) RuleCount() int { return len(e.rules) + len(e.grants) }

// HasRules reports whether the policy grants anything at all.
func (e *Engine) HasRules() bool { return len(e.rules) > 0 || len(e.grants) > 0 }

// TagExists reports whether the tag is defined in the document's tagOwners.
// An undefined tag cannot be applied to any key or node.
func (e *Engine) TagExists(tag string) bool {
	_, ok := e.doc.TagOwners[tag]
	return ok
}

// UserOwnsTag reports whether the user identified by loginName may apply tag.
// The tag must be defined in tagOwners and the user must be listed there
// directly, through a group (following nested groups), or through a
// tag-to-tag ownership chain. It is the "may this user claim this tag" check
// used when a client advertises tags.
func (e *Engine) UserOwnsTag(loginName, tag string) bool {
	if loginName == "" || tag == "" {
		return false
	}
	return e.userOwnsTag(loginName, tag, nil)
}

func (e *Engine) userOwnsTag(loginName, tag string, seen []string) bool {
	if slices.Contains(seen, tag) {
		return false
	}
	seen = append(seen, tag)

	owners, ok := e.doc.TagOwners[tag]
	if !ok {
		return false
	}
	for _, owner := range owners {
		switch {
		case strings.HasPrefix(owner, "group:"):
			if e.groupContainsUser(owner, loginName, nil) {
				return true
			}
		case strings.HasPrefix(owner, "tag:"):
			if e.userOwnsTag(loginName, owner, seen) {
				return true
			}
		default:
			if loginNameMatches(owner, loginName) {
				return true
			}
		}
	}
	return false
}

// groupContainsUser resolves a group's user members, following nested groups.
// Tag members are skipped: they name devices, not users.
func (e *Engine) groupContainsUser(group, loginName string, seen []string) bool {
	if slices.Contains(seen, group) {
		return false
	}
	seen = append(seen, group)

	for _, member := range e.doc.Groups[group] {
		switch {
		case strings.HasPrefix(member, "group:"):
			if e.groupContainsUser(member, loginName, seen) {
				return true
			}
		case strings.HasPrefix(member, "tag:"):
			// Tag membership names devices, not users.
		default:
			if loginNameMatches(member, loginName) {
				return true
			}
		}
	}
	return false
}

// loginNameMatches compares an ACL selector against a profile login name. It
// accepts the login name verbatim and, for selectors written as an email
// address, the local part: a self-hosted tailnet's users are frequently
// written as "alice@example.com" even though the local profile only carries
// the login name.
func loginNameMatches(selector, loginName string) bool {
	if strings.EqualFold(selector, loginName) {
		return true
	}
	if local, _, ok := strings.Cut(selector, "@"); ok {
		return strings.EqualFold(local, loginName)
	}
	return false
}

func (e *Engine) warnf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	// Warnings are recomputed on every netmap build, so the same note must not
	// accumulate (nor be reported twice in the console).
	if slices.Contains(e.warnings, msg) {
		return
	}
	e.warnings = append(e.warnings, msg)
}

func (e *Engine) validateGroups() error {
	for name, members := range e.doc.Groups {
		if !strings.HasPrefix(name, "group:") {
			return fmt.Errorf("policy: group %q must be named group:<name>", name)
		}
		if len(members) == 0 {
			return fmt.Errorf("policy: group %q has no members", name)
		}
		for _, m := range members {
			switch {
			case strings.HasPrefix(m, "group:"):
				if _, ok := e.doc.Groups[m]; !ok {
					return fmt.Errorf("policy: group %q references unknown group %q", name, m)
				}
			case strings.HasPrefix(m, "tag:"), isUserSelector(m):
			default:
				return fmt.Errorf("policy: group %q member %q must be a user, tag: or group:", name, m)
			}
		}
	}

	for name := range e.doc.Groups {
		if err := e.checkGroupCycle(name, nil); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) checkGroupCycle(name string, seen []string) error {
	if slices.Contains(seen, name) {
		return fmt.Errorf("policy: group %q is part of a cycle: %s", name, strings.Join(append(seen, name), " -> "))
	}
	for _, m := range e.doc.Groups[name] {
		if !strings.HasPrefix(m, "group:") {
			continue
		}
		if err := e.checkGroupCycle(m, append(slices.Clone(seen), name)); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) validateHosts() error {
	for alias, value := range e.doc.Hosts {
		if alias == "" {
			return fmt.Errorf("policy: hosts section has an empty alias")
		}
		if _, err := parseAddrOrPrefix(value); err != nil {
			return fmt.Errorf("policy: host %q = %q: %w", alias, value, err)
		}
	}
	return nil
}

func (e *Engine) validateTagOwners() error {
	for tag, owners := range e.doc.TagOwners {
		if !strings.HasPrefix(tag, "tag:") {
			return fmt.Errorf("policy: tagOwners key %q must be named tag:<name>", tag)
		}
		if len(owners) == 0 {
			return fmt.Errorf("policy: tagOwners for %q has no owners", tag)
		}
	}
	return nil
}

func (e *Engine) compileACLs() error {
	for i, row := range e.doc.ACLs {
		action := row.Action
		if action == "" {
			action = "accept"
		}
		if action != "accept" {
			return fmt.Errorf("policy: acls[%d]: unsupported action %q (only \"accept\" is implemented)", i, row.Action)
		}

		src, dst := row.Src, row.Dst
		if len(src) == 0 {
			src = row.Users
		}
		if len(dst) == 0 {
			dst = row.Ports
		}
		if len(src) == 0 || len(dst) == 0 {
			return fmt.Errorf("policy: acls[%d]: both src and dst are required", i)
		}

		proto, err := parseProto(row.Proto)
		if err != nil {
			return fmt.Errorf("policy: acls[%d]: %w", i, err)
		}

		rule := compiledRule{proto: proto}
		for _, s := range src {
			sel, err := e.classifySource(s)
			if err != nil {
				return fmt.Errorf("policy: acls[%d]: %w", i, err)
			}
			rule.src = append(rule.src, sel)
		}
		for _, d := range dst {
			sel, err := e.classifyDestination(d)
			if err != nil {
				return fmt.Errorf("policy: acls[%d]: %w", i, err)
			}
			rule.dst = append(rule.dst, sel)
		}
		e.rules = append(e.rules, rule)
	}
	return nil
}

// isUserSelector reports whether s looks like a user selector rather than a
// host alias or tag.
func isUserSelector(s string) bool {
	if s == "" || strings.Contains(s, ":") || strings.Contains(s, "/") {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false
	}
	return true
}

func (e *Engine) classifySource(s string) (selector, error) {
	sel, err := e.classifyHost(s, false)
	if err != nil {
		return selector{}, err
	}
	if sel.kind == selInternet {
		return selector{}, fmt.Errorf("autogroup:internet is only valid as a destination")
	}
	return sel, nil
}

func (e *Engine) classifyDestination(s string) (dstSelector, error) {
	host, ports, err := splitHostPort(s)
	if err != nil {
		return dstSelector{}, fmt.Errorf("destination %q: %w", s, err)
	}

	ranges, err := parsePorts(ports)
	if err != nil {
		return dstSelector{}, fmt.Errorf("destination %q: %w", s, err)
	}

	sel, err := e.classifyHost(host, true)
	if err != nil {
		return dstSelector{}, err
	}
	return dstSelector{host: sel, ports: ranges}, nil
}

// classifyHost validates and classifies a host selector.
func (e *Engine) classifyHost(s string, allowInternet bool) (selector, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return selector{}, fmt.Errorf("empty selector")
	}

	switch {
	case s == "*":
		return selector{kind: selWildcard, raw: s}, nil
	case s == "autogroup:self":
		return selector{kind: selSelf, raw: s}, nil
	case s == "autogroup:member":
		return selector{kind: selMember, raw: s}, nil
	case s == "autogroup:tagged":
		return selector{kind: selTagged, raw: s}, nil
	case s == "autogroup:internet":
		if !allowInternet {
			return selector{}, fmt.Errorf("autogroup:internet is only valid as a destination")
		}
		return selector{kind: selInternet, raw: s}, nil
	case strings.HasPrefix(s, "autogroup:"):
		return selector{}, fmt.Errorf("unsupported selector %q", s)
	case strings.HasPrefix(s, "tag:"):
		if _, ok := e.doc.TagOwners[s]; !ok {
			return selector{}, fmt.Errorf("tag %q is not declared in tagOwners", s)
		}
		return selector{kind: selTag, raw: s}, nil
	case strings.HasPrefix(s, "group:"):
		if _, ok := e.doc.Groups[s]; !ok {
			return selector{}, fmt.Errorf("group %q is not declared in groups", s)
		}
		return selector{kind: selGroup, raw: s}, nil
	}

	if target, ok := e.doc.Hosts[s]; ok {
		return selector{kind: selHost, raw: s, target: target}, nil
	}
	if prefix, err := parseAddrOrPrefix(s); err == nil {
		return selector{kind: selPrefix, raw: s, prefix: prefix}, nil
	}
	if isUserSelector(s) {
		return selector{kind: selUser, raw: s}, nil
	}
	return selector{}, fmt.Errorf("unknown selector %q (not a user, group, tag, host alias, CIDR or *)", s)
}

// splitHostPort splits a destination selector into its host and port parts.
//
// The port is everything after the last colon, with RFC 3986 brackets allowed
// for IPv6 hosts ("[fd7a::1]:443"), mirroring the official ACL grammar.
func splitHostPort(s string) (host, port string, err error) {
	if strings.HasPrefix(s, "[") {
		close := strings.Index(s, "]")
		if close == -1 {
			return "", "", fmt.Errorf("missing ] in bracketed IPv6 address")
		}
		addr := s[1:close]
		if a, err := netip.ParseAddr(addr); err != nil || !a.Is6() {
			return "", "", fmt.Errorf("brackets are only allowed around an IPv6 address, got %q", addr)
		}
		rest := s[close+1:]
		switch {
		case strings.HasPrefix(rest, ":"):
			return addr, rest[1:], nil
		case strings.HasPrefix(rest, "/"):
			s = addr + rest
		default:
			return "", "", fmt.Errorf("expected \":port\" or \"/prefix:port\" after %q", addr)
		}
	}

	host, port, ok := strings.CutLast(s, ":")
	if !ok {
		return "", "", fmt.Errorf("missing :port suffix")
	}
	if host == "" {
		return "", "", fmt.Errorf("missing host before :port")
	}
	if port == "" {
		return "", "", fmt.Errorf("missing port after host:")
	}
	return host, port, nil
}

// parsePorts parses an ACL port specification: "*", a single port, a range
// ("8000-9000"), or any comma-separated combination.
func parsePorts(spec string) ([]tailcfg.PortRange, error) {
	if spec == "*" {
		return []tailcfg.PortRange{tailcfg.PortRangeAny}, nil
	}

	var out []tailcfg.PortRange
	for part := range strings.SplitSeq(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port in %q", spec)
		}

		first, last, isRange := strings.Cut(part, "-")
		lo, err := parsePort(first)
		if err != nil {
			return nil, err
		}
		hi := lo
		if isRange {
			if hi, err = parsePort(last); err != nil {
				return nil, err
			}
			if lo > hi {
				return nil, fmt.Errorf("port range %q is inverted", part)
			}
		}
		out = append(out, tailcfg.PortRange{First: lo, Last: hi})
	}

	slices.SortFunc(out, func(a, b tailcfg.PortRange) int {
		if c := int(a.First) - int(b.First); c != 0 {
			return c
		}
		return int(a.Last) - int(b.Last)
	})
	return slices.Compact(out), nil
}

func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q (must be 1-65535)", s)
	}
	return uint16(n), nil
}

func parseAddrOrPrefix(s string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR", s)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// ianaProtocols maps ACL protocol names to IP protocol numbers.
var ianaProtocols = map[string]int{
	"icmp":      1,
	"tcp":       6,
	"udp":       17,
	"icmpv6":    58,
	"ipv6-icmp": 58,
	"sctp":      132,
}

// parseProto returns the IP protocol numbers a rule is limited to. An empty
// specification returns nil, which tailcfg defines as the client's default set
// (TCP, UDP and ICMP).
func parseProto(spec string) ([]int, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" {
		return nil, nil
	}
	if spec == "*" {
		return nil, nil
	}

	var out []int
	for part := range strings.SplitSeq(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty protocol in %q", spec)
		}
		if num, ok := ianaProtocols[part]; ok {
			out = append(out, num)
			continue
		}
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return nil, fmt.Errorf("invalid protocol %q", part)
		}
		out = append(out, num)
	}

	slices.Sort(out)
	return slices.Compact(out), nil
}

// FilterFor compiles the packet filter this node should receive.
//
// self is the node the netmap is being built for (its user decides
// autogroup:self); nodes is every node in the tailnet.
func (e *Engine) FilterFor(self state.Node, nodes []state.Node) []tailcfg.FilterRule {
	r := &resolution{engine: e, self: self, nodes: nodes}

	var out []tailcfg.FilterRule
	for _, rule := range e.rules {
		srcIPs := r.sourceIPs(rule.src)
		if len(srcIPs) == 0 {
			continue
		}
		dstPorts := r.destinations(rule.dst)
		if len(dstPorts) == 0 {
			continue
		}
		out = append(out, tailcfg.FilterRule{
			SrcIPs:   srcIPs,
			DstPorts: dstPorts,
			IPProto:  rule.proto,
		})
	}

	return append(out, e.grantFilterRules(r)...)
}

// resolution resolves selectors against one node snapshot.
type resolution struct {
	engine *Engine
	self   state.Node
	nodes  []state.Node

	// warned de-duplicates warnings emitted per resolver.
	warned map[string]bool
}

func (r *resolution) warn(format string, args ...any) {
	if r.warned == nil {
		r.warned = make(map[string]bool)
	}
	msg := fmt.Sprintf(format, args...)
	if r.warned[msg] {
		return
	}
	r.warned[msg] = true
	r.engine.warnf("%s", msg)
}

func (r *resolution) sourceIPs(sels []selector) []string {
	var out []string
	for _, sel := range sels {
		for _, ip := range r.hostIPs(sel) {
			if !slices.Contains(out, ip) {
				out = append(out, ip)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (r *resolution) destinations(sels []dstSelector) []tailcfg.NetPortRange {
	var out []tailcfg.NetPortRange
	for _, sel := range sels {
		for _, ip := range r.hostIPs(sel.host) {
			for _, ports := range sel.ports {
				npr := tailcfg.NetPortRange{IP: ip, Ports: ports}
				if !slices.ContainsFunc(out, func(x tailcfg.NetPortRange) bool {
					return x.IP == npr.IP && x.Ports == npr.Ports
				}) {
					out = append(out, npr)
				}
			}
		}
	}
	return out
}

// hostIPs resolves a host selector to wire IP strings.
func (r *resolution) hostIPs(sel selector) []string {
	switch sel.kind {
	case selWildcard:
		return []string{"*"}
	case selInternet:
		return []string{"0.0.0.0/0", "::/0"}
	case selPrefix:
		return []string{sel.prefix.String()}
	case selHost:
		prefix, err := parseAddrOrPrefix(sel.target)
		if err != nil {
			r.warn("policy: host alias %q resolves to %q, which is not an address", sel.raw, sel.target)
			return nil
		}
		return []string{prefix.String()}
	case selSelf, selMember, selTagged:
		return nodeIPs(r.matchingNodes(sel))
	case selTag:
		return nodeIPs(r.nodesWithTag(sel.raw))
	case selGroup:
		return nodeIPs(r.nodesForGroup(sel.raw, nil))
	case selUser:
		return nodeIPs(r.nodesForUser(sel.raw))
	default:
		return nil
	}
}

// matchingNodes resolves the node-set selectors.
func (r *resolution) matchingNodes(sel selector) []state.Node {
	switch sel.kind {
	case selSelf:
		return r.selfNodes()
	case selMember:
		return r.memberNodes()
	case selTagged:
		return r.taggedNodes()
	default:
		return nil
	}
}

// memberNodes returns the devices owned by a user. Tagged devices are not
// members, matching Tailscale's autogroup:member semantics; they are addressable
// through their tags or autogroup:tagged instead.
func (r *resolution) memberNodes() []state.Node {
	var out []state.Node
	for _, n := range r.nodes {
		if len(n.Tags) == 0 {
			out = append(out, n)
		}
	}
	return out
}

// selfNodes returns the untagged devices owned by the self node's user.
//
// Tagged devices are not a user's devices for matching purposes: a tagged
// node has no user identity, so autogroup:self matches neither a tagged source
// nor a tagged destination (mirrors headscale policy/v2).
func (r *resolution) selfNodes() []state.Node {
	if len(r.self.Tags) > 0 {
		return nil
	}
	return r.nodesForUserID(r.self.UserID)
}

// nodesForUserID returns the untagged devices owned by a user. Tagged devices
// are addressed through their tags (tag:... / autogroup:tagged), never through
// their owner.
func (r *resolution) nodesForUserID(id tailcfg.UserID) []state.Node {
	var out []state.Node
	for _, n := range r.nodes {
		if n.UserID == id && len(n.Tags) == 0 {
			out = append(out, n)
		}
	}
	return out
}

func (r *resolution) nodesForUser(sel string) []state.Node {
	var out []state.Node
	for _, n := range r.nodes {
		if len(n.Tags) == 0 && r.userMatches(n.UserID, sel) {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		r.warn("policy: user selector %q matches no node in the tailnet", sel)
	}
	return out
}

// userMatches reports whether a user selector names the given user.
//
// The comparison accepts the profile's login name verbatim and, for
// single-sign-on names of the form "login@domain", the local part of the
// selector — a self-hosted tailnet's users are frequently written with an email
// address even though the local profile only carries the login name.
func (r *resolution) userMatches(id tailcfg.UserID, sel string) bool {
	login := r.engine.opts.LoginName(id)
	if login == "" {
		return false
	}
	return loginNameMatches(sel, login)
}

// taggedNodes returns every node that carries at least one tag.
func (r *resolution) taggedNodes() []state.Node {
	var out []state.Node
	for _, n := range r.nodes {
		if len(n.Tags) > 0 {
			out = append(out, n)
		}
	}
	return out
}

func (r *resolution) nodesWithTag(tag string) []state.Node {
	var out []state.Node
	for _, n := range r.nodes {
		if slices.Contains(n.Tags, tag) {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		r.warn("policy: tag selector %q matches no node", tag)
	}
	return out
}

// nodesForGroup expands a group into its members, following nested groups.
func (r *resolution) nodesForGroup(name string, seen []string) []state.Node {
	if slices.Contains(seen, name) {
		return nil
	}
	seen = append(seen, name)

	var out []state.Node
	for _, member := range r.engine.doc.Groups[name] {
		switch {
		case strings.HasPrefix(member, "group:"):
			out = append(out, r.nodesForGroup(member, seen)...)
		case strings.HasPrefix(member, "tag:"):
			out = append(out, r.nodesWithTag(member)...)
		default:
			out = append(out, r.nodesForUser(member)...)
		}
	}
	return out
}

func nodeIPs(nodes []state.Node) []string {
	var out []string
	for _, n := range nodes {
		if n.IPv4.IsValid() {
			out = append(out, netip.PrefixFrom(n.IPv4, n.IPv4.BitLen()).String())
		}
		if n.IPv6.IsValid() {
			out = append(out, netip.PrefixFrom(n.IPv6, n.IPv6.BitLen()).String())
		}
	}
	return out
}
