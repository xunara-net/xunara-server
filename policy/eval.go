package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// defaultTestProtos is the protocol set an ACL test without a proto checks:
// what a client tries by default (TCP, UDP, ICMP, ICMPv6).
var defaultTestProtos = []int{1, 6, 17, 58}

// TestResult reports the outcome of one ACL test.
type TestResult struct {
	// Index is the position of the test in the document.
	Index int
	// Src is the source selector as written.
	Src string
	// Proto is the protocol the test ran under.
	Proto string
	// Failures lists every expectation the policy did not satisfy.
	Failures []string
}

// Pass reports whether the test passed.
func (r TestResult) Pass() bool { return len(r.Failures) == 0 }

// RunTests evaluates the document's tests against a node snapshot.
//
// The evaluation mirrors how clients enforce the filter: the destination node's
// rules decide whether traffic from the source node is allowed.
func (e *Engine) RunTests(nodes []state.Node) ([]TestResult, error) {
	var out []TestResult
	for i, test := range e.doc.Tests {
		srcSel := test.Src
		if srcSel == "" {
			srcSel = test.User
		}
		if srcSel == "" {
			return nil, fmt.Errorf("policy: tests[%d]: src is required", i)
		}

		protos := defaultTestProtos
		if test.Proto != "" {
			parsed, err := parseProto(test.Proto)
			if err != nil || len(parsed) == 0 {
				return nil, fmt.Errorf("policy: tests[%d]: invalid proto %q", i, test.Proto)
			}
			protos = parsed
		}

		result := TestResult{Index: i, Src: srcSel, Proto: test.Proto}

		accepted := append(slices.Clone(test.Accept), test.Allow...)
		for _, target := range accepted {
			if err := e.checkTestTarget(nodes, srcSel, target, protos, true); err != nil {
				result.Failures = append(result.Failures, err.Error())
			}
		}
		for _, target := range test.Deny {
			if err := e.checkTestTarget(nodes, srcSel, target, protos, false); err != nil {
				result.Failures = append(result.Failures, err.Error())
			}
		}
		out = append(out, result)
	}
	return out, nil
}

func (e *Engine) checkTestTarget(nodes []state.Node, srcSel, target string, protos []int, wantAllowed bool) error {
	src, err := e.singleNode(nodes, srcSel)
	if err != nil {
		return fmt.Errorf("src %q: %w", srcSel, err)
	}

	host, portSpec, err := splitHostPort(target)
	if err != nil {
		return fmt.Errorf("dst %q: %w", target, err)
	}
	ports, err := parsePorts(portSpec)
	if err != nil {
		return fmt.Errorf("dst %q: %w", target, err)
	}
	if len(ports) != 1 || ports[0].First != ports[0].Last {
		return fmt.Errorf("dst %q: a test destination must name exactly one port", target)
	}
	port := ports[0].First

	dst, err := e.singleNode(nodes, host)
	if err != nil {
		return fmt.Errorf("dst host %q: %w", host, err)
	}

	allowed := e.allows(nodes, src, dst, port, protos)
	switch {
	case wantAllowed && !allowed:
		return fmt.Errorf("%s -> %s is not allowed", srcSel, target)
	case !wantAllowed && allowed:
		return fmt.Errorf("%s -> %s is allowed but the test expects it to be denied", srcSel, target)
	}
	return nil
}

// singleNode resolves a selector that must name exactly one node.
func (e *Engine) singleNode(nodes []state.Node, sel string) (state.Node, error) {
	r := &resolution{engine: e, nodes: nodes}
	classed, err := e.classifyHost(sel, false)
	if err != nil {
		return state.Node{}, err
	}
	switch classed.kind {
	case selHost:
		if prefix, err := parseAddrOrPrefix(classed.target); err == nil {
			return e.nodeWithAddress(nodes, prefix)
		}
		return state.Node{}, fmt.Errorf("%q is not a node address", sel)
	case selPrefix:
		return e.nodeWithAddress(nodes, classed.prefix)
	case selTag:
		return pickNode(r.nodesWithTag(classed.raw))
	case selTagged:
		return pickNode(r.taggedNodes())
	case selUser:
		return pickNode(r.nodesForUser(classed.raw))
	case selSelf:
		return pickNode(r.selfNodes())
	case selMember:
		return pickNode(r.memberNodes())
	default:
		return state.Node{}, fmt.Errorf("%q does not name a single node", sel)
	}
}

func (e *Engine) nodeWithAddress(nodes []state.Node, addr netip.Prefix) (state.Node, error) {
	for _, n := range nodes {
		if n.IPv4.IsValid() && addr.Contains(n.IPv4) {
			return n, nil
		}
		if n.IPv6.IsValid() && addr.Contains(n.IPv6) {
			return n, nil
		}
	}
	return state.Node{}, fmt.Errorf("no node has address %s", addr)
}

func pickNode(nodes []state.Node) (state.Node, error) {
	switch len(nodes) {
	case 0:
		return state.Node{}, fmt.Errorf("no node matches")
	case 1:
		return nodes[0], nil
	default:
		names := make([]string, 0, len(nodes))
		for _, n := range nodes {
			names = append(names, n.Hostname)
		}
		return state.Node{}, fmt.Errorf("matches %d nodes (%s), expected exactly one", len(nodes), strings.Join(names, ", "))
	}
}

// allows reports whether the destination node's filter (as this engine compiles
// it) admits traffic from src.
func (e *Engine) allows(nodes []state.Node, src, dst state.Node, port uint16, protos []int) bool {
	filter := e.FilterFor(dst, nodes)

	for _, rule := range filter {
		if !ruleHasProto(rule, protos) {
			continue
		}
		if !ruleHasSource(rule, src) {
			continue
		}
		if ruleHasDestination(rule, dst, port) {
			return true
		}
	}
	return false
}

func ruleHasProto(rule tailcfg.FilterRule, protos []int) bool {
	if len(rule.IPProto) == 0 {
		// nil means the client default set.
		for _, p := range protos {
			if slices.Contains(defaultTestProtos, p) {
				return true
			}
		}
		return false
	}
	for _, p := range protos {
		if slices.Contains(rule.IPProto, p) {
			return true
		}
	}
	return false
}

func ruleHasSource(rule tailcfg.FilterRule, src state.Node) bool {
	for _, entry := range rule.SrcIPs {
		if entry == "*" {
			return true
		}
		if strings.HasPrefix(entry, "cap:") {
			continue
		}
		prefix, err := parseAddrOrPrefix(entry)
		if err != nil {
			continue
		}
		if matchesNode(prefix, src) {
			return true
		}
	}
	return false
}

func ruleHasDestination(rule tailcfg.FilterRule, dst state.Node, port uint16) bool {
	for _, npr := range rule.DstPorts {
		if !npr.Ports.Contains(port) {
			continue
		}
		if npr.IP == "*" {
			return true
		}
		prefix, err := parseAddrOrPrefix(npr.IP)
		if err != nil {
			continue
		}
		if matchesNode(prefix, dst) {
			return true
		}
	}
	return false
}

func matchesNode(prefix netip.Prefix, n state.Node) bool {
	if !prefix.IsValid() {
		return false
	}
	if n.IPv4.IsValid() && prefix.Contains(n.IPv4) {
		return true
	}
	return n.IPv6.IsValid() && prefix.Contains(n.IPv6)
}
