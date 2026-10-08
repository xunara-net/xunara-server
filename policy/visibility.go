package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/xunara-net/xunara-server/state"
)

// This file implements Xunara Atlas service visibility (PROJECT_SPEC section
// 46): the selectors a publishing node may declare for one of its services,
// and their resolution against a node snapshot. Visibility only narrows who
// can discover a name through MagicDNS — the ACL rules still decide who may
// connect, exactly as before.

const (
	// MaxServiceVisibilitySelectors bounds one service's visibility list.
	MaxServiceVisibilitySelectors = 16
	// MaxServiceVisibilitySelectorLen bounds one selector string.
	MaxServiceVisibilitySelectorLen = 128
)

// NormalizeServiceVisibility cleans a declared visibility list: entries are
// trimmed, must be printable (no control bytes), and the result is
// deduplicated and sorted so two declarations that mean the same thing
// compare equal. An empty list returns nil, the default: the whole
// organization may discover the service.
func NormalizeServiceVisibility(selectors []string) ([]string, error) {
	if len(selectors) == 0 {
		return nil, nil
	}
	if len(selectors) > MaxServiceVisibilitySelectors {
		return nil, fmt.Errorf("at most %d visibility selectors are allowed per service", MaxServiceVisibilitySelectors)
	}

	out := make([]string, 0, len(selectors))
	seen := make(map[string]bool, len(selectors))
	for _, raw := range selectors {
		sel := strings.TrimSpace(raw)
		if sel == "" {
			return nil, fmt.Errorf("visibility selector is empty")
		}
		if len(sel) > MaxServiceVisibilitySelectorLen {
			return nil, fmt.Errorf("visibility selector is longer than %d bytes", MaxServiceVisibilitySelectorLen)
		}
		for i := 0; i < len(sel); i++ {
			if c := sel[i]; c < 0x21 || c > 0x7e {
				return nil, fmt.Errorf("visibility selector contains a non-printable character")
			}
		}
		if seen[sel] {
			continue
		}
		seen[sel] = true
		out = append(out, sel)
	}
	slices.Sort(out)
	return out, nil
}

// ValidateServiceVisibility checks every selector against this document: the
// grammar is the ACL source-selector grammar, so a declaration naming an
// undeclared group or tag is refused at publish time instead of silently
// hiding the service from everyone.
func (e *Engine) ValidateServiceVisibility(selectors []string) error {
	for _, sel := range selectors {
		if _, err := e.classifySource(sel); err != nil {
			return fmt.Errorf("visibility: %w", err)
		}
	}
	return nil
}

// ServiceVisibility resolves a service's visibility selectors to the nodes
// that may discover it. publisher is the node that declared the service, so
// autogroup:self means that node's user's devices.
//
// Resolution is fail-closed: a selector that cannot be resolved now (an
// unknown group after a policy change, for example) contributes no nodes, so
// the service shrinks to the publisher rather than leaking to everyone.
func (e *Engine) ServiceVisibility(nodes []state.Node, publisher state.Node, selectors []string) map[state.NodeID]bool {
	r := &resolution{engine: e, self: publisher, nodes: nodes}
	out := make(map[state.NodeID]bool)
	for _, sel := range selectors {
		parsed, err := e.classifySource(sel)
		if err != nil {
			continue
		}
		for _, n := range r.nodesForSelector(parsed) {
			out[n.ID] = true
		}
	}
	return out
}
