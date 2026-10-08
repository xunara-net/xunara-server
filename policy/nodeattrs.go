package policy

import (
	"fmt"
	"slices"
	"strings"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

// This file compiles the document's "nodeAttrs" section into the per-node
// capability map (tailcfg.NodeCapMap) clients read to decide whether a feature
// is enabled for a device: "https" for serving HTTPS, "https://tailscale.com/
// cap/file-sharing" for Taildrive, and so on.
//
// Reference: reference/headscale/hscontrol/policy/v2 (nodeattrs) and
// reference/tailscale/tailcfg/nodecap for the capability names.

// maxAttrLength bounds a capability name; the names are URLs or short
// mnemonics and are rendered into clients and logs.
const maxAttrLength = 256

// unsupportedAttrs are capability names a document may declare but this build
// cannot honour end to end. Refusing them at load time keeps a policy from
// advertising a feature that does not work (fail closed, matching headscale).
var unsupportedAttrs = map[string]string{
	"funnel": "Funnel needs public ingress infrastructure, which this build does not run",
}

// compiledNodeAttr is a validated "nodeAttrs" row.
type compiledNodeAttr struct {
	target []selector
	attr   []string
}

// compileNodeAttrs validates the document's nodeAttrs rows.
func (e *Engine) compileNodeAttrs() error {
	for i, row := range e.doc.NodeAttrs {
		if len(row.Target) == 0 {
			return fmt.Errorf("policy: nodeAttrs[%d]: target is required", i)
		}
		var compiled compiledNodeAttr
		for _, t := range row.Target {
			sel, err := e.classifyHost(t, false)
			if err != nil {
				return fmt.Errorf("policy: nodeAttrs[%d]: target: %w", i, err)
			}
			switch sel.kind {
			case selSelf, selInternet:
				return fmt.Errorf("policy: nodeAttrs[%d]: target %q is not a node selector "+
					"(use a user, group, tag, autogroup:member, autogroup:tagged or *)", i, t)
			}
			compiled.target = append(compiled.target, sel)
		}
		for _, attr := range row.Attr {
			if attr == "" || len(attr) > maxAttrLength || strings.ContainsAny(attr, " \t\r\n\"") {
				return fmt.Errorf("policy: nodeAttrs[%d]: %q is not a capability name", i, attr)
			}
			if reason, bad := unsupportedAttrs[attr]; bad {
				return fmt.Errorf("policy: nodeAttrs[%d]: capability %q is not supported: %s", i, attr, reason)
			}
			if !slices.Contains(compiled.attr, attr) {
				compiled.attr = append(compiled.attr, attr)
			}
		}
		e.nodeAttrs = append(e.nodeAttrs, compiled)
	}
	return nil
}

// NodeCapMaps returns the capability map every node receives from the
// nodeAttrs section. Nodes without a grant are absent from the result.
func (e *Engine) NodeCapMaps(nodes []state.Node) map[state.NodeID]tailcfg.NodeCapMap {
	if len(e.nodeAttrs) == 0 {
		return nil
	}

	r := &resolution{engine: e, nodes: nodes}
	out := make(map[state.NodeID]tailcfg.NodeCapMap)

	for _, row := range e.nodeAttrs {
		if len(row.attr) == 0 {
			continue
		}
		for id := range r.nodesForSelectors(row.target) {
			caps := out[id]
			if caps == nil {
				caps = make(tailcfg.NodeCapMap, len(row.attr))
				out[id] = caps
			}
			for _, attr := range row.attr {
				caps[tailcfg.NodeCapability(attr)] = nil
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
