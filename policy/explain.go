package policy

import "github.com/xunara-net/xunara-server/state"

type RuleMatch struct {
	Section      string   `json:"section"`
	Index        int      `json:"index"`
	Sources      []string `json:"sources"`
	Destinations []string `json:"destinations"`
}

type Explanation struct {
	Allowed bool        `json:"allowed"`
	Matches []RuleMatch `json:"matches"`
}

// Explain 使用实际下发的 ingress 编译结果，不另写一套选择器/端口授权解释器。
func (engine *Engine) Explain(nodes []state.Node, source, destination state.Node, protocol string, port uint16) Explanation {
	result := Explanation{Matches: []RuleMatch{}}
	result.Allowed = AllowsIngress(engine.FilterFor(destination, nodes), destination, source, protocol, port)
	if !result.Allowed {
		return result
	}
	for index, rule := range engine.rules {
		isolated := &Engine{doc: engine.doc, opts: engine.opts, rules: []compiledRule{rule}}
		if AllowsIngress(isolated.FilterFor(destination, nodes), destination, source, protocol, port) {
			row := engine.doc.ACLs[index]
			sources, destinations := row.Src, row.Dst
			if len(sources) == 0 {
				sources = row.Users
			}
			if len(destinations) == 0 {
				destinations = row.Ports
			}
			result.Matches = append(result.Matches, RuleMatch{Section: "acls", Index: index, Sources: append([]string{}, sources...), Destinations: append([]string{}, destinations...)})
		}
	}
	for _, grant := range engine.grants {
		isolated := &Engine{doc: engine.doc, opts: engine.opts, grants: []compiledGrant{grant}}
		if AllowsIngress(isolated.FilterFor(destination, nodes), destination, source, protocol, port) {
			row := engine.doc.Grants[grant.index]
			result.Matches = append(result.Matches, RuleMatch{Section: "grants", Index: grant.index, Sources: append([]string{}, row.Src...), Destinations: append([]string{}, row.Dst...)})
		}
	}
	return result
}
