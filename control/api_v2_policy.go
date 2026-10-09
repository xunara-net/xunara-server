package control

import (
	"encoding/json"
	"net/http"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/policy"
	"github.com/xunara-net/xunara-server/state"
)

// 兼容只读策略摘要；托管配置与文件配置共用正在生效的编译引擎。

// policyACLView is one ACL row as written in the document.
type policyACLView struct {
	Action string   `json:"action,omitempty"`
	Proto  string   `json:"proto,omitempty"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
	// Users and Ports are the pre-v2 names of Src and Dst; they are rendered
	// when the document used them.
	Users []string `json:"users,omitempty"`
	Ports []string `json:"ports,omitempty"`
}

// policyGrantView is one grants (ACL v2) row as written.
type policyGrantView struct {
	Src []string `json:"src"`
	Dst []string `json:"dst"`
	IP  []string `json:"ip"`
	// App maps a peer capability to the JSON values delivered with it.
	App map[string][]json.RawMessage `json:"app"`
	Via []string                     `json:"via,omitempty"`
}

// policySSHView is one ssh row. CheckPeriod is "always", a Go duration string
// such as "12h0m0s", or empty when the row did not set one (the 12h default).
type policySSHView struct {
	Action      string   `json:"action"`
	Src         []string `json:"src"`
	Dst         []string `json:"dst"`
	Users       []string `json:"users"`
	AcceptEnv   []string `json:"acceptEnv"`
	CheckPeriod string   `json:"checkPeriod,omitempty"`
}

// policyNodeAttrView is one nodeAttrs row.
type policyNodeAttrView struct {
	Target []string `json:"target"`
	Attr   []string `json:"attr"`
}

// policyTestResultView is one document test's outcome against the current
// machines; a failed expectation is data, not an HTTP error.
type policyTestResultView struct {
	Index    int      `json:"index"`
	Src      string   `json:"src"`
	Proto    string   `json:"proto,omitempty"`
	Pass     bool     `json:"pass"`
	Failures []string `json:"failures"`
}

// policyTestsView answers "are the document's own assertions satisfied right
// now". Ran is false when nothing could run; Reason says why.
type policyTestsView struct {
	Total   int                    `json:"total"`
	Ran     bool                   `json:"ran"`
	Reason  string                 `json:"reason,omitempty"`
	Results []policyTestResultView `json:"results"`
}

// policyView is the JSON shape of GET /api/v2/policy.
type policyView struct {
	Configured bool `json:"configured"`
	// Path is the local document path, as in GET /api/v1/policy.
	Path      string `json:"path,omitempty"`
	RuleCount int    `json:"ruleCount"`
	// Warnings are non-fatal compile problems, such as selectors that match
	// no node right now.
	Warnings []string `json:"warnings"`
	// Unsupported lists top-level fields this build understands but ignores.
	// Ignoring them can only tighten the policy, never widen it.
	Unsupported []string `json:"unsupported"`
	// LoadError is set when the file on disk no longer parses: the watcher
	// kept the last good document, and Configured/sections describe that one.
	LoadError string `json:"loadError,omitempty"`

	ACLs      []policyACLView      `json:"acls"`
	Grants    []policyGrantView    `json:"grants"`
	Groups    map[string][]string  `json:"groups"`
	Hosts     map[string]string    `json:"hosts"`
	TagOwners map[string][]string  `json:"tagOwners"`
	SSH       []policySSHView      `json:"ssh"`
	NodeAttrs []policyNodeAttrView `json:"nodeAttrs"`
	Tests     policyTestsView      `json:"tests"`
}

// policyView renders the policy in force. It never fails: a document that
// cannot be re-read is reported through LoadError while the sections keep
// describing the document the engine is enforcing.
func (s *Server) policyView() policyView {
	view := policyView{
		Warnings:    []string{},
		Unsupported: []string{},
		ACLs:        []policyACLView{},
		Grants:      []policyGrantView{},
		Groups:      map[string][]string{},
		Hosts:       map[string]string{},
		TagOwners:   map[string][]string{},
		SSH:         []policySSHView{},
		NodeAttrs:   []policyNodeAttrView{},
		Tests:       policyTestsView{Results: []policyTestResultView{}},
	}
	if configuration := s.policyConfig.Load(); s.cfg.PolicyPath != "" && (configuration == nil || configuration.Source != "database") {
		if _, err := policy.Load(s.cfg.PolicyPath); err != nil {
			view.LoadError = err.Error()
		}
	}
	engine := s.policy.Load()
	if engine == nil {
		return view
	}

	doc := engine.Document()
	view.Configured = true
	view.Path = s.cfg.PolicyPath
	view.RuleCount = engine.RuleCount()
	view.Warnings = stringsOrEmpty(engine.Warnings())
	view.Unsupported = stringsOrEmpty(doc.Unsupported)

	for _, row := range doc.ACLs {
		view.ACLs = append(view.ACLs, policyACLView{
			Action: row.Action,
			Proto:  row.Proto,
			Src:    stringsOrEmpty(row.Src),
			Dst:    stringsOrEmpty(row.Dst),
			Users:  row.Users,
			Ports:  row.Ports,
		})
	}
	for _, row := range doc.Grants {
		app := row.App
		if app == nil {
			app = map[string][]json.RawMessage{}
		}
		view.Grants = append(view.Grants, policyGrantView{
			Src: stringsOrEmpty(row.Src),
			Dst: stringsOrEmpty(row.Dst),
			IP:  stringsOrEmpty(row.IP),
			App: app,
			Via: row.Via,
		})
	}
	for name, members := range doc.Groups {
		view.Groups[name] = stringsOrEmpty(members)
	}
	for alias, value := range doc.Hosts {
		view.Hosts[alias] = value
	}
	for tag, owners := range doc.TagOwners {
		view.TagOwners[tag] = stringsOrEmpty(owners)
	}
	for _, row := range doc.SSH {
		view.SSH = append(view.SSH, policySSHView{
			Action:      row.Action,
			Src:         stringsOrEmpty(row.Src),
			Dst:         stringsOrEmpty(row.Dst),
			Users:       stringsOrEmpty(row.Users),
			AcceptEnv:   stringsOrEmpty(row.AcceptEnv),
			CheckPeriod: sshCheckPeriodString(row.CheckPeriod),
		})
	}
	for _, row := range doc.NodeAttrs {
		view.NodeAttrs = append(view.NodeAttrs, policyNodeAttrView{
			Target: stringsOrEmpty(row.Target),
			Attr:   stringsOrEmpty(row.Attr),
		})
	}
	view.Tests = s.runPolicyTests(engine, len(doc.Tests))
	return view
}

// runPolicyTests evaluates the document's tests against the current machines,
// mirroring "xunara policy check": tests assert against real devices, so a
// tailnet with no machines yet reports Ran=false instead of misleading
// failures.
func (s *Server) runPolicyTests(engine *policy.Engine, total int) policyTestsView {
	return s.runPolicyTestsForNodes(engine, total, s.store.ListNodes())
}

func (s *Server) runPolicyTestsForNodes(engine *policy.Engine, total int, nodes []state.Node) policyTestsView {
	view := policyTestsView{Total: total, Results: []policyTestResultView{}}
	switch {
	case total == 0:
		view.Reason = "the document declares no tests"
	case len(nodes) == 0:
		view.Reason = "no machines are registered yet"
	default:
		results, err := engine.RunTests(nodes)
		if err != nil {
			view.Reason = err.Error()
			return view
		}
		view.Ran = true
		for _, result := range results {
			view.Results = append(view.Results, policyTestResultView{
				Index:    result.Index,
				Src:      result.Src,
				Proto:    result.Proto,
				Pass:     result.Pass(),
				Failures: stringsOrEmpty(result.Failures),
			})
		}
	}
	return view
}

// sshCheckPeriodString renders an ssh row's checkPeriod.
func sshCheckPeriodString(period *policy.SSHCheckPeriod) string {
	switch {
	case period == nil:
		return ""
	case period.Always:
		return "always"
	default:
		return period.Duration.String()
	}
}

// stringsOrEmpty keeps JSON arrays as [] instead of null, so an automation
// client never has to treat "absent" and "empty" differently.
func stringsOrEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// handleAPIV2Policy implements GET /api/v2/policy: the read-only view of the
// policy in force (spec section 34.1).
func (s *Server) handleAPIV2Policy(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.policyView())
}
