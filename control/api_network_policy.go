package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/networkconfig"
	"github.com/xunara-net/xunara-server/policy"
	"github.com/xunara-net/xunara-server/state"
)

type policyDraftRequest struct {
	Revision    *uint64 `json:"revision"`
	BaseHash    string  `json:"base_hash"`
	Content     string  `json:"content"`
	RestoreFrom *uint64 `json:"restore_from,omitempty"`
}

type policyDiff struct {
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
	Sections []string `json:"sections"`
}

func diffPolicy(before, after json.RawMessage) policyDiff {
	result := policyDiff{Added: []string{}, Removed: []string{}, Sections: []string{}}
	var oldSections, newSections map[string]json.RawMessage
	_ = json.Unmarshal(before, &oldSections)
	_ = json.Unmarshal(after, &newSections)
	keys := make([]string, 0, len(oldSections)+len(newSections))
	for name := range oldSections {
		keys = append(keys, name)
	}
	for name := range newSections {
		keys = append(keys, name)
	}
	slices.Sort(keys)
	for _, name := range slices.Compact(keys) {
		var oldValue, newValue any
		_ = json.Unmarshal(oldSections[name], &oldValue)
		_ = json.Unmarshal(newSections[name], &newValue)
		oldJSON, _ := json.Marshal(oldValue)
		newJSON, _ := json.Marshal(newValue)
		if string(oldJSON) == string(newJSON) {
			continue
		}
		result.Sections = append(result.Sections, name)
		beforeRows := policySectionRows(name, oldValue)
		afterRows := policySectionRows(name, newValue)
		for _, row := range afterRows {
			if !slices.Contains(beforeRows, row) {
				result.Added = append(result.Added, row)
			}
		}
		for _, row := range beforeRows {
			if !slices.Contains(afterRows, row) {
				result.Removed = append(result.Removed, row)
			}
		}
	}
	return result
}

func policySectionRows(name string, value any) []string {
	var rows []string
	if list, ok := value.([]any); ok {
		for _, row := range list {
			raw, _ := json.Marshal(row)
			rows = append(rows, name+": "+string(raw))
		}
	} else if value != nil {
		raw, _ := json.Marshal(value)
		rows = append(rows, name+": "+string(raw))
	}
	return rows
}

func (server *Server) handleAPIV2PolicyConfiguration(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireScope(writer, request, identity.ScopeRead); !ok {
		return
	}
	server.networkMu.Lock()
	defer server.networkMu.Unlock()
	if err := server.loadPolicyLocked(request.Context()); err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	configuration := server.policyConfig.Load()
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, map[string]any{
		"revision": configuration.Revision, "base_hash": contentHash(configuration.Content),
		"source": configuration.Source, "content": configuration.Content, "document": configuration.JSON,
		"can_edit": server.Plan().AllowACL || server.Plan().AllowGrants, "can_grants": server.Plan().AllowGrants,
		"csrf_token": csrfTokenFor(server.accountSessionToken(request)),
	})
}

func (server *Server) compilePolicyDraft(request *http.Request, body policyDraftRequest) (*policy.Engine, json.RawMessage, string, error) {
	content := body.Content
	if body.RestoreFrom != nil {
		if content != "" {
			return nil, nil, "", errors.New("content and restore_from cannot be combined")
		}
		document, err := server.networkConfig.Version(request.Context(), networkconfig.Policy, *body.RestoreFrom)
		if err != nil {
			return nil, nil, "", err
		}
		content = document.Content
	}
	document, normalized, err := policy.ParseManaged([]byte(content))
	if err != nil {
		return nil, nil, "", err
	}
	engine, err := policy.NewEngine(document, server.policyOptions())
	return engine, normalized, content, err
}

func (server *Server) checkPolicyEntitlement(engine *policy.Engine) error {
	document := engine.Document()
	entitlement := server.Plan()
	if !entitlement.AllowACL && len(document.ACLs) > 0 {
		return errors.New("ACL rules are not included in this plan")
	}
	if !entitlement.AllowGrants && len(document.Grants) > 0 {
		return errors.New("grants are not included in this plan")
	}
	if !entitlement.AllowACL && !entitlement.AllowGrants {
		return errors.New("policy editing is not included in this plan")
	}
	return nil
}

func policyTestsPass(tests policyTestsView) bool {
	if tests.Total > 0 && !tests.Ran {
		return false
	}
	for _, result := range tests.Results {
		if !result.Pass {
			return false
		}
	}
	return true
}

func (server *Server) handleAPIV2ValidatePolicy(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireScope(writer, request, identity.ScopeRead); !ok {
		return
	}
	var body policyDraftRequest
	if !decodeAPIBody(writer, request, &body) {
		return
	}
	engine, normalized, _, err := server.compilePolicyDraft(request, body)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, formatPolicyError(err))
		return
	}
	server.networkMu.Lock()
	defer server.networkMu.Unlock()
	if err := server.loadPolicyLocked(request.Context()); err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	configuration := server.policyConfig.Load()
	if body.Revision == nil || *body.Revision != configuration.Revision || body.BaseHash != contentHash(configuration.Content) {
		server.writeNetworkError(writer, networkconfig.ErrConflict)
		return
	}
	nodes, err := server.networkNodes(request.Context())
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	tests := server.runPolicyTestsForNodes(engine, len(engine.Document().Tests), nodes)
	entitlementError := ""
	if err := server.checkPolicyEntitlement(engine); err != nil {
		entitlementError = err.Error()
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, map[string]any{
		"document": normalized, "rule_count": engine.RuleCount(), "warnings": stringsOrEmpty(engine.Warnings()),
		"tests": tests, "publishable": policyTestsPass(tests) && entitlementError == "", "entitlement_error": entitlementError,
		"diff": diffPolicy(configuration.JSON, normalized),
	})
}

func (server *Server) handleAPIV2PublishPolicy(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireNetworkWriter(writer, request)
	if !ok {
		return
	}
	var body policyDraftRequest
	if !decodeAPIBody(writer, request, &body) {
		return
	}
	engine, normalized, content, err := server.compilePolicyDraft(request, body)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, formatPolicyError(err))
		return
	}
	if err := server.checkPolicyEntitlement(engine); err != nil {
		writeAPIError(writer, http.StatusForbidden, "PLAN_FEATURE_DISABLED: "+err.Error())
		return
	}
	nodes, err := server.networkNodes(request.Context())
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	tests := server.runPolicyTestsForNodes(engine, len(engine.Document().Tests), nodes)
	if !policyTestsPass(tests) {
		writeAPIError(writer, http.StatusBadRequest, "POLICY_TEST_FAILED: policy assertions failed or could not run")
		return
	}
	server.networkMu.Lock()
	defer server.networkMu.Unlock()
	if err := server.loadPolicyLocked(request.Context()); err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	previous := server.policyConfig.Load()
	if body.Revision == nil || *body.Revision != previous.Revision || body.BaseHash != contentHash(previous.Content) {
		server.writeNetworkError(writer, networkconfig.ErrConflict)
		return
	}
	document, err := server.networkConfig.Save(request.Context(), networkconfig.Policy, content, previous.Content, *body.Revision, networkWriter(principal))
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	server.policy.Store(engine)
	server.policyConfig.Store(&policyConfiguration{Revision: document.Revision, Source: "database", Content: content, JSON: normalized})
	server.notifyWatchers()
	writeJSON(writer, http.StatusOK, map[string]any{"revision": document.Revision, "base_hash": contentHash(content)})
}

func (server *Server) handleAPIV2PolicyHistory(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireScope(writer, request, identity.ScopeRead); !ok {
		return
	}
	items, err := server.networkConfig.History(request.Context(), networkconfig.Policy)
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

type policyProbe struct {
	Content      string   `json:"content,omitempty"`
	Source       uint64   `json:"source,omitempty"`
	Destination  uint64   `json:"destination,omitempty"`
	Sources      []uint64 `json:"sources,omitempty"`
	Destinations []uint64 `json:"destinations,omitempty"`
	Protocol     string   `json:"protocol"`
	Port         uint16   `json:"port"`
}

func (server *Server) policyProbeEngine(request *http.Request, probe policyProbe) (*policy.Engine, error) {
	if probe.Protocol != "tcp" && probe.Protocol != "udp" || probe.Port == 0 {
		return nil, errors.New("select TCP or UDP and a port between 1 and 65535")
	}
	if probe.Content != "" {
		engine, _, _, err := server.compilePolicyDraft(request, policyDraftRequest{Content: probe.Content})
		return engine, err
	}
	server.networkMu.Lock()
	defer server.networkMu.Unlock()
	if err := server.loadPolicyLocked(request.Context()); err != nil {
		return nil, err
	}
	if engine := server.policy.Load(); engine != nil {
		return engine, nil
	}
	document, _ := policy.ParseString(legacyDefaultPolicy)
	return policy.NewEngine(document, server.policyOptions())
}

func findProbeNode(nodes []state.Node, nodeID uint64) (state.Node, error) {
	for _, node := range nodes {
		if uint64(node.ID) == nodeID && !node.Expired(time.Now()) {
			return node, nil
		}
	}
	return state.Node{}, errors.New("device is missing, expired or outside this network")
}

func (server *Server) handleAPIV2SimulatePolicy(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireScope(writer, request, identity.ScopeRead); !ok {
		return
	}
	var probe policyProbe
	if !decodeAPIBody(writer, request, &probe) {
		return
	}
	engine, err := server.policyProbeEngine(request, probe)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, formatPolicyError(err))
		return
	}
	nodes, err := server.networkNodes(request.Context())
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	source, sourceErr := findProbeNode(nodes, probe.Source)
	destination, destinationErr := findProbeNode(nodes, probe.Destination)
	if sourceErr != nil || destinationErr != nil {
		writeAPIError(writer, http.StatusBadRequest, "POLICY_PROBE_INVALID: both devices must be active members of this network")
		return
	}
	result := engine.Explain(nodes, source, destination, probe.Protocol, probe.Port)
	writeJSON(writer, http.StatusOK, map[string]any{
		"allowed": result.Allowed, "matches": result.Matches, "draft": probe.Content != "",
		"reason": policyProbeReason(result.Allowed),
	})
}

func policyProbeReason(allowed bool) string {
	if allowed {
		return "matched the destination's compiled packet filter; this is policy permission, not a live connectivity test"
	}
	return "no matching network grant; access is denied by the destination's compiled packet filter"
}

func (server *Server) handleAPIV2PolicyMatrix(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireScope(writer, request, identity.ScopeRead); !ok {
		return
	}
	var probe policyProbe
	if !decodeAPIBody(writer, request, &probe) {
		return
	}
	if len(probe.Sources) == 0 || len(probe.Sources) > 12 || len(probe.Destinations) == 0 || len(probe.Destinations) > 12 {
		writeAPIError(writer, http.StatusBadRequest, "POLICY_PROBE_INVALID: select one to twelve sources and destinations per page")
		return
	}
	engine, err := server.policyProbeEngine(request, probe)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, formatPolicyError(err))
		return
	}
	nodes, err := server.networkNodes(request.Context())
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	items := make([]map[string]any, 0, len(probe.Sources)*len(probe.Destinations))
	filters := make(map[uint64][]tailcfg.FilterRule, len(probe.Destinations))
	destinations := make(map[uint64]state.Node, len(probe.Destinations))
	for _, destinationID := range probe.Destinations {
		destination, err := findProbeNode(nodes, destinationID)
		if err != nil {
			writeAPIError(writer, http.StatusBadRequest, "POLICY_PROBE_INVALID: "+err.Error())
			return
		}
		destinations[destinationID] = destination
		filters[destinationID] = engine.FilterFor(destination, nodes)
	}
	for _, sourceID := range probe.Sources {
		source, err := findProbeNode(nodes, sourceID)
		if err != nil {
			writeAPIError(writer, http.StatusBadRequest, "POLICY_PROBE_INVALID: "+err.Error())
			return
		}
		for _, destinationID := range probe.Destinations {
			destination := destinations[destinationID]
			allowed := policy.AllowsIngress(filters[destinationID], destination, source, probe.Protocol, probe.Port)
			items = append(items, map[string]any{"source": sourceID, "destination": destinationID, "allowed": allowed})
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"items": items, "draft": probe.Content != "", "service": fmt.Sprintf("%s:%d", probe.Protocol, probe.Port)})
}
