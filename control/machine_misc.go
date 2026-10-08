package control

import (
	"encoding/json"
	"net/http"
	"strings"
	"unicode"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
)

// This file implements the remaining inner (Noise) endpoints official clients
// call: health reports, client audit logs, and the debug whoami probe.

// maxAuditDetailsLen bounds the client-supplied detail string before it is
// persisted; the audit log is durable, so unbounded input is a storage risk.
const maxAuditDetailsLen = 512

// auditLogActions are the client-reported actions this build understands.
// Refusing unknown actions keeps the log greppable and prevents a client from
// writing arbitrary action names into the durable audit log.
var auditLogActions = map[tailcfg.ClientAuditAction]string{
	tailcfg.AuditNodeDisconnect: identity.AuditNodeDisconnectReported,
}

// handleAuditLog implements POST /machine/audit-log: a node reports an
// auditable client-side action (today, the user disconnecting the node).
func (ns *noiseServer) handleAuditLog(w http.ResponseWriter, req *http.Request) {
	var auditReq tailcfg.AuditLogRequest
	if err := json.NewDecoder(req.Body).Decode(&auditReq); err != nil {
		httpError(w, err)
		return
	}

	if ns.rejectUnsupported(w, auditReq.Version, auditReq.NodeKey) {
		return
	}

	node, err := ns.getAndValidateNode(tailcfg.MapRequest{NodeKey: auditReq.NodeKey})
	if err != nil {
		httpError(w, err)
		return
	}

	action, ok := auditLogActions[auditReq.Action]
	if !ok {
		httpError(w, NewHTTPError(http.StatusBadRequest, "unknown client audit action", nil))
		return
	}

	ns.server.audit(nodeActor(node), action, nodeTarget(node), cleanAuditDetails(auditReq.Details))

	writeJSON(w, http.StatusOK, struct{}{})
}

// handleUpdateHealth implements POST /machine/update-health. Health reports are
// advisory telemetry: this build logs them (bounded) and does not let them
// influence registration, policy or routing.
func (ns *noiseServer) handleUpdateHealth(w http.ResponseWriter, req *http.Request) {
	var health tailcfg.HealthChangeRequest
	if err := json.NewDecoder(req.Body).Decode(&health); err != nil {
		httpError(w, err)
		return
	}

	// Older clients send a zero node key; the Noise session's machine key is
	// still authenticated, so bind the report to a node when possible.
	if !health.NodeKey.IsZero() {
		if _, err := ns.getAndValidateNode(tailcfg.MapRequest{NodeKey: health.NodeKey}); err != nil {
			httpError(w, err)
			return
		}
	}

	ns.server.log.Debug("client health report",
		"machine_key", ns.machineKey.ShortString(),
		"subsystem", truncateClean(health.Subsys, 64),
		"error", truncateClean(health.Error, 256))

	w.WriteHeader(http.StatusNoContent)
}

// handleWhoami implements GET /machine/whoami, the debug probe `tailscale debug
// ts2021` performs after its handshake. The node is identified by the Noise
// session's machine key.
func (ns *noiseServer) handleWhoami(w http.ResponseWriter, req *http.Request) {
	nodes := ns.server.store.GetNodesByMachineKey(ns.machineKey)
	if len(nodes) == 0 {
		httpError(w, NewHTTPError(http.StatusNotFound, "machine is not registered", nil))
		return
	}

	// A machine key can host several nodes; answer deterministically with the
	// oldest one.
	node := nodes[0]
	for _, other := range nodes[1:] {
		if other.ID < node.ID {
			node = other
		}
	}

	addresses := []string{node.IPv4.String()}
	if node.IPv6.IsValid() {
		addresses = append(addresses, node.IPv6.String())
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":      int64(node.ID),
		"stable_id":    node.StableID,
		"name":         node.FQDN(strings.Trim(ns.server.cfg.Domain, ".")),
		"addresses":    addresses,
		"machine_key":  ns.machineKey.ShortString(),
		"node_key":     node.NodeKey.ShortString(),
		"capabilities": int(tailcfg.CurrentCapabilityVersion),
	})
}

// cleanAuditDetails bounds and sanitises a client-supplied detail string: the
// audit log is rendered in the console and terminal, so control characters are
// stripped and the length is capped.
func cleanAuditDetails(details string) string {
	return truncateClean(details, maxAuditDetailsLen)
}

// truncateClean strips control characters and caps a string at max runes.
func truncateClean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) <= max {
		return s
	}
	return s[:max]
}
