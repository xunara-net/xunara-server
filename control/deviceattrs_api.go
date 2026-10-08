package control

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// This file is the read side of device posture attributes: what a node reports
// through PATCH /machine/set-device-attr (/machine/set-device-attr is write-
// only from the node's perspective) is visible to operators and automation
// here. Nothing on this path can modify an attribute: only the node itself can.

// handleAPIV2MachineDeviceAttrs implements
// GET /api/v2/machines/{id}/device-attrs: one machine's device posture
// attributes, as the node reported them.
//
// The values are the JSON scalars of tailcfg.AttrUpdate. They are machine-local
// facts (an OS version, a disk-encryption flag), not secrets; the response is
// still scoped like every other machine read.
func (s *Server) handleAPIV2MachineDeviceAttrs(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}

	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid machine id")
		return
	}
	node, ok := s.store.GetNodeByID(state.NodeID(id))
	if !ok {
		// A machine of another organization is simply not found: the router
		// already selected this organization (AGENTS.md section 12).
		writeAPIError(w, http.StatusNotFound, "machine not found")
		return
	}

	attrs, err := s.store.NodeDeviceAttrs(node.ID)
	if err != nil {
		s.log.Error("reading device attributes", "node", node.StableID, "err", err)
		writeAPIError(w, http.StatusInternalServerError, "device attributes are unavailable")
		return
	}
	if attrs == nil {
		// An empty object, not null: a machine with no attributes is a normal
		// state, and a client should not have to special-case it.
		attrs = map[string]any{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"machineId": uint64(node.ID),
		"stableId":  node.StableID,
		"attrs":     attrs,
	})
}
