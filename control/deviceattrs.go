package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"unicode"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
)

// This file implements PATCH /machine/set-device-attr, the endpoint a client
// uses to report its own device posture attributes
// (tailcfg.SetDeviceAttributesRequest). Upstream marks the feature
// experimental; the shape of the request is what the official client sends
// (reference/tailscale/control/controlclient/direct.go:SetDeviceAttrs), and
// this build stores the attributes it is given — it does not invent posture
// semantics on top.
//
// What this build deliberately does *not* do yet: evaluate posture conditions
// in the ACL policy (upstream's `srcPosture` rules). Until that lands,
// attributes are informational: an operator can inspect them, and no rule
// depends on them. That is why the audit record names the attributes that
// changed but not their values (posture data can contain device identifiers,
// and the audit log is exported to webhooks).

const (
	// maxDeviceAttrNameLen bounds an attribute name. Names are namespaced by
	// convention ("foo", "custom:bar"), but the control plane treats them as
	// opaque.
	maxDeviceAttrNameLen = 128
	// maxDeviceAttrValueLen bounds a string attribute value.
	maxDeviceAttrValueLen = 256
	// maxDeviceAttrs bounds how many attributes one node may hold.
	maxDeviceAttrs = 64
	// maxDeviceAttrUpdateEntries bounds how many entries one update may carry.
	// A node holds at most maxDeviceAttrs attributes, so a larger update can
	// only be a mistake or an attempt to make the control plane chew on a map
	// nothing will read.
	maxDeviceAttrUpdateEntries = 4 * maxDeviceAttrs
	// maxDeviceAttrTotalBytes bounds the encoded size of one node's attribute
	// set, so a node cannot turn the store or the admin APIs into a bulk data
	// sink.
	maxDeviceAttrTotalBytes = 4096
)

// handleSetDeviceAttrs implements PATCH /machine/set-device-attr inside a
// Noise session: a node updates its own device posture attributes.
func (ns *noiseServer) handleSetDeviceAttrs(w http.ResponseWriter, req *http.Request) {
	var attrReq tailcfg.SetDeviceAttributesRequest
	if err := json.NewDecoder(req.Body).Decode(&attrReq); err != nil {
		// A body this build cannot parse is a client error, unlike the
		// store failures below.
		httpError(w, NewHTTPError(http.StatusBadRequest, "invalid JSON body", nil))
		return
	}

	if ns.rejectUnsupported(w, attrReq.Version, attrReq.NodeKey) {
		return
	}

	node, err := ns.getAndValidateNode(tailcfg.MapRequest{NodeKey: attrReq.NodeKey})
	if err != nil {
		httpError(w, err)
		return
	}

	// A node can only ever change its own attributes: the node key in the
	// request must belong to the machine key that opened the Noise session
	// (getAndValidateNode), and the store is updated for that node alone.
	if len(attrReq.Update) == 0 {
		writeJSON(w, http.StatusOK, struct{}{})
		return
	}

	current, err := ns.server.store.NodeDeviceAttrs(node.ID)
	if err != nil {
		ns.server.log.Error("reading device attributes", "node", node.StableID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	update, err := validateDeviceAttrUpdate(current, attrReq.Update)
	if err != nil {
		var invalid invalidDeviceAttrError
		if errors.As(err, &invalid) {
			httpError(w, NewHTTPError(http.StatusBadRequest, invalid.Error(), nil))
			return
		}
		ns.server.log.Error("validating device attributes", "node", node.StableID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}

	if err := ns.server.store.SetNodeDeviceAttrs(node.ID, update); err != nil {
		ns.server.log.Error("storing device attributes", "node", node.StableID, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}

	ns.server.audit(nodeActor(node), identity.AuditDeviceAttrsUpdated, nodeTarget(node), deviceAttrAuditDetail(update))

	writeJSON(w, http.StatusOK, struct{}{})
}

// invalidDeviceAttrError is a client mistake: a name, value or set this build
// refuses to store. It is reported as a 400 with its message.
type invalidDeviceAttrError struct {
	msg string
}

func (e invalidDeviceAttrError) Error() string { return e.msg }

func invalidDeviceAttr(format string, args ...any) error {
	return invalidDeviceAttrError{msg: fmt.Sprintf(format, args...)}
}

// validateDeviceAttrUpdate checks an update against the current attribute set
// and returns the sanitised update to apply. It fails closed: anything this
// build cannot store is refused rather than silently dropped.
func validateDeviceAttrUpdate(current, update map[string]any) (map[string]any, error) {
	if len(update) > maxDeviceAttrUpdateEntries {
		return nil, invalidDeviceAttr("an update may carry at most %d device attributes", maxDeviceAttrUpdateEntries)
	}

	clean := make(map[string]any, len(update))
	for name, value := range update {
		if err := validateDeviceAttrName(name); err != nil {
			return nil, err
		}

		switch typed := value.(type) {
		case nil:
			// A null value deletes the attribute (tailcfg.AttrUpdate).
		case string:
			if len(typed) > maxDeviceAttrValueLen {
				return nil, invalidDeviceAttr("attribute %q has a value longer than %d bytes", truncateClean(name, maxDeviceAttrNameLen), maxDeviceAttrValueLen)
			}
			if strings.ContainsFunc(typed, unicode.IsControl) {
				return nil, invalidDeviceAttr("attribute %q has a value containing control characters", truncateClean(name, maxDeviceAttrNameLen))
			}
		case bool:
		case float64:
			if math.IsNaN(typed) || math.IsInf(typed, 0) {
				return nil, invalidDeviceAttr("attribute %q has a non-finite numeric value", truncateClean(name, maxDeviceAttrNameLen))
			}
		default:
			return nil, invalidDeviceAttr("attribute %q has unsupported value type %s (want string, number, bool or null)",
				truncateClean(name, maxDeviceAttrNameLen), valueTypeName(value))
		}
		clean[name] = value
	}

	// The resulting set must also fit, not just the update: a node that is
	// already at the limit cannot add more.
	result := make(map[string]any, len(current)+len(clean))
	for name, value := range current {
		result[name] = value
	}
	for name, value := range clean {
		if value == nil {
			delete(result, name)
			continue
		}
		result[name] = value
	}
	if len(result) > maxDeviceAttrs {
		return nil, invalidDeviceAttr("a node may hold at most %d device attributes", maxDeviceAttrs)
	}

	total := 0
	for name, value := range result {
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, invalidDeviceAttr("attribute %q cannot be encoded", truncateClean(name, maxDeviceAttrNameLen))
		}
		total += len(name) + len(raw)
	}
	if total > maxDeviceAttrTotalBytes {
		return nil, invalidDeviceAttr("a node's device attributes may hold at most %d encoded bytes", maxDeviceAttrTotalBytes)
	}

	return clean, nil
}

// validateDeviceAttrName accepts any non-empty printable ASCII name: this
// build does not define the attribute namespace, so it must not reject names
// an upstream client considers valid. It does reject anything that would make
// a later renderer (audit log, console, terminal) unsafe.
func validateDeviceAttrName(name string) error {
	switch {
	case name == "":
		return invalidDeviceAttr("device attribute names must not be empty")
	case len(name) > maxDeviceAttrNameLen:
		return invalidDeviceAttr("device attribute names must be at most %d bytes", maxDeviceAttrNameLen)
	case strings.ContainsFunc(name, func(r rune) bool { return r < 0x21 || r > 0x7e }):
		return invalidDeviceAttr("device attribute names must be printable ASCII without spaces: %q", truncateClean(name, maxDeviceAttrNameLen))
	}
	return nil
}

// valueTypeName names a JSON value's Go type in a client-friendly way.
func valueTypeName(value any) string {
	switch value.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	default:
		return fmt.Sprintf("%T", value)
	}
}

// deviceAttrAuditDetail describes an update for the audit log: which
// attributes were set and which were removed, never their values.
func deviceAttrAuditDetail(update map[string]any) string {
	var set, deleted []string
	for name, value := range update {
		if value == nil {
			deleted = append(deleted, name)
			continue
		}
		set = append(set, name)
	}
	sort.Strings(set)
	sort.Strings(deleted)

	parts := make([]string, 0, 2)
	if len(set) > 0 {
		parts = append(parts, "set "+strings.Join(set, ", "))
	}
	if len(deleted) > 0 {
		parts = append(parts, "deleted "+strings.Join(deleted, ", "))
	}
	return truncateClean(strings.Join(parts, "; "), maxAuditDetailsLen)
}
