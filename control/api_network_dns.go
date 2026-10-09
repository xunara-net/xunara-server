package control

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/networkconfig"
	"github.com/xunara-net/xunara-server/state"
)

func (server *Server) handleAPIV2DNSRecords(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireScope(writer, request, identity.ScopeRead); !ok {
		return
	}
	records, err := server.networkConfig.Records(request.Context())
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, map[string]any{"items": records})
}

func (server *Server) handleAPIV2SaveDNSRecord(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireNetworkWriter(writer, request)
	if !ok {
		return
	}
	if !server.Plan().AllowCustomDNS {
		writeAPIError(writer, http.StatusForbidden, "PLAN_FEATURE_DISABLED: custom DNS is not included in this plan")
		return
	}
	var body struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Value    string `json:"value"`
		Revision uint64 `json:"revision,omitempty"`
	}
	if !decodeAPIBody(writer, request, &body) {
		return
	}
	name, nameErr := state.NormalizeDNSRecordName(body.Name)
	kind, typeErr := state.NormalizeDNSRecordType(body.Type)
	address, addressErr := netip.ParseAddr(strings.TrimSpace(body.Value))
	domain := strings.Trim(server.cfg.Domain, ".")
	if nameErr != nil || typeErr != nil || addressErr != nil || domain == "" || !strings.HasSuffix(name, "."+domain) ||
		kind != "A" && kind != "AAAA" || kind == "A" && !address.Is4() || kind == "AAAA" && (!address.Is6() || address.Is4In6()) ||
		address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" || isACMEChallengeName(name) {
		writeAPIError(writer, http.StatusBadRequest, "DNS_RECORD_INVALID: use a name under the managed domain and a matching IPv4 A or IPv6 AAAA address")
		return
	}
	var recordID uint64
	if reference := chi.URLParam(request, "id"); reference != "" {
		var err error
		recordID, err = strconv.ParseUint(reference, 10, 64)
		if err != nil || recordID == 0 || body.Revision == 0 {
			writeAPIError(writer, http.StatusBadRequest, "DNS_RECORD_INVALID: record ID and expected revision are required")
			return
		}
	}
	record, err := server.networkConfig.PutRecord(request.Context(), networkconfig.Record{
		ID: recordID, Name: name, Type: kind, Value: address.String(),
	}, body.Revision, networkWriter(principal), domain)
	if err != nil {
		server.writeDNSRecordError(writer, err)
		return
	}
	server.notifyWatchers()
	status := http.StatusOK
	if recordID == 0 {
		status = http.StatusCreated
	}
	writeJSON(writer, status, record)
}

func (server *Server) handleAPIV2DeleteDNSRecord(writer http.ResponseWriter, request *http.Request) {
	server.deleteDNSRecord(writer, request, false)
}

func (server *Server) deleteDNSRecord(writer http.ResponseWriter, request *http.Request, legacy bool) {
	principal, ok := server.requireNetworkWriter(writer, request)
	if !ok {
		return
	}
	recordID, err := strconv.ParseUint(chi.URLParam(request, "id"), 10, 64)
	if err != nil || recordID == 0 {
		writeAPIError(writer, http.StatusBadRequest, "DNS_RECORD_INVALID: invalid record ID")
		return
	}
	var revision uint64
	if !legacy {
		revision, err = strconv.ParseUint(request.Header.Get("If-Match"), 10, 64)
		if err != nil || revision == 0 {
			writeAPIError(writer, http.StatusBadRequest, "DNS_RECORD_INVALID: If-Match revision is required")
			return
		}
	}
	if err := server.networkConfig.DeleteRecord(request.Context(), recordID, revision, networkWriter(principal)); err != nil {
		server.writeDNSRecordError(writer, err)
		return
	}
	server.notifyWatchers()
	if legacy {
		writeJSON(writer, http.StatusOK, map[string]any{"deleted": recordID})
	} else {
		writer.WriteHeader(http.StatusNoContent)
	}
}

func (server *Server) writeDNSRecordError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, networkconfig.ErrRecordProtected):
		writeAPIError(writer, http.StatusForbidden, "DNS_RECORD_PROTECTED: device and certificate records cannot be edited here")
	case errors.Is(err, networkconfig.ErrRecordLimit):
		writeAPIError(writer, http.StatusForbidden, "DNS_RECORD_LIMIT_REACHED: this network has reached its DNS record limit")
	default:
		server.writeNetworkError(writer, err)
	}
}
