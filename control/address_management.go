package control

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/netspace"
	"github.com/xunara-net/xunara-server/networkconfig"
	"github.com/xunara-net/xunara-server/state"
)

type addressSource struct {
	Load     func(context.Context) (networkVersion, error)
	Change   func(context.Context, netip.Prefix, *uint64, string) (networkVersion, error)
	Validate func(context.Context, netip.Prefix) error
	Reserved []netip.Prefix
}

func (server *Server) actualAllocation(ctx context.Context) (state.AddressConfiguration, error) {
	store, ok := server.store.(*state.SQLiteStore)
	if !ok {
		return state.AddressConfiguration{}, errors.New("address management requires durable state")
	}
	return store.AddressConfiguration(ctx)
}

func allocationFromVersion(current state.AddressConfiguration, version networkVersion) (state.AddressConfiguration, error) {
	current.SourceRevision = version.Revision
	if version.Prefix == "" {
		current.IPv4 = netip.MustParsePrefix("100.64.0.0/10")
		return current, nil
	}
	prefix, err := netip.ParsePrefix(version.Prefix)
	if err != nil {
		return current, err
	}
	current.IPv4 = prefix
	return current, nil
}

// refreshAddressAllocation 收敛跨库的期望/实际状态；失败保留旧实际范围与两侧预留。
func (server *Server) refreshAddressAllocation(ctx context.Context) error {
	source := server.addressSource.Load()
	if source == nil {
		return nil
	}
	_, err := server.networkConfig.SaveAllocation(ctx, nil, func(ctx context.Context, current state.AddressConfiguration) (networkconfig.AllocationUpdate, error) {
		version, err := source.Load(ctx)
		if err != nil {
			return networkconfig.AllocationUpdate{}, err
		}
		configuration, err := allocationFromVersion(current, version)
		return networkconfig.AllocationUpdate{Configuration: configuration, Actor: version.Actor}, err
	})
	return err
}

func (server *Server) addressView(request *http.Request) (map[string]any, error) {
	allocation, err := server.actualAllocation(request.Context())
	if err != nil {
		return nil, err
	}
	desired := allocation
	if source := server.addressSource.Load(); source != nil {
		version, err := source.Load(request.Context())
		if err != nil {
			return nil, err
		}
		desired, err = allocationFromVersion(allocation, version)
		if err != nil {
			return nil, err
		}
	}
	nodes, err := server.networkNodes(request.Context())
	if err != nil {
		return nil, err
	}
	outside := 0
	for _, node := range nodes {
		if node.IPv4.IsValid() && !allocation.IPv4.Contains(node.IPv4) {
			outside++
		}
	}
	reserved := make([]string, 0)
	for _, prefix := range netspace.ClientReserved() {
		reserved = append(reserved, prefix.String())
	}
	if source := server.addressSource.Load(); source != nil {
		for _, prefix := range source.Reserved {
			if prefix.Addr().Is4() {
				reserved = append(reserved, prefix.String())
			}
		}
	}
	return map[string]any{
		"ipv4_cidr": allocation.IPv4.String(), "ipv6_cidr": allocation.IPv6.String(),
		"revision": allocation.SourceRevision, "desired_revision": desired.SourceRevision,
		"desired_ipv4_cidr": desired.IPv4.String(), "pending": allocation != desired,
		"can_edit": server.Plan().AllowCustomCIDR, "can_edit_ips": true,
		"devices_total": len(nodes), "devices_outside_range": outside,
		"reserved_ranges": reserved, "csrf_token": csrfTokenFor(server.accountSessionToken(request)),
	}, nil
}

func (server *Server) handleAPIAddressConfiguration(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireScope(writer, request, identity.ScopeRead); !ok {
		return
	}
	view, err := server.addressView(request)
	if err != nil {
		server.writeAddressError(writer, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, view)
}

func (server *Server) handleAPISaveAddressConfiguration(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireNetworkWriter(writer, request)
	if !ok {
		return
	}
	if !server.Plan().AllowCustomCIDR {
		writeAPIError(writer, http.StatusForbidden, "PLAN_FEATURE_DISABLED: custom allocation ranges are not included in this plan")
		return
	}
	var body struct {
		IPv4CIDR string  `json:"ipv4_cidr"`
		Revision *uint64 `json:"revision"`
	}
	if !decodeAPIBody(writer, request, &body) {
		return
	}
	if body.Revision == nil || *body.Revision >= state.MaxAddressRevision {
		writeAPIError(writer, http.StatusBadRequest, "ADDRESS_INVALID: expected allocation revision is required")
		return
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(body.IPv4CIDR))
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "ADDRESS_INVALID: IPv4 CIDR is required")
		return
	}
	source := server.addressSource.Load()
	var reserved []netip.Prefix
	if source != nil {
		reserved = source.Reserved
	}
	prefix, err = netspace.ValidateTailnetPrefix(prefix, reserved)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "ADDRESS_INVALID: "+err.Error())
		return
	}
	if request.Method == http.MethodPost {
		current, err := server.actualAllocation(request.Context())
		if err != nil {
			server.writeAddressError(writer, err)
			return
		}
		if current.SourceRevision != *body.Revision {
			server.writeAddressError(writer, state.ErrAddressConflict)
			return
		}
		if source != nil {
			version, err := source.Load(request.Context())
			if err != nil {
				server.writeAddressError(writer, err)
				return
			}
			if version.Revision != *body.Revision {
				server.writeAddressError(writer, state.ErrAddressConflict)
				return
			}
			if err := source.Validate(request.Context(), prefix); err != nil {
				server.writeAddressError(writer, err)
				return
			}
		}
		nodes, err := server.networkNodes(request.Context())
		if err != nil {
			server.writeAddressError(writer, err)
			return
		}
		outside := 0
		for _, node := range nodes {
			if !prefix.Contains(node.IPv4) {
				outside++
			}
		}
		writeJSON(writer, http.StatusOK, map[string]any{"ipv4_cidr": prefix.String(), "devices_retained": len(nodes), "devices_outside_range": outside})
		return
	}
	server.networkMu.Lock()
	defer server.networkMu.Unlock()
	human := networkWriter(principal)
	_, err = server.networkConfig.SaveAllocation(request.Context(), &human, func(ctx context.Context, current state.AddressConfiguration) (networkconfig.AllocationUpdate, error) {
		if current.SourceRevision != *body.Revision {
			return networkconfig.AllocationUpdate{}, state.ErrAddressConflict
		}
		if source == nil {
			if current.IPv4 != prefix {
				current.IPv4 = prefix
				current.SourceRevision++
			}
			return networkconfig.AllocationUpdate{Configuration: current, Actor: human.Actor()}, nil
		}
		version, err := source.Change(ctx, prefix, body.Revision, human.Actor())
		if err != nil {
			return networkconfig.AllocationUpdate{}, err
		}
		current, err = allocationFromVersion(current, version)
		return networkconfig.AllocationUpdate{Configuration: current, Actor: human.Actor()}, err
	})
	if err != nil {
		server.writeAddressError(writer, err)
		return
	}
	server.notifyWatchers()
	view, err := server.addressView(request)
	if err != nil {
		server.writeAddressError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, view)
}

func (server *Server) handleAPIChangeNodeIPv4(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireNetworkWriter(writer, request)
	if !ok {
		return
	}
	node, found := server.lookupAPINode(chi.URLParam(request, "ref"))
	if !found {
		writeAPIError(writer, http.StatusNotFound, "machine not found")
		return
	}
	var body struct {
		IPv4         string `json:"ipv4"`
		ExpectedIPv4 string `json:"expected_ipv4"`
	}
	if !decodeAPIBody(writer, request, &body) {
		return
	}
	address, err := netip.ParseAddr(strings.TrimSpace(body.IPv4))
	expected, expectedErr := netip.ParseAddr(strings.TrimSpace(body.ExpectedIPv4))
	if err != nil || expectedErr != nil || !address.Is4() || !expected.Is4() {
		writeAPIError(writer, http.StatusBadRequest, "ADDRESS_INVALID: current and new IPv4 addresses are required")
		return
	}
	if source := server.addressSource.Load(); source != nil {
		for _, prefix := range source.Reserved {
			if prefix.Contains(address) {
				writeAPIError(writer, http.StatusBadRequest, "ADDRESS_INVALID: address is reserved by this deployment")
				return
			}
		}
	}
	updated, err := server.networkConfig.SaveNodeIPv4(request.Context(), node.ID, node.StableID, expected, address, networkWriter(principal))
	if err != nil {
		server.writeAddressError(writer, err)
		return
	}
	server.notifyNodePeers(updated)
	writeJSON(writer, http.StatusOK, server.apiMachineView(updated))
}

func (server *Server) writeAddressError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, state.ErrAddressConflict):
		writeAPIError(writer, http.StatusConflict, "ADDRESS_CHANGED: allocation or device address changed; refresh before retrying")
	case errors.Is(err, state.ErrAddressInUse), errors.Is(err, ErrNetworkConflict):
		writeAPIError(writer, http.StatusConflict, "ADDRESS_IN_USE: address or range is reserved by another device or network")
	case errors.Is(err, state.ErrAddressInvalid):
		writeAPIError(writer, http.StatusBadRequest, "ADDRESS_INVALID: "+err.Error())
	case errors.Is(err, state.ErrAddressNodeNotFound):
		writeAPIError(writer, http.StatusNotFound, "machine not found")
	case errors.Is(err, ErrNetworkNotAllowed):
		writeAPIError(writer, http.StatusForbidden, "PLAN_FEATURE_DISABLED: custom allocation ranges are not included in this plan")
	default:
		server.writeNetworkError(writer, err)
	}
}
