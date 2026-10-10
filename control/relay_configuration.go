package control

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func (request apiRelayConfigRequest) update() state.RelayConfigUpdate {
	return state.RelayConfigUpdate{DesiredState: request.DesiredState, BandwidthLimit: request.BandwidthLimit, RegionName: request.RegionName, ConfigVersion: *request.ConfigVersion}
}

func validRelayConfigRequest(writer http.ResponseWriter, request apiRelayConfigRequest) bool {
	if request.ConfigVersion == nil {
		writeAPIError(writer, http.StatusPreconditionRequired, "RELAY_VERSION_REQUIRED: load the current configuration before editing")
		return false
	}
	if *request.ConfigVersion == 0 || *request.ConfigVersion > 1<<53-1 ||
		(request.RestoreFrom != nil && (*request.RestoreFrom == 0 || *request.RestoreFrom > 1<<53-1 || request.DesiredState != "" || request.BandwidthLimit != nil || request.RegionName != nil)) ||
		(request.RestoreFrom == nil && request.DesiredState == "" && request.BandwidthLimit == nil && request.RegionName == nil) {
		writeAPIError(writer, http.StatusBadRequest, "RELAY_CONFIG_INVALID: provide a valid version and either configuration fields or restore_from")
		return false
	}
	return true
}

// relayExpectedVersion 不接受通配符，避免删除按钮绕过另一个窗口刚保存的配置。
func relayExpectedVersion(writer http.ResponseWriter, request *http.Request) (uint64, bool) {
	header := request.Header.Get("If-Match")
	if header == "" {
		writeAPIError(writer, http.StatusPreconditionRequired, "RELAY_VERSION_REQUIRED: deletion requires If-Match with the current configuration version")
		return 0, false
	}
	expected, err := strconv.ParseUint(strings.Trim(header, `"`), 10, 64)
	if err != nil || expected == 0 || expected > 1<<53-1 {
		writeAPIError(writer, http.StatusBadRequest, "RELAY_CONFIG_INVALID: invalid If-Match version")
		return 0, false
	}
	return expected, true
}

func (server *Server) lookupManagedRelay(ctx context.Context, id string) (state.Relay, error) {
	store, ok := server.store.(*state.SQLiteStore)
	if !ok {
		return state.Relay{}, errors.New("relay configuration requires a durable store")
	}
	return store.LookupRelay(ctx, id)
}

func (server *Server) writeRelayManagementError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, state.ErrRelayNotFound):
		writeAPIError(writer, http.StatusNotFound, "relay not found")
	case errors.Is(err, state.ErrRelayConfigConflict):
		writeAPIError(writer, http.StatusConflict, "RELAY_CONFIG_CHANGED: another administrator has changed this relay; reload before saving")
	case errors.Is(err, state.ErrRelayConfigInvalid):
		writeAPIError(writer, http.StatusBadRequest, "RELAY_CONFIG_INVALID: invalid desired state, bandwidth limit or region name")
	case errors.Is(err, state.ErrRelayConfigRevoked):
		writeAPIError(writer, http.StatusForbidden, "RELAY_REVOKED: a revoked service identity cannot be reactivated; enroll a new relay")
	default:
		server.writeNetworkError(writer, err)
	}
}

func (server *Server) writeRelayHistory(writer http.ResponseWriter, request *http.Request, id string) {
	if server.networkConfig == nil {
		server.writeNetworkError(writer, errors.New("relay configuration requires a durable store"))
		return
	}
	if _, err := server.lookupManagedRelay(request.Context(), id); err != nil {
		server.writeRelayManagementError(writer, err)
		return
	}
	items, err := server.networkConfig.RelayHistory(request.Context(), id)
	if err != nil {
		server.writeRelayManagementError(writer, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, map[string]any{"items": items})
}

func (server *Server) handleAPIV2RelayHistory(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireScope(writer, request, identity.ScopeRead); !ok {
		return
	}
	server.writeRelayHistory(writer, request, chi.URLParam(request, "id"))
}
