package control

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

type deviceLifecycleView struct {
	Machine   apiMachine `json:"machine"`
	Revision  string     `json:"revision"`
	CSRFToken string     `json:"csrf_token"`
	CanExpire bool       `json:"can_expire"`
}

func (server *Server) deviceLifecycleView(node state.Node, principal apiPrincipal, request *http.Request) deviceLifecycleView {
	csrf, canManage, _ := server.routeManagementCapabilities(principal, request)
	return deviceLifecycleView{server.apiMachineView(node), state.NodeExpiryRevision(node), csrf, canManage}
}

func (server *Server) handleAPIDeviceLifecycle(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	principal, ok := server.requireScope(writer, request, identity.ScopeRead)
	if !ok {
		return
	}
	node, err := server.networkConfig.RouteNode(request.Context(), chi.URLParam(request, "ref"))
	if err != nil {
		server.writeDeviceLifecycleError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, server.deviceLifecycleView(node, principal, request))
}

func (server *Server) handleAPIExpireDevice(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireNetworkWriter(writer, request)
	if !ok {
		return
	}
	var body struct {
		Revision string `json:"revision"`
	}
	if !decodeAPIBody(writer, request, &body) {
		return
	}
	if len(body.Revision) != 64 || strings.Trim(body.Revision, "0123456789abcdef") != "" {
		writeAPIError(writer, http.StatusBadRequest, "DEVICE_REVISION_REQUIRED: refresh and confirm the current device first")
		return
	}
	node, err := server.networkConfig.ExpireNode(request.Context(), chi.URLParam(request, "ref"), body.Revision, networkWriter(principal))
	if err != nil {
		server.writeDeviceLifecycleError(writer, err)
		return
	}
	server.notifyWatchers()
	writeJSON(writer, http.StatusOK, server.deviceLifecycleView(node, principal, request))
}

func (server *Server) writeDeviceLifecycleError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, state.ErrRouteNodeNotFound):
		writeAPIError(writer, http.StatusNotFound, "DEVICE_NOT_FOUND: device not found")
	case errors.Is(err, state.ErrDeviceChanged):
		writeAPIError(writer, http.StatusConflict, "DEVICE_CHANGED: device identity or expiry changed; refresh and confirm again")
	default:
		server.writeNetworkError(writer, err)
	}
}

func (server *Server) handleAPIEnrollmentCapabilities(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	principal, ok := server.requireScope(writer, request, identity.ScopeRead)
	if !ok {
		return
	}
	used, err := server.networkConfig.AuthKeyUsage(request.Context())
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	csrf, canManage, _ := server.routeManagementCapabilities(principal, request)
	writeJSON(writer, http.StatusOK, map[string]any{"csrf_token": csrf, "can_manage": canManage,
		"used": used, "max_auth_keys": server.Plan().MaxAuthKeys})
}

func (server *Server) handleAPICreateEnrollmentKey(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireNetworkWriter(writer, request)
	if !ok {
		return
	}
	var body struct {
		TTLSeconds int `json:"ttl_seconds"`
	}
	if !decodeAPIBody(writer, request, &body) {
		return
	}
	if body.TTLSeconds < 900 || body.TTLSeconds > 86400 {
		writeAPIError(writer, http.StatusBadRequest, "AUTH_KEY_TTL_INVALID: enrollment keys must expire within 15 minutes to 24 hours")
		return
	}
	secret, err := state.NewPreAuthKeySecret()
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	authorization, err := server.networkConfig.CreateAuthKey(request.Context(), state.PreAuthKey{
		Key: secret, UserID: principal.UserID, Expiry: time.Now().UTC().Add(time.Duration(body.TTLSeconds) * time.Second),
	}, server.Plan().MaxAuthKeys, networkWriter(principal))
	if err != nil {
		server.writeAuthKeyManagementError(writer, err)
		return
	}
	// 只在创建响应返回一次；GET、日志及 URL 都不能携带该机器凭据。
	writeJSON(writer, http.StatusCreated, map[string]any{"id": authorization.ID, "key": authorization.Key,
		"expiry": authorization.Expiry, "reusable": false, "ephemeral": false})
}

func (server *Server) writeAuthKeyManagementError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, state.ErrAuthKeyLimit):
		writeAPIError(writer, http.StatusForbidden, MsgAuthKeyLimitReached)
	case errors.Is(err, identity.ErrUserNotFound):
		writeAPIError(writer, http.StatusBadRequest, "unknown or disabled user")
	default:
		server.writeNetworkError(writer, err)
	}
}
