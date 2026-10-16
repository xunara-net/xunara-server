package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// 浏览器仅交换 JSON；账户选择仍验证密码、持久限流与精确机器/节点绑定。
func (gateway *nativeGateway) browserFlow(writer http.ResponseWriter, request *http.Request) (nativeFlow, bool) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	origin, _ := url.Parse(gateway.origin)
	if !strings.EqualFold(request.Host, origin.Host) {
		http.NotFound(writer, request)
		return nativeFlow{}, false
	}
	flow, err := gateway.registry.nativeFlow(request.Context(), chi.URLParam(request, "flowID"))
	if err != nil {
		if errors.Is(err, errNativeFlow) {
			writeAPIError(writer, http.StatusGone, "AUTH_EXPIRED: restart device sign-in to get a new link")
		} else {
			writeAPIError(writer, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE: device sign-in could not be checked")
		}
		return nativeFlow{}, false
	}
	return flow, true
}

func (gateway *nativeGateway) handleFlow(writer http.ResponseWriter, request *http.Request) {
	flow, ok := gateway.browserFlow(writer, request)
	if !ok {
		return
	}
	if flow.Organization != "" {
		next, err := gateway.authorizationPath(request.Context(), flow)
		if err != nil {
			writeAPIError(writer, http.StatusConflict, "DEVICE_SCOPE_CHANGED: restart device sign-in")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{"next_path": next})
		return
	}
	var registration tailcfg.RegisterRequest
	if json.Unmarshal([]byte(flow.Registration), &registration) != nil {
		writeAPIError(writer, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE: device sign-in could not be checked")
		return
	}
	hostname := ""
	if registration.Hostinfo != nil {
		hostname = registration.Hostinfo.Hostname
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"hostname": hostname, "csrf_token": gateway.front.newFormToken("native-login:" + flow.ID),
	})
}

func (gateway *nativeGateway) handleLogin(writer http.ResponseWriter, request *http.Request) {
	flow, ok := gateway.browserFlow(writer, request)
	if !ok {
		return
	}
	var body struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if !decodeAccountBody(writer, request, &body) {
		return
	}
	if !gateway.front.checkFormToken("native-login:"+flow.ID, request.Header.Get("X-CSRF-Token"), time.Now()) {
		writeAPIError(writer, http.StatusForbidden, "CSRF_INVALID: reload this page and try again")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	org, result, err := gateway.router.signInAccount(ctx, request, body.Login, body.Password)
	if err != nil {
		status, message := http.StatusUnauthorized, "LOGIN_REJECTED: incorrect login name or password"
		if errors.Is(err, errPasswordRateLimited) {
			status, message = http.StatusTooManyRequests, "AUTH_RATE_LIMITED: try again later"
			writer.Header().Set("Retry-After", "60")
		} else if !errors.Is(err, errPasswordRejected) {
			status, message = http.StatusServiceUnavailable, "AUTH_UNAVAILABLE: try again later"
			writer.Header().Set("Retry-After", "5")
		}
		writeAPIError(writer, status, message)
		return
	}
	if !org.managed && org.site.ID != gateway.frontID {
		_ = org.site.Server.identity.RevokeSession(result.session.ID, "shared device entry unavailable")
		writeAPIError(writer, http.StatusUnauthorized, "LOGIN_REJECTED: use this account's own device entry")
		return
	}
	flow, err = gateway.registry.selectNativeFlow(ctx, flow.ID, org.site.ID, org.site.Server.noiseKey.Public().String())
	if err != nil {
		_ = org.site.Server.identity.RevokeSession(result.session.ID, "device scope rejected")
		writeAPIError(writer, http.StatusConflict, "DEVICE_SCOPE_CHANGED: this sign-in already belongs to another account; restart device sign-in")
		return
	}
	next, err := gateway.authorizationPath(ctx, flow)
	if err != nil {
		_ = org.site.Server.identity.RevokeSession(result.session.ID, "device enrollment unavailable")
		writeAPIError(writer, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE: restart device sign-in")
		return
	}
	response := gateway.router.accountSessionWriter(writer, org)
	org.site.Server.setSessionCookie(response, result.token, result.session.ExpiresAt)
	writeJSON(response, http.StatusOK, map[string]any{"next_path": next})
}

// 跳转只使用受信共享入口生成的相对路径，禁止配置错误变成开放重定向。
func (gateway *nativeGateway) authorizationPath(ctx context.Context, flow nativeFlow) (string, error) {
	location, err := gateway.authorizationURL(ctx, flow)
	if err != nil {
		return "", err
	}
	target, err := url.Parse(location)
	origin, _ := url.Parse(gateway.origin)
	if err != nil || target.Scheme != origin.Scheme || target.Host != origin.Host || target.User != nil ||
		target.RawQuery != "" || target.Fragment != "" || safeReturnTo(target.EscapedPath()) != target.EscapedPath() {
		return "", errNativeScope
	}
	return target.EscapedPath(), nil
}

func (gateway *nativeGateway) authorizationURL(ctx context.Context, flow nativeFlow) (string, error) {
	var machine key.MachinePublic
	var node key.NodePublic
	if machine.UnmarshalText([]byte(flow.MachineKey)) != nil || node.UnmarshalText([]byte(flow.NodeKey)) != nil {
		return "", errNativeFlow
	}
	org, found, err := gateway.boundOrg(ctx, machine, node)
	if err != nil || !found || org.site.ID != flow.Organization || org.site.Server.noiseKey.Public().String() != flow.NoiseKey {
		return "", errNativeScope
	}
	server := org.site.Server
	actual, err := server.networkConfig.NodeByKey(ctx, node)
	if err == nil {
		if actual.MachineKey != machine {
			return "", errNativeScope
		}
		return server.consoleURL() + "/devices", nil
	}
	if !errors.Is(err, state.ErrRouteNodeNotFound) {
		return "", err
	}
	authorization, err := server.identity.LookupDeviceAuthorizationByKeys(ctx, flow.MachineKey, flow.NodeKey)
	if err == nil && !authorization.Expired(time.Now()) {
		return server.authURL(authorization.ID), nil
	}
	if err != nil && !errors.Is(err, identity.ErrDeviceNotFound) {
		return "", err
	}
	var registration tailcfg.RegisterRequest
	if json.Unmarshal([]byte(flow.Registration), &registration) != nil || registration.NodeKey != node || registration.Auth != nil {
		return "", errNativeFlow
	}
	registration.Followup = ""
	response, err := server.handleRegister(ctx, registration, machine)
	if err != nil || response == nil || response.AuthURL == "" {
		return "", errNativeFlow
	}
	return response.AuthURL, nil
}
