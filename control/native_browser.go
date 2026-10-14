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

var nativeLoginPage = pageTemplate("native-login", publicHead+`<main id="main" class="narrow"><div class="card">
<h1>登录并接入设备</h1><p>设备：{{.Hostname}}</p>
<p>请登录要接入的账户。登录后还需确认授权；当前浏览器中其他账户的登录不会自动批准设备。</p>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
<input type="hidden" name="_csrf" value="{{.FormToken}}">
<label for="login">登录名</label><input id="login" name="login" autocomplete="username" required maxlength="128">
<label for="password">密码</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<div class="actions"><button class="approve" type="submit">登录并继续</button></div>
</form></div></main>`+publicFoot)

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
		gateway.front.renderError(writer, request, http.StatusGone, "Login link expired", "Please restart device sign-in to get a new link.")
		return flow, false
	}
	return flow, true
}

func (gateway *nativeGateway) renderLogin(writer http.ResponseWriter, request *http.Request, flow nativeFlow, message string) {
	var registration tailcfg.RegisterRequest
	if err := json.Unmarshal([]byte(flow.Registration), &registration); err != nil {
		gateway.front.renderError(writer, request, http.StatusServiceUnavailable, "Sign-in unavailable", "Please restart device sign-in.")
		return
	}
	hostname := "未命名设备"
	if registration.Hostinfo != nil && registration.Hostinfo.Hostname != "" {
		hostname = registration.Hostinfo.Hostname
	}
	gateway.front.renderPage(writer, request, nativeLoginPage, map[string]any{
		"Title": "登录并接入设备", "Hostname": hostname, "Error": message,
		"Action":    gateway.origin + "/device/" + flow.ID + "/login",
		"FormToken": gateway.front.newFormToken("native-login:" + flow.ID),
	})
}

func (gateway *nativeGateway) handleFlow(writer http.ResponseWriter, request *http.Request) {
	flow, ok := gateway.browserFlow(writer, request)
	if !ok {
		return
	}
	if flow.Organization == "" {
		gateway.renderLogin(writer, request, flow, "")
		return
	}
	// 已选择的账户只恢复自己的审批，不检查入口站的管理员 Cookie。
	location, err := gateway.authorizationURL(request.Context(), flow)
	if err != nil {
		gateway.front.renderError(writer, request, http.StatusConflict, "Sign-in unavailable", "Restart device sign-in and use your account.")
		return
	}
	http.Redirect(writer, request, location, http.StatusSeeOther)
}

func (gateway *nativeGateway) handleLogin(writer http.ResponseWriter, request *http.Request) {
	flow, ok := gateway.browserFlow(writer, request)
	if !ok {
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 16<<10)
	if request.ParseForm() != nil || !gateway.front.checkFormToken("native-login:"+flow.ID, request.PostFormValue("_csrf"), time.Now()) {
		gateway.front.renderError(writer, request, http.StatusForbidden, "Request rejected", "Reload this page and try again.")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
	defer cancel()
	org, result, err := gateway.router.signInAccount(ctx, request, request.PostFormValue("login"), request.PostFormValue("password"))
	if err != nil {
		status, message := http.StatusUnauthorized, "登录名或密码错误。"
		if errors.Is(err, errPasswordRateLimited) {
			status, message = http.StatusTooManyRequests, "尝试次数过多，请稍后再试。"
		} else if !errors.Is(err, errPasswordRejected) {
			status, message = http.StatusServiceUnavailable, "登录暂不可用，请稍后重试。"
		}
		writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		writer.WriteHeader(status)
		gateway.renderLogin(writer, request, flow, message)
		return
	}
	if !org.managed && org.site.ID != gateway.frontID {
		_ = org.site.Server.identity.RevokeSession(result.session.ID, "shared device entry unavailable")
		gateway.front.renderError(writer, request, http.StatusUnauthorized, "Sign-in failed", "Use this account's own device sign-in address.")
		return
	}
	flow, err = gateway.registry.selectNativeFlow(ctx, flow.ID, org.site.ID, org.site.Server.noiseKey.Public().String())
	if err != nil {
		_ = org.site.Server.identity.RevokeSession(result.session.ID, "device scope rejected")
		gateway.front.renderError(writer, request, http.StatusConflict, "Request rejected", "This device sign-in already belongs to another account. Restart device sign-in.")
		return
	}
	location, err := gateway.authorizationURL(ctx, flow)
	if err != nil {
		_ = org.site.Server.identity.RevokeSession(result.session.ID, "device enrollment unavailable")
		gateway.front.renderError(writer, request, http.StatusServiceUnavailable, "Sign-in unavailable", "Please restart device sign-in.")
		return
	}
	response := gateway.router.accountSessionWriter(writer, org)
	org.site.Server.setSessionCookie(response, result.token, result.session.ExpiresAt)
	http.Redirect(response, request, location, http.StatusSeeOther)
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
