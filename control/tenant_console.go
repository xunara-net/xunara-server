package control

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
)

func normalizeConsoleBase(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return "", errors.New("invalid console origin")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func tenantConsolePrefix(orgID string) string { return "/t/" + orgID }

func (server *Server) consoleURL() string {
	if endpoints := server.nativeEndpoints.Load(); endpoints != nil && endpoints.ConsoleURL != "" {
		return endpoints.ConsoleURL
	}
	if server.cfg.ConsoleURL != "" {
		return strings.TrimRight(server.cfg.ConsoleURL, "/")
	}
	return server.cfg.ServerURL
}

func tenantCookieName(name, orgID string) string { return name + "_tenant_" + orgID }

func consoleCookie(name string) bool {
	return name == sessionCookieName || name == authCookieName || name == passkeyCookieName
}

// tenantConsoleWriter 只改浏览器响应的路由和 Cookie；租户内部仍使用原认证服务。
type tenantConsoleWriter struct {
	http.ResponseWriter
	orgID    string
	secure   bool
	prepared bool
}

func (writer *tenantConsoleWriter) prepare() {
	if writer.prepared {
		return
	}
	writer.prepared = true
	headers := writer.Header()
	cookies := (&http.Response{Header: headers}).Cookies()
	headers.Del("Set-Cookie")
	for _, cookie := range cookies {
		if consoleCookie(cookie.Name) {
			cookie.Name = tenantCookieName(cookie.Name, writer.orgID)
			cookie.Domain = ""
			cookie.Path = tenantConsolePrefix(writer.orgID) + "/"
			cookie.Secure = writer.secure
		}
		http.SetCookie(writer.ResponseWriter, cookie)
	}
	if location := headers.Get("Location"); strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//") {
		headers.Set("Location", tenantConsolePrefix(writer.orgID)+location)
	}
}

func (writer *tenantConsoleWriter) WriteHeader(status int) {
	writer.prepare()
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *tenantConsoleWriter) Write(body []byte) (int, error) {
	writer.prepare()
	return writer.ResponseWriter.Write(body)
}

// handleTenantConsole 的组织 ID 仅决定路由。每次操作仍需本租户自己的会话和 CSRF。
// TS2021/Noise、全局后台及中继不能经此路径访问；共享原生入口有独立精确键路由。
func (router *Router) handleTenantConsole(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	config := router.selfService.Load()
	if config == nil || config.cfg.ConsoleURL == "" {
		http.NotFound(writer, request)
		return
	}
	base, err := url.Parse(config.cfg.ConsoleURL)
	if err != nil || !strings.EqualFold(request.Host, base.Host) {
		http.NotFound(writer, request)
		return
	}
	orgID := chi.URLParam(request, "orgID")
	org := router.orgByID(orgID)
	if !managedOrgIDPattern.MatchString(orgID) || org == nil || !org.managed || request.URL.RawPath != "" {
		http.NotFound(writer, request)
		return
	}
	prefix := tenantConsolePrefix(orgID)
	path := strings.TrimPrefix(request.URL.Path, prefix)
	devicePage := router.nativeGateway != nil && (strings.HasPrefix(path, "/register/") || strings.HasPrefix(path, "/ssh/check/"))
	if !devicePage && !strings.HasPrefix(path, "/api/v1/") && !strings.HasPrefix(path, "/api/v2/") && !strings.HasPrefix(path, "/oidc/callback/") && !strings.HasPrefix(path, "/oauth2/callback/") {
		http.NotFound(writer, request)
		return
	}
	copy := request.Clone(context.WithValue(request.Context(), chi.RouteCtxKey, chi.NewRouteContext()))
	copy.URL.Path = path
	copy.RequestURI = copy.URL.RequestURI()
	copy.Header.Del("Cookie")
	for _, cookie := range request.Cookies() {
		for _, name := range []string{sessionCookieName, authCookieName, passkeyCookieName} {
			if cookie.Name == tenantCookieName(name, orgID) {
				copy.AddCookie(&http.Cookie{Name: name, Value: cookie.Value})
			}
		}
	}
	org.handler.ServeHTTP(&tenantConsoleWriter{ResponseWriter: writer, orgID: orgID, secure: base.Scheme == "https"}, copy)
}
