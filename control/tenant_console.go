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
		if target, err := url.Parse(location); err == nil && target.Path == "/login" {
			headers.Set("Location", canonicalAccountLogin(target.Query(), tenantConsolePrefix(writer.orgID)))
		} else {
			headers.Set("Location", tenantConsolePrefix(writer.orgID)+location)
		}
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
	if !managedOrgIDPattern.MatchString(orgID) || request.URL.RawPath != "" {
		http.NotFound(writer, request)
		return
	}
	prefix := tenantConsolePrefix(orgID)
	path := strings.TrimPrefix(request.URL.Path, prefix)
	// 旧登录书签不能锁定网络，且不能通过响应判断这个租户是否仍然存在。
	if path == "/login" || path == "/login/" {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		http.Redirect(writer, request, canonicalAccountLogin(request.URL.Query(), prefix), http.StatusFound)
		return
	}
	org := router.orgByID(orgID)
	if org == nil || !org.managed {
		http.NotFound(writer, request)
		return
	}
	devicePage := router.nativeGateway != nil && (strings.HasPrefix(path, "/register/") || strings.HasPrefix(path, "/ssh/check/"))
	retiredConsole := path == "/console" || strings.HasPrefix(path, "/console/")
	if !devicePage && !retiredConsole && path != "/ui/prefs" && !strings.HasPrefix(path, "/api/v1/") && !strings.HasPrefix(path, "/api/v2/") && !strings.HasPrefix(path, "/oidc/callback/") && !strings.HasPrefix(path, "/oauth2/callback/") {
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

func canonicalAccountLogin(query url.Values, prefix string) string {
	allowed := make(url.Values)
	if targets := query["return_to"]; len(targets) == 1 {
		target := safeReturnTo(targets[0])
		if target != "/" && target != "/dashboard" && target != "/console" && target != "/console/" && target != "/login" && target != "/login/" {
			if !strings.HasPrefix(target, "/t/") {
				target = prefix + target
			}
			allowed.Set("return_to", target)
		}
	}
	for _, name := range []string{"signed_out", "password_changed"} {
		values := query[name]
		if len(values) != 1 {
			continue
		}
		if name == "signed_out" && (values[0] == "current" || values[0] == "all") || name == "password_changed" && values[0] == "1" {
			allowed.Set(name, values[0])
		}
	}
	if len(allowed) == 0 {
		return "/login"
	}
	return "/login?" + allowed.Encode()
}
