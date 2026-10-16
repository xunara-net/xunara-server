package control

import (
	"net/http"
	"net/url"
	"strings"
)

// 页面只由独立前端提供；直连 Core 时明确报告部署缺失，不能恢复旧模板或自重定向。
func webUIRequired(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writeAPIError(writer, http.StatusServiceUnavailable, "WEB_UI_REQUIRED: serve xunara-web and xunara-admin through the same-origin proxy")
}

// 退役表单不能解析正文、验证凭据或修改任何状态，包括已登录的历史页面提交。
func retiredBrowserForm(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writeAPIError(writer, http.StatusGone, "BROWSER_FORM_RETIRED: reload the current web application")
}

func (server *Server) handleRetiredPreferences(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	http.Redirect(writer, request, server.consolePageURL("/settings"), http.StatusFound)
}

// 回调错误只传固定原因码，不把提供方响应、授权码或凭据转抄进浏览器 URL。
func (server *Server) respondBrowserError(writer http.ResponseWriter, request *http.Request, status int, title, message string) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	if !strings.Contains(request.Header.Get("Accept"), "text/html") {
		writeAPIError(writer, status, message)
		return
	}
	reason := "AUTH_FAILED"
	switch {
	case status == http.StatusServiceUnavailable || status >= 500:
		reason = "AUTH_UNAVAILABLE"
	case status == http.StatusTooManyRequests:
		reason = "AUTH_RATE_LIMITED"
	case title == "Sign-in expired":
		reason = "AUTH_EXPIRED"
	case title == "Sign-in already used":
		reason = "AUTH_ALREADY_USED"
	case status == http.StatusForbidden:
		reason = "AUTH_FORBIDDEN"
	}
	http.Redirect(writer, request, server.consolePageURL("/auth/error")+"?reason="+url.QueryEscape(reason), http.StatusSeeOther)
}

func (server *Server) handleNotFound(writer http.ResponseWriter, request *http.Request) {
	http.NotFound(writer, request)
}
