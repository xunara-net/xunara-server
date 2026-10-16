package control

import (
	"net/http"
	"strings"
)

// 旧控制台只接收书签迁移，不再渲染页面或处理表单；客户端授权页不属于此入口。
var retiredConsolePages = map[string]string{
	"":           "/dashboard",
	"machines":   "/devices",
	"devices":    "/devices",
	"exit-nodes": "/routes",
	"relays":     "/relays",
	"users":      "/members",
	"dns":        "/dns",
	"derp":       "/relays",
	"auth-keys":  "/api",
	"agents":     "/api",
	"api-keys":   "/api",
	"shares":     "/shares",
	"policy":     "/permissions",
	"security":   "/security",
	"passkeys":   "/security",
	"ssh-check":  "/security#ssh-check",
	"audit":      "/audit",
	"plan":       "/plan",
	"prefs":      "/settings",
}

func (server *Server) handleRetiredConsole(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		http.Error(writer, "CONSOLE_RETIRED: use the Web console and versioned API", http.StatusGone)
		return
	}
	page := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/console"), "/")
	target, known := retiredConsolePages[strings.TrimPrefix(page, "/")]
	if !known || request.URL.RawPath != "" {
		http.NotFound(writer, request)
		return
	}
	if _, _, ok := server.requireSession(writer, request, target); !ok {
		return
	}
	// 目标只来自固定映射和部署配置，旧查询参数不能携带凭据或决定跳转地址。
	http.Redirect(writer, request, server.consolePageURL(target), http.StatusFound)
}

func (server *Server) consolePageURL(page string) string {
	if server.cfg.ConsoleURL != "" || server.nativeEndpoints.Load() != nil {
		return server.consoleURL() + page
	}
	return page
}
