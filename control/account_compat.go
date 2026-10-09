package control

import (
	"fmt"
	"net/http"
	"time"
)

// deprecatedAccountEndpoint 只公告旧地址弃用，不恢复旧业务实现。
// 先告知调用者迁移，正式删除另行公告；客户端所需的 HTML 授权入口不在此范围。
func deprecatedAccountEndpoint(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		deprecatedAt := time.Date(2026, time.October, 9, 0, 0, 0, 0, time.UTC)
		writer.Header().Set("Deprecation", fmt.Sprintf("@%d", deprecatedAt.Unix()))
		writer.Header().Add("Link", `<https://github.com/xunara-net/xunara-server/blob/main/README.md#account-api-migration>; rel="deprecation"`)
		next.ServeHTTP(writer, request)
	})
}

// 旧表单仅适配 CSRF 的传输位置和跳转，删除仍使用统一账户事务。
func (server *Server) handleLegacyDeletePasskey(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, false)
	if !ok {
		return
	}
	if !checkCSRF(request, server.accountSessionToken(request)) {
		writeAPIError(writer, http.StatusForbidden, "CSRF_INVALID: reload the account page and try again")
		return
	}
	if server.deleteAccountPasskey(writer, request, principal) {
		http.Redirect(writer, request, "/security", http.StatusFound)
	}
}
