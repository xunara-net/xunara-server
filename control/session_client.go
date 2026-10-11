package control

import (
	"net/http"

	"github.com/xunara-net/xunara-server/identity"
)

// 沿用限流的受信代理规则；只记录首次认证来源，不用后续请求覆盖它。
func (server *Server) sessionClientInfo(request *http.Request) identity.SessionClientInfo {
	return (identity.SessionClientInfo{IP: server.clientIP(request), UserAgent: request.UserAgent()}).Normalize()
}
