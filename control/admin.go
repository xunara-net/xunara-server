package control

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/xunara-net/xunara-server/identity"
	"tailscale.com/tailcfg"
)

// 旧后台不再渲染页面或接收表单；独立后台通过平台 JSON API 管理持久会话。
func (router *Router) mountAdmin(mux chi.Router) {
	mux.HandleFunc("/admin", retiredAdminPage)
	mux.HandleFunc("/admin/*", retiredAdminPage)
}

func retiredAdminPage(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		retiredBrowserForm(writer, request)
		return
	}
	webUIRequired(writer, request)
}

// auditTenant writes an audit event into one tenant's log.
func (r *Router) auditTenant(orgID, actor, action, target, detail string) {
	server := r.serverFor(orgID)
	if server == nil {
		return
	}
	if err := server.identity.AppendAudit(&identity.AuditEvent{
		Actor: actor, Action: action, Target: target, Detail: detail,
	}); err != nil {
		r.log.Error("appending platform audit event", "organization", orgID, "err", err)
	}
}

// serverFor returns the control plane of one tenant, or nil.
func (r *Router) serverFor(orgID string) *Server {
	if org := r.orgByID(orgID); org != nil {
		return org.site.Server
	}
	return nil
}

func tailcfgUserID(id uint64) tailcfg.UserID { return tailcfg.UserID(id) }
