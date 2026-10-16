package control

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xunara-net/xunara-server/identity"
)

// 人类浏览器授权与机器注册协议分开：只读取持久授权，复用既有审批事务。
func (server *Server) browserAPIRouter() http.Handler {
	router := chi.NewRouter()
	router.Get("/device-authorizations/{id}", server.handleBrowserDevice)
	router.Post("/device-authorizations/{id}/approve", server.handleBrowserDeviceApprove)
	router.Post("/device-authorizations/{id}/deny", server.handleBrowserDeviceDeny)
	router.Get("/ssh-checks/{id}", server.handleBrowserSSHCheck)
	router.Post("/ssh-checks/{id}/approve", server.handleBrowserSSHApprove)
	router.Post("/ssh-checks/{id}/deny", server.handleBrowserSSHDeny)
	return router
}

func (server *Server) browserPrincipal(writer http.ResponseWriter, request *http.Request, write bool) (apiPrincipal, bool) {
	principal, ok := server.requireAccountSession(writer, request, write)
	if !ok {
		return apiPrincipal{}, false
	}
	if write && !principal.Role.CanWrite() {
		writeAPIError(writer, http.StatusForbidden, "APPROVAL_FORBIDDEN: a read-only account cannot authorize connections")
		return apiPrincipal{}, false
	}
	return principal, true
}

func (server *Server) handleBrowserDevice(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.browserPrincipal(writer, request, false)
	if !ok {
		return
	}
	authorization, err := server.identity.LookupDeviceAuthorization(request.Context(), chi.URLParam(request, "id"))
	if err != nil {
		server.browserLookupError(writer, err, identity.ErrDeviceNotFound)
		return
	}
	state := string(authorization.State)
	if authorization.State == identity.DevicePending && authorization.Expired(time.Now()) {
		state = "expired"
	}
	metadata := decodeDeviceMetadata(authorization.ClientMetadata)
	tags := metadata.requestedTags()
	if tags == nil {
		tags = []string{}
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"id": authorization.ID, "state": state, "hostname": metadata.Hostname, "os": metadata.OS,
		"created_at": authorization.CreatedAt, "expires_at": authorization.ExpiresAt,
		"ephemeral": metadata.Ephemeral, "requested_tags": tags,
		"login_name":   server.UserProfile(principal.UserID).LoginName,
		"organization": server.Organization().ID, "can_write": principal.Role.CanWrite(),
		"csrf_token": csrfTokenFor(server.accountSessionToken(request)),
	})
}

func (server *Server) handleBrowserDeviceApprove(writer http.ResponseWriter, request *http.Request) {
	server.browserDecideDevice(writer, request, true)
}

func (server *Server) handleBrowserDeviceDeny(writer http.ResponseWriter, request *http.Request) {
	server.browserDecideDevice(writer, request, false)
}

func (server *Server) browserDecideDevice(writer http.ResponseWriter, request *http.Request, approve bool) {
	principal, ok := server.browserPrincipal(writer, request, true)
	if !ok {
		return
	}
	var body struct{}
	if !decodeAccountBody(writer, request, &body) {
		return
	}
	server.apiDecideDevice(writer, request, principal, approve)
}

func (server *Server) handleBrowserSSHCheck(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.browserPrincipal(writer, request, false)
	if !ok {
		return
	}
	session, err := server.identity.LookupSSHCheckSession(request.Context(), chi.URLParam(request, "id"))
	if err != nil {
		server.browserLookupError(writer, err, identity.ErrSSHCheckNotFound)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"session":    server.sshCheckAdminView(session, time.Now()),
		"login_name": server.UserProfile(principal.UserID).LoginName, "organization": server.Organization().ID,
		"can_write": principal.Role.CanWrite(), "csrf_token": csrfTokenFor(server.accountSessionToken(request)),
	})
}

func (server *Server) handleBrowserSSHApprove(writer http.ResponseWriter, request *http.Request) {
	server.browserDecideSSH(writer, request, identity.SSHCheckAccepted)
}

func (server *Server) handleBrowserSSHDeny(writer http.ResponseWriter, request *http.Request) {
	server.browserDecideSSH(writer, request, identity.SSHCheckRejected)
}

func (server *Server) browserDecideSSH(writer http.ResponseWriter, request *http.Request, verdict identity.SSHCheckVerdict) {
	principal, ok := server.browserPrincipal(writer, request, true)
	if !ok {
		return
	}
	var body struct{}
	if !decodeAccountBody(writer, request, &body) {
		return
	}
	id := chi.URLParam(request, "id")
	session, err := server.identity.DecideSSHCheckSession(id, verdict, principal.UserID, time.Now().UTC())
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrSSHCheckNotFound):
			writeAPIError(writer, http.StatusNotFound, "AUTH_NOT_FOUND: this authorization no longer exists")
		case errors.Is(err, identity.ErrSSHCheckExpired):
			writeAPIError(writer, http.StatusGone, "AUTH_EXPIRED: restart the SSH connection")
		case errors.Is(err, identity.ErrSSHCheckDecided):
			writeAPIError(writer, http.StatusConflict, "AUTH_ALREADY_USED: refresh to read the recorded decision")
		default:
			writeAPIError(writer, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE: refresh to check the recorded outcome before trying again")
		}
		return
	}
	action := identity.AuditSSHCheckApproved
	if verdict == identity.SSHCheckRejected {
		action = identity.AuditSSHCheckDenied
	}
	server.audit(principal.actor(), action, "sshcheck:"+id,
		fmt.Sprintf("src_node=%d dst_node=%d local_user=%s", session.SrcNodeID, session.DstNodeID, session.LocalUser))
	writeJSON(writer, http.StatusOK, map[string]any{"id": id, "state": sshCheckStateOf(session, time.Now())})
}

func (server *Server) browserLookupError(writer http.ResponseWriter, err, missing error) {
	if errors.Is(err, missing) {
		writeAPIError(writer, http.StatusNotFound, "AUTH_NOT_FOUND: this authorization does not exist in this network")
		return
	}
	writer.Header().Set("Retry-After", "5")
	writeAPIError(writer, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE: authorization could not be checked")
}
