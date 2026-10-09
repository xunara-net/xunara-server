package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/xunara-net/xunara-server/identity"
)

const passkeyNameLimit = 64

// accountPasskeyView 不暴露 credential ID、公钥或认证器状态，避免把凭据表直接序列化。
type accountPasskeyView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

func accountPasskey(passkey identity.Passkey) accountPasskeyView {
	view := accountPasskeyView{ID: passkey.ID, Name: passkey.Name, CreatedAt: passkey.CreatedAt}
	if view.Name == "" {
		view.Name = "通行密钥"
	}
	if !passkey.LastUsedAt.IsZero() {
		view.LastUsedAt = &passkey.LastUsedAt
	}
	return view
}

func (server *Server) handleAPIAccountPasskeys(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, false)
	if !ok {
		return
	}
	passkeys, err := server.identity.ListAccountPasskeys(request.Context(), principal.UserID)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "PASSKEY_LIST_FAILED: could not read account passkeys")
		return
	}
	views := make([]accountPasskeyView, 0, len(passkeys))
	for _, passkey := range passkeys {
		views = append(views, accountPasskey(passkey))
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"passkeys": views, "enabled": server.passkeys != nil,
		"csrf_token": csrfTokenFor(server.accountSessionToken(request)),
	})
}

func (server *Server) handleAPIAccountPasskeyBegin(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, true)
	if !ok || !server.requirePasskeys(writer) {
		return
	}
	user, ok := server.identity.GetUser(principal.UserID)
	if !ok {
		writeAPIError(writer, http.StatusUnauthorized, "SESSION_CHANGED: account no longer exists")
		return
	}
	options, ceremonyID, browserSecret, err := server.passkeys.BeginRegistration(user)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "PASSKEY_START_FAILED: could not start passkey registration")
		return
	}
	server.setPasskeyCookie(writer, ceremonyID, browserSecret, time.Now().Add(identity.DefaultPasskeyCeremonyTTL))
	writeJSON(writer, http.StatusOK, map[string]any{"options": options})
}

func (server *Server) handleAPIAccountPasskeyFinish(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, true)
	if !ok || !server.requirePasskeys(writer) {
		return
	}
	var body struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if !decodeAccountBodyLimit(writer, request, &body, 64<<10) {
		return
	}
	name, err := passkeyDisplayName(body.Name)
	if err != nil || len(body.Credential) == 0 || string(body.Credential) == "null" {
		writeAPIError(writer, http.StatusBadRequest, "PASSKEY_INVALID: supply a credential and a name of at most 64 characters")
		return
	}
	ceremonyID, browserSecret, ok := passkeyCookieValue(request)
	if !ok {
		writeAPIError(writer, http.StatusBadRequest, "PASSKEY_REGISTRATION_FAILED: start registration again in the same browser")
		return
	}
	user, ok := server.identity.GetUser(principal.UserID)
	if !ok {
		writeAPIError(writer, http.StatusUnauthorized, "SESSION_CHANGED: account no longer exists")
		return
	}
	// 只将 credential 交给上游解析；外层账户字段不参与 WebAuthn 签名验证。
	finish := request.Clone(request.Context())
	finish.Body = io.NopCloser(bytes.NewReader(body.Credential))
	finish.ContentLength = int64(len(body.Credential))
	passkey, err := server.passkeys.FinishRegistration(ceremonyID, browserSecret, user, principal.Session.ID, name, finish)
	server.clearPasskeyCookie(writer)
	if err != nil {
		var verificationError *protocol.Error
		switch {
		case errors.Is(err, identity.ErrSessionRevoked):
			writeAPIError(writer, http.StatusUnauthorized, "SESSION_CHANGED: initiating session is no longer active")
		case errors.As(err, &verificationError), errors.Is(err, identity.ErrPasskeyCeremonyNotFound),
			errors.Is(err, identity.ErrPasskeyCeremonyConsumed), errors.Is(err, identity.ErrPasskeyCeremonyExpired):
			writeAPIError(writer, http.StatusBadRequest, "PASSKEY_REGISTRATION_FAILED: verification failed; start registration again")
		default:
			writeAPIError(writer, http.StatusInternalServerError, "PASSKEY_SAVE_FAILED: could not save passkey; start registration again")
		}
		return
	}
	// 兼容期只保留旧 JSON 形状，不保留旧注册或审计实现。
	if strings.HasPrefix(request.URL.Path, "/console/") {
		writeJSON(writer, http.StatusOK, map[string]any{"passkey": map[string]any{
			"ID": passkey.ID, "Name": passkey.Name, "Created": passkey.CreatedAt, "LastUsed": passkey.LastUsedAt,
		}})
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"passkey": accountPasskey(passkey)})
}

func (server *Server) handleAPIDeleteAccountPasskey(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireAccountSession(writer, request, true)
	if !ok {
		return
	}
	if server.deleteAccountPasskey(writer, request, principal) {
		writer.WriteHeader(http.StatusNoContent)
	}
}

func (server *Server) deleteAccountPasskey(writer http.ResponseWriter, request *http.Request, principal apiPrincipal) bool {
	// 即使管理员关闭新增/登录，也允许用户清理已保存的旧凭据。
	err := server.identity.DeleteAccountPasskey(request.Context(), principal.UserID, principal.Session.ID, chi.URLParam(request, "id"))
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrPasskeyNotFound):
			writeAPIError(writer, http.StatusNotFound, "PASSKEY_NOT_FOUND: passkey not found")
		case errors.Is(err, identity.ErrSessionRevoked):
			writeAPIError(writer, http.StatusUnauthorized, "SESSION_CHANGED: initiating session is no longer active")
		default:
			writeAPIError(writer, http.StatusInternalServerError, "PASSKEY_DELETE_FAILED: could not delete passkey")
		}
		return false
	}
	return true
}

// 名称只是显示标签，不是身份键；拒绝控制字符，避免污染页面与审计呈现。
func passkeyDisplayName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		name = "通行密钥"
	}
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > passkeyNameLimit || strings.ContainsFunc(name, unicode.IsControl) {
		return "", errors.New("invalid passkey name")
	}
	return name, nil
}
