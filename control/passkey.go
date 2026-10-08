package control

// This file is the HTTP half of passkey (WebAuthn) sign-in: usernameless login
// on the public sign-in page and self-service credential management in the
// console.
//
// A passkey is Human Identity (AGENTS.md section 5): an assertion creates a
// browser session and never authorizes a machine. Ceremonies are persisted and
// single-use, so any instance can finish what another started (section 9).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
)

// passkeyNameLimit bounds a user-chosen passkey label. The label is cosmetic
// (it is rendered in the console and audit log), so this is a sanity bound,
// not a security one.
const passkeyNameLimit = 64

// passkeyView is a passkey as shown in the console. Cryptographic material is
// deliberately absent: only the label and timestamps are rendered.
type passkeyView struct {
	ID       string
	Name     string
	Created  time.Time
	LastUsed time.Time
}

// passkeyViews renders a user's passkeys for the console.
func (s *Server) passkeyViews(userID tailcfg.UserID) []passkeyView {
	passkeys := s.identity.ListPasskeys(userID)
	views := make([]passkeyView, 0, len(passkeys))
	for _, p := range passkeys {
		name := p.Name
		if name == "" {
			name = "Passkey"
		}
		views = append(views, passkeyView{
			ID:       p.ID,
			Name:     name,
			Created:  p.CreatedAt,
			LastUsed: p.LastUsedAt,
		})
	}
	return views
}

// passkeyJSON writes a JSON body for the fetch() clients of the ceremony
// endpoints.
func passkeyJSON(w http.ResponseWriter, code int, v any) { writeJSON(w, code, v) }

// passkeyFail writes a static JSON error. Store and library errors never reach
// the browser: they can name credentials or internal state.
func passkeyFail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// handlePasskeyLoginBegin implements POST /passkey/login/begin. It starts a
// usernameless ceremony and binds it to this browser.
func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if s.passkeys == nil {
		passkeyFail(w, http.StatusNotFound, "passkey sign-in is not configured on this server")
		return
	}

	options, ceremonyID, browserSecret, err := s.passkeys.BeginLogin()
	if err != nil {
		s.log.Error("starting passkey login", "err", err)
		passkeyFail(w, http.StatusInternalServerError, "could not start passkey sign-in; try again")
		return
	}

	s.setPasskeyCookie(w, ceremonyID, browserSecret, time.Now().Add(identity.DefaultPasskeyCeremonyTTL))
	passkeyJSON(w, http.StatusOK, map[string]any{"options": options})
}

// handlePasskeyLoginFinish implements POST /passkey/login/finish. The
// assertion is verified against the single-use ceremony, then the user is
// signed in through the same session path as every other provider.
func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if s.passkeys == nil {
		passkeyFail(w, http.StatusNotFound, "passkey sign-in is not configured on this server")
		return
	}

	ceremonyID, browserSecret, ok := passkeyCookieValue(r)
	if !ok {
		s.audit("system", identity.AuditLoginFailed, "provider:passkey", "missing browser binding")
		passkeyFail(w, http.StatusBadRequest, "this passkey sign-in was started in a different browser or has expired; start again")
		return
	}

	user, _, err := s.passkeys.FinishLogin(ceremonyID, browserSecret, r)
	if err != nil {
		s.audit("system", identity.AuditLoginFailed, "provider:passkey", passkeyLoginFailureReason(err))
		s.log.Warn("passkey login rejected", "err", err)
		passkeyFail(w, http.StatusBadRequest, "passkey sign-in failed; start again from the sign-in page")
		return
	}

	session, token, err := s.identity.CreateSession(identity.NewSessionOptions{
		UserID:     user.ID,
		AuthMethod: "passkey",
		TTL:        s.sessionTTL,
	})
	if err != nil {
		s.log.Error("creating session", "user", int(user.ID), "err", err)
		passkeyFail(w, http.StatusInternalServerError, "sign-in failed; try again")
		return
	}

	actor := fmt.Sprintf("user:%d", user.ID)
	s.audit(actor, identity.AuditLoginSucceeded, "provider:passkey",
		"authenticated "+user.LoginName+" (method=passkey)")
	s.audit(actor, identity.AuditSessionCreated, "session:"+session.ID, "auth method passkey")

	s.setSessionCookie(w, token, session.ExpiresAt)
	s.clearPasskeyCookie(w)
	passkeyJSON(w, http.StatusOK, map[string]string{
		"redirect": safeReturnTo(r.URL.Query().Get("return_to")),
	})
}

// passkeyLoginFailureReason maps a ceremony failure to a static audit reason.
func passkeyLoginFailureReason(err error) string {
	switch {
	case errors.Is(err, identity.ErrPasskeyCeremonyNotFound),
		errors.Is(err, identity.ErrPasskeyCeremonyConsumed),
		errors.Is(err, identity.ErrPasskeyCeremonyExpired):
		return "ceremony expired, replayed or not this browser"
	case errors.Is(err, identity.ErrPasskeyNotFound),
		errors.Is(err, identity.ErrUserNotFound):
		return "unknown credential"
	default:
		return "assertion verification failed"
	}
}

// handleConsolePasskeys implements GET /console/passkeys.
func (s *Server) handleConsolePasskeys(w http.ResponseWriter, r *http.Request) {
	session, data, ok := s.consoleSession(w, r, "passkeys")
	if !ok {
		return
	}
	data["Passkeys"] = s.passkeyViews(session.UserID)
	data["PasskeyEnabled"] = s.passkeys != nil
	s.renderConsole(w, consolePasskeysTemplate, data)
}

// consolePasskeySession resolves the session of a JSON ceremony endpoint.
// Unlike the console pages it answers 401 JSON instead of a redirect, because
// the caller is a fetch(), not a navigation.
func (s *Server) consolePasskeySession(w http.ResponseWriter, r *http.Request) (identity.Session, string, bool) {
	session, ok := s.currentSession(r)
	if !ok {
		passkeyFail(w, http.StatusUnauthorized, "sign in to manage passkeys")
		return identity.Session{}, "", false
	}
	return session, sessionToken(r), true
}

// handleConsolePasskeyBegin implements POST /console/passkeys/begin: it starts
// a registration ceremony for the signed-in user.
func (s *Server) handleConsolePasskeyBegin(w http.ResponseWriter, r *http.Request) {
	if s.passkeys == nil {
		passkeyFail(w, http.StatusNotFound, "passkey sign-in is not configured on this server")
		return
	}
	session, token, ok := s.consolePasskeySession(w, r)
	if !ok {
		return
	}
	if !checkCSRFHeader(r, token) {
		passkeyFail(w, http.StatusForbidden, "the form token is invalid; reload the page and try again")
		return
	}

	user, ok := s.identity.GetUser(session.UserID)
	if !ok {
		passkeyFail(w, http.StatusUnauthorized, "sign in to manage passkeys")
		return
	}

	options, ceremonyID, browserSecret, err := s.passkeys.BeginRegistration(user)
	if err != nil {
		s.log.Error("starting passkey registration", "user", int(user.ID), "err", err)
		passkeyFail(w, http.StatusInternalServerError, "could not start passkey registration; try again")
		return
	}

	s.setPasskeyCookie(w, ceremonyID, browserSecret, time.Now().Add(identity.DefaultPasskeyCeremonyTTL))
	passkeyJSON(w, http.StatusOK, map[string]any{"options": options})
}

// handleConsolePasskeyFinish implements POST /console/passkeys/finish. The
// body is {"name": ..., "credential": ...}: the name is the console's, the
// credential is the library's own JSON.
func (s *Server) handleConsolePasskeyFinish(w http.ResponseWriter, r *http.Request) {
	if s.passkeys == nil {
		passkeyFail(w, http.StatusNotFound, "passkey sign-in is not configured on this server")
		return
	}
	session, token, ok := s.consolePasskeySession(w, r)
	if !ok {
		return
	}
	if !checkCSRFHeader(r, token) {
		passkeyFail(w, http.StatusForbidden, "the form token is invalid; reload the page and try again")
		return
	}
	user, ok := s.identity.GetUser(session.UserID)
	if !ok {
		passkeyFail(w, http.StatusUnauthorized, "sign in to manage passkeys")
		return
	}

	var body struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil || len(body.Credential) == 0 {
		passkeyFail(w, http.StatusBadRequest, "the passkey response is incomplete")
		return
	}
	name, err := passkeyDisplayName(body.Name)
	if err != nil {
		passkeyFail(w, http.StatusBadRequest, err.Error())
		return
	}
	ceremonyID, browserSecret, ok := passkeyCookieValue(r)
	if !ok {
		passkeyFail(w, http.StatusBadRequest, "this passkey registration was started in a different browser or has expired; start again")
		return
	}

	// The library parses the raw credential from the request body, so hand it
	// a request whose body is exactly that JSON.
	finish := r.Clone(r.Context())
	finish.Body = io.NopCloser(bytes.NewReader(body.Credential))
	finish.ContentLength = int64(len(body.Credential))

	passkey, err := s.passkeys.FinishRegistration(ceremonyID, browserSecret, user, name, finish)
	if err != nil {
		s.log.Warn("passkey registration rejected", "user", int(user.ID), "err", err)
		passkeyFail(w, http.StatusBadRequest, "passkey registration failed; start again")
		return
	}

	s.clearPasskeyCookie(w)
	s.audit(fmt.Sprintf("user:%d", user.ID), identity.AuditPasskeyRegistered,
		"passkey:"+passkey.ID, "registered passkey "+name)
	passkeyJSON(w, http.StatusOK, map[string]any{"passkey": passkeyView{
		ID:      passkey.ID,
		Name:    name,
		Created: passkey.CreatedAt,
	}})
}

// handleConsoleDeletePasskey implements POST /console/passkeys/{id}/delete.
// Users can only delete their own credentials.
func (s *Server) handleConsoleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	session, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login?return_to=%2Fconsole%2Fpasskeys", http.StatusFound)
		return
	}
	if !s.consoleCheckCSRF(w, r) {
		return
	}

	id := chi.URLParam(r, "id")
	name := ""
	for _, p := range s.identity.ListPasskeys(session.UserID) {
		if p.ID == id {
			name = p.Name
		}
	}
	if err := s.identity.DeletePasskey(id, session.UserID); err != nil {
		if errors.Is(err, identity.ErrPasskeyNotFound) {
			s.renderError(w, r, http.StatusNotFound, "Passkey not found",
				"That passkey does not exist on this account.")
			return
		}
		s.log.Error("deleting passkey", "user", int(session.UserID), "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Delete failed", "Please try again.")
		return
	}

	if name == "" {
		name = "Passkey"
	}
	s.audit(fmt.Sprintf("user:%d", session.UserID), identity.AuditPasskeyDeleted,
		"passkey:"+id, "deleted passkey "+name)
	http.Redirect(w, r, "/console/passkeys", http.StatusFound)
}

// passkeyDisplayName normalises the user-chosen label. The label is rendered
// in the console and the audit log, so control characters are rejected.
func passkeyDisplayName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		name = "Passkey"
	}
	if utf8.RuneCountInString(name) > passkeyNameLimit {
		return "", errors.New("the passkey name is too long")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", errors.New("the passkey name contains control characters")
		}
	}
	return name, nil
}

// passkeyBrowserJS is the browser half of the WebAuthn ceremonies: base64url
// and option/response conversion shared by the sign-in page and the console.
// It contains no template actions, so it can be embedded verbatim in a
// <script> element.
const passkeyBrowserJS = `
function b64urlToBytes(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function bytesToB64url(bytes) {
  if (!bytes) return null;
  let binary = "";
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i++) binary += String.fromCharCode(view[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function passkeyPost(url, body, csrf) {
  const headers = { "Content-Type": "application/json" };
  if (csrf) headers["X-CSRF-Token"] = csrf;
  const resp = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: headers,
    body: JSON.stringify(body || {})
  });
  let data = {};
  try { data = await resp.json(); } catch (err) { data = {}; }
  if (!resp.ok) throw new Error(data.error || "the passkey ceremony failed; try again");
  return data;
}
function decodeCreationOptions(options) {
  options.challenge = b64urlToBytes(options.challenge);
  options.user.id = b64urlToBytes(options.user.id);
  for (const cred of options.excludeCredentials || []) cred.id = b64urlToBytes(cred.id);
  return options;
}
function decodeRequestOptions(options) {
  options.challenge = b64urlToBytes(options.challenge);
  for (const cred of options.allowCredentials || []) cred.id = b64urlToBytes(cred.id);
  return options;
}
function encodeAttestation(credential) {
  return {
    id: credential.id,
    rawId: bytesToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToB64url(credential.response.clientDataJSON),
      attestationObject: bytesToB64url(credential.response.attestationObject)
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}
function encodeAssertion(credential) {
  return {
    id: credential.id,
    rawId: bytesToB64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToB64url(credential.response.clientDataJSON),
      authenticatorData: bytesToB64url(credential.response.authenticatorData),
      signature: bytesToB64url(credential.response.signature),
      userHandle: bytesToB64url(credential.response.userHandle)
    },
    clientExtensionResults: credential.getClientExtensionResults()
  };
}
`
