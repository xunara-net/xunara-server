package control

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xunara-net/xunara-server/identity"
)

// Cookie names. The session cookie is the browser's bearer token; the auth
// cookie only binds a pending login to the browser that started it, and the
// passkey cookie does the same for a WebAuthn ceremony.
const (
	sessionCookieName = "xunara_session"
	authCookieName    = "xunara_auth"
	passkeyCookieName = "xunara_passkey"
)

// setSessionCookie hands the session token to the browser. The cookie is
// HttpOnly (no script access), SameSite=Lax (not sent on cross-site POSTs) and
// Secure whenever the server is served over https.
func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// setSessionCookieFor is [Server.setSessionCookie] with an explicit cookie
// domain. The platform's sign-up desk uses it to hand a session it just
// created for a brand-new tenant to the browser: without the shared parent
// domain the tenant's own host would never see the cookie and the new owner
// would have to sign in again (selfservice.go).
func (s *Server) setSessionCookieFor(w http.ResponseWriter, token string, expires time.Time, domain string) {
	if domain == "" {
		s.setSessionCookie(w, token, expires)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Domain:   domain,
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie removes the session cookie.
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// setAuthCookie binds a pending transaction to this browser.
func (s *Server) setAuthCookie(w http.ResponseWriter, txID, browserSecret string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    txID + "." + browserSecret,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearAuthCookie removes the transaction cookie.
func (s *Server) clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// authCookieValue splits the transaction cookie into its identifier and
// browser secret.
func authCookieValue(r *http.Request) (id, secret string, ok bool) {
	return splitBrowserBinding(r, authCookieName)
}

// setPasskeyCookie binds a WebAuthn ceremony to this browser. The cookie value
// is the ceremony identifier plus the binding secret; the secret is never
// echoed in a response body.
func (s *Server) setPasskeyCookie(w http.ResponseWriter, ceremonyID, browserSecret string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     passkeyCookieName,
		Value:    ceremonyID + "." + browserSecret,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearPasskeyCookie removes the ceremony cookie (single-use challenges).
func (s *Server) clearPasskeyCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     passkeyCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// passkeyCookieValue splits the ceremony cookie into its identifier and
// browser secret.
func passkeyCookieValue(r *http.Request) (id, secret string, ok bool) {
	return splitBrowserBinding(r, passkeyCookieName)
}

// splitBrowserBinding reads an "identifier.secret" binding cookie.
func splitBrowserBinding(r *http.Request, name string) (id, secret string, ok bool) {
	c, err := r.Cookie(name)
	if err != nil {
		return "", "", false
	}
	id, secret, ok = strings.Cut(c.Value, ".")
	if !ok || id == "" || secret == "" {
		return "", "", false
	}
	return id, secret, true
}

// sessionToken returns the raw session token presented by the browser.
func (server *Server) sessionToken(request *http.Request) string {
	for _, cookie := range request.Cookies() {
		if cookie.Name == sessionCookieName {
			if _, err := server.identity.GetSessionByToken(cookie.Value); err == nil {
				return cookie.Value
			}
		}
	}
	return ""
}

// currentSession resolves the request's session cookie to a live session.
func (s *Server) currentSession(r *http.Request) (identity.Session, bool) {
	token := s.sessionToken(r)
	if token == "" {
		return identity.Session{}, false
	}
	session, err := s.identity.GetSessionByToken(token)
	if err != nil {
		return identity.Session{}, false
	}
	return session, true
}

// csrfTokenFor derives a per-session CSRF token from the session secret.
//
// Deriving it from the (HttpOnly, unguessable) session token means no extra
// server-side storage and no server-local secret, so any instance can verify
// any other instance's token.
func csrfTokenFor(token string) string {
	sum := sha256.Sum256([]byte("xunara-csrf:" + token))
	return hex.EncodeToString(sum[:])
}

// checkCSRF verifies the form's CSRF token against the request's session.
func checkCSRF(r *http.Request, token string) bool {
	got := r.PostFormValue("csrf")
	want := csrfTokenFor(token)
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// checkCSRFHeader verifies the CSRF token of a JSON request, where the token
// travels in a header instead of a form field.
func checkCSRFHeader(r *http.Request, token string) bool {
	got := r.Header.Get("X-CSRF-Token")
	want := csrfTokenFor(token)
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// requireSession resolves the request's session or sends the browser to the
// login page with a return path.
func (s *Server) requireSession(w http.ResponseWriter, r *http.Request, returnTo string) (identity.Session, string, bool) {
	token := s.sessionToken(r)
	if token != "" {
		if session, err := s.identity.GetSessionByToken(token); err == nil {
			return session, token, true
		}
		s.clearSessionCookie(w)
	}
	http.Redirect(w, r, "/login?return_to="+url.QueryEscape(returnTo), http.StatusFound)
	return identity.Session{}, "", false
}
