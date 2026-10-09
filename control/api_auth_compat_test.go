package control

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestLegacySessionRoutesShareAccountSafety(t *testing.T) {
	server := newTestServer(t)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	current, _ := server.identity.GetSessionByToken(token)
	_, apiToken := seedAPIKey(t, server)
	for _, path := range []string{"/api/v1/auth/logout", "/api/v1/sessions/" + current.ID} {
		method := http.MethodPost
		if strings.Contains(path, "/sessions/") {
			method = http.MethodDelete
		}
		if response := accountRequest(t, server, method, path, nil, cookie, nil); response.Code != http.StatusForbidden {
			t.Fatal("legacy write bypassed CSRF")
		}
		response := accountRequest(t, server, method, path, nil, cookie, map[string]string{
			"Authorization": "Bearer " + apiToken, "X-CSRF-Token": csrfTokenFor(token),
		})
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "HUMAN_SESSION_REQUIRED") {
			t.Fatal("legacy write accepted service identity")
		}
	}
	store := &failingAccountSessionsStore{Store: server.identity, listError: errors.New("injected read failure"), revokeError: errors.New("injected write failure")}
	server.identity = store
	if response := accountRequest(t, server, http.MethodGet, "/api/v1/sessions", nil, cookie, nil); response.Code != http.StatusInternalServerError {
		t.Fatal("legacy list swallowed a storage error")
	}
	response := accountRequest(t, server, http.MethodPost, "/api/v1/auth/logout", nil, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusInternalServerError || response.Header().Get("Set-Cookie") != "" {
		t.Fatal("failed logout cleared the cookie or reported success")
	}
	if _, err := store.Store.GetSessionByToken(token); err != nil {
		t.Fatal("failed logout revoked the session")
	}
	store.listError = nil
	response = accountRequest(t, server, http.MethodGet, "/api/v1/sessions", nil, cookie, nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"ID"`) {
		t.Fatal("legacy list did not preserve its presentation contract")
	}
	store.revokeError = nil
	response = accountRequest(t, server, http.MethodPost, "/api/v1/auth/logout", nil, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusNoContent {
		t.Fatalf("logout did not share atomic account revocation: %d", response.Code)
	}
	if response := accountRequest(t, server, http.MethodPost, "/api/v1/auth/logout", nil, cookie, nil); response.Code != http.StatusNoContent {
		t.Fatal("anonymous repeated logout was not idempotent")
	}
	revocationAudits := 0
	for _, event := range store.Store.ListAudit(0) {
		if event.Action == identity.AuditSessionRevoked {
			revocationAudits++
		}
	}
	if revocationAudits != 1 {
		t.Fatal("logout did not create exactly one account revocation audit")
	}
}

func TestHTMLLogoutRequiresCSRFAndCommit(t *testing.T) {
	server := newTestServer(t)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	if response := accountRequest(t, server, http.MethodPost, "/logout", "", cookie, nil); response.Code != http.StatusForbidden {
		t.Fatal("HTML logout bypassed form CSRF")
	}
	store := &failingAccountSessionsStore{Store: server.identity, revokeError: errors.New("injected write failure")}
	server.identity = store
	response := accountRequest(t, server, http.MethodPost, "/logout", "csrf="+csrfTokenFor(token), cookie, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if response.Code != http.StatusInternalServerError || response.Header().Get("Set-Cookie") != "" {
		t.Fatal("HTML logout cleared a cookie before revocation committed")
	}
}
