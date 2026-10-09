package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

type accountSessionsPayload struct {
	Sessions         []accountSessionView `json:"sessions"`
	CurrentSessionID string               `json:"current_session_id"`
	CSRFToken        string               `json:"csrf_token"`
}

func TestAccountSessionListStates(t *testing.T) {
	server := newTestServer(t)
	memberID := seedRoleUser(t, server, "member", identity.RoleMember)
	cookie, token := seedUserSession(t, server, memberID)
	_, foreignToken := seedUserSession(t, server, state.DefaultUserID)
	expired, _, err := server.identity.CreateSession(identity.NewSessionOptions{UserID: memberID, TTL: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	old, oldToken, err := server.identity.CreateSession(identity.NewSessionOptions{UserID: memberID})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.identity.RevokeSession(old.ID, "rotated"); err != nil {
		t.Fatal(err)
	}
	response := accountRequest(t, server, http.MethodGet, "/api/v1/account/sessions", nil, cookie, nil)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("session list: %d", response.Code)
	}
	var payload accountSessionsPayload
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	current, _ := server.identity.GetSessionByToken(token)
	if len(payload.Sessions) != 3 || payload.CurrentSessionID != current.ID || payload.CSRFToken != csrfTokenFor(token) {
		t.Fatalf("incorrect session-list metadata: %+v", payload)
	}
	for _, session := range payload.Sessions {
		switch session.ID {
		case current.ID:
			if session.Status != "active" || session.RevokedAt != nil {
				t.Fatal("current session not marked active")
			}
		case expired.ID:
			if session.Status != "expired" || session.RevokedAt != nil {
				t.Fatal("expired session shown as active")
			}
		case old.ID:
			if session.Status != "revoked" || session.RevokedAt == nil || session.RevokedReason != "rotated" {
				t.Fatal("revoked session history lost")
			}
		default:
			t.Fatal("another user's session was listed")
		}
	}
	for _, secret := range []string{token, foreignToken, oldToken, identity.HashSecret(token)} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("session list leaked a secret")
		}
	}
}

func TestAccountSessionRevocationHumanCSRFAndTenant(t *testing.T) {
	server := newTestServer(t)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	current, _ := server.identity.GetSessionByToken(token)
	_, apiToken := seedAPIKey(t, server)
	foreignTenant := newTestServer(t)
	for _, operation := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/account/sessions"},
		{http.MethodPost, "/api/v1/account/sessions/revoke"},
		{http.MethodDelete, "/api/v1/account/sessions/" + current.ID},
	} {
		if response := accountRequest(t, server, operation.method, operation.path, map[string]string{"mode": "all"}, nil, nil); response.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous access: %d", response.Code)
		}
		response := accountRequest(t, server, operation.method, operation.path, map[string]string{"mode": "all"}, cookie, map[string]string{
			"Authorization": "Bearer " + apiToken, "X-CSRF-Token": csrfTokenFor(token),
		})
		if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "HUMAN_SESSION_REQUIRED") {
			t.Fatalf("service identity accepted: %d", response.Code)
		}
		if operation.method != http.MethodGet {
			for _, csrf := range []string{"", "wrong"} {
				response := accountRequest(t, server, operation.method, operation.path, map[string]string{"mode": "all"}, cookie, map[string]string{"X-CSRF-Token": csrf})
				if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "CSRF_INVALID") {
					t.Fatalf("missing/wrong CSRF accepted: %d", response.Code)
				}
			}
		}
		response = accountRequest(t, foreignTenant, operation.method, operation.path, map[string]string{"mode": "all"}, nil, map[string]string{
			"Authorization": "Bearer " + token, "X-CSRF-Token": csrfTokenFor(token),
		})
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("another tenant accepted a token with the same numeric user ID: %d", response.Code)
		}
	}
	if _, err := server.identity.GetSessionByToken(token); err != nil {
		t.Fatal("rejected requests revoked a session")
	}
}

func TestAccountSessionMemberBulkAndSingle(t *testing.T) {
	server := newTestServer(t)
	memberID := seedRoleUser(t, server, "member", identity.RoleMember)
	cookie, token := seedUserSession(t, server, memberID)
	_, otherToken := seedUserSession(t, server, memberID)
	other, _ := server.identity.GetSessionByToken(otherToken)
	_, foreignToken := seedUserSession(t, server, state.DefaultUserID)
	foreign, _ := server.identity.GetSessionByToken(foreignToken)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	for _, targetID := range []string{foreign.ID, "missing"} {
		response := accountRequest(t, server, http.MethodDelete, "/api/v1/account/sessions/"+targetID, nil, cookie, headers)
		if response.Code != http.StatusNotFound {
			t.Fatalf("invalid target: %d", response.Code)
		}
	}
	response := accountRequest(t, server, http.MethodPost, "/api/v1/account/sessions/revoke", map[string]string{"mode": "others"}, cookie, headers)
	if response.Code != http.StatusOK || decodeAPI(t, response.Result())["revoked_sessions"] != float64(1) {
		t.Fatalf("member revoking other sessions: %d", response.Code)
	}
	if _, err := server.identity.GetSessionByToken(token); err != nil {
		t.Fatal("other-session logout revoked the current session")
	}
	response = accountRequest(t, server, http.MethodDelete, "/api/v1/account/sessions/"+other.ID, nil, cookie, headers)
	if response.Code != http.StatusOK || decodeAPI(t, response.Result())["revoked_sessions"] != float64(0) {
		t.Fatal("repeat single revocation not idempotent")
	}
	response = accountRequest(t, server, http.MethodPost, "/api/v1/account/sessions/revoke", map[string]string{"mode": "all"}, cookie, headers)
	if response.Code != http.StatusOK {
		t.Fatalf("member revoking all sessions: %d", response.Code)
	}
	payload := decodeAPI(t, response.Result())
	if payload["revoked_sessions"] != float64(1) || payload["current_revoked"] != true {
		t.Fatalf("current revocation result: %v", payload)
	}
	cleared := false
	for _, resultCookie := range response.Result().Cookies() {
		if resultCookie.Name == sessionCookieName && resultCookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("current cookie was not cleared")
	}
	for _, oldToken := range []string{token, otherToken} {
		if _, err := server.identity.GetSessionByToken(oldToken); !errors.Is(err, identity.ErrSessionNotFound) {
			t.Fatal("revoked session remains authenticated")
		}
	}
	if _, err := server.identity.GetSessionByToken(foreignToken); err != nil || !auditActionSet(t, server)[identity.AuditSessionRevoked] {
		t.Fatal("foreign user was affected or revocation not audited")
	}
	if response := accountRequest(t, server, http.MethodPost, "/api/v1/account/sessions/revoke", map[string]string{"mode": "all"}, cookie, headers); response.Code != http.StatusUnauthorized {
		t.Fatal("revoked initiator was accepted")
	}
}

func TestAccountSessionBulkInputAllowlist(t *testing.T) {
	server := newTestServer(t)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	for _, body := range []string{`{}`, `null`, `{"mode":null}`, `{"mode":"one"}`, `{"mode":"unknown"}`, `{"mode":"all","user_id":2}`, `{"mode":"all"}{}`, strings.Repeat("x", 8193)} {
		response := accountRequest(t, server, http.MethodPost, "/api/v1/account/sessions/revoke", body, cookie, headers)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid input accepted: %d", response.Code)
		}
	}
	response := accountRequest(t, server, http.MethodPost, "/api/v1/account/sessions/revoke", `{"mode":"all"}`, cookie, map[string]string{
		"X-CSRF-Token": csrfTokenFor(token), "Content-Type": "text/plain",
	})
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatal("non-JSON revocation accepted")
	}
	if _, err := server.identity.GetSessionByToken(token); err != nil {
		t.Fatal("invalid input changed state")
	}
}

type failingAccountSessionsStore struct {
	identity.Store
	listError    error
	revokeError  error
	beforeRevoke func()
}

func (store *failingAccountSessionsStore) ListAccountSessions(ctx context.Context, userID tailcfg.UserID) ([]identity.Session, error) {
	if store.listError != nil {
		return nil, store.listError
	}
	return store.Store.ListAccountSessions(ctx, userID)
}

func (store *failingAccountSessionsStore) RevokeAccountSessions(ctx context.Context, userID tailcfg.UserID, initiatingID string, selection identity.SessionRevocation) (int64, error) {
	if store.beforeRevoke != nil {
		store.beforeRevoke()
	}
	if store.revokeError != nil {
		return 0, store.revokeError
	}
	return store.Store.RevokeAccountSessions(ctx, userID, initiatingID, selection)
}

func TestAccountSessionStorageAndInitiatorFailures(t *testing.T) {
	server := newTestServer(t)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	current, _ := server.identity.GetSessionByToken(token)
	_, otherToken := seedUserSession(t, server, state.DefaultUserID)
	store := &failingAccountSessionsStore{Store: server.identity, listError: errors.New("injected read failure"), revokeError: errors.New("injected write failure")}
	server.identity = store
	response := accountRequest(t, server, http.MethodGet, "/api/v1/account/sessions", nil, cookie, nil)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "SESSION_LIST_FAILED") {
		t.Fatal("session read failure became a successful empty list")
	}
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	response = accountRequest(t, server, http.MethodPost, "/api/v1/account/sessions/revoke", map[string]string{"mode": "all"}, cookie, headers)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "SESSION_REVOKE_FAILED") {
		t.Fatal("session revocation storage error was ignored")
	}
	store.revokeError = nil
	store.beforeRevoke = func() {
		if err := store.Store.RevokeSession(current.ID, "concurrently revoked"); err != nil {
			t.Fatal(err)
		}
	}
	response = accountRequest(t, server, http.MethodPost, "/api/v1/account/sessions/revoke", map[string]string{"mode": "all"}, cookie, headers)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "SESSION_CHANGED") {
		t.Fatal("session revoked after authentication was allowed to revoke others")
	}
	if _, err := server.identity.GetSessionByToken(otherToken); err != nil {
		t.Fatal("failed request revoked another session")
	}
}

func TestAccountSessionHumanBearerSignsOutCurrent(t *testing.T) {
	server := newTestServer(t)
	_, token := seedUserSession(t, server, state.DefaultUserID)
	current, _ := server.identity.GetSessionByToken(token)
	response := accountRequest(t, server, http.MethodDelete, "/api/v1/account/sessions/"+current.ID, nil, nil, map[string]string{
		"Authorization": "Bearer " + token, "X-CSRF-Token": csrfTokenFor(token),
	})
	if response.Code != http.StatusOK || decodeAPI(t, response.Result())["current_revoked"] != true {
		t.Fatalf("human bearer signing out itself: %d", response.Code)
	}
}
