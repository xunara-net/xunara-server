package control

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

type accountLoginHistoryPayload struct {
	Records          []accountLoginRecordView `json:"records"`
	NextCursor       string                   `json:"next_cursor"`
	CurrentSessionID string                   `json:"current_session_id"`
}

func TestAccountLoginHistoryHumanAndTenantBoundary(test *testing.T) {
	server := newTestServer(test)
	memberID := seedRoleUser(test, server, "history-member", identity.RoleMember)
	cookie, token := seedUserSession(test, server, memberID)
	_, foreignToken := seedUserSession(test, server, state.DefaultUserID)
	_, apiToken := seedAPIKey(test, server)
	if _, _, err := server.identity.CreateSession(identity.NewSessionOptions{UserID: memberID, ClientInfo: identity.SessionClientInfo{IP: "192.0.2.8", UserAgent: "Firefox Linux"}}); err != nil {
		test.Fatal(err)
	}
	for _, headers := range []map[string]string{nil, {"Authorization": "Bearer " + token}} {
		response := accountRequest(test, server, http.MethodGet, "/api/v1/account/login-history?limit=1", nil, cookie, headers)
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
			test.Fatalf("human history: %d", response.Code)
		}
		var payload accountLoginHistoryPayload
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || len(payload.Records) != 1 || payload.NextCursor == "" {
			test.Fatal("pagination metadata missing")
		}
		if record := payload.Records[0]; record.Kind != "login" || record.ClientIP != "192.0.2.8" || record.UserAgent != "Firefox Linux" || record.LastSeenAt == nil {
			test.Fatal("login origin or activity omitted from history")
		}
		next := accountRequest(test, server, http.MethodGet, "/api/v1/account/login-history?limit=1&cursor="+payload.NextCursor, nil, cookie, nil)
		var following accountLoginHistoryPayload
		if err := json.Unmarshal(next.Body.Bytes(), &following); err != nil || next.Code != http.StatusOK || len(following.Records) != 1 || following.NextCursor != "" || following.Records[0].ID == payload.Records[0].ID {
			test.Fatal("next page duplicated or lost login records")
		}
		for _, secret := range []string{token, foreignToken, identity.HashSecret(token)} {
			if strings.Contains(response.Body.String(), secret) || strings.Contains(next.Body.String(), secret) {
				test.Fatal("history leaked a token or token hash")
			}
		}
	}
	if response := accountRequest(test, server, http.MethodGet, "/api/v1/account/login-history", nil, nil, nil); response.Code != http.StatusUnauthorized {
		test.Fatal("anonymous history access accepted")
	}
	if response := accountRequest(test, server, http.MethodGet, "/api/v1/account/login-history", nil, cookie, map[string]string{"Authorization": "Bearer " + apiToken}); response.Code != http.StatusForbidden {
		test.Fatal("service identity read human history")
	}
	otherTenant := newTestServer(test)
	if response := accountRequest(test, otherTenant, http.MethodGet, "/api/v1/account/login-history", nil, cookie, nil); response.Code != http.StatusUnauthorized {
		test.Fatal("cross-tenant human session accepted")
	}
	for _, query := range []string{"user_id=1", "limit=0", "limit=101", "limit=a", "limit=1&limit=2", "cursor=forged", "cursor=%zz", "cursor=a&cursor=b"} {
		if response := accountRequest(test, server, http.MethodGet, "/api/v1/account/login-history?"+query, nil, cookie, nil); response.Code != http.StatusBadRequest {
			test.Fatalf("invalid history query accepted: %s -> %d", query, response.Code)
		}
	}
}

func TestPasswordLoginRecordsTrustedRequestSource(test *testing.T) {
	for _, trusted := range []bool{false, true} {
		server := newServerWithConfig(test, Config{TrustedProxy: trusted})
		response := accountRequest(test, server, http.MethodPost, "/api/v1/auth/login",
			apiLoginRequest{Login: state.DefaultUserProfile(state.DefaultUserID).LoginName, Password: testLocalPassword}, nil,
			map[string]string{"User-Agent": "Firefox/120 Linux", "X-Forwarded-For": "203.0.113.1, 198.51.100.8"})
		if response.Code != http.StatusOK {
			test.Fatalf("password login failed: %d", response.Code)
		}
		expected := "192.0.2.1"
		if trusted {
			expected = "198.51.100.8"
		}
		page, err := server.identity.ListAccountLoginHistory(test.Context(), state.DefaultUserID, identity.LoginHistoryOptions{})
		if err != nil || len(page.Records) != 1 || page.Records[0].ClientInfo.IP != expected || page.Records[0].ClientInfo.UserAgent != "Firefox/120 Linux" {
			test.Fatal("login origin trusted a forged first hop or lost request metadata")
		}
	}
}

func TestHumanActivityFailureKeepsCookieAndHistoryErrorIsNotEmpty(test *testing.T) {
	server := newTestServer(test)
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	session, _ := server.identity.GetSessionByToken(token)
	database := server.store.(*state.SQLiteStore).DB()
	if _, err := database.Exec("UPDATE sessions SET last_seen_at = ? WHERE id = ?", time.Now().Add(-time.Hour).UnixNano(), session.ID); err != nil {
		test.Fatal(err)
	}
	if _, err := database.Exec("CREATE TRIGGER history_activity_failure BEFORE UPDATE ON account_login_records BEGIN SELECT RAISE(IGNORE); END"); err != nil {
		test.Fatal(err)
	}
	for _, path := range []string{"/api/v1/auth/session", "/api/v1/account/login-history"} {
		for _, headers := range []map[string]string{nil, {"Authorization": "Bearer " + token}} {
			response := accountRequest(test, server, http.MethodGet, path, nil, cookie, headers)
			if response.Code != http.StatusServiceUnavailable || response.Header().Get("Set-Cookie") != "" || !strings.Contains(response.Body.String(), "AUTH_UNAVAILABLE") {
				test.Fatal("activity storage failure cleared a cookie or was interpreted as invalid authentication")
			}
		}
	}
	if _, err := database.Exec("DROP TRIGGER history_activity_failure"); err != nil {
		test.Fatal(err)
	}
	if response := accountRequest(test, server, http.MethodGet, "/api/v1/account/login-history", nil, cookie, nil); response.Code != http.StatusOK {
		test.Fatal("original session could not recover from activity storage failure")
	}
	if _, err := database.Exec("DROP TABLE account_login_records"); err != nil {
		test.Fatal(err)
	}
	response := accountRequest(test, server, http.MethodGet, "/api/v1/account/login-history", nil, cookie, nil)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "LOGIN_HISTORY_FAILED") || strings.Contains(response.Body.String(), "no such table") {
		test.Fatal("history read failure leaked diagnostics or appeared empty")
	}
}
