package control

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestPasswordAdmissionFailsClosedOnStorageFailure(t *testing.T) {
	for _, fault := range []struct {
		name    string
		prepare string
		install string
		recover string
	}{
		{"rate insert", "", "CREATE TRIGGER unavailable_password_rate BEFORE INSERT ON rate_limits BEGIN SELECT RAISE(ABORT, 'private password admission diagnostic'); END", "DROP TRIGGER unavailable_password_rate"},
		{"rate update", "INSERT INTO rate_limits (scope, window_start, count) VALUES ('login-ip:127.0.0.1', 0, 1)", "CREATE TRIGGER unavailable_password_rate BEFORE UPDATE ON rate_limits BEGIN SELECT RAISE(ABORT, 'private password admission diagnostic'); END", "DROP TRIGGER unavailable_password_rate"},
		{"user read", "", "ALTER TABLE users RENAME TO unavailable_password_users", "ALTER TABLE unavailable_password_users RENAME TO users"},
		{"credential read and setup count", "", "ALTER TABLE local_credentials RENAME TO unavailable_password_credentials", "ALTER TABLE unavailable_password_credentials RENAME TO local_credentials"},
		{"session insert", "", "CREATE TRIGGER unavailable_password_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT, 'private password admission diagnostic'); END", "DROP TRIGGER unavailable_password_session"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			server := newTestServer(t)
			host := newTestHTTPServer(t, server)
			client := noRedirectClient()
			oldSession, oldToken, err := server.identity.CreateSession(identity.NewSessionOptions{UserID: state.DefaultUserID, TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			oldCookie := &http.Cookie{Name: sessionCookieName, Value: oldToken}
			credentials := apiLoginRequest{Login: state.DefaultUserProfile(state.DefaultUserID).LoginName, Password: testLocalPassword}
			formToken := server.newFormToken(formPurposeLogin)
			database := server.store.(*state.SQLiteStore).DB()
			if fault.prepare != "" {
				if _, err := database.Exec(fault.prepare); err != nil {
					t.Fatal(err)
				}
			}
			// 用真实数据库故障保留后台观察器的 Store，夹具本身不能制造指针竞争。
			if _, err := database.Exec(fault.install); err != nil {
				t.Fatal(err)
			}
			for _, endpoint := range []string{"/api/v1/auth/login", "/login"} {
				var response *http.Response
				if endpoint == "/login" {
					response = postForm(t, client, host.URL+endpoint, url.Values{
						"_csrf": {formToken}, "login": {credentials.Login}, "password": {credentials.Password}, "return_to": {"/console/"},
					}, oldCookie)
				} else {
					response = postJSON(t, client, host.URL+endpoint, credentials, oldCookie)
				}
				body := bodyString(t, response)
				if response.StatusCode != http.StatusServiceUnavailable {
					t.Fatalf("%s returned %d instead of unavailable", endpoint, response.StatusCode)
				}
				if response.Header.Get("Retry-After") == "" || response.Header.Get("Cache-Control") != "no-store" {
					t.Fatal("unavailable password login omitted retry or cache protection")
				}
				if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Location") != "" {
					t.Fatal("unavailable password login changed a cookie or redirected")
				}
				for _, private := range []string{testLocalPassword, oldToken, "private password admission diagnostic", "unavailable_password_"} {
					if strings.Contains(body, private) {
						t.Fatal("password failure exposed private data")
					}
				}
			}
			if _, err := database.Exec(fault.recover); err != nil {
				t.Fatal(err)
			}
			sessions, err := server.identity.ListAccountSessions(t.Context(), state.DefaultUserID)
			if err != nil || len(sessions) != 1 || sessions[0].ID != oldSession.ID || !sessions[0].RevokedAt.IsZero() {
				t.Fatal("password storage failure created or revoked a session")
			}
			probe := getRequest(t, client, host.URL+"/api/v1/auth/session", oldCookie)
			if probe.StatusCode != http.StatusOK || !strings.Contains(bodyString(t, probe), `"authenticated":true`) {
				t.Fatal("original login was lost after storage recovery")
			}
			response := postJSON(t, client, host.URL+"/api/v1/auth/login", credentials, nil)
			if response.StatusCode != http.StatusOK {
				t.Fatal("password login did not recover")
			}
			cookieNamed(t, response, sessionCookieName)
			response = postForm(t, client, host.URL+"/login", url.Values{
				"_csrf": {formToken}, "login": {credentials.Login}, "password": {credentials.Password}, "return_to": {"/console/"},
			}, nil)
			if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "/console/" {
				t.Fatal("legacy password login did not preserve its recovered target")
			}
			cookieNamed(t, response, sessionCookieName)
		})
	}
}

func TestPasswordAdmissionSharesBudgetAcrossJSONAndHTML(t *testing.T) {
	server := newTestServer(t)
	host := newTestHTTPServer(t, server)
	client := noRedirectClient()
	formToken := server.newFormToken(formPurposeLogin)
	login := state.DefaultUserProfile(state.DefaultUserID).LoginName
	for attempt := 0; attempt <= loginNameLimit; attempt++ {
		var response *http.Response
		if attempt%2 == 0 {
			response = postJSON(t, client, host.URL+"/api/v1/auth/login", apiLoginRequest{Login: login, Password: "wrong shared-budget password"}, nil)
		} else {
			response = postForm(t, client, host.URL+"/login", url.Values{
				"_csrf": {formToken}, "login": {strings.ToUpper(login)}, "password": {"wrong shared-budget password"},
			}, nil)
		}
		if attempt < loginNameLimit {
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("allowed attempt %d returned %d", attempt, response.StatusCode)
			}
		} else if response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") == "" {
			t.Fatal("switching password entry points bypassed the shared budget")
		}
		if response.Header.Get("Set-Cookie") != "" {
			t.Fatal("rejected password attempt returned a cookie")
		}
	}
}

func TestPasswordAdmissionCancellationDoesNotWrite(t *testing.T) {
	server := newTestServer(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err := server.signInWithPassword(ctx, "127.0.0.1", state.DefaultUserProfile(state.DefaultUserID).LoginName, testLocalPassword)
	if !errors.Is(err, context.Canceled) || result.token != "" || result.session.ID != "" || result.user.ID != 0 {
		t.Fatal("cancelled password sign-in returned an identity or lost cancellation")
	}
	var counts int
	if err := server.store.(*state.SQLiteStore).DB().QueryRow("SELECT (SELECT COUNT(*) FROM rate_limits) + (SELECT COUNT(*) FROM sessions)").Scan(&counts); err != nil || counts != 0 {
		t.Fatal("cancelled password sign-in changed admission or session state")
	}
}
