package control

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func setupAdmissionForm(server *Server) url.Values {
	return url.Values{
		"_csrf": {server.newFormToken(formPurposeSetup)}, "token": {server.readSetupToken()},
		"login": {"bootstrap-owner"}, "display_name": {"初始化所有者"}, "email": {"owner@example.test"},
		"password": {"correct horse battery staple"}, "confirm": {"correct horse battery staple"},
	}
}

func assertBootstrapUnavailable(t *testing.T, response *http.Response, private ...string) {
	t.Helper()
	body := bodyString(t, response)
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("bootstrap admission returned %d instead of unavailable", response.StatusCode)
	}
	if response.Header.Get("Retry-After") == "" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("bootstrap failure omitted retry or cache protection")
	}
	if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Location") != "" {
		t.Fatal("bootstrap failure changed a cookie or redirected")
	}
	for _, secret := range private {
		if secret != "" && strings.Contains(body, secret) {
			t.Fatal("bootstrap failure exposed private data")
		}
	}
}

func TestBootstrapAdmissionFailsClosedOnRateStorageFailure(t *testing.T) {
	for _, operation := range []string{"INSERT", "UPDATE"} {
		t.Run(operation, func(t *testing.T) {
			server := newUnconfiguredServer(t)
			host := newTestHTTPServer(t, server)
			form := setupAdmissionForm(server)
			database := server.store.(*state.SQLiteStore).DB()
			before, err := server.identity.LookupUser(t.Context(), state.DefaultUserID)
			if err != nil {
				t.Fatal(err)
			}
			if operation == "UPDATE" {
				if _, err := database.Exec("INSERT INTO rate_limits (scope, window_start, count) VALUES ('setup:127.0.0.1', 0, 1)"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := database.Exec(fmt.Sprintf("CREATE TRIGGER unavailable_setup_rate BEFORE %s ON rate_limits BEGIN SELECT RAISE(ABORT, 'private bootstrap diagnostic'); END", operation)); err != nil {
				t.Fatal(err)
			}
			response := postForm(t, noRedirectClient(), host.URL+"/setup", form, nil)
			assertBootstrapUnavailable(t, response, form.Get("token"), form.Get("password"), "private bootstrap diagnostic")
			after, err := server.identity.LookupUser(t.Context(), state.DefaultUserID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("rate storage failure changed the owner")
			}
			if count, err := server.identity.LocalCredentialCount(t.Context()); err != nil || count != 0 {
				t.Fatal("rate storage failure created a password")
			}
			if sessions, err := server.identity.ListAccountSessions(t.Context(), state.DefaultUserID); err != nil || len(sessions) != 0 {
				t.Fatal("rate storage failure created a session")
			}
			if server.readSetupToken() != form.Get("token") {
				t.Fatal("rate storage failure consumed the setup token")
			}
			if _, err := database.Exec("DROP TRIGGER unavailable_setup_rate"); err != nil {
				t.Fatal(err)
			}
			response = postForm(t, noRedirectClient(), host.URL+"/setup", form, nil)
			if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "/console/" {
				t.Fatal("bootstrap did not recover after rate storage became available")
			}
			cookieNamed(t, response, sessionCookieName)
		})
	}
}

func TestBootstrapTransactionFailurePreservesOwnerProofAndSession(t *testing.T) {
	for _, fault := range []struct {
		table     string
		operation string
	}{
		{"users", "UPDATE"}, {"local_credentials", "INSERT"}, {"sessions", "INSERT"}, {"audit_events", "INSERT"},
	} {
		t.Run(fault.table, func(t *testing.T) {
			server := newUnconfiguredServer(t)
			host := newTestHTTPServer(t, server)
			form := setupAdmissionForm(server)
			before, err := server.identity.LookupUser(t.Context(), state.DefaultUserID)
			if err != nil {
				t.Fatal(err)
			}
			oldSession, oldToken, err := server.identity.CreateSession(identity.NewSessionOptions{UserID: before.ID, TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			oldCookie := &http.Cookie{Name: sessionCookieName, Value: oldToken}
			auditBefore := server.identity.ListAudit(0)
			database := server.store.(*state.SQLiteStore).DB()
			if _, err := database.Exec(fmt.Sprintf("CREATE TRIGGER unavailable_bootstrap_write BEFORE %s ON %s BEGIN SELECT RAISE(ABORT, 'private bootstrap diagnostic'); END", fault.operation, fault.table)); err != nil {
				t.Fatal(err)
			}
			response := postForm(t, noRedirectClient(), host.URL+"/setup", form, oldCookie)
			assertBootstrapUnavailable(t, response, form.Get("token"), form.Get("password"), oldToken, "private bootstrap diagnostic")
			after, err := server.identity.LookupUser(t.Context(), before.ID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("failed bootstrap left a partially claimed owner")
			}
			if count, err := server.identity.LocalCredentialCount(t.Context()); err != nil || count != 0 {
				t.Fatal("failed bootstrap left a password")
			}
			if sessions, err := server.identity.ListAccountSessions(t.Context(), before.ID); err != nil || len(sessions) != 1 || sessions[0].ID != oldSession.ID || !sessions[0].RevokedAt.IsZero() {
				t.Fatal("failed bootstrap changed the original session")
			}
			if !reflect.DeepEqual(auditBefore, server.identity.ListAudit(0)) || server.readSetupToken() != form.Get("token") {
				t.Fatal("failed bootstrap consumed proof or left a success audit")
			}
			if _, err := database.Exec("DROP TRIGGER unavailable_bootstrap_write"); err != nil {
				t.Fatal(err)
			}
			response = postForm(t, noRedirectClient(), host.URL+"/setup", form, oldCookie)
			if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "/console/" {
				t.Fatal("rolled-back bootstrap could not retry")
			}
			cookieNamed(t, response, sessionCookieName)
		})
	}
}

func TestBootstrapMetadataStorageFailureIsNotSetupRequired(t *testing.T) {
	for _, initialized := range []bool{false, true} {
		t.Run(fmt.Sprint(initialized), func(t *testing.T) {
			server := newUnconfiguredServer(t)
			if initialized {
				if err := seedTestCredential(server); err != nil {
					t.Fatal(err)
				}
			}
			host := newTestHTTPServer(t, server)
			form := setupAdmissionForm(server)
			database := server.store.(*state.SQLiteStore).DB()
			if _, err := database.Exec("ALTER TABLE local_credentials RENAME TO unavailable_bootstrap_credentials"); err != nil {
				t.Fatal(err)
			}
			for _, endpoint := range []string{"/api/v1/auth/providers", "/api/v1/auth/session", "/api/v1/capabilities", "/setup", "/login", "/signup", "/"} {
				t.Run(endpoint, func(t *testing.T) {
					response := getHTML(t, noRedirectClient(), host.URL+endpoint)
					assertBootstrapUnavailable(t, response, form.Get("token"), form.Get("password"), "unavailable_bootstrap_credentials")
				})
			}
			response := postForm(t, noRedirectClient(), host.URL+"/setup", form, nil)
			assertBootstrapUnavailable(t, response, form.Get("token"), form.Get("password"))
			response = postForm(t, noRedirectClient(), host.URL+"/signup", url.Values{"_csrf": {server.newFormToken(formPurposeSignup)}}, nil)
			assertBootstrapUnavailable(t, response)
			response = postJSON(t, noRedirectClient(), host.URL+"/api/v1/auth/signup", apiSignupRequest{Login: "outsider", Password: "correct horse battery staple"}, nil)
			assertBootstrapUnavailable(t, response)
			if _, err := database.Exec("ALTER TABLE unavailable_bootstrap_credentials RENAME TO local_credentials"); err != nil {
				t.Fatal(err)
			}
			response = getRequest(t, noRedirectClient(), host.URL+"/api/v1/auth/providers", nil)
			if response.StatusCode != http.StatusOK || !strings.Contains(bodyString(t, response), fmt.Sprintf(`"setup_required":%t`, !initialized)) {
				t.Fatal("metadata did not recover its persisted setup state")
			}
		})
	}
}

func TestBootstrapInvitationGateStorageFailureIsNotDisabled(t *testing.T) {
	server := newTestServer(t)
	host := newTestHTTPServer(t, server)
	token := inviteOwnerToken(t, server)
	cookie := &http.Cookie{Name: sessionCookieName, Value: token}
	database := server.store.(*state.SQLiteStore).DB()
	if _, err := database.Exec("ALTER TABLE local_bootstrap_state RENAME TO unavailable_invite_bootstrap"); err != nil {
		t.Fatal(err)
	}
	endpoint := host.URL + "/api/v1/member-invitations"
	response := memberInviteRequestForTest(t, noRedirectClient(), http.MethodGet, endpoint, token, "", nil)
	assertBootstrapUnavailable(t, response, token, "unavailable_invite_bootstrap")
	response = memberInviteRequestForTest(t, noRedirectClient(), http.MethodPost, endpoint, token, csrfTokenFor(token), memberInviteRequest{Role: "member", TTLHours: 1})
	assertBootstrapUnavailable(t, response, token, "unavailable_invite_bootstrap")
	response = getHTML(t, noRedirectClient(), host.URL+"/console/users", cookie)
	assertBootstrapUnavailable(t, response, token, "unavailable_invite_bootstrap")
	if invites, err := server.identity.ListRegistrationInvitesContext(t.Context()); err != nil || len(invites) != 0 {
		t.Fatal("failed invitation gate persisted an invitation")
	}
	if _, err := database.Exec("ALTER TABLE unavailable_invite_bootstrap RENAME TO local_bootstrap_state"); err != nil {
		t.Fatal(err)
	}
	response = memberInviteRequestForTest(t, noRedirectClient(), http.MethodPost, endpoint, token, csrfTokenFor(token), memberInviteRequest{Role: "member", TTLHours: 1})
	if response.StatusCode != http.StatusCreated {
		t.Fatal("invitation gate did not recover")
	}
}
