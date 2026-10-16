package control

import (
	"bytes"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestCoreHasNoEmbeddedBrowserFrontend(test *testing.T) {
	err := filepath.WalkDir(".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		for _, marker := range []string{`"html/template"`, "<form", "<html", "pageTemplate(", "passkeyBrowserJS", "publicFoot", "siteTokens"} {
			if bytes.Contains(source, []byte(marker)) {
				test.Errorf("%s contains retired UI marker %q", name, marker)
			}
		}
		return nil
	})
	if err != nil {
		test.Fatal(err)
	}
}

func TestRetiredAdminFormsCannotCreateSessionsOrChangePlans(test *testing.T) {
	router, plans, _ := newAdminTestRouter(test)
	handler := router.Handler()
	before := plans.Catalog().List()
	for _, endpoint := range []string{"/admin/login", "/admin/logout", "/admin/tenants/plan", "/admin/tenants/network", "/admin/tenants/delete", "/admin/users/delete", "/admin/users/revoke", "/admin/plans/save", "/admin/plans/delete"} {
		request := platformAuthRequest(test, handler, http.MethodPost, endpoint, "", map[string]string{"token": "test-platform-token"}, nil)
		if request.Code != http.StatusGone || len(request.Result().Cookies()) != 0 {
			test.Fatalf("retired admin form remains active: %s", endpoint)
		}
	}
	after := plans.Catalog().List()
	if len(before) != len(after) {
		test.Fatal("retired admin form changed plans")
	}
}

func TestBrowserSSHReadAndDecisionRejectServiceIdentity(test *testing.T) {
	server := newTestServer(test)
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	session, err := server.identity.CreateSSHCheckSession(identity.NewSSHCheckOptions{SrcNodeID: 1, DstNodeID: 2, LocalUser: "root"})
	if err != nil {
		test.Fatal(err)
	}
	endpoint := "/api/v1/browser/ssh-checks/" + session.ID
	read := accountRequest(test, server, http.MethodGet, endpoint, nil, cookie, nil)
	if read.Code != http.StatusOK || !strings.Contains(read.Body.String(), `"state":"pending"`) {
		test.Fatal("SSH browser metadata is unavailable")
	}
	if missing := accountRequest(test, server, http.MethodPost, endpoint+"/approve", map[string]any{}, cookie, nil); missing.Code != http.StatusForbidden {
		test.Fatal("SSH decision bypassed CSRF")
	}
	_, serviceToken, err := server.identity.CreateAPIKey(identity.NewAPIKeyOptions{Name: "browser-service-denial", UserID: state.DefaultUserID, Scopes: []string{identity.ScopeRead, identity.ScopeWrite}})
	if err != nil {
		test.Fatal(err)
	}
	for _, operation := range []struct{ method, suffix string }{{http.MethodGet, ""}, {http.MethodPost, "/approve"}} {
		response := accountRequest(test, server, operation.method, endpoint+operation.suffix, map[string]any{}, nil, map[string]string{"Authorization": "Bearer " + serviceToken, "X-CSRF-Token": csrfTokenFor(serviceToken)})
		if response.Code != http.StatusForbidden {
			test.Fatal("service identity was accepted as human SSH authorization")
		}
	}
	decided := accountRequest(test, server, http.MethodPost, endpoint+"/approve", map[string]any{}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if decided.Code != http.StatusOK {
		test.Fatalf("human SSH approval failed: %d", decided.Code)
	}
	replay := accountRequest(test, server, http.MethodPost, endpoint+"/deny", map[string]any{}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if replay.Code != http.StatusConflict {
		test.Fatal("SSH approval was overwritten by a replay")
	}
	database := server.store.(*state.SQLiteStore).DB()
	if _, err := database.Exec("ALTER TABLE ssh_check_sessions RENAME TO unavailable_browser_checks"); err != nil {
		test.Fatal(err)
	}
	response := accountRequest(test, server, http.MethodGet, endpoint, nil, cookie, nil)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "unavailable_browser_checks") {
		test.Fatal("SSH storage failure was hidden or exposed")
	}
}
