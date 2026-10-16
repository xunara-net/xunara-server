package control

import (
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/state"
)

func TestRetiredConsoleBookmarksOnlyReachWeb(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := seedUserSession(t, server, state.DefaultUserID)
	for page, target := range retiredConsolePages {
		for _, suffix := range []string{"", "/"} {
			path := "/console/" + page + suffix
			if page == "" {
				path = "/console" + suffix
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				response := accountRequest(t, server, method, path+"?return_to=https://untrusted.test&token=discarded", nil, cookie, nil)
				if response.Code != http.StatusFound || response.Header().Get("Location") != target || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("%s %s did not migrate to %s: %d %s", method, path, target, response.Code, response.Header().Get("Location"))
				}
				if strings.Contains(response.Body.String(), "Xunara console") || response.Header().Get("Set-Cookie") != "" {
					t.Fatal("retired bookmark rendered the old center or changed a cookie")
				}
			}
		}
		response := accountRequest(t, server, http.MethodGet, "/console/"+page, nil, nil, nil)
		if response.Code != http.StatusFound || response.Header().Get("Location") != "/login?return_to="+url.QueryEscape(target) {
			t.Fatal("anonymous bookmark retained an old console login return path")
		}
	}
	for _, path := range []string{"/console/unknown", "/console/reach/deadbeef", "/console/%73sh-check"} {
		if response := accountRequest(t, server, http.MethodGet, path, nil, cookie, nil); response.Code != http.StatusNotFound {
			t.Fatalf("unsupported console bookmark was revived: %s (%d)", path, response.Code)
		}
	}
}

func TestRetiredConsoleWritesNeverMutateState(t *testing.T) {
	server := newTestServer(t)
	node := seedAPIMachine(t, server, "existing-device", nil)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	beforeNodes := server.store.ListNodes()
	beforeUsers := server.identity.ListUsers()
	beforeAudit := server.identity.ListAudit(0)
	for _, path := range []string{
		"/console/machines/" + node.StableID + "/delete",
		"/console/machines/" + node.StableID + "/routes",
		"/console/devices/pending/approve", "/console/devices/pending/deny",
		"/console/users/1", "/console/invites", "/console/invites/old/delete",
		"/console/auth-keys", "/console/auth-keys/1/delete", "/console/dns/delete",
		"/console/agents/old/revoke", "/console/api-keys", "/console/api-keys/old/revoke",
		"/console/shares", "/console/shares/old/accept", "/console/shares/old/reject", "/console/shares/old/revoke",
		"/console/webhooks", "/console/webhooks/old/delete",
		"/console/passkeys/begin", "/console/passkeys/finish", "/console/passkeys/old/delete",
	} {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			for _, active := range []*http.Cookie{nil, cookie} {
				response := accountRequest(t, server, method, path, map[string]string{"csrf": csrfTokenFor(token)}, active, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
				if response.Code != http.StatusGone || response.Header().Get("Location") != "" || response.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("old write remains active: %s %s (%d)", method, path, response.Code)
				}
			}
		}
	}
	if !reflect.DeepEqual(beforeNodes, server.store.ListNodes()) || !reflect.DeepEqual(beforeUsers, server.identity.ListUsers()) || !reflect.DeepEqual(beforeAudit, server.identity.ListAudit(0)) {
		t.Fatal("retired HTML form changed devices, users or audit records")
	}
}

func TestRetiredConsoleKeepsTenantBoundary(t *testing.T) {
	router, _ := selfServiceRouter(t, &SelfServiceConfig{DomainSuffix: "native.example.test", ConsoleURL: "https://app.xunara.test"})
	created := tenantConsoleRequest(t, router, http.MethodPost, selfServiceSignupPath, selfServiceRequest{Login: "bookmark-owner", Password: "SharedOwner-Strong-2026"})
	if created.Code != http.StatusCreated {
		t.Fatal("fixture signup failed")
	}
	cookies := created.Result().Cookies()
	path := "/t/bookmark-owner/console/ssh-check"
	response := tenantConsoleRequest(t, router, http.MethodGet, path, nil, cookies...)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/t/bookmark-owner/security#ssh-check" {
		t.Fatalf("bookmark escaped its tenant: %d %s", response.Code, response.Header().Get("Location"))
	}
	response = tenantConsoleRequest(t, router, http.MethodGet, path, nil)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/login?return_to=%2Ft%2Fbookmark-owner%2Fsecurity%23ssh-check" {
		t.Fatal("anonymous bookmark bypassed canonical account login")
	}
	response = tenantConsoleRequest(t, router, http.MethodGet, "/t/unknown/console/ssh-check", nil, cookies...)
	if response.Code != http.StatusNotFound {
		t.Fatal("unknown tenant exposed a console")
	}
	server := router.serverFor("bookmark-owner")
	if len(server.store.ListNodes()) != 0 || len(server.identity.ListUsers()) != 1 {
		t.Fatal("bookmark navigation modified tenant identities")
	}
}

func TestRetiredPagePreferencesUseModernSettings(t *testing.T) {
	server := newTestServer(t)
	for _, target := range []string{"", "https://untrusted.test", "//untrusted.test", "/dashboard"} {
		response := accountRequest(t, server, http.MethodGet, "/ui/prefs?lang=zh&return_to="+url.QueryEscape(target), nil, nil, nil)
		if response.Code != http.StatusFound || response.Header().Get("Location") != "/settings" || len(response.Result().Cookies()) != 0 {
			t.Fatal("retired preferences restored Go UI settings or an untrusted redirect")
		}
	}
}
