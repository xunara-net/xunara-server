package control

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestBrowserDeviceApprovalUsesPersistentAuthorization(test *testing.T) {
	server := newTestServer(test)
	host := newTestHTTPServer(test, server)
	client := noRedirectClient()
	connection, _, _, id := startRegistration(test, host, "modern-device")
	defer connection.Close()
	endpoint := host.URL + "/api/v1/browser/device-authorizations/" + id
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	for _, operation := range []string{"", "/approve", "/deny"} {
		var response *http.Response
		if operation == "" {
			response = getRequest(test, client, endpoint, nil)
		} else {
			response = postBrowserDecision(test, client, endpoint+operation, "", nil)
		}
		if response.StatusCode != http.StatusUnauthorized || response.Header.Get("Location") != "" {
			test.Fatal("anonymous browser authorization was not refused as JSON")
		}
	}
	response := getRequest(test, client, endpoint, cookie)
	payload := decodeAPI(test, response)
	if payload["hostname"] != "modern-device" || payload["state"] != "pending" || payload["can_write"] != true {
		test.Fatal("browser detail lost its persisted authorization")
	}
	for _, key := range []string{"machineKey", "nodeKey", "machine_key", "node_key"} {
		if _, present := payload[key]; present {
			test.Fatal("browser view leaked machine key material")
		}
	}
	for _, proof := range []string{"", "wrong"} {
		if response := postBrowserDecision(test, client, endpoint+"/approve", proof, cookie); response.StatusCode != http.StatusForbidden {
			test.Fatal("browser approval bypassed CSRF")
		}
	}
	if len(server.store.ListNodes()) != 0 {
		test.Fatal("failed approval created a device")
	}
	if response := postBrowserDecision(test, client, endpoint+"/approve", csrfTokenFor(token), cookie); response.StatusCode != http.StatusOK {
		test.Fatalf("approval failed: %d %s", response.StatusCode, bodyString(test, response))
	}
	if len(server.store.ListNodes()) != 1 {
		test.Fatal("approval did not commit the device")
	}
	if response := postBrowserDecision(test, client, endpoint+"/deny", csrfTokenFor(token), cookie); response.StatusCode != http.StatusConflict {
		test.Fatal("opposite replay changed a device decision")
	}
	payload = decodeAPI(test, getRequest(test, client, endpoint, cookie))
	if payload["state"] != "approved" || len(server.store.ListNodes()) != 1 {
		test.Fatal("decision was not durable")
	}
}

func TestBrowserDeviceUnknownExpiredDeniedAndStorageFailure(test *testing.T) {
	server := newTestServer(test)
	host := newTestHTTPServer(test, server)
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	client := noRedirectClient()
	base := host.URL + "/api/v1/browser/device-authorizations/"
	if response := getRequest(test, client, base+"unknown", cookie); response.StatusCode != http.StatusNotFound {
		test.Fatal("unknown authorization was not reported")
	}
	expired, err := server.identity.CreateDeviceAuthorization(identity.NewDeviceAuthorizationOptions{
		MachineKey: "expired-machine", NodeKey: "expired-node", TTL: -time.Hour,
	})
	if err != nil {
		test.Fatal(err)
	}
	// 存储的过期事实不能被展示为可审批的新请求。
	database := server.store.(*state.SQLiteStore).DB()
	if _, err := database.Exec("UPDATE device_authorizations SET expires_at = ? WHERE id = ?", time.Now().Add(-time.Hour).UnixNano(), expired.ID); err != nil {
		test.Fatal(err)
	}
	payload := decodeAPI(test, getRequest(test, client, base+expired.ID, cookie))
	if payload["state"] != "expired" {
		test.Fatal("expired authorization was offered as pending")
	}
	connection, _, _, pending := startRegistration(test, host, "denied-modern-device")
	defer connection.Close()
	if response := postBrowserDecision(test, client, base+pending+"/deny", csrfTokenFor(token), cookie); response.StatusCode != http.StatusOK {
		test.Fatal("denial failed")
	}
	if payload := decodeAPI(test, getRequest(test, client, base+pending, cookie)); payload["state"] != "denied" {
		test.Fatal("denial result was lost")
	}
	if _, err := database.Exec("ALTER TABLE device_authorizations RENAME TO unavailable_browser_authorizations"); err != nil {
		test.Fatal(err)
	}
	response := getRequest(test, client, base+pending, cookie)
	if response.StatusCode != http.StatusServiceUnavailable || strings.Contains(bodyString(test, response), "unavailable_browser_authorizations") {
		test.Fatal("storage failure was exposed or confused with missing authorization")
	}
}

func TestBrowserFormsAreRetiredWithoutSideEffects(test *testing.T) {
	server := newTestServer(test)
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	beforeNodes, beforeUsers, beforeAudit := server.store.ListNodes(), server.identity.ListUsers(), server.identity.ListAudit(0)
	for _, page := range []string{"/login", "/setup", "/signup", "/register/pending", "/ssh/check/pending"} {
		response := accountRequest(test, server, http.MethodGet, page, nil, cookie, map[string]string{"Accept": "text/html"})
		if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "<form") || strings.Contains(response.Header().Get("Content-Type"), "text/html") {
			test.Fatal("Core still serves a legacy browser page")
		}
	}
	for _, endpoint := range []string{"/login", "/setup", "/signup", "/logout", "/passkey/login/begin", "/passkey/login/finish", "/register/pending/approve", "/register/pending/deny", "/ssh/check/pending/approve", "/ssh/check/pending/deny"} {
		response := accountRequest(test, server, http.MethodPost, endpoint, map[string]string{"password": testLocalPassword}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
		if response.Code != http.StatusGone || len(response.Result().Cookies()) != 0 || response.Header().Get("Location") != "" {
			test.Fatalf("old browser form remains active: %s", endpoint)
		}
	}
	if !reflect.DeepEqual(beforeNodes, server.store.ListNodes()) || !reflect.DeepEqual(beforeUsers, server.identity.ListUsers()) || !reflect.DeepEqual(beforeAudit, server.identity.ListAudit(0)) {
		test.Fatal("retired form changed identities, devices or audit")
	}
}

func TestBrowserCallbackErrorsUseSafeModernPage(test *testing.T) {
	server := newTestServer(test)
	response := accountRequest(test, server, http.MethodGet, "/oidc/callback/unknown?code=private-code&error_description=private-provider", nil, nil, map[string]string{"Accept": "text/html"})
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/auth/error?reason=AUTH_FAILED" ||
		strings.Contains(response.Body.String(), "private") || response.Header().Get("Referrer-Policy") != "no-referrer" {
		test.Fatal("callback error did not navigate safely to the modern page")
	}
}
