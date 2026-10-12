package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestDeviceLifecycleAndEnrollmentPermissions(test *testing.T) {
	server := newTestServer(test)
	ownerCookie, ownerToken := seedUserSession(test, server, state.DefaultUserID)
	member := seedRoleUser(test, server, "expiry-member", identity.RoleMember)
	memberCookie, memberToken := seedUserSession(test, server, member)
	node := state.Node{MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), UserID: state.DefaultUserID}
	if err := server.store.CreateNode(&node); err != nil {
		test.Fatal(err)
	}
	path := "/api/v2/machines/" + node.StableID
	for _, cookie := range []*http.Cookie{ownerCookie, memberCookie} {
		response := accountRequest(test, server, "GET", path+"/lifecycle", nil, cookie, nil)
		if response.Code != 200 || response.Header().Get("Cache-Control") != "no-store" {
			test.Fatal("lifecycle read failed")
		}
		payload := decodeAPI(test, response.Result())
		if payload["can_expire"] != (cookie == ownerCookie) {
			test.Fatal("lifecycle authority incorrect")
		}
	}
	for _, attempt := range []struct {
		cookie *http.Cookie
		token  string
		body   any
	}{
		{memberCookie, csrfTokenFor(memberToken), map[string]any{"revision": state.NodeExpiryRevision(node)}},
		{ownerCookie, "", map[string]any{"revision": state.NodeExpiryRevision(node)}},
		{ownerCookie, csrfTokenFor(ownerToken), map[string]any{}},
	} {
		response := accountRequest(test, server, "POST", path+"/expire", attempt.body, attempt.cookie, map[string]string{"X-CSRF-Token": attempt.token})
		if response.Code != 403 && response.Code != 400 {
			test.Fatalf("unauthorized/missing confirmation: %d", response.Code)
		}
	}
	for _, cookie := range []*http.Cookie{ownerCookie, memberCookie} {
		payload := decodeAPI(test, accountRequest(test, server, "GET", "/api/v2/auth-keys/enrollment", nil, cookie, nil).Result())
		if payload["can_manage"] != (cookie == ownerCookie) {
			test.Fatal("enrollment authority incorrect")
		}
	}
	for _, endpoint := range []string{"/api/v2/auth-keys/enrollment", "/api/v1/auth-keys"} {
		if response := accountRequest(test, server, "POST", endpoint, map[string]any{}, ownerCookie, nil); response.Code != 403 {
			test.Fatal("key issuance without CSRF accepted")
		}
	}
	if response := accountRequest(test, server, "GET", "/api/v2/machines/foreign-tenant/lifecycle", nil, ownerCookie, nil); response.Code != 404 {
		test.Fatal("unknown tenant device accepted")
	}
}

func TestTS2021EnrollmentManualExpiryAndReauthorization(test *testing.T) {
	server := newTestServer(test)
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	csrf := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	issue := func() string {
		response := accountRequest(test, server, "POST", "/api/v2/auth-keys/enrollment", map[string]any{"ttl_seconds": 900}, cookie, csrf)
		if response.Code != 201 {
			test.Fatalf("enrollment key issuance: %d", response.Code)
		}
		payload := decodeAPI(test, response.Result())
		secret := payload["key"].(string)
		if !strings.HasPrefix(secret, "tskey-auth-") || payload["reusable"] != false {
			test.Fatal("not a one-use machine credential")
		}
		if strings.Contains(accountRequest(test, server, "GET", "/api/v1/auth-keys", nil, cookie, nil).Body.String(), secret) {
			test.Fatal("list exposed credential")
		}
		return secret
	}
	transport := httptest.NewServer(server.Handler())
	defer transport.Close()
	machine := key.NewMachine()
	connection := dialNoise(test, transport, machine)
	defer connection.Close()
	client := h2Client(connection)
	nodeKey := key.NewNode().Public()
	register := func(nodeKey key.NodePublic, secret string) tailcfg.RegisterResponse {
		return decodeJSON[tailcfg.RegisterResponse](test, postRaw(test, client, "/machine/register", tailcfg.RegisterRequest{
			Version: tailcfg.CurrentCapabilityVersion, NodeKey: nodeKey, Hostinfo: &tailcfg.Hostinfo{Hostname: "one-click"},
			Auth: &tailcfg.RegisterResponseAuth{AuthKey: secret},
		}))
	}
	if response := register(nodeKey, issue()); !response.MachineAuthorized || response.AuthURL != "" {
		test.Fatal("key required browser approval")
	}
	original, _ := server.store.GetNodeByNodeKey(nodeKey)
	path := "/api/v2/machines/" + original.StableID + "/expire"
	response := accountRequest(test, server, "POST", path, map[string]any{"revision": state.NodeExpiryRevision(original)}, cookie, csrf)
	if response.Code != 200 {
		test.Fatalf("manual expiry: %d", response.Code)
	}
	expired, _ := server.store.GetNodeByID(original.ID)
	if !expired.Expired(time.Now()) || expired.IPv4 != original.IPv4 {
		test.Fatal("device not expired in place")
	}
	if registration := register(nodeKey, ""); !registration.NodeKeyExpired {
		test.Fatal("official Register did not report expired key")
	}
	mapResponse := decodeMapResponse(test, postRaw(test, client, "/machine/map", tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: nodeKey}), "")
	if mapResponse.Node == nil || !mapResponse.Node.Expired || mapResponse.Node.MachineAuthorized || !mapResponse.Node.KeyExpiry.Equal(expired.Expiry) {
		test.Fatal("official Map did not carry expiry")
	}
	if response := accountRequest(test, server, "POST", path, map[string]any{"revision": state.NodeExpiryRevision(original)}, cookie, csrf); response.Code != 409 {
		test.Fatal("stale identity confirmation accepted")
	}
	freshKey := key.NewNode().Public()
	if response := register(freshKey, issue()); !response.MachineAuthorized || response.NodeKeyExpired {
		test.Fatal("fresh key reauthorization failed")
	}
	updated, _ := server.store.GetNodeByNodeKey(freshKey)
	if updated.ID != original.ID || updated.StableID != original.StableID || updated.IPv4 != original.IPv4 || updated.IPv6 != original.IPv6 || len(server.store.ListNodes()) != 1 {
		test.Fatal("reauthentication duplicated device")
	}
}
