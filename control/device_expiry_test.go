package control

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestDeviceExpirySettingsAPIValidationAndPermissions(test *testing.T) {
	server := newTestServer(test)
	owner, token := seedUserSession(test, server, state.DefaultUserID)
	member, memberToken := seedUserSession(test, server, seedRoleUser(test, server, "expiry-settings-reader", identity.RoleMember))
	node := state.Node{MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), UserID: state.DefaultUserID}
	if err := server.store.CreateNode(&node); err != nil {
		test.Fatal(err)
	}
	endpoint := "/api/v2/machines/" + node.StableID + "/expiry"
	csrf := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	body := func(mode string) map[string]any {
		return map[string]any{"revision": state.NodeExpiryRevision(node), "mode": mode}
	}
	for _, attempt := range []struct {
		cookie  *http.Cookie
		headers map[string]string
	}{
		{nil, nil}, {owner, nil}, {member, map[string]string{"X-CSRF-Token": csrfTokenFor(memberToken)}},
	} {
		response := accountRequest(test, server, "POST", endpoint, body("disable"), attempt.cookie, attempt.headers)
		if response.Code != 401 && response.Code != 403 {
			test.Fatalf("unauthorized expiry: %d", response.Code)
		}
	}
	for _, invalid := range []map[string]any{
		body("schedule"), body("unknown"), {"mode": "disable"},
		{"revision": state.NodeExpiryRevision(node), "mode": "schedule", "duration_seconds": 0},
		{"revision": state.NodeExpiryRevision(node), "mode": "schedule", "duration_seconds": 86400.5},
		{"revision": state.NodeExpiryRevision(node), "mode": "schedule", "expires_at": "not-a-time"},
		{"revision": state.NodeExpiryRevision(node), "mode": "schedule", "expires_at": time.Now().Add(-time.Hour)},
		{"revision": state.NodeExpiryRevision(node), "mode": "schedule", "expires_at": time.Now().Add(time.Hour), "duration_seconds": 86400},
		{"revision": state.NodeExpiryRevision(node), "mode": "disable", "duration_seconds": 86400},
		{"revision": state.NodeExpiryRevision(node), "mode": "disable", "unexpected": true},
	} {
		response := accountRequest(test, server, "POST", endpoint, invalid, owner, csrf)
		if response.Code != 400 {
			test.Fatalf("invalid expiry: %d", response.Code)
		}
	}
	if response := accountRequest(test, server, "POST", endpoint, body("extend"), owner, csrf); response.Code != 409 {
		test.Fatal("active device extended")
	}
	if response := accountRequest(test, server, "POST", "/api/v2/machines/foreign-tenant/expiry", body("disable"), owner, csrf); response.Code != 404 {
		test.Fatal("foreign device accepted")
	}
	readback := decodeAPI(test, accountRequest(test, server, "GET", "/api/v2/machines/"+node.StableID+"/lifecycle", nil, owner, nil).Result())
	policy := readback["expiry_policy"].(map[string]any)
	if policy["extension_seconds"] != float64(1800) || policy["max_duration_seconds"] != float64(180*86400) || readback["server_time"] == nil {
		test.Fatal("expiry policy missing")
	}
}

func TestTS2021DeviceExpirySettingsMapAndRecovery(test *testing.T) {
	server := newTestServer(test)
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	csrf := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	machine, nodeKey := key.NewMachine(), key.NewNode().Public()
	node := state.Node{MachineKey: machine.Public(), NodeKey: nodeKey, UserID: state.DefaultUserID}
	if err := server.store.CreateNode(&node); err != nil {
		test.Fatal(err)
	}
	transport := httptest.NewServer(server.Handler())
	defer transport.Close()
	connection := dialNoise(test, transport, machine)
	defer connection.Close()
	client := h2Client(connection)
	for _, mode := range []string{"schedule", "disable", "expire", "extend"} {
		body := map[string]any{"revision": state.NodeExpiryRevision(node), "mode": mode}
		if mode == "schedule" {
			body["duration_seconds"] = 86400
		}
		response := accountRequest(test, server, "POST", "/api/v2/machines/"+node.StableID+"/expiry", body, cookie, csrf)
		if response.Code != 200 {
			test.Fatalf("%s: %d", mode, response.Code)
		}
		node, _ = server.store.GetNodeByID(node.ID)
		mapping := decodeMapResponse(test, postRaw(test, client, "/machine/map", tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: nodeKey}), "")
		if mapping.Node == nil || !mapping.Node.KeyExpiry.Equal(node.Expiry) || mapping.Node.Expired != (mode == "expire") || mapping.Node.MachineAuthorized != (mode != "expire") {
			test.Fatalf("official Map expiry mismatch: %s", mode)
		}
		if mode == "expire" {
			for _, rejected := range []string{"schedule", "disable"} {
				body["revision"], body["mode"] = state.NodeExpiryRevision(node), rejected
				if rejected == "schedule" {
					body["duration_seconds"] = 86400
				} else {
					delete(body, "duration_seconds")
				}
				if response := accountRequest(test, server, "POST", "/api/v2/machines/"+node.StableID+"/expiry", body, cookie, csrf); response.Code != 409 {
					test.Fatal("expired device silently restored")
				}
			}
		}
	}
	registration := decodeJSON[tailcfg.RegisterResponse](test, postRaw(test, client, "/machine/register", tailcfg.RegisterRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: nodeKey}))
	if !registration.MachineAuthorized || registration.NodeKeyExpired {
		test.Fatal("official Register did not recognize temporary window")
	}
}
