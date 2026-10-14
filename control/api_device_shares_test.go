package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func deviceShareRequest(t *testing.T, server *Server, cookie *http.Cookie, method, path string, body any, csrf bool) *httptest.ResponseRecorder {
	t.Helper()
	content, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(content))
	request.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		request.AddCookie(cookie)
		if csrf {
			request.Header.Set("X-CSRF-Token", csrfTokenFor(cookie.Value))
		}
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	return response
}

func decodeDeviceShare(t *testing.T, response *httptest.ResponseRecorder, status int) deviceShareView {
	t.Helper()
	if response.Code != status {
		t.Fatalf("share response = %d: %s", response.Code, response.Body.String())
	}
	var view deviceShareView
	if err := json.Unmarshal(response.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	return view
}

func listDeviceShareViews(t *testing.T, server *Server, cookie *http.Cookie) []deviceShareView {
	t.Helper()
	response := deviceShareRequest(t, server, cookie, "GET", "/api/v2/device-shares", nil, false)
	if response.Code != http.StatusOK {
		t.Fatalf("list shares: %d %s", response.Code, response.Body)
	}
	var payload struct {
		Items []deviceShareView `json:"items"`
		CSRF  string            `json:"csrf_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CSRF == "" || payload.Items == nil {
		t.Fatal("missing durable-session csrf or explicit list")
	}
	return payload.Items
}

func TestAccountDeviceSharesLifecycle(t *testing.T) {
	_, _, source, target := newShareRouter(t, t.TempDir())
	node := seedAPIMachine(t, source, "shared-laptop", nil)
	node.DiscoKey = key.NewDisco().Public()
	if err := source.store.UpdateNode(node); err != nil {
		t.Fatal(err)
	}
	userID := seedRoleUser(t, target, "recipient", identity.RoleMember)
	otherID := seedRoleUser(t, target, "other-member", identity.RoleMember)
	clientNode := state.Node{MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(), DiscoKey: key.NewDisco().Public(), UserID: userID, Hostname: "recipient-phone"}
	if err := target.store.CreateNode(&clientNode); err != nil {
		t.Fatal(err)
	}
	sourceCookie, _ := seedUserSession(t, source, state.DefaultUserID)
	targetCookie, _ := seedUserSession(t, target, userID)
	otherCookie, _ := seedUserSession(t, target, otherID)
	body := map[string]string{"node": node.StableID, "recipient_login": "RECIPIENT"}
	if response := deviceShareRequest(t, source, sourceCookie, "POST", "/api/v2/device-shares", body, false); response.Code != 403 {
		t.Fatal("cookie mutation without CSRF accepted")
	}
	created := decodeDeviceShare(t, deviceShareRequest(t, source, sourceCookie, "POST", "/api/v2/device-shares", body, true), 201)
	if created.TargetUser != "recipient" || created.CreatedBy != "local" || !created.CanRevoke || created.CanDecide || !created.Available || created.Direction != "outgoing" {
		t.Fatalf("created share = %+v", created)
	}
	if response := deviceShareRequest(t, source, sourceCookie, "POST", "/api/v2/device-shares", body, true); response.Code != 409 {
		t.Fatalf("duplicate = %d", response.Code)
	}
	incoming := listDeviceShareViews(t, target, targetCookie)
	if len(incoming) != 1 || !incoming[0].CanDecide || incoming[0].IPv4 != "" || incoming[0].IPv6 != "" {
		t.Fatalf("pending inbox = %+v", incoming)
	}
	if target.sharePeersFor(clientNode) != nil {
		t.Fatal("pending invitation exposes a peer")
	}
	if list := listDeviceShareViews(t, target, otherCookie); len(list) != 0 {
		t.Fatal("another member can read invitation")
	}
	path := "/api/v2/device-shares/" + created.ID
	if response := deviceShareRequest(t, target, otherCookie, "POST", path+"/accept", nil, true); response.Code != 404 {
		t.Fatal("another member accepted")
	}
	request := httptest.NewRequest("POST", path+"/accept", nil)
	request.Header.Set("Authorization", "Bearer "+seedAPIKeyForUser(t, target, userID))
	response := httptest.NewRecorder()
	target.Handler().ServeHTTP(response, request)
	if response.Code != 403 {
		t.Fatal("service key accepted human invitation")
	}
	accepted := decodeDeviceShare(t, deviceShareRequest(t, target, targetCookie, "POST", path+"/accept", nil, true), 200)
	if accepted.Status != ShareAccepted || accepted.IPv4 == "" || accepted.IPv4 == node.IPv4.String() || accepted.DNSName == "" || accepted.CanDecide || !accepted.CanRevoke {
		t.Fatalf("accepted = %+v", accepted)
	}
	if len(target.store.ListNodes()) != 1 {
		t.Fatal("foreign machine added to tenant-owned CRUD objects")
	}
	if len(listDeviceShareViews(t, source, sourceCookie)) != 1 {
		t.Fatal("source cannot manage outgoing share")
	}
	if peers := target.sharePeersFor(clientNode); peers == nil || len(peers.nodes) != 1 || peers.nodes[0].NodeKey != node.NodeKey || peers.nodes[0].MachineKey != node.MachineKey || peers.nodes[0].DiscoKey != node.DiscoKey {
		t.Fatal("missing public protocol keys")
	}
	if response := deviceShareRequest(t, target, targetCookie, "POST", "/api/v2/shares/"+created.ID+"/accept", nil, true); response.Code != 403 {
		t.Fatal("legacy route can mutate account-targeted share")
	}
	if response := deviceShareRequest(t, target, targetCookie, "POST", path+"/reject", nil, true); response.Code != 409 {
		t.Fatal("accepted invitation can be rejected")
	}
	removed := decodeDeviceShare(t, deviceShareRequest(t, target, targetCookie, "DELETE", path, nil, true), 200)
	if removed.Status != ShareRevoked || removed.CanRevoke || removed.IPv4 != "" {
		t.Fatal("revoke retained permissions")
	}
	if target.sharePeersFor(clientNode) != nil || source.sharePeersFor(node) != nil {
		t.Fatal("revoke left foreign peers")
	}
	decodeDeviceShare(t, deviceShareRequest(t, source, sourceCookie, "DELETE", path, nil, true), 200)
	created = decodeDeviceShare(t, deviceShareRequest(t, source, sourceCookie, "POST", "/api/v2/device-shares", body, true), 201)
	decodeDeviceShare(t, deviceShareRequest(t, target, targetCookie, "POST", "/api/v2/device-shares/"+created.ID+"/reject", nil, true), 200)
}

func TestAccountShareLifetimeAndLookupBoundaries(t *testing.T) {
	router, _, source, target := newShareRouter(t, t.TempDir())
	node := seedAPIMachine(t, source, "laptop", nil)
	userID := seedRoleUser(t, target, "recipient", identity.RoleMember)
	actor := shareTestPrincipal(state.DefaultUserID, identity.RoleOwner)
	for _, login := range []string{"", "missing", "bad\nname", "bad name"} {
		if _, err := source.prepareAccountShare(t.Context(), actor, node.StableID, login); !errors.Is(err, errShareAccountUnknown) {
			t.Fatalf("invalid target %q: %v", login, err)
		}
	}
	share, err := source.prepareAccountShare(t.Context(), actor, node.StableID, "recipient")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := source.boundShareParties(share); !ok {
		t.Fatal("fresh share not bound")
	}
	clone := share
	clone.SourceStableID = "another-node"
	if _, _, _, ok := source.boundShareParties(clone); ok {
		t.Fatal("numeric node ID can rebind")
	}
	clone = share
	clone.SourceUserCreated++
	if _, _, _, ok := source.boundShareParties(clone); ok {
		t.Fatal("replaced creator can rebind")
	}
	clone = share
	clone.TargetAccountCreated++
	if _, _, _, ok := source.boundShareParties(clone); ok {
		t.Fatal("replaced recipient can rebind")
	}
	previous := target.noiseKey
	target.noiseKey = key.NewMachine()
	if _, _, _, ok := source.boundShareParties(share); ok {
		t.Fatal("new tenant lifetime can inherit share")
	}
	target.noiseKey = previous
	duplicate := seedRoleUser(t, source, "recipient", identity.RoleMember)
	if _, _, err := router.ResolveShareAccount(t.Context(), "RECIPIENT"); !errors.Is(err, errShareAccountUnknown) {
		t.Fatal("duplicate login guessed a tenant")
	}
	if err := source.identity.DeleteUser(duplicate); err != nil {
		t.Fatal(err)
	}
	user, _ := target.identity.GetUser(userID)
	if _, err := target.identity.SetUserStatusByPlatform(t.Context(), userID, identity.UserStatusChange{Disabled: true, Reason: "test", ExpectedUpdatedAt: user.UpdatedAt}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := source.boundShareParties(share); ok {
		t.Fatal("disabled user still has shared access")
	}
	if _, _, err := router.ResolveShareAccount(t.Context(), "recipient"); !errors.Is(err, errShareAccountUnknown) {
		t.Fatal("disabled user can receive")
	}
	if err := target.identity.DeleteUser(userID); err != nil {
		t.Fatal(err)
	}
	seedRoleUser(t, target, "recipient", identity.RoleMember)
	if _, _, _, ok := source.boundShareParties(share); ok {
		t.Fatal("re-registered user inherited old share")
	}
}

func TestAccountShareActorRecheckedUnderLock(t *testing.T) {
	_, _, source, target := newShareRouter(t, t.TempDir())
	userID := seedRoleUser(t, source, "writer", identity.RoleAdmin)
	cookie, _ := seedUserSession(t, source, userID)
	request := httptest.NewRequest("GET", "/", nil)
	request.AddCookie(cookie)
	actor, err := source.authenticateAPI(request)
	if err != nil {
		t.Fatal(err)
	}
	user, _ := source.identity.GetUser(userID)
	user.Role = identity.RoleMember
	if err := source.identity.UpdateUser(user); err != nil {
		t.Fatal(err)
	}
	called := false
	callback := func() (Share, error) { called = true; return Share{}, nil }
	if _, err := source.withShareActor(t.Context(), actor, true, callback); !errors.Is(err, identity.ErrNetworkWriterForbidden) || called {
		t.Fatal("downgraded snapshot can share")
	}
	if err := source.identity.RevokeSession(actor.Session.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.withShareActor(t.Context(), actor, false, callback); !errors.Is(err, identity.ErrSessionRevoked) || called {
		t.Fatal("revoked session can accept")
	}
	if target.sharingEnabled() != true {
		t.Fatal("fixture sharing disabled")
	}
}

func TestSharedNodePublicKeysOverOfficialNoise(t *testing.T) {
	fixture := newShareFixture(t)
	fixture.y.DiscoKey = key.NewDisco().Public()
	if err := fixture.acme.store.UpdateNode(fixture.y); err != nil {
		t.Fatal(err)
	}
	private := key.NewMachine()
	fixture.x.MachineKey = private.Public()
	if err := fixture.globex.store.UpdateNode(fixture.x); err != nil {
		t.Fatal(err)
	}
	host := httptest.NewServer(fixture.globex.Handler())
	defer host.Close()
	connection := dialNoise(t, host, private)
	defer connection.Close()
	client := h2Client(connection)
	response := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: fixture.x.NodeKey}), "")
	if len(response.Peers) != 1 {
		t.Fatalf("official Noise map peers = %d", len(response.Peers))
	}
	peer := response.Peers[0]
	if peer.Key != fixture.y.NodeKey || peer.Machine != fixture.y.MachineKey || peer.DiscoKey != fixture.y.DiscoKey || peer.Key.IsZero() {
		t.Fatal("wire netmap lost shared public keys")
	}
	if peer.SelfNodeV4MasqAddrForThisPeer == nil || peer.SelfNodeV6MasqAddrForThisPeer == nil || len(peer.AllowedIPs) != 2 || peer.Hostinfo.AsStruct().RoutableIPs != nil {
		t.Fatal("wire netmap has invalid masquerade or foreign subnet routes")
	}
	for _, prefix := range peer.Addresses {
		if prefix.Addr() == fixture.y.IPv4 || prefix.Addr() == fixture.y.IPv6 {
			t.Fatal("real foreign addresses leaked")
		}
	}
	if _, err := fixture.acme.revokeShare(context.Background(), shareTestPrincipal(state.DefaultUserID, identity.RoleOwner), fixture.share.ID); err != nil {
		t.Fatal(err)
	}
	updated := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{Version: tailcfg.CurrentCapabilityVersion, NodeKey: fixture.x.NodeKey}), "")
	if len(updated.Peers) != 0 {
		t.Fatal("official client retains peer after revoke")
	}
}
