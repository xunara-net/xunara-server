package control

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
)

// getDeviceList reads GET /api/v2/devices and returns the raw body (for leak
// checks) plus the decoded view.
func getDeviceList(t *testing.T, client *http.Client, baseURL, token string) (string, pendingDevicesView) {
	t.Helper()

	resp := apiRequest(t, client, http.MethodGet, baseURL+"/api/v2/devices", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list devices status = %d (%s)", resp.StatusCode, bodyString(t, resp))
	}
	raw := bodyString(t, resp)
	return raw, decodeJSON[pendingDevicesView](t, []byte(raw))
}

// TestAPIV2DeviceApproval drives the device authorization API end to end:
// list, decision scopes, approval ownership, idempotency, denial, audit
// attribution and the fail-closed error cases.
func TestAPIV2DeviceApproval(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	conn, _, _, authID := startRegistration(t, hs, "api-v2-device")
	defer conn.Close()

	da, ok := s.Identity().GetDeviceAuthorization(authID)
	if !ok {
		t.Fatalf("device authorization %s not found", authID)
	}

	// Anonymous requests are rejected before the store is consulted.
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/devices", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous list status = %d, want 401", resp.StatusCode)
	}

	// A read-scope member sees the pending device; the payload names it and
	// carries no key material.
	member := seedRoleUser(t, s, "member@example.com", identity.RoleMember)
	memberRead := seedAPIKeyForUser(t, s, member, identity.ScopeRead)
	raw, list := getDeviceList(t, client, hs.URL, memberRead)
	if strings.Contains(raw, da.MachineKey) || strings.Contains(raw, da.NodeKey) {
		t.Fatalf("device listing leaked key material: %s", raw)
	}
	if len(list.Devices) != 1 {
		t.Fatalf("devices = %+v, want one pending device", list.Devices)
	}
	device := list.Devices[0]
	if device.ID != authID || device.Hostname != "api-v2-device" {
		t.Errorf("device = %+v, want id %s hostname api-v2-device", device, authID)
	}
	if device.Created.IsZero() || device.Expires.IsZero() {
		t.Errorf("device timestamps = %+v, want both set", device)
	}

	// Field closure: changing the response shape has to be deliberate, so a
	// key or secret cannot ride along unnoticed.
	var shape struct {
		Devices []map[string]json.RawMessage `json:"devices"`
	}
	if err := json.Unmarshal([]byte(raw), &shape); err != nil {
		t.Fatalf("decoding device shape: %v", err)
	}
	got := make([]string, 0, len(shape.Devices[0]))
	for name := range shape.Devices[0] {
		got = append(got, name)
	}
	slices.Sort(got)
	if want := []string{"created", "expires", "hostname", "id", "os"}; !slices.Equal(got, want) {
		t.Errorf("device fields = %v, want %v", got, want)
	}

	// A read scope cannot decide, and the write scope alone does not make a
	// member a writer (AGENTS.md section 5: role and scope both bound).
	if resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v2/devices/"+authID+"/approve", memberRead, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("read-scope approve status = %d, want 403", resp.StatusCode)
	}
	memberWrite := seedAPIKeyForUser(t, s, member, identity.ScopeRead, identity.ScopeWrite)
	if resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v2/devices/"+authID+"/approve", memberWrite, nil); resp.StatusCode != http.StatusForbidden {
		t.Errorf("member approve status = %d, want 403", resp.StatusCode)
	}

	// An admin approves: the caller becomes the node's owner, exactly like
	// the console and the registration page.
	admin := seedRoleUser(t, s, "admin@example.com", identity.RoleAdmin)
	adminKey, adminToken, err := s.Identity().CreateAPIKey(identity.NewAPIKeyOptions{
		Name: "admin-approval", UserID: admin,
		Scopes: []string{identity.ScopeRead, identity.ScopeWrite},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v2/devices/"+authID+"/approve", adminToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status = %d (%s)", resp.StatusCode, bodyString(t, resp))
	}
	decided := decodeAPI(t, resp)
	if decided["id"] != authID || decided["state"] != string(identity.DeviceApproved) {
		t.Errorf("approve response = %v", decided)
	}

	approved, ok := s.Identity().GetDeviceAuthorization(authID)
	if !ok || approved.State != identity.DeviceApproved || approved.UserID != admin {
		t.Fatalf("device authorization = %+v (ok=%v), want approved by %d", approved, ok, admin)
	}
	node, ok := s.Store().GetNodeByNodeKey(nodeKeyOfRegistration(t, s, authID))
	if !ok {
		t.Fatal("approving through the API did not create the node")
	}
	if node.UserID != admin {
		t.Errorf("node owner = %d, want the approving user %d", node.UserID, admin)
	}

	// Repeating the same decision is idempotent; the opposite one conflicts.
	if resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v2/devices/"+authID+"/approve", adminToken, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("repeated approve status = %d, want 200", resp.StatusCode)
	}
	if resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v2/devices/"+authID+"/deny", adminToken, nil); resp.StatusCode != http.StatusConflict {
		t.Errorf("deny-after-approve status = %d, want 409", resp.StatusCode)
	}

	// The decision is attributed to the API key that made it.
	audited := false
	for _, e := range s.Identity().ListAudit(0) {
		if e.Action == identity.AuditNodeApproved && strings.Contains(e.Actor, "/apikey:"+adminKey.ID) {
			audited = true
		}
	}
	if !audited {
		t.Error("device approval was not attributed to the API key")
	}

	// A second device is denied; the decision sticks and it leaves the list.
	denyConn, _, _, denyID := startRegistration(t, hs, "api-v2-denied")
	defer denyConn.Close()
	resp = apiRequest(t, client, http.MethodPost, hs.URL+"/api/v2/devices/"+denyID+"/deny", adminToken, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deny status = %d (%s)", resp.StatusCode, bodyString(t, resp))
	}
	if decided := decodeAPI(t, resp); decided["state"] != string(identity.DeviceDenied) {
		t.Errorf("deny response = %v", decided)
	}
	if denied, ok := s.Identity().GetDeviceAuthorization(denyID); !ok || denied.State != identity.DeviceDenied {
		t.Fatalf("denied authorization = %+v (ok=%v)", denied, ok)
	}
	deniedAudited := false
	for _, e := range s.Identity().ListAudit(0) {
		if e.Action == identity.AuditDeviceDenied && strings.Contains(e.Actor, "/apikey:"+adminKey.ID) {
			deniedAudited = true
		}
	}
	if !deniedAudited {
		t.Error("device denial was not attributed to the API key")
	}
	if _, list = getDeviceList(t, client, hs.URL, memberRead); len(list.Devices) != 0 {
		t.Errorf("pending devices after decisions = %+v, want none", list.Devices)
	}

	// Unknown IDs are 404 on both decisions.
	for _, action := range []string{"approve", "deny"} {
		resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v2/devices/deadbeef/"+action, adminToken, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s of an unknown device status = %d, want 404", action, resp.StatusCode)
		}
	}

	// An authorization that aged out is 410 (gone, restart the flow), not a
	// silent success.
	if _, err := s.Identity().CreateDeviceAuthorization(identity.NewDeviceAuthorizationOptions{
		ID:         "expired-device",
		MachineKey: key.NewMachine().Public().String(),
		NodeKey:    key.NewNode().Public().String(),
		TTL:        time.Nanosecond,
	}); err != nil {
		t.Fatalf("CreateDeviceAuthorization: %v", err)
	}
	if resp := apiRequest(t, client, http.MethodPost, hs.URL+"/api/v2/devices/expired-device/approve", adminToken, nil); resp.StatusCode != http.StatusGone {
		t.Errorf("expired approve status = %d, want 410", resp.StatusCode)
	}
}

// TestAPIV2DeviceListClaims checks the client's own claims (ephemeral, tags)
// reach the approver, and that the list is capped with a truncation marker.
func TestAPIV2DeviceListClaimsAndCap(t *testing.T) {
	s := newTestServer(t)
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()
	_, token := seedAPIKey(t, s, identity.ScopeRead)

	meta := encodeDeviceMetadata(tailcfg.RegisterRequest{
		Ephemeral: true,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname:    "tagged-device",
			OS:          "linux",
			RequestTags: []string{"tag:example"},
		},
	})
	if _, err := s.Identity().CreateDeviceAuthorization(identity.NewDeviceAuthorizationOptions{
		ID:             "tagged-device",
		MachineKey:     key.NewMachine().Public().String(),
		NodeKey:        key.NewNode().Public().String(),
		ClientMetadata: meta,
		TTL:            time.Minute,
	}); err != nil {
		t.Fatalf("CreateDeviceAuthorization: %v", err)
	}

	_, list := getDeviceList(t, client, hs.URL, token)
	if len(list.Devices) != 1 {
		t.Fatalf("devices = %+v, want one", list.Devices)
	}
	if !list.Devices[0].Ephemeral || !slices.Equal(list.Devices[0].RequestedTags, []string{"tag:example"}) {
		t.Errorf("device claims = %+v, want ephemeral with tag:example", list.Devices[0])
	}
	if list.Truncated {
		t.Error("a one-device list reports truncation")
	}

	// Fill past the cap: the response is bounded, says so, and keeps the
	// newest requests (the ones that can still be decided).
	for i := 0; i <= pendingDeviceLimit; i++ {
		if _, err := s.Identity().CreateDeviceAuthorization(identity.NewDeviceAuthorizationOptions{
			ID:         "filler-" + itoa64(uint64(i)),
			MachineKey: key.NewMachine().Public().String(),
			NodeKey:    key.NewNode().Public().String(),
			TTL:        time.Minute,
		}); err != nil {
			t.Fatalf("CreateDeviceAuthorization(%d): %v", i, err)
		}
	}

	_, list = getDeviceList(t, client, hs.URL, token)
	if !list.Truncated {
		t.Error("list past the cap does not report truncation")
	}
	if len(list.Devices) != pendingDeviceLimit {
		t.Fatalf("capped list has %d devices, want %d", len(list.Devices), pendingDeviceLimit)
	}
	if got := list.Devices[0].ID; got != "filler-"+itoa64(uint64(pendingDeviceLimit)) {
		t.Errorf("first (newest) device = %s, want the last created", got)
	}
	if got := list.Devices[len(list.Devices)-1].ID; got != "filler-1" {
		t.Errorf("last (oldest kept) device = %s, want filler-1", got)
	}
	for _, device := range list.Devices {
		if device.ID == "tagged-device" || device.ID == "filler-0" {
			t.Errorf("truncated list still contains the oldest device %s", device.ID)
		}
	}
}
