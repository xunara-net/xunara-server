package control

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/state"
)

// registerPreAuthedNode registers a node authorised by a pre-auth key and
// returns its live Noise connection, HTTP client and node key.
func registerPreAuthedNode(t *testing.T, hs *httptest.Server, hostname, secret string) (net.Conn, *http.Client, key.NodePrivate) {
	t.Helper()

	machineKey := key.NewMachine()
	nodeKey := key.NewNode()

	conn := dialNoise(t, hs, machineKey)
	client := h2Client(conn)

	resp := decodeJSON[tailcfg.RegisterResponse](t, postRaw(t, client, "/machine/register", tailcfg.RegisterRequest{
		Version:  tailcfg.CurrentCapabilityVersion,
		NodeKey:  nodeKey.Public(),
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: secret},
		Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
	}))
	if !resp.MachineAuthorized {
		t.Fatalf("pre-authed registration was not authorized: %+v", resp)
	}
	return conn, client, nodeKey
}

// TestNodeAttrsCapsReachNetmap checks policy nodeAttrs grants land in the
// netmap CapMap of the nodes the target names, and only those.
func TestNodeAttrsCapsReachNetmap(t *testing.T) {
	s := newServerWithConfig(t, Config{
		PolicyPath: policyFile(t, `{
			"tagOwners": {"tag:server": ["local"]},
			"nodeAttrs": [{"target": ["tag:server"], "attr": ["https"]}],
			"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
		}`),
	})
	hs := newTestHTTPServer(t, s)

	secret := seedPreAuthKey(t, s, state.PreAuthKey{Tags: []string{"tag:server"}})
	serverConn, serverClient, serverKey := registerPreAuthedNode(t, hs, "attrs-server", secret)
	defer serverConn.Close()
	clientConn, clientClient, clientKey := registerNode(t, s, hs, "attrs-client")
	defer clientConn.Close()

	resp := decodeMapResponse(t, postRaw(t, serverClient, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: serverKey.Public(),
	}), "")

	if resp.Node == nil {
		t.Fatal("no self node in the map response")
	}
	if _, ok := resp.Node.CapMap[tailcfg.CapabilityHTTPS]; !ok {
		t.Errorf("tagged self CapMap = %v, want %s", resp.Node.CapMap, tailcfg.CapabilityHTTPS)
	}
	if _, ok := resp.Node.CapMap[tailcfg.CapabilitySSH]; ok {
		t.Errorf("self CapMap = %v, want no cap/ssh without an ssh section", resp.Node.CapMap)
	}

	var peerSeen bool
	for _, peer := range resp.Peers {
		if strings.HasPrefix(peer.Name, "attrs-client.") {
			peerSeen = true
			if len(peer.CapMap) != 0 {
				t.Errorf("untagged peer CapMap = %v, want none", peer.CapMap)
			}
		}
	}
	if !peerSeen {
		t.Fatalf("peer attrs-client missing from netmap: %+v", resp.Peers)
	}

	// The untagged node's own netmap must not carry the grant either.
	plain := decodeMapResponse(t, postRaw(t, clientClient, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: clientKey.Public(),
	}), "")
	if len(plain.Node.CapMap) != 0 {
		t.Errorf("untagged self CapMap = %v, want none", plain.Node.CapMap)
	}
}

// TestNodeAttrsNoGrantMeansNoCapMap keeps a tailnet without nodeAttrs free of
// capabilities.
func TestNodeAttrsNoGrantMeansNoCapMap(t *testing.T) {
	s := newServerWithConfig(t, Config{
		PolicyPath: policyFile(t, `{
			"tagOwners": {"tag:server": ["local"]},
			"nodeAttrs": [{"target": ["tag:server"], "attr": ["https"]}],
			"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
		}`),
	})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "plain")
	defer conn.Close()

	resp := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")
	if len(resp.Node.CapMap) != 0 {
		t.Errorf("CapMap = %v, want none for an untargeted node", resp.Node.CapMap)
	}
}

// TestNodeAttrsMergeWithSSHCap checks a node that both is an SSH destination
// and holds nodeAttrs grants advertises both capabilities.
func TestNodeAttrsMergeWithSSHCap(t *testing.T) {
	s := newServerWithConfig(t, Config{
		PolicyPath: policyFile(t, `{
			"nodeAttrs": [{"target": ["autogroup:member"], "attr": ["https"]}],
			"ssh": [{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["autogroup:self"],
				"users": ["root"],
			}],
			"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
		}`),
	})
	hs := newTestHTTPServer(t, s)

	conn, client, nodeKey := registerNode(t, s, hs, "both")
	defer conn.Close()

	resp := decodeMapResponse(t, postRaw(t, client, "/machine/map", tailcfg.MapRequest{
		Version: tailcfg.CurrentCapabilityVersion,
		NodeKey: nodeKey.Public(),
	}), "")
	if _, ok := resp.Node.CapMap[tailcfg.CapabilityHTTPS]; !ok {
		t.Errorf("CapMap = %v, want %s from nodeAttrs", resp.Node.CapMap, tailcfg.CapabilityHTTPS)
	}
	if _, ok := resp.Node.CapMap[tailcfg.CapabilitySSH]; !ok {
		t.Errorf("CapMap = %v, want %s from the ssh section", resp.Node.CapMap, tailcfg.CapabilitySSH)
	}
}
