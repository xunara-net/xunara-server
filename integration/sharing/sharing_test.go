package sharing_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/control"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func TestDeviceSharingWithOfficialClients(test *testing.T) {
	require := func(ok bool, stage string) {
		test.Helper()
		if !ok {
			test.Fatal(stage)
		}
	}
	test.Setenv("TS_NO_LOGS_NO_SUPPORT", "true")
	directory := test.TempDir()
	derp := derpserver.New(key.NewNode(), logger.Discard)
	defer derp.Close()
	derpHTTP := httptest.NewTLSServer(derpserver.Handler(derp))
	defer derpHTTP.Close()
	_, portRaw, _ := net.SplitHostPort(derpHTTP.Listener.Addr().String())
	port, _ := strconv.Atoi(portRaw)
	derpMap := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{990: {RegionID: 990, RegionCode: "test", RegionName: "isolated sharing", Nodes: []*tailcfg.DERPNode{{Name: "990a", RegionID: 990, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: port, STUNPort: -1, InsecureForTests: true}}}}}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	source, err := control.New(control.Config{StateDir: filepath.Join(directory, "source"), Domain: "source.test", DERPMap: derpMap, Logger: quiet})
	require(err == nil, "source")
	defer source.Close()
	target, err := control.New(control.Config{StateDir: filepath.Join(directory, "target"), Domain: "target.test", DERPMap: derpMap, Logger: quiet})
	require(err == nil, "target")
	defer target.Close()
	registry, err := control.OpenShareRegistry(context.Background(), control.ShareRegistryConfig{Path: filepath.Join(directory, "shares.db")})
	require(err == nil, "registry")
	defer registry.Close()
	_, err = control.NewRouter(control.RouterConfig{Shares: registry, Orgs: []control.OrgSite{{ID: "source", Domains: []string{"source.test"}, Server: source}, {ID: "target", Domains: []string{"target.test"}, Server: target}}})
	require(err == nil, "router")
	owner, ok := source.Identity().GetUser(state.DefaultUserID)
	require(ok, "source owner")
	owner.LoginName = "sender"
	require(source.Identity().UpdateUser(owner) == nil, "source login")
	recipient, ok := target.Identity().GetUser(state.DefaultUserID)
	require(ok, "target owner")
	recipient.LoginName = "recipient"
	require(target.Identity().UpdateUser(recipient) == nil, "target login")
	sourceHTTP, targetHTTP := httptest.NewServer(source.Handler()), httptest.NewServer(target.Handler())
	defer sourceHTTP.Close()
	defer targetHTTP.Close()
	newKey := func(server *control.Server) string {
		secret, err := state.NewPreAuthKeySecret()
		require(err == nil, "auth key generation")
		auth := state.PreAuthKey{Key: secret, UserID: state.DefaultUserID, Expiry: time.Now().Add(time.Hour)}
		require(server.Store().CreatePreAuthKey(&auth) == nil, "auth key")
		return secret
	}
	sender := &tsnet.Server{Dir: filepath.Join(directory, "sender-client"), Hostname: "shared-server", ControlURL: sourceHTTP.URL, AuthKey: newKey(source), Logf: logger.Discard, UserLogf: logger.Discard}
	defer sender.Close()
	receiver := &tsnet.Server{Dir: filepath.Join(directory, "receiver-client"), Hostname: "recipient-client", ControlURL: targetHTTP.URL, AuthKey: newKey(target), Logf: logger.Discard, UserLogf: logger.Discard}
	defer receiver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	_, err = sender.Up(ctx)
	require(err == nil, "source official client up")
	_, err = receiver.Up(ctx)
	require(err == nil, "recipient official client up")
	test.Log("official-clients-registered")
	newSession := func(server *control.Server) string {
		_, token, err := server.Identity().CreateSession(identity.NewSessionOptions{UserID: state.DefaultUserID, AuthMethod: "test", TTL: time.Hour})
		require(err == nil, "human session")
		return token
	}
	sourceToken, targetToken := newSession(source), newSession(target)
	request := func(url, method, token, csrf string, body any) map[string]any {
		content, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(content))
		req.AddCookie(&http.Cookie{Name: "xunara_session", Value: token})
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		response, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
		require(err == nil, "share http")
		defer response.Body.Close()
		require(response.StatusCode < 300, "share status")
		var output map[string]any
		require(json.NewDecoder(response.Body).Decode(&output) == nil, "share response")
		return output
	}
	sourceMeta := request(sourceHTTP.URL+"/api/v2/device-shares", "GET", sourceToken, "", nil)
	targetMeta := request(targetHTTP.URL+"/api/v2/device-shares", "GET", targetToken, "", nil)
	nodes := source.Store().ListNodes()
	require(len(nodes) == 1, "source registered device")
	share := request(sourceHTTP.URL+"/api/v2/device-shares", "POST", sourceToken, sourceMeta["csrf_token"].(string), map[string]string{"node": nodes[0].StableID, "recipient_login": "recipient"})
	id := share["id"].(string)
	accepted := request(targetHTTP.URL+"/api/v2/device-shares/"+id+"/accept", "POST", targetToken, targetMeta["csrf_token"].(string), nil)
	address := accepted["ipv4"].(string)
	require(address != nodes[0].IPv4.String(), "masquerade isolation")
	listener, err := sender.Listen("tcp", ":8080")
	require(err == nil, "source listener")
	defer listener.Close()
	web := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		io.WriteString(writer, "sharing-dataplane-ok")
	})}
	defer web.Close()
	go web.Serve(listener)
	var connection net.Conn
	for attempt := 0; attempt < 12; attempt++ {
		dialCtx, stop := context.WithTimeout(ctx, 4*time.Second)
		connection, err = receiver.Dial(dialCtx, "tcp", net.JoinHostPort(address, "8080"))
		stop()
		if err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	require(err == nil, "cross-tenant TCP over masquerade")
	connection.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(connection, "GET / HTTP/1.1\r\nHost: isolated\r\nConnection: close\r\n\r\n")
	content, err := io.ReadAll(connection)
	connection.Close()
	require(err == nil && bytes.Contains(content, []byte("sharing-dataplane-ok")), "cross-tenant request and reply")
	test.Log("cross-tenant-tcp-request-and-reply-pass")
	// 两个独立地址池故意重叠，IPv4/IPv6 均通过官方 masquerade 而非跨网真实地址访问。
	targetNodes := target.Store().ListNodes()
	require(len(targetNodes) == 1 && targetNodes[0].IPv4 == nodes[0].IPv4, "overlapping native address fixture")
	ipv6, ok := accepted["ipv6"].(string)
	require(ok && ipv6 != "", "shared IPv6 address")
	connection, err = receiver.Dial(ctx, "tcp", net.JoinHostPort(ipv6, "8080"))
	require(err == nil, "cross-tenant IPv6 TCP")
	connection.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(connection, "GET / HTTP/1.1\r\nHost: isolated\r\nConnection: close\r\n\r\n")
	content, err = io.ReadAll(connection)
	connection.Close()
	require(err == nil && bytes.Contains(content, []byte("sharing-dataplane-ok")), "IPv6 request and reply")
	test.Log("overlapping-addresses-and-ipv6-pass")
	reverseListener, err := receiver.Listen("tcp", ":8081")
	require(err == nil, "recipient listener")
	defer reverseListener.Close()
	reverseWeb := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		io.WriteString(writer, "recipient-private-service")
	})}
	defer reverseWeb.Close()
	go reverseWeb.Serve(reverseListener)
	reverseAddress, _, err := source.Store().EnsureShareAddress("target", targetNodes[0].StableID)
	require(err == nil, "source-visible recipient address")
	quarantineContext, stopQuarantine := context.WithTimeout(ctx, 3*time.Second)
	connection, err = sender.Dial(quarantineContext, "tcp", net.JoinHostPort(reverseAddress.String(), "8081"))
	stopQuarantine()
	if connection != nil {
		connection.Close()
	}
	require(err != nil, "quarantine prevents source-initiated TCP")
	test.Log("quarantine-source-initiation-denied-pass")
	request(sourceHTTP.URL+"/api/v2/device-shares/"+id, "DELETE", sourceToken, sourceMeta["csrf_token"].(string), nil)
	local, err := receiver.LocalClient()
	require(err == nil, "local status")
	for attempt := 0; attempt < 80; attempt++ {
		status, err := local.Status(ctx)
		require(err == nil, "status after revoke")
		if len(status.Peer) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	dialCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	connection, err = receiver.Dial(dialCtx, "tcp", net.JoinHostPort(address, "8080"))
	if connection != nil {
		connection.Close()
	}
	require(err != nil, "revoke removed actual data access")
	test.Log("revoked-data-access-pass")
}
