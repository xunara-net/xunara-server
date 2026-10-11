package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func pinnedRelayHealthFixture(test *testing.T, status int) (state.Relay, func(context.Context, string, string) (net.Conn, error)) {
	test.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		test.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay.example.com"},
		DNSNames: []string{"relay.example.com"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	encoded, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &private.PublicKey, private)
	if err != nil {
		test.Fatal(err)
	}
	encodedKey, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		test.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encodedKey}))
	if err != nil {
		test.Fatal(err)
	}
	fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/derp/probe" || request.URL.RawQuery != "" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			test.Error("probe forwarded credentials or reached a non-probe path")
		}
		if status == 302 {
			writer.Header().Set("Location", "https://127.0.0.1/private")
		}
		writer.WriteHeader(status)
	}))
	fixture.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	fixture.StartTLS()
	test.Cleanup(fixture.Close)
	digest := sha256.Sum256(encoded)
	relay := state.Relay{ID: "health-fixture", HostName: "relay.example.com", DERPPort: 443, ConfigVersion: 3,
		CertName: "sha256-raw:" + hex.EncodeToString(digest[:])}
	// 只在隔离 TLS 夹具替代 TCP 目标；生产 handler 固定使用带公网/DNS 校验的 dialer。
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, fixture.Listener.Addr().String())
	}
	return relay, dial
}

func TestRelayProbeRealTLSAndNoRedirect(test *testing.T) {
	for _, status := range []int{200, 302, 503} {
		relay, dial := pinnedRelayHealthFixture(test, status)
		result := probeManagedRelay(test.Context(), relay, dial)
		if !result.TLSVerified || result.HTTPStatus != status || result.RelayID != relay.ID || result.ConfigVersion != 3 {
			test.Fatal("TLS/target facts missing")
		}
		if (result.Status == "reachable") != (status == 200) || (result.LatencyMilliseconds != nil) != (status == 200) {
			test.Fatal("redirect/failed probe reported as reachable")
		}
	}
}

func TestRelayProbeRejectsWrongPinAndCancellation(test *testing.T) {
	relay, dial := pinnedRelayHealthFixture(test, 200)
	relay.CertName = "sha256-raw:" + strings.Repeat("0", 64)
	if result := probeManagedRelay(test.Context(), relay, dial); result.Status != "unreachable" || result.TLSVerified {
		test.Fatal("wrong pin accepted")
	}
	relay.CertName = "sha256-raw:bad"
	if result := probeManagedRelay(test.Context(), relay, dial); result.Code != "TLS_PIN_INVALID" {
		test.Fatal("bad pin not blocked")
	}
	ctx, cancel := context.WithCancel(test.Context())
	cancel()
	relay.CertName = ""
	if result := probeManagedRelay(ctx, relay, dial); result.Status == "reachable" {
		test.Fatal("canceled probe succeeded")
	}
}

func TestRelayProbeBlocksReservedTargetsBeforeDial(test *testing.T) {
	for _, hostname := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254", "::1", "fc00::1", "64:ff9b::7f00:1", "192.0.2.1", "localhost", "metadata.internal"} {
		called := false
		result := probeManagedRelay(test.Context(), state.Relay{HostName: hostname, DERPPort: 443}, func(context.Context, string, string) (net.Conn, error) {
			called = true
			return nil, context.Canceled
		})
		if called || result.Status != "blocked" {
			test.Fatalf("reserved target was not blocked: %s", hostname)
		}
	}
}

func TestRelayHealthAPICSRFRateAuditAndUnchangedState(test *testing.T) {
	server := newTestServer(test)
	secret, err := state.NewRelayTokenSecret()
	if err != nil {
		test.Fatal(err)
	}
	if err := server.store.CreateRelay(state.Relay{ID: "health-local", HostName: "127.0.0.1", DERPPort: 9091, DesiredState: "online"}, secret); err != nil {
		test.Fatal(err)
	}
	before, err := server.lookupManagedRelay(test.Context(), "health-local")
	if err != nil {
		test.Fatal(err)
	}
	cookie, token := seedUserSession(test, server, state.DefaultUserID)
	endpoint := "/api/v2/relays/health-local/health"
	if response := accountRequest(test, server, http.MethodPost, endpoint, map[string]any{}, nil, nil); response.Code != 401 {
		test.Fatal("anonymous probe allowed")
	}
	if response := accountRequest(test, server, http.MethodPost, endpoint, map[string]any{}, cookie, nil); response.Code != 403 {
		test.Fatal("CSRF was not required")
	}
	member := seedRoleUser(test, server, "health-member", identity.RoleMember)
	memberCookie, memberToken := seedUserSession(test, server, member)
	if response := accountRequest(test, server, http.MethodPost, endpoint, map[string]any{}, memberCookie,
		map[string]string{"X-CSRF-Token": csrfTokenFor(memberToken)}); response.Code != 403 {
		test.Fatal("member allowed privileged probe")
	}
	host := newTestHTTPServer(test, server)
	_, readKey := seedAPIKey(test, server, identity.ScopeRead)
	response := apiRequest(test, host.Client(), http.MethodPost, host.URL+endpoint, readKey, map[string]any{})
	if response.StatusCode != 403 {
		test.Fatal("read-only API key allowed active probe")
	}
	readBody(test, response)
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	for index := 0; index < 12; index++ {
		response := accountRequest(test, server, http.MethodPost, endpoint, map[string]any{}, cookie, headers)
		var result relayHealthResult
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Status != "blocked" || strings.Contains(response.Body.String(), secret) {
			test.Fatal("blocked target result invalid or exposes service credential")
		}
	}
	recorder := accountRequest(test, server, http.MethodPost, endpoint, map[string]any{}, cookie, headers)
	if recorder.Code != 429 || recorder.Header().Get("Retry-After") == "" {
		test.Fatal("probe rate not bounded")
	}
	after, err := server.lookupManagedRelay(test.Context(), "health-local")
	if err != nil || !reflect.DeepEqual(before, after) {
		test.Fatal("probe changed stored relay heartbeat/configuration")
	}
	events := server.identity.ListAudit(0)
	count := 0
	for _, event := range events {
		if event.Action == "relay.health_checked" {
			count++
		}
	}
	if count != 12 {
		test.Fatal("probe audits missing")
	}
	recorder = accountRequest(test, server, http.MethodPost, "/api/v2/relays/missing/health", map[string]any{}, cookie, headers)
	if recorder.Code != 404 {
		test.Fatal("unknown relay did not fail closed")
	}
}

func TestRelayHealthAPIAuditFailureDoesNotReturnSuccess(test *testing.T) {
	for _, failure := range []string{"RAISE(ABORT, 'fixture')", "RAISE(IGNORE)"} {
		server := newTestServer(test)
		seedConfigurationRelay(test, server)
		cookie, token := seedUserSession(test, server, state.DefaultUserID)
		database := server.store.(*state.SQLiteStore).DB()
		if _, err := database.Exec(`CREATE TRIGGER reject_health_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'relay.health_checked' BEGIN SELECT ` + failure + `; END`); err != nil {
			test.Fatal(err)
		}
		response := accountRequest(test, server, http.MethodPost, "/api/v2/relays/relay-history/health", map[string]any{}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
		if response.Code != 503 || strings.Contains(response.Body.String(), `"status"`) {
			test.Fatal("unrecorded probe reported success")
		}
	}
}

func TestRelayHealthTenantBoundary(test *testing.T) {
	first, second := newTestServer(test), newTestServer(test)
	for _, server := range []*Server{first, second} {
		seedConfigurationRelay(test, server)
	}
	_, firstToken := seedAPIKey(test, first, identity.ScopeWrite)
	_, secondToken := seedAPIKey(test, second, identity.ScopeWrite)
	router := newTestRouter(test, RouterConfig{Orgs: []OrgSite{
		{ID: "first", Domains: []string{"first.example.com"}, Server: first},
		{ID: "second", Domains: []string{"second.example.com"}, Server: second},
	}})
	host := httptest.NewServer(router.Handler())
	defer host.Close()
	for index, attempt := range []struct {
		hostname, token string
		expected        int
	}{
		{"first.example.com", firstToken, 200}, {"second.example.com", firstToken, 401}, {"second.example.com", secondToken, 200},
	} {
		request, err := http.NewRequest(http.MethodPost, host.URL+"/api/v2/relays/relay-history/health", strings.NewReader("{}"))
		if err != nil {
			test.Fatal(err)
		}
		request.Host = attempt.hostname
		request.Header.Set("Authorization", "Bearer "+attempt.token)
		response, err := host.Client().Do(request)
		if err != nil {
			test.Fatal(err)
		}
		readBody(test, response)
		if response.StatusCode != attempt.expected {
			test.Fatal("cross-tenant health authorization failed at " + strconv.Itoa(index))
		}
	}
	for _, server := range []*Server{first, second} {
		count := 0
		for _, event := range server.identity.ListAudit(0) {
			if event.Action == "relay.health_checked" {
				count++
			}
		}
		if count != 1 {
			test.Fatal("health audit crossed tenant boundary")
		}
	}
}
