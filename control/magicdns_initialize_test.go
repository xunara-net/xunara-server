package control

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/plan"
	"github.com/xunara-net/xunara-server/state"
)

func TestMagicDNSInitializeFreeAndRestart(t *testing.T) {
	free, _ := plan.DefaultCatalog().Get(plan.FreeID)
	server := newServerWithConfig(t, Config{PlanSource: func(string) plan.Plan { return free }})
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	node := seedAPIMachine(t, server, "laptop", nil)
	configuration := accountRequest(t, server, http.MethodGet, "/api/v2/dns/configuration", nil, cookie, nil)
	payload := decodeAPI(t, configuration.Result())
	if payload["domain"] != "" || payload["can_initialize"] != true || payload["can_edit"] != false {
		t.Fatalf("initial DNS: %v", payload)
	}
	body := map[string]any{"revision": payload["revision"], "base_hash": payload["base_hash"]}
	headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
	response := accountRequest(t, server, http.MethodPost, "/api/v2/dns/initialize", body, cookie, headers)
	if response.Code != http.StatusOK {
		t.Fatalf("initialize: %d %s", response.Code, response.Body.String())
	}
	initialized := decodeAPI(t, response.Result())
	domain := initialized["domain"].(string)
	if domain == "" || domain != server.suggestedDNSDomain() || initialized["settings"].(map[string]any)["magic_dns"] != true {
		t.Fatal("initialization did not enable MagicDNS")
	}
	actual, _ := server.store.GetNodeByID(node.ID)
	if actual.IPv4 != node.IPv4 || actual.DNSName != node.DNSName {
		t.Fatal("initialization changed existing device IP or name")
	}
	wire := server.dnsConfigFor(actual)
	if wire == nil || !wire.Proxied || len(wire.Domains) != 1 || wire.Domains[0] != domain || server.mapperConfig().Domain != domain {
		t.Fatal("official client DNS config not enabled")
	}
	if response := accountRequest(t, server, http.MethodPost, "/api/v2/dns/initialize", body, cookie, headers); response.Code != http.StatusConflict {
		t.Fatal("initialization replay accepted")
	}
	settings := initialized["settings"].(map[string]any)
	settings["magic_dns"] = false
	updated := map[string]any{"revision": initialized["revision"], "base_hash": initialized["base_hash"], "settings": settings}
	response = accountRequest(t, server, http.MethodPut, "/api/v2/dns/configuration", updated, cookie, headers)
	if response.Code != http.StatusOK {
		t.Fatalf("basic DNS off on Free: %d %s", response.Code, response.Body.String())
	}
	disabled := decodeAPI(t, response.Result())
	settings["nameservers"] = []string{"1.1.1.1"}
	updated["revision"], updated["base_hash"] = disabled["revision"], disabled["base_hash"]
	if response := accountRequest(t, server, http.MethodPut, "/api/v2/dns/configuration", updated, cookie, headers); response.Code != http.StatusForbidden {
		t.Fatal("basic MagicDNS bypassed custom DNS entitlement")
	}
	cfg := server.cfg
	cfg.Domain = ""
	server.Close()
	restarted, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if restarted.networkDomain() != domain || restarted.dnsConfig.Load().Settings.MagicDNS {
		t.Fatal("restart lost domain or reset user DNS toggle")
	}
	if err := state.CheckDNSNamespace(t.Context(), cfg.DBPath, ""); err != nil {
		t.Fatal("read-only preflight cannot resume initialized namespace")
	}
}

func TestMagicDNSInitializeGuardsAndRollback(t *testing.T) {
	for _, scenario := range []string{"member", "csrf", "conflict", "audit failure", "audit ignore"} {
		t.Run(scenario, func(t *testing.T) {
			server := newTestServer(t)
			userID := state.DefaultUserID
			if scenario == "member" {
				userID = seedRoleUser(t, server, "member", identity.RoleMember)
			}
			cookie, token := seedUserSession(t, server, userID)
			configuration := decodeAPI(t, accountRequest(t, server, http.MethodGet, "/api/v2/dns/configuration", nil, cookie, nil).Result())
			body := map[string]any{"revision": configuration["revision"], "base_hash": configuration["base_hash"]}
			headers := map[string]string{"X-CSRF-Token": csrfTokenFor(token)}
			if scenario == "csrf" {
				headers = nil
			}
			if scenario == "conflict" {
				body["base_hash"] = "stale"
			}
			if scenario == "audit failure" || scenario == "audit ignore" {
				failure := "RAISE(ABORT, 'test')"
				if scenario == "audit ignore" {
					failure = "RAISE(IGNORE)"
				}
				if _, err := server.store.(*state.SQLiteStore).DB().Exec("CREATE TRIGGER reject_dns_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'dns.published' BEGIN SELECT " + failure + "; END"); err != nil {
					t.Fatal(err)
				}
			}
			response := accountRequest(t, server, http.MethodPost, "/api/v2/dns/initialize", body, cookie, headers)
			if response.Code < 400 {
				t.Fatal("invalid DNS initialization was accepted")
			}
			_, bound, err := state.ReadDNSDomain(t.Context(), server.store.(*state.SQLiteStore).DB())
			if err != nil || bound || server.networkDomain() != "" {
				t.Fatal("failed initialization partially bound namespace")
			}
		})
	}
}

func TestMagicDNSInitializeUpdatesExistingNoiseStream(t *testing.T) {
	server := newTestServer(t)
	host := newTestHTTPServer(t, server)
	connection, client, nodeKey := registerNode(t, server, host, "before-init")
	defer connection.Close()
	stream := openMapSession(t, client, nodeKey.Public())
	defer stream.Body.Close()
	frames, view := mapFrames(stream.Body), newNetmapView()
	first := waitForNetmapFrame(t, frames, view, func(view *netmapView) bool { return view.self != nil })
	if first.Domain != "" {
		t.Fatal("fixture did not start with an empty DNS domain")
	}
	addresses := slices.Clone(first.Node.Addresses)
	cookie, token := seedUserSession(t, server, state.DefaultUserID)
	configuration := decodeAPI(t, accountRequest(t, server, http.MethodGet, "/api/v2/dns/configuration", nil, cookie, nil).Result())
	response := accountRequest(t, server, http.MethodPost, "/api/v2/dns/initialize", map[string]any{"revision": configuration["revision"], "base_hash": configuration["base_hash"]}, cookie, map[string]string{"X-CSRF-Token": csrfTokenFor(token)})
	if response.Code != http.StatusOK {
		t.Fatal("MagicDNS could not initialize")
	}
	domain := server.networkDomain()
	update := waitForNetmapFrame(t, frames, view, func(view *netmapView) bool {
		return view.self != nil && strings.HasSuffix(view.self.Name, "."+domain+".")
	})
	if update.Domain != domain || update.DNSConfig == nil || !update.DNSConfig.Proxied || len(update.DNSConfig.Domains) != 1 || update.DNSConfig.Domains[0] != domain {
		t.Fatal("live stream omitted the new domain or DNS configuration")
	}
	if !slices.Equal(update.Node.Addresses, addresses) || len(update.DNSConfig.CertDomains) != 0 {
		t.Fatal("DNS initialization changed addresses or advertised unsupported certificates")
	}
	if update.Node.Key != nodeKey.Public() || first.Node.Key != update.Node.Key {
		t.Fatal("initialization changed machine identity")
	}
}
