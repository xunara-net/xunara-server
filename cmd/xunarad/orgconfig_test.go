package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xunara-net/xunara-server/control"
)

// writeOrgConfig writes a config file into a temp dir and returns its path.
func writeOrgConfig(t *testing.T, doc string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "orgs.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing org config: %v", err)
	}
	return path
}

// TestLoadOrgSitesHostsEachOrganization builds one server per row and checks
// the isolation-critical fields (distinct state directories, distinct keys).
func TestLoadOrgSitesHostsEachOrganization(t *testing.T) {
	base := t.TempDir()
	path := writeOrgConfig(t, `{
		"organizations": [
			{"id": "acme", "name": "Acme", "domains": ["login.acme.example.com"],
			 "server_url": "https://login.acme.example.com",
			 "state_dir": "`+base+`/acme", "domain": "acme.example.com",
			 "node_key_expiry": "180d", "service_health_ttl": "2m", "nameservers": ["1.1.1.1"]},
			{"id": "globex", "name": "Globex", "domains": ["*.globex.example.com"],
			 "server_url": "https://login.globex.example.com",
			 "state_dir": "`+base+`/globex", "domain": "globex.example.com"}
		]
	}`)

	sites, err := loadOrgSites(path, slog.Default())
	if err != nil {
		t.Fatalf("loadOrgSites: %v", err)
	}
	defer func() {
		for _, site := range sites {
			_ = site.Server.Close()
		}
	}()

	if len(sites) != 2 {
		t.Fatalf("sites = %d, want 2", len(sites))
	}
	if sites[0].ID != "acme" || sites[0].Name != "Acme" || sites[1].ID != "globex" {
		t.Errorf("site metadata = %+v / %+v", sites[0], sites[1])
	}
	if sites[0].Server.NoisePublicKey() == sites[1].Server.NoisePublicKey() {
		t.Error("organizations share a Noise key; each state directory must own its key")
	}
}

// TestLoadOrgSitesRejectsBrokenTables pins the fail-closed validation.
func TestLoadOrgSitesRejectsBrokenTables(t *testing.T) {
	base := t.TempDir()
	dir := func(name string) string { return filepath.Join(base, name) }

	valid := `{"id": "acme", "name": "Acme", "domains": ["login.acme.example.com"],
		"server_url": "https://login.acme.example.com", "state_dir": "%s", "domain": "acme.example.com"}`

	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"empty list", `{"organizations": []}`, "no organizations"},
		{"unknown field", `{"organizations": [` + sprintf(valid, dir("a")) + `], "extra": 1}`, "unknown field"},
		{"missing id", `{"organizations": [{"name": "x", "server_url": "https://x.example.com", "state_dir": "` + dir("b") + `"}]}`, "id is required"},
		{"missing server url", `{"organizations": [{"id": "a", "state_dir": "` + dir("c") + `"}]}`, "server_url is required"},
		{"missing state dir", `{"organizations": [{"id": "a", "server_url": "https://a.example.com"}]}`, "state_dir is required"},
		{"shared state dir", `{"organizations": [` + sprintf(valid, dir("d")) + `, {"id": "b", "server_url": "https://b.example.com", "state_dir": "` + dir("d") + `"}]}`, "already used"},
		{"bad expiry", `{"organizations": [` + strings.Replace(sprintf(valid, dir("e")), `"id": "acme"`, `"id": "acme", "node_key_expiry": "180x"`, 1) + `]}`, "node_key_expiry"},
		{"bad health ttl syntax", `{"organizations": [` + strings.Replace(sprintf(valid, dir("j")), `"id": "acme"`, `"id": "acme", "service_health_ttl": "banana"`, 1) + `]}`, "service_health_ttl"},
		{"health ttl out of range", `{"organizations": [` + strings.Replace(sprintf(valid, dir("k")), `"id": "acme"`, `"id": "acme", "service_health_ttl": "5s"`, 1) + `]}`, "service health TTL"},
		{"negative token rate limit", `{"organizations": [` + strings.Replace(sprintf(valid, dir("l")), `"id": "acme"`, `"id": "acme", "id_token_rate_limit": -1`, 1) + `]}`, "id_token_rate_limit"},
		{"bad derp map", `{"organizations": [` + strings.Replace(sprintf(valid, dir("f")), `"id": "acme"`, `"id": "acme", "derp_map": "`+dir("missing.json")+`"`, 1) + `]}`, "no such file"},
		{"derp policy without a map", `{"organizations": [` + strings.Replace(sprintf(valid, dir("g")), `"id": "acme"`, `"id": "acme", "derp_policy": {"mode": "regions", "regions": [900]}`, 1) + `]}`, "needs a configured DERP map"},
		{"derp policy unknown region", `{"organizations": [` + strings.Replace(sprintf(valid, dir("h")), `"id": "acme"`, `"id": "acme", "derp_map": "`+writeDERPMapFile(t, 900)+`", "derp_policy": {"mode": "regions", "regions": [7]}`, 1) + `]}`, "not in the configured DERP map"},
		{"derp regions without the mode", `{"organizations": [` + strings.Replace(sprintf(valid, dir("i")), `"id": "acme"`, `"id": "acme", "derp_policy": {"mode": "none", "regions": [900]}`, 1) + `]}`, "only meaningful with policy mode"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeOrgConfig(t, tc.doc)
			sites, err := loadOrgSites(path, slog.Default())
			for _, site := range sites {
				_ = site.Server.Close()
			}
			if err == nil {
				t.Fatal("loadOrgSites accepted an invalid table")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// writeDERPMapFile writes a minimal tailcfg.DERPMap JSON document holding the
// given region IDs and returns its path.
func writeDERPMapFile(t *testing.T, regionIDs ...int) string {
	t.Helper()

	regions := make([]string, 0, len(regionIDs))
	for _, id := range regionIDs {
		regions = append(regions, fmt.Sprintf(
			`"%d": {"RegionID": %d, "RegionCode": "r%d", "Nodes": [{"Name": "r%da", "RegionID": %d, "HostName": "derp.example.com"}]}`,
			id, id, id, id, id))
	}
	doc := `{"Regions": {` + strings.Join(regions, ",") + `}}`

	path := filepath.Join(t.TempDir(), "derp.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing DERP map: %v", err)
	}
	return path
}

// TestLoadOrgSitesDERPPolicy checks the policy travels from the organization
// table into the per-organization server, filtered against its DERP map.
func TestLoadOrgSitesDERPPolicy(t *testing.T) {
	base := t.TempDir()
	derpMap := writeDERPMapFile(t, 900, 901)
	path := writeOrgConfig(t, `{
		"organizations": [
			{"id": "acme", "name": "Acme", "domains": ["login.acme.example.com"],
			 "server_url": "https://login.acme.example.com",
			 "state_dir": "`+base+`/acme", "domain": "acme.example.com",
			 "derp_map": "`+derpMap+`",
			 "derp_policy": {"mode": "regions", "regions": [900]}}
		]
	}`)

	sites, err := loadOrgSites(path, slog.Default())
	if err != nil {
		t.Fatalf("loadOrgSites: %v", err)
	}
	defer func() {
		for _, site := range sites {
			_ = site.Server.Close()
		}
	}()

	served := sites[0].Server.DERPMap()
	if served == nil || len(served.Regions) != 1 {
		t.Fatalf("served DERP map = %+v, want only region 900", served)
	}
	if served.Regions[900] == nil {
		t.Error("region 900 is missing from the served map")
	}
	if _, ok := served.Regions[901]; ok {
		t.Error("region 901 was filtered out of the map but is still served")
	}
}

// TestParseNodeKeyExpiry covers the day-suffix extension.
func TestParseNodeKeyExpiry(t *testing.T) {
	cases := map[string]time.Duration{
		"":      0,
		"180d":  180 * 24 * time.Hour,
		"4320h": 180 * 24 * time.Hour,
	}
	for in, want := range cases {
		got, err := parseNodeKeyExpiry(in)
		if err != nil {
			t.Fatalf("parseNodeKeyExpiry(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("parseNodeKeyExpiry(%q) = %v, want %v", in, got, want)
		}
	}
	for _, bad := range []string{"180x", "d", "-1d"} {
		if _, err := parseNodeKeyExpiry(bad); err == nil {
			t.Errorf("parseNodeKeyExpiry(%q) accepted an invalid value", bad)
		}
	}
}

// TestParseServiceHealthTTL covers the readiness TTL: empty keeps the server
// default, anything else is a Go duration the range check in control.New
// validates.
func TestParseServiceHealthTTL(t *testing.T) {
	cases := map[string]time.Duration{
		"":     0,
		" 2m ": 2 * time.Minute,
		"30s":  30 * time.Second,
		"15m":  15 * time.Minute,
	}
	for in, want := range cases {
		got, err := parseServiceHealthTTL(in)
		if err != nil {
			t.Fatalf("parseServiceHealthTTL(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("parseServiceHealthTTL(%q) = %v, want %v", in, got, want)
		}
	}
	// Out-of-range durations parse; they are rejected by control.New, which
	// knows the organization and the server default.
	for _, bad := range []string{"banana", "90"} {
		if _, err := parseServiceHealthTTL(bad); err == nil {
			t.Errorf("parseServiceHealthTTL(%q) accepted an invalid value", bad)
		}
	}
}

// TestCheckOrgScopedFlags keeps the ambiguity guard honest.
func TestCheckOrgScopedFlags(t *testing.T) {
	if err := checkOrgScopedFlags([]string{"listen", "log-level"}); err != nil {
		t.Errorf("process-level flags rejected: %v", err)
	}
	err := checkOrgScopedFlags([]string{"state-dir", "policy"})
	if err == nil {
		t.Fatal("org-scoped flags accepted in -org-config mode")
	}
	if !strings.Contains(err.Error(), "-state-dir") || !strings.Contains(err.Error(), "-policy") {
		t.Errorf("error = %v, want both offending flags named", err)
	}
	if err := checkOrgScopedFlags([]string{"flux", "flux-ttl"}); err == nil || !strings.Contains(err.Error(), "-flux") {
		t.Errorf("flux flags in -org-config mode = %v, want them rejected", err)
	}
}

// sprintf keeps the table literals readable.
func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

// TestOrgConfigFlux covers the organization-table half of Flux enablement:
// the same opt-in rule, with the TTL parsed from its JSON string.
func TestOrgConfigFlux(t *testing.T) {
	base := orgConfig{
		ID:        "acme",
		StateDir:  t.TempDir(),
		ServerURL: "https://login.acme.example.com",
	}

	on := base
	on.FluxEnabled = true
	on.FluxDir = "/srv/flux"
	on.FluxMaxSize = 1 << 20
	on.FluxTTL = "30m"
	cfg, err := on.controlConfig(slog.Default())
	if err != nil {
		t.Fatalf("controlConfig: %v", err)
	}
	if cfg.Flux == nil || cfg.Flux.Disabled || cfg.Flux.Dir != "/srv/flux" ||
		cfg.Flux.MaxSize != 1<<20 || cfg.Flux.TTL != 30*time.Minute {
		t.Fatalf("flux config = %+v", cfg.Flux)
	}

	off := base
	if cfg, err := off.controlConfig(slog.Default()); err != nil || cfg.Flux != nil {
		t.Errorf("disabled = %+v, %v; want nil, nil", cfg.Flux, err)
	}

	settingsOnly := base
	settingsOnly.FluxTTL = "30m"
	if _, err := settingsOnly.controlConfig(slog.Default()); err == nil {
		t.Error("flux_ttl without flux_enabled was accepted")
	}

	badTTL := base
	badTTL.FluxEnabled = true
	badTTL.FluxTTL = "half an hour"
	if _, err := badTTL.controlConfig(slog.Default()); err == nil || !strings.Contains(err.Error(), "flux_ttl") {
		t.Errorf("bad flux_ttl error = %v, want it to name flux_ttl", err)
	}
}

// TestLoadOrgConfigReadsSelfService checks the deployment-wide half of
// -org-config: the sign-up desk and the per-organization registration mode.
// The mode is observed through the providers endpoint rather than the struct,
// because that is exactly what the console reads.
func TestLoadOrgConfigReadsSelfService(t *testing.T) {
	base := t.TempDir()
	path := writeOrgConfig(t, `{
		"organizations": [
			{"id": "portal", "name": "Xunara Cloud", "domains": ["app.xunara.test"],
			 "server_url": "https://app.xunara.test",
			 "state_dir": "`+base+`/portal", "registration": "open"},
			{"id": "acme", "name": "Acme", "domains": ["acme.xunara.test"],
			 "server_url": "https://acme.xunara.test",
			 "state_dir": "`+base+`/acme"}
		],
		"self_service": {
			"site": "portal",
			"domain_suffix": "xunara.test",
			"scheme": "https",
			"cookie_domain": "xunara.test",
			"plan": "pro"
		}
	}`)

	sites, selfService, err := loadOrgConfig(path, slog.Default())
	if err != nil {
		t.Fatalf("loadOrgConfig: %v", err)
	}
	defer func() {
		for _, site := range sites {
			_ = site.Server.Close()
		}
	}()

	if selfService == nil {
		t.Fatal("self_service was not parsed")
	}
	want := control.SelfServiceConfig{
		Site:         "portal",
		DomainSuffix: "xunara.test",
		Scheme:       "https",
		CookieDomain: "xunara.test",
		Plan:         "pro",
	}
	if *selfService != want {
		t.Errorf("self_service = %+v, want %+v", *selfService, want)
	}

	// The configured mode must reach the control plane; an unset row keeps
	// the default (invite).
	for _, tc := range []struct {
		site int
		want string
	}{
		{0, `"registration":"open"`},
		{1, `"registration":"invite"`},
	} {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/providers", nil)
		sites[tc.site].Server.Handler().ServeHTTP(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s providers = %d", sites[tc.site].ID, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), tc.want) {
			t.Errorf("%s providers = %s, want it to contain %s",
				sites[tc.site].ID, recorder.Body.String(), tc.want)
		}
	}
}
