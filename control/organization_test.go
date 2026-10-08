package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
	"github.com/xunara-net/xunara-server/identity"
)

// organizationAtHost performs an authenticated GET addressed to an explicit
// Host, standing in for DNS pointing a login-server URL at this router.
func organizationAtHost(t *testing.T, hs *httptest.Server, host, token string) (*http.Response, map[string]any) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, hs.URL+"/api/v2/organization", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Host = host
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := hs.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /api/v2/organization (host %s): %v", host, err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	if resp.StatusCode != http.StatusOK {
		return resp, nil
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decoding the organization response: %v", err)
	}
	return resp, out
}

// TestAPIV2OrganizationSingleTenant checks the honest minimum a deployment
// without an organization table can report: no platform ID, but a stable
// shape (domains is an array, never null).
func TestAPIV2OrganizationSingleTenant(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com", ServerURL: "https://login.example.com"})
	hs := newTestHTTPServer(t, s)
	client := noRedirectClient()

	// Authentication and scope rules match the rest of /api/v2.
	if resp := apiRequest(t, client, http.MethodGet, hs.URL+"/api/v2/organization", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}
	_, token := seedAPIKey(t, s, identity.ScopeRead)

	resp, body := organizationAtHost(t, hs, "login.example.com", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if _, ok := body["id"]; ok {
		t.Errorf("single-tenant id = %v, want omitted", body["id"])
	}
	if _, ok := body["name"]; ok {
		t.Errorf("single-tenant name = %v, want omitted", body["name"])
	}
	domains, ok := body["domains"].([]any)
	if !ok {
		t.Fatalf("domains = %#v, want an array", body["domains"])
	}
	if len(domains) != 0 {
		t.Errorf("domains = %v, want []", domains)
	}
	if managed, _ := body["managed"].(bool); managed {
		t.Error("single-tenant organization reported as managed")
	}
	if body["magicDnsDomain"] != "example.com" || body["serverUrl"] != "https://login.example.com" {
		t.Errorf("domain/serverUrl = %v/%v", body["magicDnsDomain"], body["serverUrl"])
	}
}

// TestAPIV2OrganizationRoutesByHost checks that the identity is the Host
// routing decision: two organizations behind one listener each report
// themselves, and the request cannot ask for another.
func TestAPIV2OrganizationRoutesByHost(t *testing.T) {
	acme := newTestServer(t)
	globex := newTestServer(t)
	router := newTestRouter(t, RouterConfig{Orgs: []OrgSite{
		{ID: "acme", Name: "Acme Corp", Domains: []string{"login.acme.example.com"}, Server: acme},
		{ID: "globex", Name: "Globex", Domains: []string{"*.globex.example.com"}, Server: globex},
	}})
	hs := httptest.NewServer(router.Handler())
	t.Cleanup(hs.Close)

	_, acmeToken := seedAPIKey(t, acme, identity.ScopeRead)
	_, globexToken := seedAPIKey(t, globex, identity.ScopeRead)

	for _, tc := range []struct {
		host    string
		token   string
		wantID  string
		want    string
		domains []string
	}{
		{"login.acme.example.com", acmeToken, "acme", "Acme Corp", []string{"login.acme.example.com"}},
		{"login.globex.example.com", globexToken, "globex", "Globex", []string{"*.globex.example.com"}},
	} {
		resp, body := organizationAtHost(t, hs, tc.host, tc.token)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", tc.host, resp.StatusCode)
		}
		if body["id"] != tc.wantID || body["name"] != tc.want {
			t.Errorf("%s identity = %v/%v, want %s/%s", tc.host, body["id"], body["name"], tc.wantID, tc.want)
		}
		if managed, _ := body["managed"].(bool); managed {
			t.Errorf("%s configured organization reported as managed", tc.host)
		}
		domains, _ := body["domains"].([]any)
		if len(domains) != len(tc.domains) || domains[0] != tc.domains[0] {
			t.Errorf("%s domains = %v, want %v", tc.host, domains, tc.domains)
		}
	}

	// Another organization's credential does not unlock this one.
	if resp, _ := organizationAtHost(t, hs, "login.acme.example.com", globexToken); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("cross-organization credential = %d, want 401", resp.StatusCode)
	}
	// An unknown host leaks nothing.
	if resp, _ := organizationAtHost(t, hs, "attacker.example.net", acmeToken); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown host = %d, want 404", resp.StatusCode)
	}
}

// TestOrganizationIdentityFollowsManagedUpdate checks that a rename through
// the platform API updates what the organization reports about itself.
func TestOrganizationIdentityFollowsManagedUpdate(t *testing.T) {
	router, hs := newManagedOrgRouter(t, t.TempDir())
	const token = "platform-secret"

	resp := platformJSONRequest(t, hs, http.MethodPost, "login.acme.example.com",
		"/api/platform/v1/organizations", token, globexCreateBody())
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d (%s), want 201", resp.StatusCode, bodyString(t, resp))
	}

	created := router.orgByID("globex")
	if created == nil {
		t.Fatal("created organization is not registered")
	}
	if org := created.site.Server.Organization(); org.ID != "globex" || !org.Managed {
		t.Fatalf("managed organization identity = %+v", org)
	}

	newName := "Globex International"
	if _, err := router.UpdateManagedOrg(context.Background(), "globex", &newName, []string{"login.globex.example.com"}); err != nil {
		t.Fatalf("UpdateManagedOrg: %v", err)
	}
	org := created.site.Server.Organization()
	if org.Name != newName {
		t.Errorf("identity name = %q, want %q", org.Name, newName)
	}
	if len(org.Domains) != 1 || org.Domains[0] != "login.globex.example.com" {
		t.Errorf("identity domains = %v", org.Domains)
	}
}

// TestPlatformGRPCGetOrganizationIdentity checks the gRPC mirror.
func TestPlatformGRPCGetOrganizationIdentity(t *testing.T) {
	s := newServerWithConfig(t, Config{Domain: "example.com", ServerURL: "https://login.example.com"})
	s.setOrganization(OrgIdentity{ID: "acme", Name: "Acme Corp", Domains: []string{"login.acme.example.com"}})
	client := startGRPCTestServer(t, s.RegisterPlatformGRPC)

	if _, err := client.GetOrganizationIdentity(grpcCtx(""), &xunarav2.GetOrganizationIdentityRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("anonymous error = %v, want Unauthenticated", err)
	}
	_, readToken := seedAPIKey(t, s, identity.ScopeRead)

	org, err := client.GetOrganizationIdentity(grpcCtx(readToken), &xunarav2.GetOrganizationIdentityRequest{})
	if err != nil {
		t.Fatalf("GetOrganizationIdentity: %v", err)
	}
	if org.GetId() != "acme" || org.GetName() != "Acme Corp" || org.GetManaged() {
		t.Errorf("organization = %+v", org)
	}
	if got := org.GetDomains(); len(got) != 1 || got[0] != "login.acme.example.com" {
		t.Errorf("domains = %v", got)
	}
	if org.GetMagicDnsDomain() != "example.com" || org.GetServerUrl() != "https://login.example.com" {
		t.Errorf("domain/serverUrl = %q/%q", org.GetMagicDnsDomain(), org.GetServerUrl())
	}

	// A credential without the read scope is refused, like every other v2
	// endpoint.
	_, writeOnly := seedAPIKey(t, s, identity.ScopeWrite)
	if _, err := client.GetOrganizationIdentity(grpcCtx(writeOnly), &xunarav2.GetOrganizationIdentityRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("write-only error = %v, want PermissionDenied", err)
	}
}
