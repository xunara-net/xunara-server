package control

import (
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
	"github.com/xunara-net/xunara-server/identity"
)

// startPlatformAdminClient serves both router platform surfaces and returns
// the deployment-level client.
func startPlatformAdminClient(t *testing.T, router *Router) xunarav2.PlatformAdminServiceClient {
	t.Helper()
	conn := startGRPCConn(t, func(reg grpc.ServiceRegistrar) {
		registerPlatformGRPCServices(reg, router)
	})
	return xunarav2.NewPlatformAdminServiceClient(conn)
}

func TestPlatformAdminGRPCRequiresPlatformToken(t *testing.T) {
	router, _ := newManagedOrgRouter(t, t.TempDir())
	client := startPlatformAdminClient(t, router)

	if _, err := client.ListOrganizations(grpcCtx(""), &xunarav2.ListOrganizationsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("anonymous list error = %v, want Unauthenticated", err)
	}
	if _, err := client.ListOrganizations(grpcCtx("wrong"), &xunarav2.ListOrganizationsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("wrong token error = %v, want Unauthenticated", err)
	}

	// An organization API key is not a platform credential: the tenant
	// boundary holds even though the key is valid for its own organization.
	org := router.orgByID("acme")
	if org == nil {
		t.Fatal("configured organization is missing")
	}
	_, orgToken := seedAPIKey(t, org.site.Server, identity.ScopeRead, identity.ScopeWrite)
	if _, err := client.ListOrganizations(grpcCtx(orgToken), &xunarav2.ListOrganizationsRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("organization key error = %v, want Unauthenticated", err)
	}

	if _, err := client.ListOrganizations(grpcCtx("platform-secret"), &xunarav2.ListOrganizationsRequest{}); err != nil {
		t.Fatalf("platform token list: %v", err)
	}

	// A deployment without a platform token fails closed.
	bare := newTestRouter(t, RouterConfig{Orgs: []OrgSite{
		{ID: "only", Name: "Only", Server: newTestServer(t)},
	}})
	bareClient := startPlatformAdminClient(t, bare)
	if _, err := bareClient.ListOrganizations(grpcCtx("platform-secret"), &xunarav2.ListOrganizationsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("disabled platform API error = %v, want PermissionDenied", err)
	}
}

func TestPlatformAdminGRPCOrganizationLifecycle(t *testing.T) {
	router, _ := newManagedOrgRouter(t, t.TempDir())
	client := startPlatformAdminClient(t, router)
	ctx := grpcCtx("platform-secret")

	created, err := client.CreateOrganization(ctx, &xunarav2.CreateOrganizationRequest{
		Id:        "Globex", // trimmed, then rejected by validation
		Name:      "Globex",
		Domains:   []string{"Login.Globex.Example.com"},
		ServerUrl: "https://login.globex.example.com",
		Domain:    "globex.example.com",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("uppercase id error = %v (%+v), want InvalidArgument", err, created)
	}

	created, err = client.CreateOrganization(ctx, &xunarav2.CreateOrganizationRequest{
		Id:        "globex",
		Name:      "Globex",
		Domains:   []string{"Login.Globex.Example.com"},
		ServerUrl: "https://login.globex.example.com",
		Domain:    "globex.example.com",
	})
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if created.GetId() != "globex" || !created.GetManaged() || created.GetStats() == nil {
		t.Fatalf("created organization = %+v", created)
	}
	// Domains are canonicalised (lowercase) and managed.
	wantDomains := []string{"login.globex.example.com"}
	if len(created.GetDomains()) != len(wantDomains) || created.GetDomains()[0] != wantDomains[0] {
		t.Errorf("created domains = %v, want %v", created.GetDomains(), wantDomains)
	}

	list, err := client.ListOrganizations(ctx, &xunarav2.ListOrganizationsRequest{})
	if err != nil {
		t.Fatalf("ListOrganizations: %v", err)
	}
	if len(list.GetOrganizations()) != 2 {
		t.Fatalf("organizations = %d, want 2", len(list.GetOrganizations()))
	}

	got, err := client.GetOrganization(ctx, &xunarav2.GetOrganizationRequest{Id: "globex"})
	if err != nil || got.GetId() != "globex" {
		t.Fatalf("GetOrganization = %+v (%v)", got, err)
	}
	if _, err := client.GetOrganization(ctx, &xunarav2.GetOrganizationRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty id error = %v, want InvalidArgument", err)
	}
	if _, err := client.GetOrganization(ctx, &xunarav2.GetOrganizationRequest{Id: "nope"}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown id error = %v, want NotFound", err)
	}

	// Creating the same ID twice conflicts; so does taking a served domain.
	if _, err := client.CreateOrganization(ctx, &xunarav2.CreateOrganizationRequest{
		Id: "globex", Name: "Globex", Domains: []string{"login.globex.example.com"},
		ServerUrl: "https://login.globex.example.com",
	}); status.Code(err) != codes.AlreadyExists {
		t.Errorf("duplicate id error = %v, want AlreadyExists", err)
	}
	if _, err := client.CreateOrganization(ctx, &xunarav2.CreateOrganizationRequest{
		Id: "other", Name: "Other", Domains: []string{"login.acme.example.com"},
		ServerUrl: "https://login.acme.example.com",
	}); status.Code(err) != codes.AlreadyExists {
		t.Errorf("duplicate domain error = %v, want AlreadyExists", err)
	}
	// Validation failures are INVALID_ARGUMENT with the operator-facing message.
	if _, err := client.CreateOrganization(ctx, &xunarav2.CreateOrganizationRequest{
		Id: "bad", Name: "Bad", Domains: []string{"login.bad.example.com"},
		ServerUrl: "ftp://login.bad.example.com",
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad server_url error = %v, want InvalidArgument", err)
	}

	// Updates: name only, then a domain replacement.
	name := "Globex Corp"
	updated, err := client.UpdateOrganization(ctx, &xunarav2.UpdateOrganizationRequest{Id: "globex", Name: &name})
	if err != nil {
		t.Fatalf("UpdateOrganization name: %v", err)
	}
	if updated.GetName() != "Globex Corp" || len(updated.GetDomains()) != 1 {
		t.Fatalf("updated name view = %+v", updated)
	}
	updated, err = client.UpdateOrganization(ctx, &xunarav2.UpdateOrganizationRequest{
		Id:      "globex",
		Domains: &xunarav2.StringList{Values: []string{"login.globex.example.com", "sso.globex.example.com"}},
	})
	if err != nil {
		t.Fatalf("UpdateOrganization domains: %v", err)
	}
	if len(updated.GetDomains()) != 2 {
		t.Errorf("updated domains = %v", updated.GetDomains())
	}
	if _, err := client.UpdateOrganization(ctx, &xunarav2.UpdateOrganizationRequest{Id: "globex"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty update error = %v, want InvalidArgument", err)
	}

	// Configured organizations stay read-only.
	configuredName := "Renamed"
	if _, err := client.UpdateOrganization(ctx, &xunarav2.UpdateOrganizationRequest{Id: "acme", Name: &configuredName}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("configured update error = %v, want FailedPrecondition", err)
	}
	if _, err := client.DeleteOrganization(ctx, &xunarav2.DeleteOrganizationRequest{Id: "acme"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("configured delete error = %v, want FailedPrecondition", err)
	}

	// Delete archives the organization state and is not idempotent.
	deleted, err := client.DeleteOrganization(ctx, &xunarav2.DeleteOrganizationRequest{Id: "globex"})
	if err != nil {
		t.Fatalf("DeleteOrganization: %v", err)
	}
	if !deleted.GetDeleted() || deleted.GetArchivedAt() == "" {
		t.Errorf("delete response = %+v", deleted)
	}
	if _, err := client.DeleteOrganization(ctx, &xunarav2.DeleteOrganizationRequest{Id: "globex"}); status.Code(err) != codes.NotFound {
		t.Errorf("repeated delete error = %v, want NotFound", err)
	}
	if list, err = client.ListOrganizations(ctx, &xunarav2.ListOrganizationsRequest{}); err != nil || len(list.GetOrganizations()) != 1 {
		t.Errorf("list after delete = %d organizations (%v)", len(list.GetOrganizations()), err)
	}
}

func TestPlatformAdminGRPCManagedOrgsDisabled(t *testing.T) {
	acme := newTestServer(t)
	router := newTestRouter(t, RouterConfig{
		Orgs:               []OrgSite{{ID: "acme", Name: "Acme", Domains: []string{"login.acme.example.com"}, Server: acme}},
		PlatformAdminToken: "platform-secret",
	})
	client := startPlatformAdminClient(t, router)
	ctx := grpcCtx("platform-secret")

	if _, err := client.ListOrganizations(ctx, &xunarav2.ListOrganizationsRequest{}); err != nil {
		t.Fatalf("ListOrganizations without a registry: %v", err)
	}
	if _, err := client.CreateOrganization(ctx, &xunarav2.CreateOrganizationRequest{
		Id: "globex", Name: "Globex", Domains: []string{"login.globex.example.com"},
		ServerUrl: "https://login.globex.example.com",
	}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("create without a registry error = %v, want PermissionDenied", err)
	}
}

func TestPlatformAdminGRPCListAudit(t *testing.T) {
	router, _ := newManagedOrgRouter(t, t.TempDir())
	client := startPlatformAdminClient(t, router)
	ctx := grpcCtx("platform-secret")

	acme := router.orgByID("acme")
	if acme == nil {
		t.Fatal("configured organization is missing")
	}
	acme.site.Server.audit("tester", "node.approved", "node:1", "first")
	acme.site.Server.audit("robot", "user.created", "user:2", "second")

	if _, err := client.CreateOrganization(ctx, &xunarav2.CreateOrganizationRequest{
		Id: "globex", Name: "Globex", Domains: []string{"login.globex.example.com"},
		ServerUrl: "https://login.globex.example.com",
	}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	all, err := client.ListAudit(ctx, &xunarav2.ListPlatformAuditRequest{Limit: 100})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(all.GetEvents()) == 0 {
		t.Fatal("platform audit export is empty")
	}
	var sawAcme, sawGlobex bool
	for _, event := range all.GetEvents() {
		if event.GetTime() == nil || event.GetOrg() == "" || event.GetAction() == "" {
			t.Fatalf("incomplete audit event: %+v", event)
		}
		switch event.GetOrg() {
		case "acme":
			sawAcme = true
		case "globex":
			sawGlobex = true
		}
	}
	if !sawAcme || !sawGlobex {
		t.Errorf("export covered acme=%v globex=%v, want both", sawAcme, sawGlobex)
	}
	// Cursors advance to the last consumed ID of every exported organization.
	if all.GetCursors()["acme"] == 0 || all.GetCursors()["globex"] == 0 {
		t.Errorf("cursors = %v", all.GetCursors())
	}
	for i := 1; i < len(all.GetEvents()); i++ {
		if all.GetEvents()[i-1].GetTime().AsTime().After(all.GetEvents()[i].GetTime().AsTime()) {
			t.Error("audit export is not time ordered")
		}
	}

	// A one-event page reports more data, and resuming from the cursors
	// continues instead of repeating.
	page, err := client.ListAudit(ctx, &xunarav2.ListPlatformAuditRequest{Limit: 1})
	if err != nil {
		t.Fatalf("ListAudit limit 1: %v", err)
	}
	if len(page.GetEvents()) == 0 || !page.GetHasMore() {
		t.Fatalf("first page = %d events, hasMore %v", len(page.GetEvents()), page.GetHasMore())
	}
	var resume []string
	for org, id := range page.GetCursors() {
		resume = append(resume, org+":"+itoa64(id))
	}
	next, err := client.ListAudit(ctx, &xunarav2.ListPlatformAuditRequest{Limit: 100, Cursors: resume})
	if err != nil {
		t.Fatalf("ListAudit resume: %v", err)
	}
	for _, before := range all.GetEvents() {
		for _, after := range next.GetEvents() {
			if after.GetOrg() == before.GetOrg() && after.GetId() <= before.GetId() && after.GetId() <= page.GetCursors()[after.GetOrg()] {
				t.Errorf("resumed page repeated %s:%d", after.GetOrg(), after.GetId())
			}
		}
	}

	// Filters validate eagerly: a bad glob fails even when nothing matches.
	filtered, err := client.ListAudit(ctx, &xunarav2.ListPlatformAuditRequest{Actions: []string{"node.*"}})
	if err != nil {
		t.Fatalf("ListAudit filter: %v", err)
	}
	for _, event := range filtered.GetEvents() {
		if event.GetAction() != "node.approved" {
			t.Errorf("filtered export contains %q", event.GetAction())
		}
	}
	if _, err := client.ListAudit(ctx, &xunarav2.ListPlatformAuditRequest{Actions: []string{"node[0-9"}}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad glob error = %v, want InvalidArgument", err)
	}
	if _, err := client.ListAudit(ctx, &xunarav2.ListPlatformAuditRequest{Orgs: []string{"nope"}}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("unknown org error = %v, want InvalidArgument", err)
	}
	if _, err := client.ListAudit(ctx, &xunarav2.ListPlatformAuditRequest{Cursors: []string{"acme"}}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad cursor error = %v, want InvalidArgument", err)
	}
	if _, err := client.ListAudit(ctx, &xunarav2.ListPlatformAuditRequest{Orgs: []string{"acme"}}); err != nil {
		t.Errorf("single-org export: %v", err)
	}
}
