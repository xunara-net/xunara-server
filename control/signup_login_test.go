package control

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
)

func signupTestOrg(id string) ManagedOrg {
	return ManagedOrg{ID: id, Name: id, Domains: []string{id + ".example.com"}, ServerURL: "https://" + id + ".example.com"}
}

func TestSelfServiceDuplicateLoginIsRejectedWithoutAnotherTenant(t *testing.T) {
	router, plans := selfServiceRouter(t, &SelfServiceConfig{DomainSuffix: "xunara.test"})
	handler := router.Handler()
	first := postJSONAtHost(t, handler, "app.xunara.test", selfServiceSignupPath, map[string]string{
		"login": "alice", "password": "correct horse battery staple",
	})
	if first.Code != http.StatusCreated {
		t.Fatalf("first signup = %d (%s)", first.Code, first.Body.String())
	}
	org := router.orgByID("alice")
	original := org.site.Server.identity.ListUsers()
	allocation, allocated, err := plans.Get(t.Context(), "alice")
	if err != nil || !allocated {
		t.Fatal(err)
	}
	for _, login := range []string{"alice", "ALICE", "  Alice  "} {
		repeated := postJSONAtHost(t, handler, "app.xunara.test", selfServiceSignupPath, map[string]string{
			"login": login, "password": "another correct horse battery staple",
		})
		if repeated.Code != http.StatusConflict || !strings.Contains(repeated.Body.String(), "LOGIN_NAME_TAKEN") || len(repeated.Result().Cookies()) != 0 {
			t.Fatalf("duplicate = %d (%s), cookies = %d", repeated.Code, repeated.Body.String(), len(repeated.Result().Cookies()))
		}
	}
	records, err := router.cfg.Registry.List(t.Context())
	if err != nil || len(records) != 1 || len(router.orgSnapshot()) != 3 {
		t.Fatalf("duplicate created another tenant: records=%v, err=%v", records, err)
	}
	current, _, err := plans.Get(t.Context(), "alice")
	users := org.site.Server.identity.ListUsers()
	if err != nil || current != allocation || len(users) != 1 || users[0].ID != original[0].ID || users[0].LoginName != original[0].LoginName || users[0].UpdatedAt != original[0].UpdatedAt {
		t.Fatal("duplicate registration modified the original account or allocation")
	}
}

func TestSelfServiceConcurrentDuplicateLogin(t *testing.T) {
	router, _ := selfServiceRouter(t, &SelfServiceConfig{DomainSuffix: "xunara.test"})
	start := make(chan struct{})
	statuses := make(chan int, 2)
	var workers sync.WaitGroup
	for _, login := range []string{"bob", "BOB"} {
		workers.Go(func() {
			<-start
			response := postJSONAtHost(t, router.Handler(), "app.xunara.test", selfServiceSignupPath, map[string]string{
				"login": login, "password": "correct horse battery staple",
			})
			statuses <- response.Code
		})
	}
	close(start)
	workers.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[http.StatusCreated] != 1 || counts[http.StatusConflict] != 1 {
		t.Fatalf("concurrent signup statuses = %v", counts)
	}
}

func TestSelfServiceRejectsLossyAndOversizeLoginNames(t *testing.T) {
	for _, login := range []string{"", "user/name", "用户", "alice!", ".alice", strings.Repeat("a", 129)} {
		t.Run(fmt.Sprintf("name-%d-%s", len(login), login[:min(len(login), 8)]), func(t *testing.T) {
			router, _ := selfServiceRouter(t, &SelfServiceConfig{DomainSuffix: "xunara.test"})
			response := postJSONAtHost(t, router.Handler(), "app.xunara.test", selfServiceSignupPath, map[string]string{
				"login": login, "password": "correct horse battery staple",
			})
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "LOGIN_NAME_INVALID") {
				t.Fatalf("invalid name = %d (%s)", response.Code, response.Body.String())
			}
			if records, err := router.cfg.Registry.List(t.Context()); err != nil || len(records) != 0 {
				t.Fatalf("invalid name created a tenant: %v, %v", records, err)
			}
		})
	}
}

func TestSignupLoginClaimSerializesTwoDatabaseConnectionsAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	first := newTestRegistry(t, dir)
	second := newTestRegistry(t, dir)
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for index, registry := range []*OrgRegistry{first, second} {
		workers.Go(func() {
			<-start
			_, err := registry.create(t.Context(), signupTestOrg(fmt.Sprintf("claim-%d", index)), "shared-name")
			results <- err
		})
	}
	close(start)
	workers.Wait()
	close(results)
	successes, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, errSignupLoginTaken):
			rejected++
		default:
			t.Fatalf("unexpected race error: %v", err)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("successes=%d rejected=%d", successes, rejected)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := newTestRegistry(t, dir)
	t.Cleanup(func() { reopened.Close() })
	if _, err := reopened.create(t.Context(), signupTestOrg("after-restart"), "SHARED-NAME"); !errors.Is(err, errSignupLoginTaken) {
		t.Fatalf("duplicate after restart = %v", err)
	}
	if records, err := reopened.List(t.Context()); err != nil || len(records) != 1 {
		t.Fatalf("rejected transaction left an organization: %v, %v", records, err)
	}
}

func TestSignupLoginClaimRollbackAndCompletedNameProtection(t *testing.T) {
	registry := newTestRegistry(t, t.TempDir())
	t.Cleanup(func() { registry.Close() })
	ctx := t.Context()
	if _, err := registry.create(ctx, signupTestOrg("pending"), "alice"); err != nil {
		t.Fatal(err)
	}
	if err := registry.releaseFailedSignupLogin(ctx, "alice", "pending"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.create(ctx, signupTestOrg("still-active"), "alice"); !errors.Is(err, errSignupLoginTaken) {
		t.Fatal("cleanup released a name while its organization still exists")
	}
	if err := registry.Delete(ctx, "pending"); err != nil {
		t.Fatal(err)
	}
	if err := registry.releaseFailedSignupLogin(ctx, "alice", "another-org"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.create(ctx, signupTestOrg("wrong-owner"), "alice"); !errors.Is(err, errSignupLoginTaken) {
		t.Fatal("cleanup released another registration's name")
	}
	if err := registry.releaseFailedSignupLogin(ctx, "alice", "pending"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.create(ctx, signupTestOrg("completed"), "alice"); err != nil {
		t.Fatalf("safe rollback did not release the name: %v", err)
	}
	if err := registry.completeSignupLogin(ctx, "alice", "completed"); err != nil {
		t.Fatal(err)
	}
	if err := registry.Delete(ctx, "completed"); err != nil {
		t.Fatal(err)
	}
	if err := registry.releaseFailedSignupLogin(ctx, "alice", "completed"); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.create(ctx, signupTestOrg("reused"), "ALICE"); !errors.Is(err, errSignupLoginTaken) {
		t.Fatal("completed name was recycled after deletion")
	}
	if err := registry.completeSignupLogin(ctx, "unknown", "missing"); err == nil {
		t.Fatal("completion of a missing reservation was accepted")
	}
}

func TestSignupLoginBackfillsLegacyDuplicatesWithoutChangingOwners(t *testing.T) {
	registry := newTestRegistry(t, t.TempDir())
	for _, id := range []string{"legacy", "legacy-copy"} {
		record, err := registry.Create(t.Context(), signupTestOrg(id))
		if err != nil {
			t.Fatal(err)
		}
		server, err := registry.NewServer(record)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := server.identity.ClaimLocalAccount(t.Context(), identity.LocalAccountClaim{
			Kind: identity.ClaimTenantOwner, LoginName: "legacy-user", PasswordHash: []byte("unchanged-legacy-hash"),
		}); err != nil {
			t.Fatal(err)
		}
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
	}
	router, err := NewRouter(RouterConfig{
		Orgs: []OrgSite{{ID: "portal", Domains: []string{"app.example.com"}, Server: newTestServer(t)}}, Registry: registry,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { router.Close() })
	if _, err := registry.create(t.Context(), signupTestOrg("another-copy"), "LEGACY-USER"); !errors.Is(err, errSignupLoginTaken) {
		t.Fatalf("legacy duplicate signup = %v", err)
	}
	for _, id := range []string{"legacy", "legacy-copy"} {
		user, err := router.orgByID(id).site.Server.identity.LookupUserByLoginName(t.Context(), "legacy-user")
		if err != nil || user.Role != identity.RoleOwner {
			t.Fatalf("legacy account lost: %s, %v", id, err)
		}
		credential, err := router.orgByID(id).site.Server.identity.LookupLocalCredential(t.Context(), user.ID)
		if err != nil || string(credential.PasswordHash) != "unchanged-legacy-hash" {
			t.Fatal("legacy duplicate was reset or merged")
		}
	}
}

func TestSignupLoginCreationFailsClosedOnCancellationAndStorageError(t *testing.T) {
	registry := newTestRegistry(t, t.TempDir())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := registry.create(ctx, signupTestOrg("cancelled"), "cancelled-user"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled creation = %v", err)
	}
	if records, err := registry.List(t.Context()); err != nil || len(records) != 0 {
		t.Fatal("cancelled transaction created an organization")
	}
	registry.Close()
	if _, err := registry.create(t.Context(), signupTestOrg("unavailable"), "unavailable-user"); err == nil || errors.Is(err, errSignupLoginTaken) {
		t.Fatalf("closed database misreported as available or duplicate: %v", err)
	}
}

func TestSignupLoginUpgradeFromRegistryV1AndIdentityReadFailure(t *testing.T) {
	dir := t.TempDir()
	registry := newTestRegistry(t, dir)
	if _, err := registry.Create(t.Context(), signupTestOrg("legacy")); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.db.ExecContext(t.Context(), "DROP TABLE signup_login_claims; PRAGMA user_version = 1"); err != nil {
		t.Fatal(err)
	}
	registry.Close()
	registry = newTestRegistry(t, dir)
	t.Cleanup(func() { registry.Close() })
	var version int
	if err := registry.db.QueryRowContext(t.Context(), "PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		t.Fatalf("upgraded registry version = %d, %v", version, err)
	}
	if records, err := registry.List(t.Context()); err != nil || len(records) != 1 || records[0].ID != "legacy" {
		t.Fatal("migration changed legacy organizations")
	}
	front := newTestServer(t)
	front.Close()
	if router, err := NewRouter(RouterConfig{
		Orgs: []OrgSite{{ID: "portal", Domains: []string{"app.example.com"}, Server: front}}, Registry: registry,
	}); err == nil || router != nil {
		t.Fatal("unreadable identities disabled uniqueness checks instead of failing closed")
	}
}

type signupClaimOutcomeStore struct {
	identity.Store
	commitFirst bool
}

func (store signupClaimOutcomeStore) ClaimLocalAccount(ctx context.Context, claim identity.LocalAccountClaim) (identity.User, identity.Session, string, error) {
	if store.commitFirst {
		if _, _, _, err := store.Store.ClaimLocalAccount(ctx, claim); err != nil {
			return identity.User{}, identity.Session{}, "", err
		}
	}
	return identity.User{}, identity.Session{}, "", errors.New("fixture: lost claim acknowledgement")
}

func TestSelfServicePreservesCommittedOwnerWhenClaimAcknowledgementIsLost(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprintf("committed-%t", committed), func(t *testing.T) {
			router, _ := selfServiceRouterWith(t, selfServiceTestOptions{
				cfg: &SelfServiceConfig{DomainSuffix: "xunara.test"},
				prepareTenant: func(server *Server) error {
					server.identity = signupClaimOutcomeStore{Store: server.identity, commitFirst: committed}
					return nil
				},
			})
			body := map[string]string{"login": "uncertain", "password": "correct horse battery staple"}
			response := postJSONAtHost(t, router.Handler(), "app.xunara.test", selfServiceSignupPath, body)
			if response.Code != http.StatusServiceUnavailable || len(response.Result().Cookies()) != 0 {
				t.Fatalf("claim uncertainty = %d", response.Code)
			}
			if committed {
				if !strings.Contains(response.Body.String(), "REGISTRATION_OUTCOME_UNKNOWN") || router.orgByID("uncertain") == nil {
					t.Fatal("lost acknowledgement deleted a committed owner's tenant")
				}
				login := postJSONAtHost(t, router.Handler(), "uncertain.xunara.test", "/api/v1/auth/login", body)
				if login.Code != http.StatusOK {
					t.Fatalf("committed owner cannot sign in: %d (%s)", login.Code, login.Body.String())
				}
				duplicate := postJSONAtHost(t, router.Handler(), "app.xunara.test", selfServiceSignupPath, body)
				if duplicate.Code != http.StatusConflict {
					t.Fatal("lost acknowledgement allowed duplicate registration")
				}
			} else {
				if router.orgByID("uncertain") != nil || !strings.Contains(response.Body.String(), "REGISTRATION_UNAVAILABLE") {
					t.Fatal("uncommitted owner left an active tenant")
				}
				if _, err := router.cfg.Registry.create(t.Context(), signupTestOrg("retry-after-cleanup"), "uncertain"); err != nil {
					t.Fatalf("uncommitted owner left a name reservation: %v", err)
				}
			}
		})
	}
}
