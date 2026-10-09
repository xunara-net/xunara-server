package control

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/state"
)

func TestSelfServiceAdmissionFailsClosedOnRateStorageFailure(t *testing.T) {
	for _, operation := range []string{"INSERT", "UPDATE"} {
		t.Run(operation, func(t *testing.T) {
			router, plans := selfServiceRouter(t, &SelfServiceConfig{DomainSuffix: "xunara.test"})
			front := router.orgByID("portal").site.Server
			database := front.store.(*state.SQLiteStore).DB()
			before := router.orgSnapshot()
			if operation == "UPDATE" {
				if _, err := database.Exec("INSERT INTO rate_limits (scope, window_start, count) VALUES ('self-signup:192.0.2.1', 0, 1)"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := database.Exec(fmt.Sprintf("CREATE TRIGGER unavailable_self_service_rate BEFORE %s ON rate_limits BEGIN SELECT RAISE(ABORT, 'private self-service diagnostic'); END", operation)); err != nil {
				t.Fatal(err)
			}
			recorder := postJSONAtHost(t, router.Handler(), "app.xunara.test", selfServiceSignupPath, map[string]string{
				"login": "admission-owner", "password": "correct horse battery staple",
			})
			if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") == "" || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Set-Cookie") != "" {
				t.Fatal("self-service rate storage failure did not fail closed")
			}
			if strings.Contains(recorder.Body.String(), "private self-service diagnostic") || strings.Contains(recorder.Body.String(), "correct horse battery staple") {
				t.Fatal("self-service failure exposed private data")
			}
			if !reflect.DeepEqual(before, router.orgSnapshot()) {
				t.Fatal("rate storage failure published an organization")
			}
			if records, err := router.cfg.Registry.List(t.Context()); err != nil || len(records) != 0 {
				t.Fatal("rate storage failure persisted an organization")
			}
			if assignments, err := plans.List(t.Context()); err != nil || len(assignments) != 0 {
				t.Fatal("rate storage failure allocated a plan or network")
			}
			if _, err := database.Exec("DROP TRIGGER unavailable_self_service_rate"); err != nil {
				t.Fatal(err)
			}
			recorder = postJSONAtHost(t, router.Handler(), "app.xunara.test", selfServiceSignupPath, map[string]string{
				"login": "admission-owner", "password": "correct horse battery staple",
			})
			if recorder.Code != http.StatusCreated {
				t.Fatal("self-service did not recover after rate storage became available")
			}
		})
	}
}

func TestSelfServiceOwnerFailureReleasesOrganizationAndAllocation(t *testing.T) {
	for _, table := range []string{"local_bootstrap_state", "local_credentials", "sessions", "audit_events"} {
		t.Run(table, func(t *testing.T) {
			failClaim := true
			router, plans := selfServiceRouterWith(t, selfServiceTestOptions{
				cfg: &SelfServiceConfig{DomainSuffix: "xunara.test"},
				prepareTenant: func(server *Server) error {
					if !failClaim {
						return nil
					}
					_, err := server.store.(*state.SQLiteStore).DB().Exec(fmt.Sprintf(
						"CREATE TRIGGER unavailable_tenant_owner BEFORE INSERT ON %s BEGIN SELECT RAISE(ABORT, 'private tenant owner diagnostic'); END", table))
					return err
				},
			})
			before := router.orgSnapshot()
			recorder := postJSONAtHost(t, router.Handler(), "app.xunara.test", selfServiceSignupPath, map[string]string{
				"login": "retry-owner", "password": "correct horse battery staple",
			})
			if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") == "" || recorder.Header().Get("Set-Cookie") != "" || strings.Contains(recorder.Body.String(), "private tenant owner diagnostic") {
				t.Fatal("failed tenant owner claim returned success or exposed private data")
			}
			if !reflect.DeepEqual(before, router.orgSnapshot()) {
				t.Fatal("failed tenant owner claim remained routable")
			}
			if records, err := router.cfg.Registry.List(t.Context()); err != nil || len(records) != 0 {
				t.Fatal("failed tenant owner claim left an organization record")
			}
			if assignments, err := plans.List(t.Context()); err != nil || len(assignments) != 0 {
				t.Fatal("failed tenant owner claim leaked a plan or network allocation")
			}
			failClaim = false
			recorder = postJSONAtHost(t, router.Handler(), "app.xunara.test", selfServiceSignupPath, map[string]string{
				"login": "retry-owner", "password": "correct horse battery staple",
			})
			if recorder.Code != http.StatusCreated || router.orgByID("retry-owner") == nil {
				t.Fatal("failed tenant owner claim prevented a clean retry")
			}
			owner := router.orgByID("retry-owner").site.Server
			if len(owner.identity.ListUsers()) != 1 || owner.readSetupToken() != "" {
				t.Fatal("recovered self-service wasted a member slot or left a setup token")
			}
			if required, err := owner.localSetupRequired(t.Context()); err != nil || required {
				t.Fatal("recovered tenant owner was not durably initialized")
			}
		})
	}
}

func TestSelfServiceCancelledAdmissionDoesNotWrite(t *testing.T) {
	router, plans := selfServiceRouter(t, &SelfServiceConfig{DomainSuffix: "xunara.test"})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "http://app.xunara.test"+selfServiceSignupPath, strings.NewReader(`{"login":"cancelled-owner","password":"correct horse battery staple"}`)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Set-Cookie") != "" {
		t.Fatal("cancelled admission did not fail closed")
	}
	if assignments, err := plans.List(t.Context()); err != nil || len(assignments) != 0 || len(router.orgSnapshot()) != 2 {
		t.Fatal("cancelled admission allocated a tenant")
	}
	var count int
	if err := router.orgByID("portal").site.Server.store.(*state.SQLiteStore).DB().QueryRow("SELECT COUNT(*) FROM rate_limits").Scan(&count); err != nil || count != 0 {
		t.Fatal("cancelled admission wrote a rate budget")
	}
}
