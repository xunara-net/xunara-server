package control

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

func TestRelayEnrollmentStorageFailureHTTP(test *testing.T) {
	for _, failure := range []string{"lookup", "commit"} {
		test.Run(failure, func(subtest *testing.T) {
			server := newTestServer(subtest)
			_, apiKey := seedAPIKey(subtest, server, identity.ScopeRead, identity.ScopeWrite)
			endpoint := newTestHTTPServer(subtest, server)
			token, identifier := issueRelayEnrollToken(subtest, endpoint, apiKey, "")
			store := server.store.(*state.SQLiteStore)
			if failure == "lookup" {
				if err := store.Close(); err != nil {
					subtest.Fatal(err)
				}
			} else if _, err := store.DB().Exec(`CREATE TRIGGER reject_enrollment BEFORE UPDATE OF used_at ON relay_enrollment_tokens
				BEGIN SELECT RAISE(ABORT, 'injected internal database detail'); END`); err != nil {
				subtest.Fatal(err)
			}
			response := enrollRelay(subtest, endpoint, token, nil)
			body, err := io.ReadAll(response.Body)
			if err != nil {
				subtest.Fatal(err)
			}
			if response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), `"RELAY_INTERNAL"`) {
				subtest.Fatalf("storage failure status = %d, want a structured 503", response.StatusCode)
			}
			if strings.Contains(string(body), token) || strings.Contains(string(body), "database detail") || strings.Contains(string(body), "database is closed") {
				subtest.Fatal("enrollment error exposed a secret or storage detail")
			}
			if response.Header.Get("Cache-Control") != "no-store" {
				subtest.Fatal("enrollment storage error can be cached")
			}
			if failure == "commit" {
				record, exists := store.RelayEnrollmentTokenByID(identifier)
				if !exists || record.Used() || len(store.ListRelays()) != 0 {
					subtest.Fatal("failed HTTP enrollment left partial state")
				}
				if _, err := store.DB().Exec(`DROP TRIGGER reject_enrollment`); err != nil {
					subtest.Fatal(err)
				}
				if response := enrollRelay(subtest, endpoint, token, nil); response.StatusCode != http.StatusOK {
					subtest.Fatalf("recovery status = %d, want 200", response.StatusCode)
				}
			}
		})
	}
}

func TestRelayEnrollmentTenantCredentialIsolation(test *testing.T) {
	owner := newTestServer(test)
	_, apiKey := seedAPIKey(test, owner, identity.ScopeRead, identity.ScopeWrite)
	ownerEndpoint := newTestHTTPServer(test, owner)
	other := newTestServer(test)
	otherEndpoint := newTestHTTPServer(test, other)
	token, identifier := issueRelayEnrollToken(test, ownerEndpoint, apiKey, "")
	response := enrollRelay(test, otherEndpoint, token, nil)
	if response.StatusCode != http.StatusUnauthorized {
		test.Fatalf("cross-tenant enrollment status = %d, want 401", response.StatusCode)
	}
	record, exists := owner.store.RelayEnrollmentTokenByID(identifier)
	if !exists || record.Used() || len(other.store.ListRelays()) != 0 {
		test.Fatal("cross-tenant rejection mutated either tenant")
	}
	if response := enrollRelay(test, ownerEndpoint, token, nil); response.StatusCode != http.StatusOK {
		test.Fatalf("owner enrollment status = %d, want 200", response.StatusCode)
	}
}
