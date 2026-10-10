package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
)

type interceptedMemberStore struct {
	identity.Store
	beforeUpdate func()
	updateError  error
	listError    error
	lookupError  error
	lookupID     tailcfg.UserID
}

func (store *interceptedMemberStore) UpdateMember(ctx context.Context, caller identity.MemberCaller, userID tailcfg.UserID, patch identity.MemberPatch) (identity.User, error) {
	if store.beforeUpdate != nil {
		store.beforeUpdate()
	}
	if store.updateError != nil {
		return identity.User{}, store.updateError
	}
	return store.Store.UpdateMember(ctx, caller, userID, patch)
}

func (store *interceptedMemberStore) ListUsersContext(ctx context.Context) ([]identity.User, error) {
	if store.listError != nil {
		return nil, store.listError
	}
	return store.Store.ListUsersContext(ctx)
}

func (store *interceptedMemberStore) LookupUser(ctx context.Context, userID tailcfg.UserID) (identity.User, error) {
	if store.lookupError != nil && userID == store.lookupID {
		return identity.User{}, store.lookupError
	}
	return store.Store.LookupUser(ctx, userID)
}

func TestAPIMemberVersionedUpdatesAndNoOpAudit(test *testing.T) {
	server := newTestServer(test)
	host := newTestHTTPServer(test, server)
	client := noRedirectClient()
	cookie, _ := seedUserSession(test, server, 1)
	memberID := seedRoleUser(test, server, "versioned-member", identity.RoleMember)
	member, _ := server.identity.GetUser(memberID)
	listed := getRequest(test, client, host.URL+"/api/v1/users", cookie)
	var payload struct {
		Users []apiUser `json:"users"`
	}
	if err := json.NewDecoder(listed.Body).Decode(&payload); err != nil {
		test.Fatal(err)
	}
	listed.Body.Close()
	if listed.StatusCode != http.StatusOK || len(payload.Users) != 2 || !payload.Users[1].UpdatedAt.Equal(member.UpdatedAt) {
		test.Fatal("member listing omitted the persisted version")
	}
	baseline := len(server.identity.ListAudit(0))
	updated := apiRequestWithCookie(test, client, http.MethodPatch, host.URL+"/api/v1/users/"+itoa(memberID), cookie,
		map[string]any{"role": "admin", "expectedUpdatedAt": member.UpdatedAt})
	var view apiUser
	if err := json.NewDecoder(updated.Body).Decode(&view); err != nil {
		test.Fatal(err)
	}
	updated.Body.Close()
	if updated.StatusCode != http.StatusOK || view.Role != "admin" || !view.UpdatedAt.After(member.UpdatedAt) {
		test.Fatal("update response did not return committed facts")
	}
	stale := apiRequestWithCookie(test, client, http.MethodPatch, host.URL+"/api/v1/users/"+itoa(memberID), cookie,
		map[string]any{"role": "member", "expectedUpdatedAt": member.UpdatedAt})
	if stale.StatusCode != http.StatusConflict || !strings.Contains(bodyString(test, stale), "MEMBER_CHANGED") {
		test.Fatal("stale browser confirmation overwrote the role")
	}
	repeated := apiRequestWithCookie(test, client, http.MethodPatch, host.URL+"/api/v1/users/"+itoa(memberID), cookie,
		map[string]any{"role": "admin", "expectedUpdatedAt": view.UpdatedAt})
	repeated.Body.Close()
	if repeated.StatusCode != http.StatusOK || len(server.identity.ListAudit(0)) != baseline+1 {
		test.Fatal("failed/no-op updates appended success audits")
	}
}

func TestAPIMemberUpdateRechecksActualCredentials(test *testing.T) {
	for _, changed := range []string{"session revoked", "owner demoted", "service key revoked", "service owner demoted"} {
		for _, noChange := range []bool{false, true} {
			test.Run(changed+map[bool]string{true: "/no-op", false: "/change"}[noChange], func(test *testing.T) {
				server := newTestServer(test)
				host := newTestHTTPServer(test, server)
				client := noRedirectClient()
				original := server.identity
				seedRoleUser(test, server, "backup-owner", identity.RoleOwner)
				memberID := seedRoleUser(test, server, "target-member", identity.RoleMember)
				member, _ := original.GetUser(memberID)
				owner, _ := original.GetUser(1)
				cookie, token := seedUserSession(test, server, owner.ID)
				session, err := original.GetSessionByToken(token)
				if err != nil {
					test.Fatal(err)
				}
				service := strings.HasPrefix(changed, "service")
				if service {
					token = seedAPIKeyForUser(test, server, owner.ID)
				}
				baseline := len(original.ListAudit(0))
				// HTTP 门禁已通过后再撤销/降权，验证写事务不会使用门禁时的旧快照。
				server.identity = &interceptedMemberStore{Store: original, beforeUpdate: func() {
					switch changed {
					case "session revoked":
						if err := original.RevokeSession(session.ID, "test revocation"); err != nil {
							test.Fatal(err)
						}
					case "service key revoked":
						credential, err := original.GetAPIKeyByToken(token)
						if err != nil {
							test.Fatal(err)
						}
						if err := original.RevokeAPIKey(credential.ID); err != nil {
							test.Fatal(err)
						}
					default:
						owner.Role = identity.RoleMember
						if err := original.UpdateUser(owner); err != nil {
							test.Fatal(err)
						}
					}
				}}
				role := "admin"
				if noChange {
					role = "member"
				}
				body := map[string]any{"role": role, "expectedUpdatedAt": member.UpdatedAt}
				var response *http.Response
				if service {
					response = apiRequest(test, client, http.MethodPatch, host.URL+"/api/v1/users/"+itoa(memberID), token, body)
				} else {
					response = apiRequestWithCookie(test, client, http.MethodPatch, host.URL+"/api/v1/users/"+itoa(memberID), cookie, body)
				}
				response.Body.Close()
				want := http.StatusForbidden
				if changed == "session revoked" {
					want = http.StatusUnauthorized
				}
				stored, _ := original.GetUser(memberID)
				if response.StatusCode != want || stored != member || len(original.ListAudit(0)) != baseline {
					test.Fatalf("old principal still writes: %d, %+v", response.StatusCode, stored)
				}
			})
		}
	}
}

func TestAPIMemberStorageFailuresAreNotEmptyOrMissing(test *testing.T) {
	for _, failure := range []string{"list", "lookup", "update"} {
		test.Run(failure, func(test *testing.T) {
			server := newTestServer(test)
			host := newTestHTTPServer(test, server)
			client := noRedirectClient()
			cookie, _ := seedUserSession(test, server, 1)
			memberID := seedRoleUser(test, server, "target-member", identity.RoleMember)
			member, _ := server.identity.GetUser(memberID)
			original := server.identity
			broken := &interceptedMemberStore{Store: original, lookupID: memberID}
			privateFailure := errors.New("injected private storage detail")
			switch failure {
			case "list":
				broken.listError = privateFailure
			case "lookup":
				broken.lookupError = privateFailure
			case "update":
				broken.updateError = privateFailure
			}
			server.identity = broken
			var response *http.Response
			if failure == "list" {
				response = getRequest(test, client, host.URL+"/api/v1/users", cookie)
			} else {
				response = apiRequestWithCookie(test, client, http.MethodPatch, host.URL+"/api/v1/users/"+itoa(memberID), cookie,
					map[string]any{"role": "admin", "expectedUpdatedAt": member.UpdatedAt})
			}
			body := bodyString(test, response)
			stored, _ := original.GetUser(memberID)
			if response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "MEMBERS_UNAVAILABLE") || strings.Contains(body, privateFailure.Error()) || stored != member {
				test.Fatalf("storage fault became success/missing or leaked details: %d %s", response.StatusCode, body)
			}
		})
	}
}

func TestConsoleMemberUpdateSharesVersionAndAudit(test *testing.T) {
	server := newTestServer(test)
	host := newTestHTTPServer(test, server)
	client := noRedirectClient()
	cookie, token := seedUserSession(test, server, 1)
	memberID := seedRoleUser(test, server, "console-member", identity.RoleMember)
	member, _ := server.identity.GetUser(memberID)
	response := getRequest(test, client, host.URL+"/console/users", cookie)
	if response.StatusCode != http.StatusOK || !strings.Contains(bodyString(test, response), `name="expectedUpdatedAt"`) {
		test.Fatal("compatibility form omitted the version")
	}
	fields := map[string][]string{"csrf": {csrfTokenFor(token)}, "role": {"admin"}, "expectedUpdatedAt": {member.UpdatedAt.Format("2006-01-02T15:04:05.999999999Z07:00")}}
	baseline := len(server.identity.ListAudit(0))
	response = postForm(test, client, host.URL+"/console/users/"+itoa(memberID), fields, cookie)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		test.Fatalf("compatibility form update failed: %d", response.StatusCode)
	}
	fields["role"] = []string{"member"}
	response = postForm(test, client, host.URL+"/console/users/"+itoa(memberID), fields, cookie)
	if response.StatusCode != http.StatusConflict || !strings.Contains(bodyString(test, response), "MEMBER_CHANGED") {
		test.Fatal("compatibility form bypassed the same version check")
	}
	stored, _ := server.identity.GetUser(memberID)
	if stored.Role != identity.RoleAdmin || len(server.identity.ListAudit(0)) != baseline+1 {
		test.Fatal("form and API did not share atomic audit behavior")
	}
}
