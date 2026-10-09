package control

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"tailscale.com/tailcfg"

	xunarav2 "github.com/xunara-net/xunara-server/api/gen/xunara/v2"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

type failingAuthenticationStore struct {
	identity.Store
	sessionError error
	userError    error
	keyError     error
	faultToken   string
}

func (store *failingAuthenticationStore) GetSessionByToken(token string) (identity.Session, error) {
	if store.sessionError != nil && (store.faultToken == "" || store.faultToken == token) {
		return identity.Session{}, store.sessionError
	}
	return store.Store.GetSessionByToken(token)
}

func (store *failingAuthenticationStore) LookupUser(ctx context.Context, userID tailcfg.UserID) (identity.User, error) {
	if store.userError != nil {
		return identity.User{}, store.userError
	}
	return store.Store.LookupUser(ctx, userID)
}

func (store *failingAuthenticationStore) GetAPIKeyByToken(token string) (identity.APIKey, error) {
	if store.keyError != nil {
		return identity.APIKey{}, store.keyError
	}
	return store.Store.GetAPIKeyByToken(token)
}

func TestHTTPAuthenticationStorageFailureDoesNotSignOut(t *testing.T) {
	for _, failure := range []string{"session", "user"} {
		t.Run(failure, func(t *testing.T) {
			server := newTestServer(t)
			cookie, token := seedUserSession(t, server, state.DefaultUserID)
			store := &failingAuthenticationStore{Store: server.identity}
			privateError := errors.New("private-database-detail")
			if failure == "session" {
				store.sessionError = privateError
			} else {
				store.userError = privateError
			}
			server.identity = store
			for _, endpoint := range []struct{ method, path string }{
				{http.MethodGet, "/api/v1/auth/session"},
				{http.MethodGet, "/api/v1/account"},
				{http.MethodGet, "/api/v1/account/sessions"},
				{http.MethodGet, "/api/v1/account/passkeys"},
				{http.MethodGet, "/api/v1/overview"},
				{http.MethodPost, "/api/v1/auth/logout"},
			} {
				response := accountRequest(t, server, endpoint.method, endpoint.path, nil, cookie, nil)
				if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "AUTH_UNAVAILABLE") {
					t.Fatalf("%s returned %d instead of a temporary authentication failure", endpoint.path, response.Code)
				}
				if response.Header().Get("Set-Cookie") != "" || response.Header().Get("Retry-After") == "" ||
					response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), privateError.Error()) {
					t.Fatal("authentication failure cleared a cookie, leaked details or was cacheable")
				}
			}
			store.sessionError, store.userError = nil, nil
			response := accountRequest(t, server, http.MethodGet, "/api/v1/auth/session", nil, cookie, nil)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"authenticated":true`) {
				t.Fatal("original login was not usable after storage recovery")
			}
			if _, err := store.Store.GetSessionByToken(token); err != nil {
				t.Fatal("failed authentication revoked the durable session")
			}
		})
	}
}

func TestHTMLAuthenticationFailureKeepsCookie(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := seedUserSession(t, server, state.DefaultUserID)
	server.identity = &failingAuthenticationStore{Store: server.identity, sessionError: errors.New("private-database-detail")}
	for _, endpoint := range []struct{ method, path string }{
		{http.MethodPost, "/logout"},
		{http.MethodGet, "/console"},
	} {
		response := accountRequest(t, server, endpoint.method, endpoint.path, nil, cookie, nil)
		if response.Code != http.StatusServiceUnavailable || response.Header().Get("Set-Cookie") != "" ||
			response.Header().Get("Location") != "" || strings.Contains(response.Body.String(), "private-database-detail") {
			t.Fatalf("%s treated a storage failure as a successful logout or redirect: %d", endpoint.path, response.Code)
		}
	}
}

func TestCookieResolutionDoesNotHideAuthenticationFailure(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := seedUserSession(t, server, state.DefaultUserID)
	server.identity = &failingAuthenticationStore{Store: server.identity, sessionError: errors.New("temporary failure"), faultToken: "faulty-old-cookie"}
	response := accountRequest(t, server, http.MethodGet, "/api/v1/auth/session", nil, nil, map[string]string{
		"Cookie": sessionCookieName + "=faulty-old-cookie; " + sessionCookieName + "=" + cookie.Value,
	})
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"authenticated":true`) {
		t.Fatal("an earlier faulty Cookie hid a later verified session")
	}
	response = accountRequest(t, server, http.MethodGet, "/api/v1/auth/session", nil, nil, map[string]string{
		"Cookie": sessionCookieName + "=faulty-old-cookie; " + sessionCookieName + "=unknown-cookie",
	})
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("unresolved Cookie failure was reported as anonymous")
	}
}

func TestBearerAuthenticationFailuresAgreeAcrossTransports(t *testing.T) {
	for _, failure := range []string{"session", "user", "service-key"} {
		t.Run(failure, func(t *testing.T) {
			server := newTestServer(t)
			_, token := seedUserSession(t, server, state.DefaultUserID)
			store := &failingAuthenticationStore{Store: server.identity}
			switch failure {
			case "session":
				store.sessionError = errors.New("private-database-detail")
			case "user":
				store.userError = errors.New("private-database-detail")
			case "service-key":
				_, token = seedAPIKey(t, server)
				store.keyError = errors.New("private-database-detail")
			}
			server.identity = store
			response := accountRequest(t, server, http.MethodGet, "/api/v1/overview", nil, nil, map[string]string{"Authorization": "Bearer " + token})
			if response.Code != http.StatusServiceUnavailable {
				t.Fatal("HTTP authentication failure was not temporary")
			}
			client := startGRPCTestServer(t, server.RegisterPlatformGRPC)
			_, err := client.GetMeta(grpcCtx(token), &xunarav2.GetMetaRequest{})
			if status.Code(err) != codes.Unavailable || strings.Contains(err.Error(), "private-database-detail") {
				t.Fatal("gRPC authentication did not preserve the same failure boundary")
			}
		})
	}
}
