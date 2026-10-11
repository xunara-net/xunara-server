package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type oauth2Fixture struct {
	server      *httptest.Server
	mu          sync.Mutex
	codes       map[string]AuthTransaction
	sequence    int
	exchanges   int
	profiles    int
	profile     string
	profileType string
	profileCode int
	token       string
	tokenType   string
	tokenCode   int
	redirect    string
}

func newOAuth2Fixture(test *testing.T) *oauth2Fixture {
	test.Helper()
	fixture := &oauth2Fixture{codes: make(map[string]AuthTransaction), profile: `{"id":9007199254740993,"login":"renamable","name":"授权用户","email":null,"site_admin":true,"api_key":"must-not-retain"}`,
		profileType: "application/json", profileCode: http.StatusOK, tokenType: "application/json", tokenCode: http.StatusOK,
		token: `{"access_token":"fixture-bearer-never-log","refresh_token":"must-not-retain","token_type":"Bearer","expires_in":120}`}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		if request.URL.RawQuery != "" {
			test.Error("secret-bearing backchannel requests must have no query")
		}
		if request.Method == http.MethodPost {
			fixture.exchanges++
			if err := request.ParseForm(); err != nil {
				test.Error("malformed token request")
			}
			clientID, secret, basic := request.BasicAuth()
			if !basic {
				clientID, secret = request.PostForm.Get("client_id"), request.PostForm.Get("client_secret")
			}
			transaction, exists := fixture.codes[request.PostForm.Get("code")]
			if !exists || clientID != "fixture-client" || secret != "fixture-client-secret-never-log" || request.PostForm.Get("grant_type") != "authorization_code" || request.PostForm.Get("redirect_uri") != transaction.RedirectURI || PKCEChallenge(request.PostForm.Get("code_verifier")) != transaction.PKCEChallenge {
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(writer, `{"error":"invalid_grant","error_description":"fixture-client-secret-never-log"}`)
				return
			}
			delete(fixture.codes, request.PostForm.Get("code"))
			if fixture.redirect == "token" {
				http.Redirect(writer, request, fixture.server.URL+"/unexpected", http.StatusTemporaryRedirect)
				return
			}
			writer.Header().Set("Content-Type", fixture.tokenType)
			writer.WriteHeader(fixture.tokenCode)
			fmt.Fprint(writer, fixture.token)
			return
		}
		fixture.profiles++
		if request.Header.Get("Authorization") != "Bearer fixture-bearer-never-log" || request.Header.Get("User-Agent") == "" {
			test.Error("profile must use Bearer header and User-Agent")
		}
		if fixture.redirect == "profile" {
			http.Redirect(writer, request, fixture.server.URL+"/unexpected", http.StatusFound)
			return
		}
		writer.Header().Set("Content-Type", fixture.profileType)
		writer.WriteHeader(fixture.profileCode)
		fmt.Fprint(writer, fixture.profile)
	}))
	test.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *oauth2Fixture) config() OAuth2Config {
	return OAuth2Config{ID: "fixture", Type: "generic", ClientID: "fixture-client", ClientSecret: "fixture-client-secret-never-log",
		RedirectURL: "https://console.example/oauth2/callback/fixture", AuthURL: fixture.server.URL + "/authorize", TokenURL: fixture.server.URL + "/token", UserInfoURL: fixture.server.URL + "/user",
		SubjectField: "id", NameField: "name", UsernameField: "login", EmailField: "email"}
}

func oauth2TestTransaction(provider *OAuth2Provider) AuthTransaction {
	verifier := strings.Repeat("v", 43)
	return AuthTransaction{ProviderID: provider.ID(), State: "fixture-state", PKCEVerifier: verifier, PKCEChallenge: PKCEChallenge(verifier), PKCEMethod: "S256",
		RedirectURI: provider.RedirectURL(), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
}

func (fixture *oauth2Fixture) request(transaction AuthTransaction) *CallbackRequest {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.sequence++
	code := fmt.Sprintf("fixture-code-%d", fixture.sequence)
	fixture.codes[code] = transaction
	return &CallbackRequest{Code: code, State: transaction.State}
}

func TestOAuth2CodePKCEProfileAndReplay(test *testing.T) {
	for _, authStyle := range []string{"client_secret_post", "client_secret_basic"} {
		test.Run(authStyle, func(test *testing.T) {
			fixture := newOAuth2Fixture(test)
			config := fixture.config()
			config.AuthStyle = authStyle
			provider, err := NewOAuth2Provider(config)
			if err != nil {
				test.Fatal(err)
			}
			transaction := oauth2TestTransaction(provider)
			authorization, err := provider.Begin(test.Context(), &transaction)
			if err != nil {
				test.Fatal(err)
			}
			parsed, err := url.Parse(authorization.URL)
			if err != nil {
				test.Fatal(err)
			}
			query := parsed.Query()
			if query.Get("state") != transaction.State || query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") != transaction.PKCEChallenge || query.Get("redirect_uri") != transaction.RedirectURI || query.Get("nonce") != "" || strings.Contains(authorization.URL, config.ClientSecret) {
				test.Fatal("authorization parameters not securely bound")
			}
			request := fixture.request(transaction)
			result, err := provider.Callback(test.Context(), &transaction, request)
			if err != nil {
				test.Fatal(err)
			}
			if result.Subject != "9007199254740993" || result.ProviderID != provider.ID() || result.DisplayName != "授权用户" || result.Email != "" || len(result.Claims) != 0 {
				test.Fatal("profile ID must retain integer precision and discard secret/role claims")
			}
			if _, err := provider.Callback(test.Context(), &transaction, request); !errors.Is(err, ErrOAuth2Exchange) || strings.Contains(err.Error(), config.ClientSecret) {
				test.Fatal("authorization code replay or secret-bearing error accepted")
			}
		})
	}
}

type oauth2RewriteTransport struct {
	target string
}

func (transport oauth2RewriteTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copyRequest := request.Clone(request.Context())
	parsed, _ := url.Parse(transport.target)
	copyRequest.URL.Scheme, copyRequest.URL.Host = parsed.Scheme, parsed.Host
	return http.DefaultTransport.RoundTrip(copyRequest)
}

func TestOAuth2BuiltInProfilesAndMinimalScopes(test *testing.T) {
	for _, kind := range []string{"github", "gitlab", "gitea"} {
		test.Run(kind, func(test *testing.T) {
			fixture := newOAuth2Fixture(test)
			config := OAuth2Config{Type: kind, ClientID: "fixture-client", ClientSecret: "fixture-client-secret-never-log", RedirectURL: "https://console.example/oauth2/callback/" + kind}
			if kind != "github" {
				config.BaseURL = fixture.server.URL + "/subpath"
			}
			provider, err := NewOAuth2Provider(config)
			if err != nil {
				test.Fatal(err)
			}
			if provider.Protocol() != "oauth2" || len(provider.cfg.Scopes) != 1 || provider.cfg.SubjectField != "id" {
				test.Fatal("built-in defaults changed")
			}
			transaction := oauth2TestTransaction(provider)
			ctx := context.WithValue(test.Context(), oauth2.HTTPClient, &http.Client{Transport: oauth2RewriteTransport{target: fixture.server.URL}})
			result, err := provider.Callback(ctx, &transaction, fixture.request(transaction))
			if err != nil || result.Subject != "9007199254740993" {
				test.Fatalf("built-in callback rejected: %v", err)
			}
		})
	}
}

func TestOAuth2RejectsInvalidTransactionsBeforeHTTP(test *testing.T) {
	fixture := newOAuth2Fixture(test)
	provider, err := NewOAuth2Provider(fixture.config())
	if err != nil {
		test.Fatal(err)
	}
	for _, mutate := range []func(*AuthTransaction){
		func(transaction *AuthTransaction) { transaction.ProviderID = "another" },
		func(transaction *AuthTransaction) { transaction.RedirectURI = "https://evil.example/callback" },
		func(transaction *AuthTransaction) { transaction.PKCEVerifier = "short" },
		func(transaction *AuthTransaction) { transaction.PKCEMethod = "plain" },
		func(transaction *AuthTransaction) { transaction.PKCEChallenge = "wrong" },
		func(transaction *AuthTransaction) { transaction.State = "" },
		func(transaction *AuthTransaction) { transaction.ExpiresAt = time.Now().Add(-time.Second) },
		func(transaction *AuthTransaction) { transaction.ConsumedAt = time.Now() },
	} {
		transaction := oauth2TestTransaction(provider)
		mutate(&transaction)
		if _, err := provider.Begin(test.Context(), &transaction); err == nil {
			test.Fatal("invalid transaction began")
		}
		if _, err := provider.Callback(test.Context(), &transaction, &CallbackRequest{State: transaction.State, Code: "code"}); err == nil {
			test.Fatal("invalid transaction callback accepted")
		}
	}
	transaction := oauth2TestTransaction(provider)
	if _, err := provider.Callback(test.Context(), &transaction, &CallbackRequest{State: "wrong", Code: "code"}); !errors.Is(err, ErrStateMismatch) {
		test.Fatal("wrong state accepted")
	}
	if fixture.exchanges != 0 || fixture.profiles != 0 {
		test.Fatal("invalid binding contacted provider")
	}
	request := fixture.request(transaction)
	transaction.PKCEVerifier = strings.Repeat("x", 43)
	transaction.PKCEChallenge = PKCEChallenge(transaction.PKCEVerifier)
	if _, err := provider.Callback(test.Context(), &transaction, request); !errors.Is(err, ErrOAuth2Exchange) {
		test.Fatal("provider accepted a mismatched PKCE verifier")
	}
}

func TestOAuth2RejectsBackchannelErrorsAndUnsafeProfiles(test *testing.T) {
	cases := []struct {
		name string
		set  func(*oauth2Fixture)
		want error
	}{
		{"token failure", func(fixture *oauth2Fixture) { fixture.tokenCode = 400 }, ErrOAuth2Exchange},
		{"token malformed", func(fixture *oauth2Fixture) { fixture.token = `{` }, ErrOAuth2Exchange},
		{"token absent", func(fixture *oauth2Fixture) { fixture.token = `{"token_type":"Bearer"}` }, ErrOAuth2Exchange},
		{"token expired", func(fixture *oauth2Fixture) {
			fixture.token = `{"access_token":"fixture-bearer-never-log","token_type":"Bearer","expires_in":-60}`
		}, ErrOAuth2Token},
		{"token type", func(fixture *oauth2Fixture) {
			fixture.token = `{"access_token":"fixture-bearer-never-log","token_type":"Basic"}`
		}, ErrOAuth2Token},
		{"token newline", func(fixture *oauth2Fixture) { fixture.token = `{"access_token":"bad\r\nheader","token_type":"Bearer"}` }, ErrOAuth2Token},
		{"token redirect", func(fixture *oauth2Fixture) { fixture.redirect = "token" }, ErrOAuth2Exchange},
		{"profile redirect", func(fixture *oauth2Fixture) { fixture.redirect = "profile" }, ErrOAuth2Profile},
		{"profile forbidden", func(fixture *oauth2Fixture) { fixture.profileCode = 403 }, ErrOAuth2Profile},
		{"profile html", func(fixture *oauth2Fixture) { fixture.profileType = "text/html" }, ErrOAuth2Profile},
		{"profile oversized", func(fixture *oauth2Fixture) { fixture.profile = strings.Repeat(" ", (1<<20)+1) }, ErrOAuth2Profile},
		{"profile malformed", func(fixture *oauth2Fixture) { fixture.profile = `{` }, ErrOAuth2Profile},
		{"profile trailing", func(fixture *oauth2Fixture) { fixture.profile += `{}` }, ErrOAuth2Profile},
		{"profile array", func(fixture *oauth2Fixture) { fixture.profile = `[]` }, ErrOAuth2Profile},
		{"subject missing", func(fixture *oauth2Fixture) { fixture.profile = `{"email":"same@example.test"}` }, ErrOAuth2Profile},
		{"subject bool", func(fixture *oauth2Fixture) { fixture.profile = `{"id":true}` }, ErrOAuth2Profile},
		{"subject negative", func(fixture *oauth2Fixture) { fixture.profile = `{"id":-1}` }, ErrOAuth2Profile},
		{"subject zero", func(fixture *oauth2Fixture) { fixture.profile = `{"id":0}` }, ErrOAuth2Profile},
		{"subject fraction", func(fixture *oauth2Fixture) { fixture.profile = `{"id":1.5}` }, ErrOAuth2Profile},
		{"subject object", func(fixture *oauth2Fixture) { fixture.profile = `{"id":{}}` }, ErrOAuth2Profile},
		{"subject whitespace", func(fixture *oauth2Fixture) { fixture.profile = `{"id":" user "}` }, ErrOAuth2Profile},
		{"subject invalid unicode", func(fixture *oauth2Fixture) { fixture.profile = `{"id":"\ud800"}` }, ErrOAuth2Profile},
		{"profile invalid UTF8", func(fixture *oauth2Fixture) { fixture.profile = "{\"id\":\"\xff\"}" }, ErrOAuth2Profile},
		{"profile attribute type", func(fixture *oauth2Fixture) { fixture.profile = `{"id":1,"name":true}` }, ErrOAuth2Profile},
	}
	for _, item := range cases {
		test.Run(item.name, func(test *testing.T) {
			fixture := newOAuth2Fixture(test)
			item.set(fixture)
			provider, err := NewOAuth2Provider(fixture.config())
			if err != nil {
				test.Fatal(err)
			}
			transaction := oauth2TestTransaction(provider)
			_, err = provider.Callback(test.Context(), &transaction, fixture.request(transaction))
			if !errors.Is(err, item.want) || strings.Contains(err.Error(), "never-log") || strings.Contains(err.Error(), fixture.server.URL) {
				test.Fatalf("unexpected or unsafe error: %v", err)
			}
			if fixture.exchanges != 1 || fixture.profiles > 1 {
				test.Fatal("backchannel retried or followed a redirect")
			}
		})
	}
}

func TestOAuth2SecureConfiguration(test *testing.T) {
	fixture := newOAuth2Fixture(test)
	for _, mutate := range []func(*OAuth2Config){
		func(config *OAuth2Config) { config.ClientID = "" },
		func(config *OAuth2Config) { config.ClientSecret = "" },
		func(config *OAuth2Config) { config.ID = LocalProviderID },
		func(config *OAuth2Config) { config.ID = "../../callback" },
		func(config *OAuth2Config) { config.Type = "unknown" },
		func(config *OAuth2Config) { config.SubjectField = "email" },
		func(config *OAuth2Config) { config.SubjectField = "login" },
		func(config *OAuth2Config) { config.AuthStyle = "query" },
		func(config *OAuth2Config) { config.TokenURL = "http://idp.example/token" },
		func(config *OAuth2Config) { config.TokenURL = "https://idp.example/token?client_secret=never-log" },
		func(config *OAuth2Config) { config.UserInfoURL = "https://idp.example/user#token" },
		func(config *OAuth2Config) { config.AuthURL = "https://user:never-log@idp.example/auth" },
		func(config *OAuth2Config) { config.RedirectURL = "//outside.example" },
	} {
		config := fixture.config()
		mutate(&config)
		_, err := NewOAuth2Provider(config)
		if err == nil || strings.Contains(err.Error(), "never-log") {
			test.Fatal("unsafe provider configuration accepted or logged")
		}
	}
	if strings.Contains(fmt.Sprint(fixture.config()), "never-log") {
		test.Fatal("configuration string leaks secret")
	}
	provider, err := NewOAuth2Provider(fixture.config())
	if err != nil {
		test.Fatal(err)
	}
	transaction := oauth2TestTransaction(provider)
	cancelled, cancel := context.WithCancel(test.Context())
	cancel()
	if _, err := provider.Begin(cancelled, &transaction); !errors.Is(err, context.Canceled) {
		test.Fatal("Begin ignored context cancellation")
	}
	if _, err := provider.Callback(cancelled, &transaction, fixture.request(transaction)); !errors.Is(err, ErrOAuth2Exchange) || fixture.exchanges != 0 {
		test.Fatal("Callback ignored context cancellation")
	}
	fixture.profile = `{"id":"opaque-user","login":"renamed","name":null,"email":"display-only@example.test"}`
	result, err := provider.Callback(test.Context(), &transaction, fixture.request(transaction))
	if err != nil || result.Subject != "opaque-user" || result.DisplayName != "renamed" || result.Email != "display-only@example.test" {
		test.Fatal("generic opaque subject or name fallback rejected")
	}
	fixture.tokenType, fixture.token = "application/x-www-form-urlencoded", "access_token=fixture-bearer-never-log&token_type=bearer"
	if _, err := provider.Callback(test.Context(), &transaction, fixture.request(transaction)); err != nil {
		test.Fatalf("standard form-encoded token rejected: %v", err)
	}
	if _, err := json.Marshal(result); err != nil {
		test.Fatal(err)
	}
}
