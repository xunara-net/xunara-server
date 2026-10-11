package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/oauth2"
)

var (
	ErrOAuth2Exchange = errors.New("identity: OAuth2 code exchange rejected")
	ErrOAuth2Token    = errors.New("identity: OAuth2 bearer token rejected")
	ErrOAuth2Profile  = errors.New("identity: OAuth2 current-user response rejected")
)

// OAuth2Config 只描述人类账户认证，不能用提供方资料直接决定租户、角色或设备信任。
type OAuth2Config struct {
	ID, Type, DisplayName          string
	ClientID, ClientSecret         string
	RedirectURL, BaseURL           string
	AuthURL, TokenURL, UserInfoURL string
	SubjectField, NameField        string
	UsernameField, EmailField      string
	AuthStyle                      string
	Scopes                         []string
}

func (config OAuth2Config) String() string {
	return fmt.Sprintf("OAuth2Config{ID:%s Type:%s}", config.ID, config.Type)
}

type OAuth2Provider struct {
	cfg   OAuth2Config
	oauth oauth2.Config
}

var _ IdentityProvider = (*OAuth2Provider)(nil)

func NewOAuth2Provider(config OAuth2Config) (*OAuth2Provider, error) {
	if config.ID == "" {
		config.ID = config.Type
	}
	if !validOAuth2ProviderID(config.ID) || config.ID == LocalProviderID {
		return nil, errors.New("identity: OAuth2 needs a non-reserved provider ID (1-64 letters, digits, hyphen or underscore)")
	}
	if config.DisplayName == "" {
		config.DisplayName = config.ID
	}
	if config.ClientID == "" || config.ClientSecret == "" {
		return nil, errors.New("identity: OAuth2 needs a client ID and a server-side client secret")
	}
	if err := validateOAuth2URL(config.RedirectURL); err != nil {
		return nil, errors.New("identity: OAuth2 redirect URL must be HTTPS or loopback HTTP without credentials, query or fragment")
	}
	if config.Type != "generic" {
		// 内置提供方不能被自定义端点或身份字段冒名替换；换发行方必须使用新 ID。
		if config.AuthURL != "" || config.TokenURL != "" || config.UserInfoURL != "" || config.SubjectField != "" || config.NameField != "" || config.UsernameField != "" || config.EmailField != "" {
			return nil, errors.New("identity: built-in OAuth2 providers do not accept endpoint or identity field overrides")
		}
		config.SubjectField, config.NameField, config.EmailField = "id", "name", "email"
		switch config.Type {
		case "github":
			if config.BaseURL != "" {
				return nil, errors.New("identity: GitHub OAuth2 uses the fixed github.com endpoints")
			}
			config.DisplayName = defaultOAuth2Name(config.DisplayName, config.ID, "GitHub")
			config.AuthURL, config.TokenURL, config.UserInfoURL = "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token", "https://api.github.com/user"
			config.UsernameField = "login"
			if len(config.Scopes) == 0 {
				config.Scopes = []string{"read:user"}
			}
		case "gitlab", "gitea":
			if config.BaseURL == "" && config.Type == "gitlab" {
				config.BaseURL = "https://gitlab.com"
			}
			if err := validateOAuth2URL(config.BaseURL); err != nil {
				return nil, errors.New("identity: GitLab/Gitea OAuth2 needs a secure base URL without credentials, query or fragment")
			}
			base := strings.TrimRight(config.BaseURL, "/")
			if config.Type == "gitlab" {
				config.DisplayName = defaultOAuth2Name(config.DisplayName, config.ID, "GitLab")
				config.AuthURL, config.TokenURL, config.UserInfoURL = base+"/oauth/authorize", base+"/oauth/token", base+"/api/v4/user"
				config.UsernameField = "username"
				if len(config.Scopes) == 0 {
					config.Scopes = []string{"read_user"}
				}
			} else {
				config.DisplayName = defaultOAuth2Name(config.DisplayName, config.ID, "Gitea")
				config.AuthURL, config.TokenURL, config.UserInfoURL = base+"/login/oauth/authorize", base+"/login/oauth/access_token", base+"/api/v1/user"
				config.UsernameField = "login"
				if len(config.Scopes) == 0 {
					config.Scopes = []string{"read:user"}
				}
			}
		default:
			return nil, errors.New("identity: unsupported OAuth2 provider type")
		}
	} else {
		if config.BaseURL != "" || !validOAuth2SubjectField(config.SubjectField) {
			return nil, errors.New("identity: generic OAuth2 needs an immutable subject field, not email, name or username")
		}
	}
	for _, endpoint := range []string{config.AuthURL, config.TokenURL, config.UserInfoURL} {
		if err := validateOAuth2URL(endpoint); err != nil {
			return nil, errors.New("identity: OAuth2 endpoints must be HTTPS or loopback HTTP without credentials, query or fragment")
		}
	}
	style := oauth2.AuthStyleInParams
	switch config.AuthStyle {
	case "", "client_secret_post":
		config.AuthStyle = "client_secret_post"
	case "client_secret_basic":
		if config.Type != "generic" {
			return nil, errors.New("identity: built-in OAuth2 providers use client_secret_post")
		}
		style = oauth2.AuthStyleInHeader
	default:
		return nil, errors.New("identity: unsupported OAuth2 client authentication style")
	}
	config.Scopes = append([]string(nil), config.Scopes...)
	return &OAuth2Provider{cfg: config, oauth: oauth2.Config{
		ClientID: config.ClientID, ClientSecret: config.ClientSecret, RedirectURL: config.RedirectURL,
		Scopes: config.Scopes, Endpoint: oauth2.Endpoint{AuthURL: config.AuthURL, TokenURL: config.TokenURL, AuthStyle: style},
	}}, nil
}

func (provider *OAuth2Provider) ID() string          { return provider.cfg.ID }
func (provider *OAuth2Provider) DisplayName() string { return provider.cfg.DisplayName }
func (provider *OAuth2Provider) RedirectURL() string { return provider.cfg.RedirectURL }
func (provider *OAuth2Provider) Protocol() string    { return "oauth2" }

func (provider *OAuth2Provider) Begin(ctx context.Context, transaction *AuthTransaction) (*AuthorizationRequest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := provider.validateTransaction(transaction); err != nil {
		return nil, err
	}
	return &AuthorizationRequest{URL: provider.oauth.AuthCodeURL(transaction.State, oauth2.S256ChallengeOption(transaction.PKCEVerifier))}, nil
}

func (provider *OAuth2Provider) Callback(ctx context.Context, transaction *AuthTransaction, request *CallbackRequest) (*IdentityResult, error) {
	if err := provider.validateTransaction(transaction); err != nil {
		return nil, err
	}
	if request == nil || request.State == "" || !constantTimeEqual(transaction.State, request.State) {
		return nil, ErrStateMismatch
	}
	if request.Error != "" {
		return nil, &ProviderError{ProviderID: provider.ID(), Code: "authorization_rejected"}
	}
	if request.Code == "" || len(request.Code) > 4096 {
		return nil, ErrOAuth2Exchange
	}
	client := oauth2HTTPClient(ctx)
	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	// 固定客户端认证方式，避免自动探测重兑同一授权码；错误正文可能含秘密，不能向上透传。
	token, err := provider.oauth.Exchange(ctx, request.Code, oauth2.VerifierOption(transaction.PKCEVerifier))
	if err != nil {
		return nil, ErrOAuth2Exchange
	}
	if !token.Valid() || !strings.EqualFold(token.TokenType, "Bearer") || !validOAuth2Bearer(token.AccessToken) {
		return nil, ErrOAuth2Token
	}
	profileRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.cfg.UserInfoURL, nil)
	if err != nil {
		return nil, ErrOAuth2Profile
	}
	profileRequest.Header.Set("Authorization", "Bearer "+token.AccessToken)
	profileRequest.Header.Set("Accept", "application/json")
	profileRequest.Header.Set("User-Agent", "Xunara-OAuth2")
	if provider.cfg.Type == "github" {
		profileRequest.Header.Set("Accept", "application/vnd.github+json")
	}
	response, err := client.Do(profileRequest)
	if err != nil {
		return nil, ErrOAuth2Profile
	}
	defer response.Body.Close()
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || err != nil || contentType != "application/json" && !strings.HasSuffix(contentType, "+json") {
		return nil, ErrOAuth2Profile
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 || !utf8.Valid(body) {
		return nil, ErrOAuth2Profile
	}
	var profile map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&profile); err != nil || profile == nil || decoder.Decode(new(any)) != io.EOF {
		return nil, ErrOAuth2Profile
	}
	subject, ok := oauth2Subject(profile[provider.cfg.SubjectField], provider.cfg.Type != "generic")
	if !ok {
		return nil, ErrOAuth2Profile
	}
	name, nameOK := oauth2ProfileString(profile, provider.cfg.NameField)
	username, usernameOK := oauth2ProfileString(profile, provider.cfg.UsernameField)
	email, emailOK := oauth2ProfileString(profile, provider.cfg.EmailField)
	if !nameOK || !usernameOK || !emailOK {
		return nil, ErrOAuth2Profile
	}
	if name == "" {
		name = username
	}
	if name == "" {
		name = subject
	}
	// 只保留公开展示属性；丢弃 api_key、token、groups、site_admin 等原始资料，绝不按邮箱合并。
	return &IdentityResult{ProviderID: provider.ID(), Subject: subject, DisplayName: name, Email: email}, nil
}

func (provider *OAuth2Provider) validateTransaction(transaction *AuthTransaction) error {
	if transaction == nil || transaction.ProviderID != provider.ID() || transaction.State == "" || transaction.RedirectURI != provider.RedirectURL() || transaction.PKCEMethod != "S256" || !validPKCEVerifier(transaction.PKCEVerifier) || !constantTimeEqual(transaction.PKCEChallenge, PKCEChallenge(transaction.PKCEVerifier)) || transaction.ExpiresAt.IsZero() {
		return errors.New("identity: OAuth2 transaction binding rejected")
	}
	if transaction.Consumed() {
		return ErrTransactionConsumed
	}
	if !time.Now().Before(transaction.ExpiresAt) {
		return ErrTransactionExpired
	}
	return nil
}

func oauth2HTTPClient(ctx context.Context) *http.Client {
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if existing, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && existing != nil {
		client.Transport = existing.Transport
	}
	return client
}

func validateOAuth2URL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Hostname() == "" {
		return errors.New("invalid OAuth2 endpoint")
	}
	return ValidateSecureURL(raw)
}

func validOAuth2ProviderID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || index > 0 && (character == '-' || character == '_') {
			continue
		}
		return false
	}
	return true
}

func validOAuth2SubjectField(value string) bool {
	if !validOAuth2ProviderID(value) {
		return false
	}
	switch strings.ToLower(value) {
	case "email", "mail", "name", "username", "login", "display_name", "preferred_username", "access_token", "refresh_token", "api_key":
		return false
	}
	return true
}

func validPKCEVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("-._~", character) {
			continue
		}
		return false
	}
	return true
}

func validOAuth2Bearer(value string) bool {
	if len(value) == 0 || len(value) > 8192 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("-._~+/=", character) {
			continue
		}
		return false
	}
	return true
}

func oauth2Subject(value any, numericOnly bool) (string, bool) {
	if number, ok := value.(json.Number); ok {
		parsed, err := strconv.ParseUint(string(number), 10, 64)
		return strconv.FormatUint(parsed, 10), err == nil && parsed != 0
	}
	if text, ok := value.(string); ok && !numericOnly && len(text) > 0 && len(text) <= 512 && strings.TrimSpace(text) == text && utf8.ValidString(text) && !strings.ContainsRune(text, utf8.RuneError) && strings.IndexFunc(text, unicode.IsControl) < 0 {
		return text, true
	}
	return "", false
}

func oauth2ProfileString(profile map[string]any, field string) (string, bool) {
	if field == "" || profile[field] == nil {
		return "", true
	}
	value, ok := profile[field].(string)
	return value, ok && len(value) <= 512 && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func defaultOAuth2Name(name, id, fallback string) string {
	if name == id {
		return fallback
	}
	return name
}
