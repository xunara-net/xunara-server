package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/xunara-net/xunara-server/identity"
)

// 配置只保存密钥引用；不能把 client_secret 写进可分发的组织 JSON 或进程参数。
type oauth2ProviderConfig struct {
	ID               string   `json:"id"`
	Type             string   `json:"type"`
	DisplayName      string   `json:"display_name"`
	ClientID         string   `json:"client_id"`
	ClientSecretEnv  string   `json:"client_secret_env"`
	ClientSecretFile string   `json:"client_secret_file"`
	RedirectURL      string   `json:"redirect_url"`
	BaseURL          string   `json:"base_url"`
	AuthURL          string   `json:"auth_url"`
	TokenURL         string   `json:"token_url"`
	UserInfoURL      string   `json:"userinfo_url"`
	SubjectField     string   `json:"subject_field"`
	NameField        string   `json:"name_field"`
	UsernameField    string   `json:"username_field"`
	EmailField       string   `json:"email_field"`
	AuthStyle        string   `json:"auth_style"`
	Scopes           []string `json:"scopes"`
}

func loadOAuth2ConfigFile(filename string) ([]identity.OAuth2Config, error) {
	if filename == "" {
		return nil, nil
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, errors.New("cannot open OAuth2 configuration file")
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(contents) > 1<<20 {
		return nil, errors.New("OAuth2 configuration file must not exceed 1 MiB")
	}
	var config []oauth2ProviderConfig
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF || len(config) == 0 {
		return nil, errors.New("OAuth2 configuration must be a nonempty JSON array of provider configurations without unknown fields")
	}
	return buildOAuth2Configs(config)
}

func buildOAuth2Configs(configs []oauth2ProviderConfig) ([]identity.OAuth2Config, error) {
	if len(configs) > 16 {
		return nil, errors.New("at most 16 OAuth2 providers can be configured per tenant")
	}
	providers := make([]identity.OAuth2Config, 0, len(configs))
	for index, config := range configs {
		secret, err := oauth2ClientSecret(config)
		if err != nil {
			return nil, fmt.Errorf("OAuth2 provider[%d]: %w", index, err)
		}
		providers = append(providers, identity.OAuth2Config{
			ID: config.ID, Type: config.Type, DisplayName: config.DisplayName,
			ClientID: config.ClientID, ClientSecret: secret, RedirectURL: config.RedirectURL,
			BaseURL: config.BaseURL, AuthURL: config.AuthURL, TokenURL: config.TokenURL, UserInfoURL: config.UserInfoURL,
			SubjectField: config.SubjectField, NameField: config.NameField, UsernameField: config.UsernameField,
			EmailField: config.EmailField, AuthStyle: config.AuthStyle, Scopes: config.Scopes,
		})
	}
	return providers, nil
}

func oauth2ClientSecret(config oauth2ProviderConfig) (string, error) {
	if (config.ClientSecretEnv == "") == (config.ClientSecretFile == "") {
		return "", errors.New("choose exactly one client_secret_env or client_secret_file")
	}
	var secret string
	if config.ClientSecretEnv != "" {
		secret = os.Getenv(config.ClientSecretEnv)
	} else {
		if !filepath.IsAbs(config.ClientSecretFile) {
			return "", errors.New("OAuth2 client secret file must use an absolute path")
		}
		info, err := os.Lstat(config.ClientSecretFile)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return "", errors.New("OAuth2 client secret file must be a regular non-symlink file with mode 0600")
		}
		file, err := os.Open(config.ClientSecretFile)
		if err != nil {
			return "", errors.New("cannot read OAuth2 client secret file")
		}
		defer file.Close()
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 {
			return "", errors.New("OAuth2 client secret file changed while opening")
		}
		contents, err := io.ReadAll(io.LimitReader(file, 8193))
		if err != nil || len(contents) > 8192 {
			return "", errors.New("OAuth2 client secret file must not exceed 8192 bytes")
		}
		secret = strings.TrimSpace(string(contents))
	}
	if secret == "" || len(secret) > 8192 || strings.ContainsAny(secret, "\r\n\x00") {
		return "", errors.New("OAuth2 client secret is missing or invalid")
	}
	return secret, nil
}
