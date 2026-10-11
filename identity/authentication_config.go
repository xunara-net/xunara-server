package identity

import (
	"context"
	"errors"

	"tailscale.com/tailcfg"
)

var ErrAuthenticationConfigChanged = errors.New("identity: authentication configuration changed")

const AuditAuthenticationConfigured = "authentication.configured"

// 配置正文对存储层是不透明的密封数据；不能把提供方密钥写入审计或响应。
type AuthenticationConfig struct {
	Revision uint64
	Payload  []byte
}

type AuthenticationConfigWrite struct {
	UserID    tailcfg.UserID
	SessionID string
	Platform  bool
	Removed   []string
	Methods   LoginMethods
	Detail    string
}

type AuthenticationConfigStore interface {
	ReadAuthenticationConfig(context.Context) (AuthenticationConfig, error)
	SaveAuthenticationConfig(context.Context, AuthenticationConfig, AuthenticationConfigWrite) (AuthenticationConfig, error)
}
