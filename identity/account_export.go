package identity

import (
	"errors"
	"time"
)

const MaxAccountExportRows = 5000
const MaxAccountExportTextBytes = 8 << 20

type AccountExportScope string

const (
	AccountSecurityExportScope AccountExportScope = "account-security"
	LoginHistoryExportScope    AccountExportScope = "login-history"
)

var (
	ErrInvalidAccountExport  = errors.New("identity: invalid account export options")
	ErrAccountExportTooLarge = errors.New("identity: account export exceeds the row limit")
)

type AccountExportOptions struct {
	Scope AccountExportScope
	From  time.Time
	Until time.Time
}

func (options AccountExportOptions) validate() error {
	if options.Scope != AccountSecurityExportScope && options.Scope != LoginHistoryExportScope {
		return ErrInvalidAccountExport
	}
	for _, timestamp := range []time.Time{options.From, options.Until} {
		if !timestamp.IsZero() && (timestamp.UnixNano() <= 0 || !time.Unix(0, timestamp.UnixNano()).Equal(timestamp)) {
			return ErrInvalidAccountExport
		}
	}
	if !options.From.IsZero() && !options.Until.IsZero() && !options.From.Before(options.Until) {
		return ErrInvalidAccountExport
	}
	return nil
}

// 导出只持有允许公开给本人的字段，不读取外部 subject 或通行密钥认证材料。
type AccountExportIdentity struct {
	ProviderID  string
	DisplayName string
	Email       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type AccountExportPasskey struct {
	ID         string
	Name       string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

type AccountExportSnapshot struct {
	GeneratedAt             time.Time
	Options                 AccountExportOptions
	User                    User
	LocalPasswordConfigured bool
	Sessions                []Session
	LoginHistory            []LoginRecord
	Identities              []AccountExportIdentity
	Passkeys                []AccountExportPasskey
}

// 在读取期间累计白名单文本，避免大量历史外部属性先撑大内存再被文件上限拒绝。
func consumeAccountExportText(remaining *int, values ...string) error {
	for _, value := range values {
		if len(value) > *remaining {
			return ErrAccountExportTooLarge
		}
		*remaining -= len(value)
	}
	return nil
}
