package identity

import (
	"context"
	"errors"
	"time"
)

var ErrMemberLimitReached = errors.New("identity: member limit reached")

// LocalRegistration 包含事务提交所需数据；密码校验和慢哈希在调用方完成。
// MaxUsers 为 -1 时不限，0 时拒绝新增；额度来自 Entitlement，不解释套餐名称。
type LocalRegistration struct {
	LoginName    string
	DisplayName  string
	Email        string
	PasswordHash []byte
	InviteToken  string
	MaxUsers     int
	SessionTTL   time.Duration
}

type RegistrationStore interface {
	// RegisterLocalAccount 将账户、凭据、邀请、配额、会话和审计作为一个提交单元。
	// 不接受请求传入角色；邀请角色在事务内读取，无邀请的新账户只能是 member。
	RegisterLocalAccount(ctx context.Context, registration LocalRegistration) (User, Session, string, error)
}
