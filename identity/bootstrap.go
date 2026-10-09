package identity

import (
	"context"
	"errors"
	"time"
)

var ErrLocalAccountClaimed = errors.New("identity: local account initialization already completed")

type LocalAccountClaimKind string

const (
	ClaimAdministrator LocalAccountClaimKind = "administrator"
	ClaimTenantOwner   LocalAccountClaimKind = "tenant-owner"
)

// LocalAccountClaim 只允许服务端指定开通来源，不接受请求传入用户 ID 或角色。
// 密码策略与慢哈希在事务外处理；邮件仍是属性，不参与身份认领。
type LocalAccountClaim struct {
	Kind         LocalAccountClaimKind
	LoginName    string
	DisplayName  string
	Email        string
	PasswordHash []byte
	SessionTTL   time.Duration
}

type BootstrapStore interface {
	// LocalAccountSetupRequired 区分未初始化与存储故障，完成事实不随密码删除而撤销。
	LocalAccountSetupRequired(ctx context.Context) (bool, error)
	// ClaimLocalAccount 原子认领内置 owner、创建凭据及会话、写入成功审计。
	// 重复认领不可用来改密；任何失败都返回空结果并回滚全部身份写入。
	ClaimLocalAccount(ctx context.Context, claim LocalAccountClaim) (User, Session, string, error)
}
