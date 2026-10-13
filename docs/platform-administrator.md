# 平台用户创建与管理员通行密钥

## 使用

1. 从可信 HTTPS 管理入口 `/admin/login` 使用平台管理令牌首次登录。
2. 打开“管理员安全”，分别绑定手机、电脑或安全密钥，名称可自定义；支持多把。
3. 后续在后台登录页选择“使用通行密钥登录”。租户的密码、Passkey、Cookie 或 API Key
  不具备平台权限，即使用户名、邮箱或内部数字 ID 相同。
4. 在管理员安全中解绑凭据会撤销全部管理员 Passkey 会话，包括当前 Passkey 会话；
   使用其他已绑定凭据或恢复令牌重新登录。未配置恢复令牌时禁止解绑最后一把。
5. “用户管理 → 添加用户”选择已有网络，填写用户名、资料、角色和初始密码。
   这不是公开开户，不创建新 Tailnet、不代登录、不批准设备，也不授予平台管理员权限。

新增成员遵守当前 Entitlement 的成员数量限制；关闭公开/邀请注册不妨碍平台创建，
但目标网络必须允许本地密码登录。密码只经请求正文传递，响应和必需审计不包含密码。
管理员只设置初始密码，不能读取旧密码；通过可靠渠道交付并请用户及时修改。
联系邮箱仍是未验证属性。

## 配置与持久化

配置以 `cmd/xunarad/main.go`、`control/platform_auth.go` 为准：

- `-platform-passkey` 默认开启。自动从主配置网络的公网 URL 推导固定 origin；
  普通 HTTP/IP 入口不能使用 WebAuthn，隐式推导失败保留原令牌方式。
- `-platform-admin-origin` 显式指定完整 origin（包括非默认端口），配置无效时启动失败。
  必须使用可信 HTTPS 域名；localhost 开发例外。不能靠请求 Host 或转发头扩展允许列表。
- 多租户使用 `<platform-state-dir>/platform-identity.db`；未指定平台目录或单租户
  使用第一个配置网络状态目录内的独立 `platform-identity.db`。不能与租户状态文件相同。
- 备份时保存这个文件及 SQLite 一致性快照；不要仅复制正在写入的数据库而忽略 WAL。
  它不含恢复令牌或认证器私钥；会话和浏览器挑战只保存摘要，Passkey 保存公钥。

平台恢复令牌仍用于既有 Bearer 自动化。启用新认证时，浏览器先换取四小时、可撤销的
平台人类会话，仅保存此短期凭据到本标签页 `sessionStorage`，不保存永久恢复令牌。
绑定/解绑需最近 15 分钟内验证，退出登录执行服务端撤销，不是单纯清空浏览器存储。
通行密钥挑战仅用于管理员 origin，Cookie 为 host-only、HttpOnly、SameSite=Strict，
HTTPS 时 Secure；注册还绑定发起会话，验证沿用 go-webauthn 的签名/RP/origin/UV 检查。

平台的 WebAuthn user handle 额外带固定身份域前缀，同域同数字用户 ID 也不能
覆盖旧租户在同一认证器上的驻留凭据。已上线租户八字节 handle 保持原样。

升级顺序为服务端后后台前端：旧前端仍可用原 Bearer 令牌访问新版服务端；新版
后台需要新的认证状态接口，读取失败不会自动降级为保存永久令牌。

## API 与事务边界

API 的字段及实现以源文件为准：

- `control/platform_auth.go`：登录状态、恢复令牌换会话、Passkey 登录/列表/绑定/解绑、退出。
- `control/platform_users.go`：`POST /api/platform/v1/organizations/{orgID}/users`。
- `identity/sqlite_platform_account.go`：平台人身份/会话/审计，以及成员/凭据/本地身份/配额/审计的原子提交。
- `identity/sqlite_account_passkeys.go`：解绑与管理员 Passkey 会话撤销同事务，最后登录方式保护。

没有修改官方客户端协议或已发布数据库迁移；新的独立文件使用现有存储迁移。
回退旧版本时保留平台身份文件，旧版本不使用新文件，恢复令牌自动化仍兼容。
跨连接成员创建不能争抢同一名额，但套餐目录的跨数据库变更与完整多实例部署仍需进一步验收。

## 明确边界

当前只有一个独立部署运营者身份，不是多超级管理员账户/RBAC，也不是 TOTP 两步验证。
轮换恢复令牌不等于删除失窃 Passkey 或撤销已建立的会话。凭据安全记录保存在独立
平台数据库；现有跨租户审计列表尚未合并该来源。
隔离浏览器的虚拟认证器测试不代替 Android/iOS/Windows/macOS 或真实硬件实测。

决策与上游依据见 [Proposal](proposals/platform-passkey-administration.md) 与
[ADR-0040](adr/ADR-0040-platform-passkey-administration.md)。
