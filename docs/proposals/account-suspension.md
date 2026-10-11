# Proposal：可恢复的租户账号禁用

- 日期：2026-10-11
- 状态：Accepted，实施与验证中
- 范围：xunara-server → xunara-admin / xunara-web → xunara-docs / xunara-deploy

## 问题与边界

平台只能删除账号或撤销现有会话；撤销后账号仍能再次登录。规格 §45 要求
禁用 / 解禁，不能靠隐藏按钮或删除密码实现。账号仍属于原租户，不新建跨租户身份。

## 决策

1. Identity 仅追加 v16：用户的禁用时间和原因。旧用户默认启用，已有角色、
   登录方法、外部 `(provider_id, subject)`、设备与套餐不变。
2. 平台新增版本化状态修改入口；提交必须包含用户完整 `updatedAt` 和操作原因。
   事务内读取当前事实、核对版本、保护最后一位启用的 owner；过期页面必须刷新。
3. 禁用事实、全部未撤销浏览器会话的撤销和操作审计在同一写事务内提交。
   失败（含触发器忽略写入）不得部分成功；解禁不恢复任何旧会话。
4. 持久会话查询、所有会话签发及安全修改共用启用状态门禁；密码在慢哈希后
   复查，OIDC / OAuth2 和 Passkey 在签发事务中复查。匿名登录不泄露禁用事实，
   存储故障保留为服务不可用，不伪装密码错误。
5. 服务 API Key 仍是独立凭据，但其授权委托当前账号角色；账号禁用期间不授予
   此权限。解禁后仍有效的服务 key 可使用，撤销 key 必须另行操作。
6. 不修改或撤销 Machine Identity、预授权设备 Key、在线节点、独立中继身份或
   官方协议。此功能不是“冻结 tailnet”，也不是支付停服或设备紧急隔离。
7. 角色变更 / 删除复用“启用的 owner”不变量，禁用 owner 不能当作最后恢复入口。
   禁用用户仍占成员额度，避免通过禁用绕过 Entitlement。
8. Admin 展示状态、禁用时间、原因、启用 / 禁用筛选及带原因的二次确认弹窗。
   不增加普通租户用户调用平台接口的权限，不自动重放失败或版本冲突操作。
   Web 成员页仅展示禁用状态，不公开平台操作原因；角色编辑仍保护最后启用 owner。

## 验证与风险

覆盖旧库迁移、最后 owner、跨连接并发禁用 / 删除 / 降权、CAS、审计与撤销故障
回滚、各类会话签发、HTTP / gRPC / Cookie / 服务 key、同 ID 跨租户隔离、解禁
不恢复会话、节点及服务身份不变；Go build / vet / 全量 test / race，Admin 单测 /
typecheck / build 与真实隔离浏览器操作。

本切片不实现密码找回、邮件、2FA、独立平台人身份、账户注销与网络冻结；
已经接纳的在途请求不承诺强制终止，安全写事务会重新复核会话。
匿名外部登录事务未绑定用户前无法按用户取消；禁用期间最终签发失败，解禁后
仍需完整成功验证提供方，不恢复旧 Session。

## 依据

- [Xunara 主规范 §45](https://github.com/xunara-net/xunara-docs/blob/main/specs/ai-development-architecture.md)。
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)：服务端撤销是会话失效的事实依据。
- 本仓库 `identity/sqlite_session.go`、`identity/sqlite_member.go`、
  `identity/sqlite_account_identities.go`：复用既有持久会话、角色事务与外部身份链。
