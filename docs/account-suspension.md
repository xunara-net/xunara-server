# 平台账号禁用与解禁

平台后台「用户管理」可禁用或解禁指定租户的账号。普通租户所有者不能调用平台
状态入口；用户中心「成员与权限」仅显示只读禁用标识，不显示平台操作原因。

## 操作效果

- 禁用阻止本地密码、OIDC / OAuth2、Passkey 的新会话签发，并撤销全部未撤销
  浏览器 Session。Cookie、Session Bearer 和 gRPC 都不能继续使用这些会话。
- API Key 仍是独立服务凭据，但禁用期间不能取得所委托账号的 API 权限。
  解禁后未撤销且未过期的 key 可使用；永久撤销 key 要另行明确操作。
- 解禁允许重新登录，**不会恢复任何旧会话**。密码、通行密钥、身份绑定和
  注册历史保留；禁用账号继续占用成员额度。
- 不能禁用最后一位启用的 owner。降权与删除同样只把启用 owner 计作恢复入口。
  将禁用成员改成 owner 不会自动解禁，也不能绕过这个规则。
- 已连接节点、Machine / Node Key、预授权设备 Key、ACL、网络、DNS、套餐、
  独立中继身份不变。禁用账号**不是冻结 tailnet 或设备紧急隔离**。

## HTTP 契约

入口以 `control/platform.go`、`control/platform_users.go` 为准：

| 接口 | 用途 |
|---|---|
| `GET /api/platform/v1/users` | 全平台列表，包含 `org`、`id`、`updatedAt`、`disabled`、可选 `disabledAt`、`disabledReason` |
| `PATCH /api/platform/v1/organizations/{orgID}/users/{userID}/status` | 平台 Bearer 授权；普通租户 Session / API Key 不接受 |
| `GET /api/v1/users` | 既有租户读取权限，补只读 `disabled` 与可选 `disabledAt`，不公开原因 |

状态请求的 JSON 形状：

```json
{
  "disabled": true,
  "reason": "管理核对账号",
  "expected_updated_at": "2026-10-11T01:00:00.123456789Z"
}
```

版本必须原样来自列表，不用 JavaScript Date 转换成毫秒。`disabled` 必填，
`reason` 是 1～256 个 Unicode 字符的单行原因，禁止控制字符；不要填密码或令牌。
启用也需要原因，当前禁用原因清空，但历史原因仍在审计中。
严格 JSON 拒绝额外字段、拼接正文及非 JSON；正文上限 4 KiB。

成功返回目标 `org`、`id`、新 `updatedAt`、状态元数据及 `revoked` 数量，
不返回密码、密钥或任何 Session Token。同状态同版本请求不产生新修订或审计。

| 状态 | 代码 / 处理 |
|---|---|
| 401 | 平台身份无效；租户 Cookie 或服务 key 不能替代平台授权 |
| 404 | `USER_NOT_FOUND` |
| 428 | `USER_VERSION_REQUIRED`，刷新列表取得版本 |
| 400 | `USER_STATUS_INVALID`，核对布尔值与原因 |
| 409 | `USER_STATUS_CHANGED` 或 `LAST_ACTIVE_OWNER`，刷新核对后再次确认 |
| 503 | `USER_STATUS_UNAVAILABLE`，不能推测成启用 / 空列表；核对实际结果，不自动重试 |

页面保留冲突或失败草稿，暂停重复提交。「刷新核对账号」保留原操作方向，
若目标已达到，不自动反转成另一操作。手机号 / 邮箱不是身份键，也不参与禁用定位。

## 原子性与升级

[ADR-0030](adr/ADR-0030-account-suspension.md) / [Proposal](proposals/account-suspension.md)。
Identity **v16** 只追加 `users.disabled_at` 和 `users.disabled_reason`，旧用户默认启用。
迁移不改变旧会话、角色或外部身份。状态、Session 撤销及必需 `user.disabled` /
`user.enabled` 审计共用写事务；任何写入失败或忽略都回滚，跨连接竞争保护 owner。
所有会话签发使用当前数据库启用事实，不依赖前端判断或实例缓存。

上线前停止外部写入与所有旧版本服务实例，备份数据库（含 WAL / SHM）、认证密封密钥、
配置、旧二进制及静态资源。先升级 server，再升级 Web/Admin；旧前端无新按钮
但服务端仍生效，旧后端状态或版本缺失时新 Admin 只读显示未知、禁止状态修改。
不允许旧新服务实例混跑：旧进程没有状态门禁，不能把新迁移当成旧进程会自动执行的规则。
旧二进制会拒绝 v16；不能直接覆盖二进制降级。仅在恢复公开写入前可使用同批次
数据库与程序快照回退，恢复写入后必须另做前滚修复 / 数据恢复评审。

## 验证边界

`identity/user_status_test.go` 与 `control/platform_user_status_test.go` 覆盖迁移、
持久状态、权限、CAS、最后启用 owner、跨连接禁用 / 删除 / 降权 / 签发竞争、
忽略与故障回滚、密码 / Passkey / 外部身份签发、HTTP / gRPC、额度及机器身份不变。
Admin 单测覆盖原始纳秒版本与响应租户 / 状态 / 撤销数量校验；Web 覆盖禁用 owner
的角色保护。`xunara-admin/scripts/authentication-browser-smoke.cjs` 使用隔离 HTTPS
租户验证真实页面修改、冲突、审计故障、重启、旧会话不恢复与手机弹窗。

本功能不实现邮箱验证 / 找回密码、2FA、独立平台管理员账号或网络冻结。在途请求
不承诺强制终止；已有安全写事务会复核会话。未知用户的匿名外部登录事务不能按
用户提前取消，禁用期间最终签发被拒绝，解禁后仍必须完整验证提供方。
