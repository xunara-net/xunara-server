# 平台辅助密码重置

这是经过人工核实后的恢复，不是自动邮件找回或完整账户接管恢复。联系邮箱未经
验证，不能据此确认身份。管理员看不到旧密码，也不为用户选择新密码。
设计见 [ADR-0031](adr/ADR-0031-platform-password-recovery.md) 与
[Proposal](proposals/platform-password-recovery.md)。

## 产品入口

- 平台 `/admin/users`：重置密码 → 填原因 → 确认已核实持有人 → 显示一次重置码。
- 用户 `/login`：「忘记密码」→ `/reset-password`，手动输入码和两次新密码。
- 仅平台 Bearer 可生成；普通租户 owner/admin Cookie、服务 API Key 和匿名均拒绝。
- 仅已启用、已有本地密码且部署允许密码登录的账号可生成，不给 external-only
  账号新增密码。安全恢复不按套餐收费，不改变任何成员 / 设备额度。

生成不改密码、不退出登录；码 256-bit 随机、15 分钟有效、一账号一待用码。
再次生成使前码失效。必须由平台通过已核实的独立渠道交付，只在可信 HTTPS
输入，不写网址、argv、日志、工单或浏览器持久存储。关闭 / 离页清除本页原码；
后续查询只有待用状态 / 期限，不能取回原码。勾选是运营者的明确声明，不等于
系统完成独立超管身份、证件验证或 MFA。

## API（以本仓库为准）

响应 no-store，严格 JSON body 限 4 KiB，拒绝额外字段和拼接 JSON。不自动重试。

### 平台生成

`POST /api/platform/v1/organizations/{orgID}/users/{userID}/password-reset`，
`Authorization: Bearer`。请求 `reason`、`ownership_verified=true` 和
`expected_updated_at`（平台列表中的完整版本，保留纳秒字符串，不转成 JS Date）。
原因限 1～256 字单行文字，不输入秘密或证件资料。

201：`org`、`id`、`updatedAt`、`resetId`、仅本次的 `code`、`createdAt`、
`expiresAt`、`passwordChanged=false`、`sessionsRevoked=0`。
列表新增 `passwordResetAvailable`、可选 `passwordResetExpiresAt`，不返回码或哈希。
旧服务端缺少能力 / 状态 / 版本时前端只读，禁用生成，不猜可用。

- 缺版本 428 `PASSWORD_RESET_VERSION_REQUIRED`；冲突 409 `PASSWORD_RESET_CHANGED`。
- 核实 / 原因无效 400 `PASSWORD_RESET_REQUEST_INVALID`；不存在 404。
- 停用、无密码或关闭本地登录 409 `PASSWORD_RESET_NOT_AVAILABLE`。
- 存储故障 503 `PASSWORD_RESET_UNAVAILABLE`，不回显数据库诊断。

超时 / 冲突 / 未确认结果保留原因，暂停再次提交。必须显式刷新核对、重新确认
核实和生成；待用状态不代表原码可取回。取消无写入，再次生成会替换原码。

### 匿名兑换

`POST /api/v1/auth/password-reset`，JSON body：`code`、`new_password`、
`confirm_password`。不接受邮箱、用户 ID、query 码，也不以 Cookie / API Key 代替。
有 Origin 时只允许本网络同源，拒绝跨站浏览器请求；无 Origin 的非浏览器调用
仍必须有用途限定凭证。密码至少 12 字、最多 72 字节、不等于登录名，确认一致。

无效、过期、已使用、禁用、跨租户及凭据变化统一 400 `PASSWORD_RESET_INVALID`，
不透露用户信息。密码策略 / 确认错误 400；429 `PASSWORD_RESET_RATE_LIMITED`
带 Retry-After；存储 / 准入错误 503。每来源 IP 每 15 分钟 20 次、已验证码每
15 分钟 5 次，预算持久化；随机无效码不建立独立码预算，避免无限扩张状态。

200：`changed=true`、`revoked_sessions`。不发登录 Cookie、不创建 Session、不清除
其他账号 Cookie。前端清空输入，正常登录；结果未知先尝试新密码登录、联系
管理员核对，不自动重放；离页清空内存。未发送任何邮件或自动建立已验证邮箱。

## 数据与原子性

Identity v17 只追加 `password_reset_tickets`：一用户一待用记录、公开 ID、码哈希、
原密码指纹 / 更新时间、创建 / 到期时间。原码与新明文密码不落库，不复用 Session、
OAuth State、DeviceAuthorization 或内存 map。

生成事务核对用户 / 状态 / 凭据 / 核实声明 / 版本，替换待用码、推进用户版本、
写必需 `user.password_reset_issued`，不改密码 / 会话。兑换在慢哈希前预检，
写事务再次核对有效期 / 状态 / 原密码版本；替换密码、删除码、撤销全部未撤销
人类会话、推进版本和必需 `user.password_reset_used` 同事务。错误 / 忽略写入均
回滚，竞争兑换至多成功一次。审计不包含码、码哈希或密码。

自助改密删除待用码、推进用户版本；禁用 / 解禁 / 删除在事务中删除待用码。
直接密码存储变化再由指纹 / 更新时间核对，旧码不能恢复旧快照。保留外部绑定、
Passkey、API Key、设备 Key、节点和中继；不改角色、套餐、CIDR、DNS、ACL、
注册准入或官方客户端协议。其他既有登录方法仍可重新认证，不宣称全面接管恢复。

共享平台 Bearer 仍只审计为平台，不冒充可识别的运营人员。邮件通知 / 邮箱验证、
自动邮件找回、强 MFA / Break Glass 与独立超管身份未在本切片交付。

## 升级与验证

停止全部旧控制面、私有成套备份数据库 / 密封密钥 / 环境 / 服务 / 静态产物后追加
identity v17，state v24 / plans v4 不变，原用户初始无待用码。旧二进制不支持新
身份库，不能混版本滚动运行。仅尚未开放写入时可成套恢复；开放业务后不可用
旧快照覆盖新数据。

在 Server 仓库执行：

```sh
go build ./... && go vet ./... && go test ./... -count=1
go test -race ./... -count=1 -timeout=20m
```

覆盖旧库、跨连接、CAS、期限、重复生成 / 消费、密码变化 / 登录竞争、状态、
同 ID 跨租户、必需写入故障 / 忽略回滚。真实隔离 HTTPS 浏览器复用 Admin 认证
脚本，不接生产账号或公网 IdP；运行目录 / 前置条件见
[Admin 验收](https://github.com/xunara-net/xunara-admin#浏览器集成验收)。
