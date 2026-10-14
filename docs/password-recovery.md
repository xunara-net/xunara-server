# 超管重置随机临时密码

平台管理员核实持有人后，**直接重置随机临时密码**，不再要求用户兑换重置码。
管理员不能读取旧密码；临时密码只有本次弹窗可见，用户首次登录必须设置自己的
新密码。设计见 [ADR-0042](adr/ADR-0042-platform-random-password-reset.md) 与
[Proposal](proposals/platform-random-password-reset.md)。

## 操作入口

1. 超管后台「用户管理」核对所属网络和登录名，点击「重置密码」。
2. 填写原因、勾选已通过可靠渠道核实持有人，确认立即重置。
3. 系统立即替换密码、撤销该账号所有人类会话；弹窗只显示一次随机临时密码。
4. 通过已核实的独立渠道交付，并告知用户所属网络的正常登录地址。
5. 用户输入临时密码登录后，只能进入「设置自己的新密码」或退出登录。
6. 本人改密成功后全部旧人类会话退出，再以新密码登录使用控制台。

取消确认不写入。关闭弹窗 / 离开页面清除本页明文，不写 URL、argv、日志、
审计或浏览器持久存储；复制后清理剪贴板。勾选是运营者声明，不代表系统完成证件核验。
仅已有本地密码、已启用且网络允许密码登录的账号可重置，不给第三方专用账号新增密码。

## API（以本仓库为准）

`POST /api/platform/v1/organizations/{orgID}/users/{userID}/password-reset/random`，
平台 `Authorization: Bearer` 授权。只接受 4 KiB 内 JSON body：

- `reason`：1～256 字单行管理原因，不包含秘密或证件资料。
- `ownership_verified=true`：已核实持有人。
- `expected_updated_at`：平台列表的完整账号版本，保留纳秒原字符串。

200：`org`、`id`、`updatedAt`、仅本次的 `temporaryPassword`、
`passwordChanged=true`、`passwordChangeRequired=true`、`sessionsRevoked`。
明文由 crypto/rand 生成 24 字节随机值，编码为 32 个 URL-safe 字符；只持久化 bcrypt 哈希。
响应 `Cache-Control: no-store`、`Referrer-Policy: no-referrer`。

平台列表只返回 `passwordResetAvailable`、`passwordResetMode=temporary_password`
与 `passwordChangeRequired`，不提供明文查询。新版后台遇到旧服务端不猜测重置语义。

缺版本 428；版本冲突 409 `PASSWORD_RESET_CHANGED`；核实 / 原因 / 额外字段无效 400；
无账号 404；停用 / 无密码 / 关闭密码登录 409；存储故障 503 `PASSWORD_RESET_UNAVAILABLE`。
结果未知不得自动重复重置。刷新账号版本，重新核实并明确确认后可以再重置，先前密码失效。

## 强制改密不是前端限制

账号的持久 `password_change_required` 由 Identity 维护，所有人类登录方法共用。
临时登录只能读取本人账户 / 会话、修改密码、退出当前会话，不能读写网络、绑定
新提供方或通行密钥、批准设备，也不能通过 gRPC 或旧 HTML 管理入口绕过限制。
Web 显示独立、适配手机的 `/change-password` 页面，不挂载控制台菜单。

复用 `POST /api/v1/account/password`，要求当前临时密码、新密码、会话绑定 CSRF。
新密码至少 12 个字符、最多 72 字节，不能等于登录名或当前密码；前端二次确认。
成功原子清除限制并撤销全部人类会话，再正常登录；故障不部分写入、不自动重试。
登录 / 账户响应新增 `user.password_change_required`；个人导出 schema v1 不增字段。

## 兼容与身份边界

原生成码 API 和匿名兑换 API 保留明确 410 `PASSWORD_RESET_RETIRED` 提示，
不悄悄把「生成不改密」变为「立即改密」。Web `/reset-password` 变为联系管理员
的指导页，旧码不再有效，生成 / 兑换实现与输入表单已删除。

Identity **仅追加 v19**：新持久改密标志默认 0，并清空旧待用重置码。
旧 v17 表保留迁移 / 成套回退结构，不运行旧恢复流程。state / plans 不变。
旧账号的密码、原人类会话、设备地址和机器身份不因升级自动改变。

重置事务复核用户 / 凭据 / 启用状态 / CAS，密码、限制、旧码清理、会话撤销、
用户版本和必需 `user.password_reset` 审计同事务；错误或忽略写入都回滚。
不改变外部绑定、Passkey、API Key、设备接入 Key、在线节点或 Relay、角色、套餐、
网段、DNS / ACL、注册准入或官方 Tailscale 协议。独立服务凭据仍可按原授权使用。

这不是全面接管恢复；疑似泄漏时需另查其他凭据与绑定。邮箱验证、自动邮件找回、
完整 MFA 和运营核实 / 通知流程不是本功能交付的能力。

## 验证与升级

停止全部旧控制面、成套私有备份后配套升级 Server → Admin / Web。
旧二进制不能打开 v19 身份库，不能混版本运行。只在恢复对外写入前允许成套回退，
开放业务后不可用旧快照覆盖新数据。不要擅自重置生产用户密码。

在 Server 仓库执行：

```sh
go build ./... && go vet ./... && go test ./... -count=1
go test -race ./... -count=1 -timeout=30m
```

覆盖迁移、跨连接 / 同 ID 跨租户、并发 CAS、旧密码登录 / 改密 / 禁用竞争、
失败 / 忽略写入回滚、强制改密 HTTP / gRPC / 旧页面和退出边界。
隔离 HTTPS 浏览器、真实审计故障 / 重启与手机验证入口见
[Admin 验收](https://github.com/xunara-net/xunara-admin#浏览器集成验收)。
