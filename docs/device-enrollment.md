# 设备立即过期与预授权接入

「设备」列表行操作和详情提供立即过期；确认当前设备身份/有效期后只使该设备
节点密钥到期，不删除设备、不归还额度、不撤销人类会话或中继。可能中断
VPN/SSH/RDP，请先准备备用连接与原设备重新认证方式。失败、版本冲突或结果
未知不自动重放；刷新当前状态后重新确认。

## 添加设备

默认选择平台，复制一个完整命令；浏览器接入仍需用户登录与设备审批。
Linux 可同时安装客户端，取消安装勾选则只接入。名称、MagicDNS、接收路由、
子网/出口与 Token 有效期收进「高级选项」。仅输出偏离官方 CLI 默认值的参数，
Windows/macOS 默认接收路由，Linux 默认不接收；不自动重置已有设备设置。

显式勾选「使用 Token 免网页登录」后，粘贴设备 Auth Key 或生成现有 API 的短期
一次性密钥（默认 15 分钟），自动写入同一命令的 `--auth-key`。不再分别复制
Token、隐藏输入、创建桌面临时密钥脚本或下载设备私有接入文件。它不是平台
管理员令牌/API Key，不将人类/服务凭据当机器身份。

前置条件：可信 Linux 新设备，已有 Bash/curl，sudo 可用（root 环境可去掉
sudo），属于官方安装脚本支持的发行版。替换示例根地址与设备密钥，直接在目标
设备终端执行；已安装客户端时不需要第一行。目标系统必须信任控制面证书。
下面仅使用占位密钥，不是真实 Token：

```sh
bash -o pipefail -c 'curl -fsSL https://tailscale.com/install.sh | sh' &&
sudo tailscale up --login-server="https://control.example.test" --auth-key="tskey-auth-REPLACE_WITH_DEVICE_KEY"
```

Bash pipefail 确保下载或安装失败不继续携带密钥接入。Windows/macOS 先安装官方
客户端；Windows 用管理员终端，macOS 使用既有 login 命令。未做这些平台的现场
执行验收。Android/iOS 使用 APP 的自定义控制服务器与浏览器授权，不伪造手机
CLI Token 接入；私有中继安装流程不受这次设备弹窗简化影响。

## 密钥安全取舍

按用户明确要求，含 Token 的复制命令会进入剪贴板，执行时可能进入 shell
历史、进程参数、终端/审计记录；**不是无密钥泄露的安全命令**。页面必须在
显式选择时提示风险，推荐短期一次性密钥。勿分享、录屏、入 Git 或公开存放；
执行后按本机策略清理历史与剪贴板，必要时在密钥页撤销。

不把 Token 拼进 URL/query、应用日志或浏览器持久存储。关闭/离页/切换浏览器
或手机清除本页秘密，但不自动撤销未使用的密钥。不自动签发或重试；
权限未知禁签发，已有密钥按原 reusable/expiry 属性。无 TLS 跳过、重置或强制
重登录选项，预授权不替代设备额度、ACL、路由批准或设备 IP 转发。

交互决策以[简化接入 Proposal](proposals/2026-10-12-simplified-device-enrollment.md)
及 [ADR-0038 后续调整](adr/ADR-0038-device-expiry-and-token-enrollment.md#后续交互调整2026-10-12)
为准；后端事务与身份分离保持不变。

## 平台契约

下列接口均位于当前租户：GET 需要 read，Cookie 写需要 write + CSRF，服务写
另外要求 API Entitlement；写事务内复查持久凭据、启用用户及 owner/admin。
读写均 no-store，存储失败不冒充不存在或无额度。

- `GET /api/v2/machines/{ref}/lifecycle` 返回白名单 machine、身份/有效期摘要
  revision、csrf_token、can_expire；numeric/stable ID，普通在线活动不制造假冲突。
- `POST /api/v2/machines/{ref}/expire` 只收 revision。当前身份/归属/有效期不匹配
  返回 `409 DEVICE_CHANGED`，缺设备 `404 DEVICE_NOT_FOUND`，未确认版本 400。
  只改 expiry，必需 `node.expired` 审计和配置通知同事务，提交后才通知客户端。
- `GET /api/v2/auth-keys/enrollment` 返回 csrf_token、can_manage、可用密钥 used
  和 Entitlement max_auth_keys（-1 为不限），不返回秘密。
- `POST /api/v2/auth-keys/enrollment` 收 ttl_seconds（900～86400），创建成功
  201 一次返回 id/key/expiry/reusable=false/ephemeral=false，不从 GET 恢复秘密。
- v1 Auth Key 创建/撤销及旧 HTML 委托同一持久授权、配额、必需审计流程；v1
  Cookie 调用现在必须带 CSRF，响应形状不变。服务 key 不扩张创建者角色。

密钥签发配额、一次性消费、设备计数、新建/轮换、必需审计/通知均在租户写事务。
审计/计数/节点写或密钥消费被拒绝或忽略则全量回滚，不返回授权成功；跨连接
并发不能重复使用一次性密钥或超出设备/密钥额度。满额已有机器仍可合法重新认证。
浏览器审批最终新建也使用同一写锁下的受限创建器，不能与 Token 注册竞争到
Free 第 11 台。历史浏览器审批的授权状态/审计仍属既有流程，不把本次配额修复
冒充整套审批事务已经重构；这些接口并不允许未授权的人类审批设备。
新节点与轮换共用地址/DNS 和稳定身份逻辑，机器键、节点键及租户共同绑定，歧义
机器拒绝。格式错误的持久标签拒绝授权，不静默降级到无标签用户设备。

客户端缩短有效期和注册补充公钥只更新相应字段，旧快照不能恢复已过期设备或
覆盖路由。已有客户端签名验证、标签归属和轮换语义不变；无迁移或 wire 改动。
官方 `NodeKeyExpired`、`Node.Expired/KeyExpiry` 已承载过期结果。

上游核对：项目锁定 Tailscale v1.104.0 CLI `up.go` 的 auth-key/file: 和共有 login
flags；官方[密钥管理](https://tailscale.com/docs/reference/key-secret-management)及
[节点密钥过期](https://tailscale.com/docs/features/access-control/key-expiry)。

## 验证入口

执行目录 `xunara-server`，工具链按 go.mod：

```sh
go build ./...
go vet ./...
go test ./... -count=1
go test -race ./... -count=1 -timeout=30m
```

写入 ABORT/IGNORE、配额/一次性跨连接竞争、旧客户端不能恢复 expiry、持久
角色/凭据变更、CSRF、租户和真实上游 Noise 注册→过期 Map→重新认证有回归。
Web 验证类型、响应失效关闭、命令参数/注入拒绝、Linux mock 安装/CLI 实际执行
（安装/下载失败阻断、参数与注入边界），不是全 OS 或真实 Linux
软件包安装现场证明。共享隔离浏览器覆盖单一复制、清除、手机确认、故障/冲突及只读成员。
