# 设备立即过期与 Token 接入

## 用户操作

设备列表每行及设备详情顶部提供「立即过期」，仅网络 owner/admin 可操作。
弹窗先读取当前设备身份和有效期，显示设备及 IP，确认已准备好重新认证后提交。
此操作可能中断 VPN/SSH/RDP；设备、地址、标签、路由及额度占用保留，不删除设备、
不撤销网页会话或其他设备。已过期不重复写入。冲突/失败或结果未知不自动重试，
先读最新状态再确认。在原设备重新登录或用新的设备预授权凭据重新认证。

「设备 → 添加设备 → 预授权 Token」可粘贴设备 Auth Key，或由网络管理员生成
15 分钟（默认）、1 小时、24 小时有效的一次性普通设备密钥。本页新生成的密钥
不附带标签、可复用或临时设备权限；需要这些能力可在「API 与密钥」管理现有密钥。
关闭/切到浏览器或手机/离页清除本页秘密，不自动撤销未使用密钥，可在密钥页撤销。
Token 不是平台管理令牌、人类会话或 API Key，不可互换。

- **Linux**：安装/仅加入和名称、DNS、接收路由、子网/出口选项继续生效。
  可复制命令不会包含真实密钥，运行后隐藏输入，客户端通过 `--auth-key=file:`
  读取私有临时文件。先成功下载官方安装器才执行；支持 root 或 sudo。
- **Linux 私有一键文件**：填入密钥后明确确认私有保管，下载
  `xunara-device-join.sh`，在可信 Linux 主机的下载目录执行下面命令。
  文件本身包含真实密钥，勿转发、入 Git、公开存放；执行后删除源脚本。
- **Windows/macOS**：先通过官方渠道安装，复制隐藏输入命令；Windows 用管理员
  PowerShell，并限制临时目录 ACL。未做真实 Windows/macOS 现场执行验收。
- **Android/iOS**：仍用 APP 自定义控制面地址和浏览器授权，不伪造手机 CLI Token 接入。

前置条件：已下载私有脚本，目标 Linux 可运行 sh/curl/mktemp，安装可用 root/sudo，
测试控制面 CA 已核实并安装到目标系统信任库；执行目录为脚本所在的下载目录。

```sh
chmod 700 xunara-device-join.sh && sh ./xunara-device-join.sh
```

脚本运行前关闭 xtrace/verbose，umask 077、目录 0700、密钥 0600；真实秘密只进
文件/stdin，不进 URL、外部进程 argv、终端输出或浏览器持久存储。复制 Token 是
单独的显式敏感操作，使用后清理剪贴板。无 TLS 跳过、重置或强制重登录选项。
预授权不等于 ACL 放行、路由批准或 IP 转发；仍按 Entitlement 限制设备数量。

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
（root/sudo、失败、xtrace/verbose、权限/argv/输出/清理），不是全 OS 或真实 Linux
软件包安装现场证明。共享隔离浏览器覆盖下载、清除、手机确认、故障/冲突及只读成员。
