# Xunara Server（玄序 · 服务端）

Xunara（玄序）是一个 **Tailscale 兼容的多租户网络服务平台**。
本仓库是它的服务端：控制面 + 产品层 + Xunara Core API。产品 Web UI 由独立仓库
提供；官方客户端必需的授权页面与尚未对等迁移的旧模板仍保留，见 ADR-0003。

```text
xunara-web（用户控制台）   xunara-admin（平台后台）   CLI / SDK / 未来客户端
              └──────────────────┬──────────────────────────┘
                                 ▼
                    Xunara Core API（/api/v1、/api/v2、/api/platform、gRPC）
                                 │
                        xunara-server（本仓库）
                    控制面 · 用户 · 组织 · 设备 · 网络 · 套餐 · 审计
                                 │
                    官方 Tailscale 客户端（Windows/macOS/Linux/Android/iOS）
```

## 能力

- **官方客户端兼容**：TS2021 / Noise / Map / DERP 协调，官方客户端可直接接入。
- **多租户**：组织、成员、角色（owner / admin / member）、单租户部署兼容。
- **用户与身份**：本地密码登录、邀请/开放注册、OIDC/OAuth、Passkey、会话管理、
  自助资料与密码修改、API Key、身份令牌。
- **设备与网络**：设备注册与审批、Tailnet 网段分配、子网路由、Exit Node、
  MagicDNS、DERP 策略、共享与访问策略。
- **网络控制台**：持久 ACL / Grants 发布、编译器模拟与版本恢复、DNS 设置与地址
  记录、租户私有 DERP 地区与 TLS pin；[实现与升级边界](docs/network-console.md)。
- **商业化**：套餐目录（内置 free/pro/business 或 `-plans` 外置）、设备/成员/
  密钥/路由配额、租户网段自定义与冲突检测、平台运营 API。
- **可观测与审计**：结构化日志、`/health`、`/version`、审计日志、Webhook、
  Prometheus 风格指标（部分）、gRPC 平台面。
- **JSON API**：`/api/v1/auth/*`（登录/注册/会话）、`/api/v1/capabilities`、
  `/api/v2/*`（设备、DNS、DERP、策略、审计、共享、中继……）。

## 构建

```bash
go build ./cmd/xunarad          # 服务端
go build ./cmd/xunara           # 管理 CLI
go build ./cmd/xunara-agent     # 节点 Agent
```

## 运行（单租户）

```bash
./xunarad -listen 0.0.0.0:8080 \
  -server-url https://login.example.com \
  -state-dir /var/lib/xunara \
  -plans builtin \
  -network-pool 100.100.0.0/16
```

首次启动会写出一次性初始化令牌（`<state-dir>/setup-token`），浏览器打开
`/setup` 完成管理员初始化。

初始化与自助租户 owner 开通共用一次性身份事务：资料、密码、会话和成功审计
任一失败都回滚，重试不留下半账号，也不额外占用 Free 成员名额。完成事实独立
于密码与文件；删除密码或留下旧令牌不会重启初始化，初始化不是密码重置入口。
存储故障返回脱敏 503、保留 Cookie / 文件证明；启动无法读取状态或遇到非普通
文件、非 `0600`、损坏的证明时拒绝启动，不能把故障当成新部署。

此改动只**追加身份迁移 v13**，回填已有凭据或明确完成审计；不改已有用户、密码、
外部身份链接、设备或套餐。旧版本不能直接打开 v13，升级前必须暂停写流量并保留
完整一致性状态与旧产物，恢复公网写入后不得直接覆盖旧快照。见
[ADR-0017](docs/adr/ADR-0017-atomic-owner-bootstrap.md)及
[部署回退约束](https://github.com/xunara-net/xunara-deploy/blob/main/README.md#升级与回滚)。

控制面经反向代理（nginx）暴露时加 `-trusted-proxy`：限流改为按
`X-Forwarded-For` 的最后一跳（代理追加的真实客户端地址）计数。不加时所有请求
都记在代理地址上，一个客户端的失败尝试会拖住所有人；直接对公网暴露控制面时
必须保持默认关闭。

注册策略由 `-registration` 决定：`closed`（只允许管理员建号）、`invite`（邀请码，
默认）或 `open`（任何人可注册；单租户部署注册为该租户成员，受套餐成员配额约束）。

多租户部署使用 `-org-config <file>` 描述组织与域名。在其中配置 `self_service`
后，入口站开放自助开租户：访客注册即得到自己的 tailnet（ADR-0007）。

```json
{
  "organizations": [
    {"id": "portal", "name": "Xunara Cloud", "domains": ["app.example.com"],
     "server_url": "https://app.example.com", "state_dir": "/var/lib/xunara/portal",
     "registration": "open"}
  ],
  "self_service": {
    "site": "portal",
    "domain_suffix": "tailnet.example.com",
    "scheme": "https",
    "port": "9090",
    "cookie_domain": "example.com",
    "plan": "free"
  }
}
```

`-org-config` 需配合 `-platform-state-dir`（托管组织
与地址池记录）与 `-plans`（每个新租户都要落在某个套餐上）。`domain_suffix`
下需要 `*.tailnet.example.com` 泛解析。

入口站的旧本地注册端点不会再给访客创建公共网络成员；旧 `/signup` 跳转到
控制台 `/register`，API 返回 `TENANT_SIGNUP_REQUIRED`。目标租户自己的邀请注册不变。

托管租户使用部署显式指定的公共中继池（[ADR-0008](docs/adr/ADR-0008-managed-relay-admission.md)）：

```sh
go run ./cmd/xunarad \
  -listen 127.0.0.1:9190 \
  -org-config /etc/xunara/orgs.json \
  -platform-state-dir /var/lib/xunara \
  -plans builtin -network-pool 100.100.0.0/16 \
  -managed-derp-map /var/lib/xunara-relay/derp.json
```

在本仓库执行，先准备组织配置和公共中继 map。中继的 `-verify-url` 指向本机
`http://127.0.0.1:9190/api/relay/v1/admit`，不依赖租户 Host；只有有效 map 包含该
中继、节点已注册且未过期、租户策略允许时才放行。静态组织仍使用各自配置中的
`derp_map`，不会把某个租户的私有中继、身份或密钥复制给其他租户。

## 第三方登录与成员邀请

正式 Web 的提供方入口从 `/api/v1/auth/providers` 获取，浏览器整页导航到
`/api/v1/auth/start`，不再把 GET `/login` 的 SPA 页面当成认证 API。
`return_to` 只接受本站路径；OIDC callback URI 仍来自服务配置而非请求输入。
新旧第三方入口共享持久限流和认证事务，不改变客户端设备授权流程。

成员页面通过 `/api/v1/member-invitations` 提供列表、创建和按 ID 撤销。
仅有效 owner 人类会话可操作；写入需会话绑定 CSRF，服务 API Key 不可代替人类身份。
创建代码仅展示一次，注册页面地址单独分享，不把代码放进 URL。
新邀请有期限，只授予 member/admin；已有兑换记录保留，Free 的单成员额度仍拒绝新增。
邀请模式与独立网络自助开通严格区分，不接受在入口租户绕过开通规则。

注册通过 `identity.RegistrationStore` 将成员额度、账户、密码、身份链接、邀请、会话
和审计合并提交。任一步失败全部回滚，邀请仍可重试；旧补偿删除和独立兑换入口已移除。
旧控制台只作为兼容适配，共用相同邀请业务，不再生成带代码的链接，也不允许 admin
管理邀请。未实现的 viewer 角色不在 Web 角色下拉框提供。

数据流、测试范围及未闭环并发路径见 [ADR-0014](docs/adr/ADR-0014-browser-auth-and-member-invitations.md)。
此处不代表邮箱验证/找回、2FA 或第三方首次建号事务已经全部完成。
自助开通入口拒绝未知第三方身份直接加入入口网络，不按邮箱认领 owner；已有显式
绑定仍可登录。第三方自动创建独立租户尚未完成，见
[ADR-0015](docs/adr/ADR-0015-self-service-external-admission.md)。

## 账户自助管理

用户控制台的个人设置使用独立账户接口（[ADR-0009](docs/adr/ADR-0009-account-self-service.md)）：

- `GET /api/v1/account` 返回当前用户资料、`password_change_enabled` 和
  `csrf_token`，仅接受本租户的人类 Session，API Key 不可访问。
- `PATCH /api/v1/account` 仅接受可选的 `display_name` 与 `email`，不接受用户
  ID、登录名、角色或组织。昵称最多 100 个字符；邮箱仅是可清空的未验证联系属性。
- `POST /api/v1/account/password` 接受 `current_password` 与 `new_password`，
  新密码沿用至少 12 个字符、最多 72 字节的规则，不能与登录名或当前密码相同。
- 两个写接口要求 `application/json` 和 `X-CSRF-Token`，JSON 上限 8 KiB；
  CSRF 值从账户读取接口取得，不放入 URL。
- 改密成功时返回 `changed`、`revoked_sessions`，原子撤销该用户所有控制台
  会话并写审计；必须重新登录。已注册的设备、API Key 和外部身份不受影响。
  新建本地登录会话也检查已验证密码是否被并发替换。
- 密码修改每用户 15 分钟最多 5 次、每 IP 最多 20 次；限流故障拒绝操作。
  未启用本地登录或没有本地密码的用户不能通过此接口创建密码。

原 `PATCH /api/v1/users/{id}` 和旧 HTML 用户管理写接口仅允许 owner。
普通成员与 admin 使用自助账户接口管理自己的资料。邮箱验证、密码找回与
2FA 不包含在本次实现内；正式使用必须部署 HTTPS。

### 控制台登录管理

安全中心使用独立人类账户接口（[ADR-0010](docs/adr/ADR-0010-account-session-revocation.md)），
普通成员也可管理自己的登录，不受套餐 API 权限限制：

- `GET /api/v1/account/sessions` 返回 `sessions`、`current_session_id`、
  `generated_at` 和 `csrf_token`。会话包含 `id`、`auth_method`、`created_at`、
  `expires_at`、`status`（`active` / `expired` / `revoked`），已撤销记录另含
  `revoked_at`、`revoked_reason`；不返回令牌、哈希或未采集的来源信息。
- `DELETE /api/v1/account/sessions/{id}` 撤销自己的单个登录；未知或其他
  用户的目标统一返回 404。已失效的本用户目标返回零次变更，不改写历史。
- `POST /api/v1/account/sessions/revoke` 仅接受 `{"mode":"others"}` 或
  `{"mode":"all"}`，JSON 上限 8 KiB；“其他”保留发起会话。
- 写接口要求 `X-CSRF-Token`，所有接口仅接受本租户人类 Session，拒绝 API Key。
  写入前事务内重新验证发起会话；撤销与 `session.revoked` 审计原子提交。
  成功返回 `revoked_sessions` 与 `current_revoked`；当前登录被撤销时清除 Cookie。
- 只撤销操作时仍活动的登录，不修改密码，不阻止之后重新登录。
  机器连接、API Key、身份提供方登录、其他用户与租户均不受影响。
  历史列表只含仍保留的会话记录，过期清理后不再展示，不是完整登录历史。

旧 `/api/v1/sessions` 与平台管理员强制下线接口保留兼容。读写存储故障返回
明确错误，不把失败显示为零活动登录或退出成功。

认证查询只将已确认不存在、过期或撤销的凭据视为无效。会话、服务密钥或用户
存储故障时，HTTP 返回不含内部错误的 503 与重试提示，gRPC 返回 Unavailable；
不返回匿名会话、不清 Cookie，也不报告退出成功。独立 Web 显示可重试故障页，
保留原访问地址。数据库结构与官方客户端协议不变，见
[ADR-0012](docs/adr/ADR-0012-authentication-storage-failures.md)。

JSON 与兼容 HTML 密码登录共用同一限流、身份查询、密码验证和会话签发路径。
限流、密码登录的初始化状态、账户/凭据读取或会话存储故障均中止认证，返回脱敏
503 与重试提示，不改变 Cookie 或引导重新初始化；未知账户、无本地密码和错误
密码仍统一 401。登录预算与 bcrypt 成本保持，见
[ADR-0016](docs/adr/ADR-0016-password-login-consolidation.md)。成功登录审计的原子性
和其他历史调用仍需继续复核，不把本切片写成全部认证流程已完成。

### 通行密钥

登录页与安全中心通过统一账户接口使用 WebAuthn（[ADR-0011](docs/adr/ADR-0011-passkey-web-and-auth-consolidation.md)）：

- `POST /api/v1/auth/passkey/begin` 返回浏览器登录参数；`POST .../finish`
  接受认证器断言，成功返回与密码登录相同的会话快照，Cookie 为 HttpOnly。
  登录挑战每个 IP 五分钟最多发起 20 次；挑战持久化、浏览器绑定且单次消费。
- `GET /api/v1/account/passkeys` 返回 `enabled`、`csrf_token` 和公开凭据列表
  （`id`、`name`、`created_at`、可选 `last_used_at`），不返回凭据原始 ID、公钥或私钥。
- `POST .../passkeys/begin`、`POST .../passkeys/finish` 注册自己的凭据；完成请求
  是 `{"name":"我的笔记本","credential":<WebAuthn JSON>}`，JSON 上限 64 KiB、
  名称最多 64 个字符。验证由 go-webauthn 完成，凭据与审计事务提交，成功返回 201。
- `DELETE .../passkeys/{id}` 删除自己的凭据，成功返回 204；不撤销已建立的登录。
  需退出旧登录时使用会话管理。关闭功能后仍可读取、删除已有凭据。
- 所有账户接口仅接受本租户 Human Session，普通成员亦可使用；所有写入需要
  当前会话的 CSRF，事务内再次检查发起会话。签发新登录前也复核凭据未被删除。

通行密钥需要固定域名、HTTPS 和正确的 RP ID / Origin allowlist；仅 localhost
开发环境可使用 HTTP。以下在本仓库启动 API，并配合另一个终端在 `xunara-web`
目录执行 `npm run dev`，由默认开发代理保证浏览器同源。先在
`http://localhost:8080/setup` 完成初始化，再访问 `http://localhost:5173/login`：

```sh
go run ./cmd/xunarad -listen 127.0.0.1:8080 -server-url http://localhost:5173
```

`-passkey-rpid` 与可重复的 `-passkey-origin` 可显式配置；多租户使用组织配置中
对应的 WebAuthn 配置，配置入口以 `cmd/xunarad/orgconfig.go` 为准。
本功能只建立人类会话，不自动审批设备，也不是 TOTP/2FA 或账号恢复。

<a id="account-api-migration"></a>

### 旧账户接口迁移

旧通行密钥管理模板和旧撤销业务实现已删除；以下地址仅保留薄适配，不维护第二套逻辑。
它们返回 `Deprecation` 日期头与指向本节的 `Link`，最终删除时间另行公告：

| 旧入口 | 新入口 |
| --- | --- |
| `/console/passkeys` | 重定向到 Web `/security` |
| `POST /console/passkeys/begin`、`finish` | `/api/v1/account/passkeys/begin`、`finish` |
| `POST /console/passkeys/{id}/delete`（表单 CSRF） | `DELETE /api/v1/account/passkeys/{id}`（CSRF header） |
| `GET /api/v1/sessions`、`DELETE .../sessions/{id}` | `/api/v1/account/sessions` 与单个撤销接口 |
| `POST /api/v1/auth/logout` | 撤销当前 `/api/v1/account/sessions/{id}` |

旧 JSON 会话写接口也必须使用 Human Session + CSRF；API Key 和无 CSRF 写入不再支持。
顶部退出与安全中心已统一调用新接口，存储失败不会清 Cookie 或假报成功。
官方客户端授权必需的 HTML 登录及其通行密钥登录入口保留；其他尚未功能对等的
内嵌控制台模块按 ADR-0003 继续分阶段迁移，不把它们混入新的产品前端。

## 测试

```bash
go build ./...
go test ./...
go vet ./...
go test -race ./...
```

- **中继平台**：`/api/relay/v1/enroll` 与 `/heartbeat`（一次性注册 + 长期身份）、
  期望状态/限速/区域名下发、按套餐的中继配额、`/api/v2/relays/*` 与平台级中继管理。
  注册把额度检查、身份创建和令牌消费合并为同一事务，失败不消耗令牌；
  注册读取的存储故障返回可重试的 503，不伪装为无效凭据。
  注册事务边界见 [ADR-0013](docs/adr/ADR-0013-atomic-relay-enrollment.md)。配置编辑/恢复与删除
  现在要求版本前置条件，历史、审计和通知同事务提交；旧管理调用须升级，详见
  [ADR-0020](docs/adr/ADR-0020-relay-configuration-history.md)。期望配置下发不等于中继已执行，
  新版 Relay 已实现实际热更/停用断连及服务自报回执，旧版执行状态仍为未知；
  详见 [ADR-0021](docs/adr/ADR-0021-relay-runtime-execution.md)。只追加 state v22，
  identity v13、官方客户端协议、套餐及静态公共中继配置不变。

## 仓库关系

| 仓库 | 职责 |
| --- | --- |
| `xunara-server` | 控制面 + 产品后端 + Core API（本仓库） |
| `xunara-web` | 用户控制台（Vue 3） |
| `xunara-admin` | 平台超级管理员后台（Vue 3） |
| `xunara-relay` | 中继平台（DERP / STUN / 限速 / 注册） |
| `xunara-deploy` | systemd / Docker Compose / 安装脚本 |
| `xunara-docs` | 规范、架构、ADR、运维文档 |

## 文档与规范

- 长期规范与架构：[xunara-docs](https://github.com/xunara-net/xunara-docs)
- 本仓库结构：[ARCHITECTURE.md](ARCHITECTURE.md)
- AI 开发规则：[AI_DEVELOPMENT.md](AI_DEVELOPMENT.md)
- 架构决策记录：[docs/adr](docs/adr/)
