# Xunara Server（玄序 · 服务端）

Xunara（玄序）是一个 **Tailscale 兼容的多租户网络服务平台**。
本仓库是它的服务端：控制面 + 产品层 + Xunara Core API。**不含 Web UI。**

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
- **多租户**：组织、成员、角色（owner / admin / member / viewer）、单租户部署兼容。
- **用户与身份**：本地密码登录、邀请/开放注册、OIDC/OAuth、Passkey、会话管理、
  自助资料与密码修改、API Key、身份令牌。
- **设备与网络**：设备注册与审批、Tailnet 网段分配、子网路由、Exit Node、
  MagicDNS、DERP 策略、共享与访问策略。
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

## 测试

```bash
go build ./...
go test ./...
go vet ./...
go test -race ./...
```

- **中继平台**：`/api/relay/v1/enroll` 与 `/heartbeat`（一次性注册 + 长期身份）、
  期望状态/限速/区域名下发、按套餐的中继配额、`/api/v2/relays/*` 与平台级中继管理。

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
