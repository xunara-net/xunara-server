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
- **用户与身份**：本地密码登录、邀请注册、OIDC/OAuth、Passkey、会话管理、
  API Key、身份令牌。
- **设备与网络**：设备注册与审批、Tailnet 网段分配、子网路由、Exit Node、
  MagicDNS、DERP 策略、共享与访问策略。
- **商业化**：套餐目录（内置 free/pro/business 或 `-plans` 外置）、设备/成员/
  密钥/路由配额、租户网段自定义与冲突检测、平台运营 API。
- **可观测与审计**：结构化日志、`/health`、`/version`、审计日志、Webhook、
  Prometheus 风格指标（部分）、gRPC 平台面。
- **JSON API**：`/api/v1/auth/*`（登录/注册/会话）、`/api/v1/capabilities`、
  `/api/v2/*`（设备、DNS、DERP、策略、审计、共享……）。

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

多租户部署使用 `-org-config <file>` 描述组织与域名。

## 测试

```bash
go test ./...
go vet ./...
```

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
