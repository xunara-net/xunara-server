# Xunara Server 架构

> 本文档描述 `xunara-server` 的内部结构、依赖方向与边界。
> 产品级规范见 [xunara-docs](https://github.com/xunara-net/xunara-docs)
> （`AI_DEVELOPMENT.md`、`PROJECT_SPEC.md`、`ROADMAP.md`）。

## 1. 定位

`xunara-server` 是 Xunara 的服务端，负责三件事：

1. **控制面**：与官方 Tailscale 客户端对话（TS2021 / Noise / MapRequest /
   MapResponse / DERP 协调），保证官方客户端永远可以加入 Tailnet。
2. **产品层**：用户、组织、成员、Tailnet、设备、网络、权限、套餐与配额、
  审计、通知、事件。
3. **Xunara Core API**：`/api/v1`、`/api/v2`、`/api/agent/v1`、`/api/platform/*`
   与 gRPC 平台面。前端（xunara-web / xunara-admin）、CLI、未来客户端全部
   经由这一层，任何前端都不允许直接接触控制面内部状态。

本仓库**不含 Web UI**。用户控制台是 `xunara-web`，平台后台是 `xunara-admin`。

## 2. 分层与依赖方向

```text
        xunara-web        xunara-admin        CLI / SDK / Client
             │                 │                     │
             └────────────┬────┴─────────────────────┘
                          ▼
                 Xunara Core API（/api/v1、/api/v2、/api/platform、gRPC）
                          │
   ┌──────────────────────┼───────────────────────────────┐
   │                      │                               │
 identity              control                          plan / netspace
 用户/会话/OAuth        Tailnet/设备/策略/路由             套餐/配额/网段
   │                      │                               │
   └──────────────────────┴───────────────┬───────────────┘
                                          ▼
                              Tailscale 协议兼容层
                              （TS2021 / Noise / Map / DERP 协调）
                                          │
                                          官方 Tailscale 客户端
```

依赖规则：

- `plan`、`netspace`、`policy` 是**纯库**：不依赖 HTTP、不依赖 WebUI、
  不依赖具体的部署形态。
- `identity` 只知道用户与会话，不知道 Tailnet 协议细节。
- `control` 是组合层：把身份、状态、策略与协议兼容层接在一起。
- `cmd/*` 只做参数解析与装配，不含业务规则。

## 3. 包结构

| 目录 | 职责 |
| --- | --- |
| `control/` | 控制面 + 产品 API（HTTP/gRPC 路由、协议兼容、策略编译、平台面） |
| `identity/` | 用户、会话、外部身份、邀请、Passkey、API Key、审计记录 |
| `state/` | 节点/路由/DNS/密钥等持久状态（SQLite + 内存实现） |
| `policy/` | 策略模型、解析、校验、编译（Grants / ACL） |
| `plan/` | 套餐数据模型与配额算术（无副作用） |
| `netspace/` | 租户网段校验、保留段、冲突检测与分配池 |
| `dnsprovider/` | DNS 提供方适配器 |
| `webhook/` | Webhook 投递 |
| `idtoken/` | 身份令牌（OIDC 风格的 ID Token 签发） |
| `client/` | 节点 Agent 与协议客户端（`xunara-agent`） |
| `cmd/xunarad` | 服务端主程序 |
| `cmd/xunara` | 管理 CLI（直接操作状态目录） |
| `cmd/xunara-agent` | 节点 Agent（服务发现、Reach、Flux） |
| `api/proto` | 平台面 gRPC 定义与生成代码 |

## 4. 数据边界

- **Xunara 数据**（用户、套餐、分配、审计、组织）保存在 Xunara 自己的存储里。
- **Tailnet 状态**（节点、密钥、路由、策略）由控制面管理。
- 两者之间的映射由控制面完成，业务代码不直接读写协议层的表结构。

## 5. 套餐与配额

- `plan.Catalog` 是套餐目录（内置 `free` / `pro` / `business`，可由
  `-plans <file>` 替换）。
- `control.PlanRegistry` 保存「租户 → 套餐」与「租户 → 网段」的分配。
- 配额在**资源创建点**强制（设备注册、密钥签发、成员加入、路由审批、
  API Key、审计读取），越权请求返回稳定的错误码前缀（如
  `DEVICE_LIMIT_REACHED:`），前端按前缀本地化。
- 没有套餐配置的部署得到 `plan.UnlimitedPlan()`，所有闸门为 no-op：
  自托管与商业部署共用同一份代码。

## 6. 迁移中的部分

旧版把控制台页面内嵌在服务端（`control/console_pages*.go`、
`control/admin_pages.go`、`control/public*.go`）。按多仓库规范，产品 UI 属于
`xunara-web` / `xunara-admin`；服务端只保留**设备授权流程必需的浏览器页面**
（`/register/{authID}`、`/login`、`/signup`、`/setup`、`/ssh/check/*`）。

迁移路径见 `docs/adr/ADR-0003-server-web-split.md`。
