# ADR-0006：中继平台的服务端实现（注册 / 心跳 / 配额）

- 状态：Accepted
- 日期：2026-10-09

## 背景

`xunara-relay` 从第一天独立成仓，并在 `docs/relay-protocol.md` 冻结了控制协议：
一次性 enrollment token 换取长期 Relay Identity，然后用心跳上报状态并领取期望
配置。在此之前服务端只有「准入」（`/derp/admit`）而没有注册与心跳，托管模式无法
真正使用（补充规范 §6–§21、§49）。

## 决策

- 协议端点挂在**组织自己的 Server** 上（`POST /api/relay/v1/enroll`、
  `POST /api/relay/v1/heartbeat`）：中继是租户资源，多租户部署下请求按 Host 落到
  所属组织，单租户部署同样可用。
- 长期状态落在组织的 `state.Store`（新表 `relays`、`relay_enrollment_tokens`，
  迁移 v19）：relay 记录 + 最近一次心跳遥测 + 期望配置（desired state、带宽限速、
  区域名、config_version）。
- 两种凭据都只存 SHA-256：enrollment token 一次性（原子消费，重复 409、过期 410），
  relay token 长期（撤销后心跳 403）。凭据绝不进入日志与 URL。
- 配额走 Entitlement：`plan.Plan.MaxRelays`（Free 1 / Pro 5 / Business 20，
  未配置套餐 = unlimited），在签发 token 与注册两处检查，返回
  `403 RELAY_LIMIT_REACHED`。
- 运营面复用同一实现：`/api/v2/relays/*`（租户，会话/API Key + Scope）与
  `/api/platform/v1/relays`、`.../organizations/{orgID}/relays/*`（平台令牌）。
- 请求解析容忍未知字段：新中继必须能与旧控制面通信（协议 §4 的向后兼容约定），
  但字段内容严格校验（hostname、node key、端口、可见性）。

## 备选方案

- 把中继注册放在平台层（`/api/platform`）而不是组织层：平台令牌无法下发给用户
  自建私有中继，且多租户下无法确定归属。
- 复用 API Key 作为中继凭据：中继是机器/服务身份，复用人身份密钥会混淆边界
  （AGENTS.md §5），也无法表达"一次注册、长期心跳"的生命周期。

## 影响

- 官方客户端协议不受影响：中继注册只关心 DERP 数据面与自己的凭据。
- 新增两份迁移（只追加）；`MaxRelays` 是套餐模型的新增字段，旧的套餐文件仍然
  合法（缺省 0 = 不允许中继；内置目录已给出 Free/Pro/Business 的配额）。
- 部署仓库的托管模式（`XUNARA_RELAY_MANAGED=1`）从此可用；独立模式保持不变。

## 后续

- 控制台/超管后台的中继管理页面（列表、限速、可见性、拓扑、成本）。
- 中继流量计费与用量上报的持久化（当前只保留最近一次心跳计数）。
- 服务端 `/api/relay/v1/*` 与 relay 仓库契约的跨仓库兼容测试。
