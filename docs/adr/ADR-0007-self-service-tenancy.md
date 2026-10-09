# ADR-0007：自助注册即开租户（托管部署的账户模型）

- 状态：Accepted
- 日期：2026-10-09

## 背景

托管部署需要一条不依赖人工的获客链路：访客在入口站注册，立即拿到属于自己
的网络空间并开始接入设备。此前只有邀请码注册，且注册出来的是**当前租户的
成员**——在托管模型里这等于把新客户放进别人的网络，方向是错的。

同时必须回答三个问题：

1. 新账户加入哪个 tailnet？——托管部署里答案是「新建一个」；
2. 商业规则（设备数、成员数、网段）由谁执行？——由套餐（Entitlement）执行；
3. 注册策略（关闭 / 邀请 / 开放）在哪里表达？——一处表达，所有入口一致。

## 决策

- 新增 `RegistrationMode = closed | invite | open`（`control/registration.go`），
  默认 `invite`；所有注册入口（HTML `/signup`、JSON `/api/v1/auth/signup`、
  控制台能力位）读同一个值，禁止各处自判。
- 开放注册的语义随部署形态而定：
  - 单租户部署：注册者是**该租户的 member**，受套餐成员配额约束；
  - 托管部署（配置了 `self_service`）：入口站注册 = **新建租户**，
    注册者成为新租户的 owner。
- 自助开租户由 Router 执行（`control/selfservice.go`），因为只有它同时持有
  组织表、套餐注册表与地址池（AGENTS.md §13：Platform → Core）。
  端点：`POST /api/self-service/v1/signup`，仅入口站主机应答。
- 一次注册的完整副作用（任一失败全量回滚 `DeleteManagedOrg`）：
  组织行 → 套餐分配 → 地址池块下发 (`SetAddressPrefix`) → 成员配额校验 →
  认领内置 owner 账号 → 会话与 Cookie → 审计。
- 新租户认领内置本地账号（`identity.EnsureLocalUser`，ID=1）而不是新建第二个
  用户：Free 套餐 `max_users=1`，多建一个「不能登录的占位账号」会把配额烧掉。
- 入口站必须处于 `open`（启动时校验）：否则控制台显示邀请表单而 API 却对
  任何人开租户，两面不一致。
- 会话 Cookie 可带父域（`cookie_domain`），注册完成后浏览器带着会话直接落到
  `<org>.<suffix>`；不带父域时降级为「到新域名再登录一次」。

## 备选方案

- 邀请码 + 手动开租户：获客链路依赖人工，否决为默认形态（邀请模式仍保留）。
- 所有新用户进同一个 tailnet，用 ACL 隔离：违背租户边界（AGENTS.md §12），否决。
- 注册时新建第二个 owner 用户、保留内置账号：烧掉 Free 的 1 人配额，否决。
- 在控制面（而非 Router）内建租户：控制面只服务一个组织，无法创建另一个，否决。

## 影响

- 兼容性：不改动任何 Tailscale 客户端协议；TS2021/Noise/Map 路径不变。
- 安全：新租户与既有租户同样隔离（各自 state 目录、各自地址块）；入口站
  限流 5 租户/小时/IP；注册只授予最小角色（owner 仅限自己的租户）。
- 数据：不新增表；`organizations` 行由既有 Registry 管理，删除走既有路径。
- 运维：多租户部署需要 `-org-config`（含 `self_service`）+ `-platform-state-dir`
  + `-plans`；单租户部署只需 `-registration open`。
- 域名：`self_service.domain_suffix` 下的每个租户需要一条泛解析（`*.suffix`）。

## 后续

- 计费对接（支付回调改套餐）与配额超额提醒。
- 入口站的邮件验证与图形验证码（当前仅 IP 限流）。
- 租户自助注销与数据导出。
