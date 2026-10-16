# 六仓代码清理审查（2026-10-15）

## 范围与方法

现用源码为 `xunara-net` 组织的 Server、Web、Admin、Relay、Deploy 和 Docs 六仓库。
工作区外层旧单仓 README 已明确归档，只读追溯历史，不在其中混入本轮修复。
依赖目录、构建产物、生成的 protobuf、上游参考检出不当作手写冗余代码删除；
证书、状态、诊断转储和用户上传文件不属于本轮源码清理对象。

先核对仓库规则、架构 / README、相关规范与 ADR，再用定义、调用方、测试、
入口可达性及实际数据流交叉验证。检查覆盖服务端 19 个主模块 Go 包和独立
`integration/sharing` 模块、中继全部 Go 包、两个前端的 TS / Vue 依赖图、
部署渲染 / 路由 / 安装与跨仓库浏览器脚本入口。

- Go：`deadcode v0.50.0` 分别分析生产根和测试根；`staticcheck v0.8.2` 对照无用
  声明、无效赋值与完整诊断。分析器仅为本机审查工具，不加入服务端运行依赖。
- 前端：Vue 类型检查开启 `noUnusedLocals` / `noUnusedParameters`；导出 / 文件扫描
  结果必须复查 Vue 类型引用、动态导入与兄弟仓库 CJS 调用，不能直接自动删除。
- 重复体检查：AST 去除注释后，核对两个 Go 仓库 2,439 个生产函数；七条及以上
  顶层语句的函数体未发现完全相同副本。这不排除改名或语义相似的重复实现。
- 运行入口复核重点：注册 / 会话、共享账户与设备授权、密钥 / 成员配额、配置
  事务、网段 / 策略 / DNS、Relay 身份与管理面。历史测试与全部扩展模块未宣称
  完成逐行安全审计；静态扫描和回归也不能证明“再无缺陷”或“全部功能完成”。

## What changed

删除 11 个 Go 遗留函数 / 适配器、两个无人使用的 Admin 组件和三个前端方法，
同时移除未使用的测试字段、无效初始赋值、相应导入和误导性旧注释：

| 移除项 | 定义与调用复核结论 |
|---|---|
| `PlanRegistry.validateNetwork` | 单池包装器已被多池 `validateNetworks` 替代，无生产或测试调用 |
| `policyModTime` | 配置刷新按实际内容与版本比较，不再使用旧文件修改时间辅助函数 |
| `Server.relayViews` | 列表使用现行读取 / 视图路径；该旧列表包装器无人调用 |
| `validShareStatus` / `ShareOrg.shareRegistry` | 状态转换和平台注册表装配已在现用路径完成，没有此校验 / 接口回调的调用 |
| `assertAuthKeyQuota` / `assertUserQuota` | 仅旧单测调用的“先读列表”校验；实际创建已在持久事务内检查额度 |
| `loadOrgSites` | 仅为旧单测保留，且丢弃自助配置；测试改为与启动共用 `loadOrgConfig` |
| `Server.denyDevice` | 单个测试使用的无上下文包装器；测试改为调用现行设备决定服务 |
| `readMapResponse` / `decodeSecurity` | 无调用测试辅助函数；保留实际使用的协议解码器与断言 |
| Admin `AsyncSection.vue` / `StatusBadge.vue` | 无静态、动态、模板或跨仓库导入；Web 的同名在用组件不删除 |
| Admin `getOrganization` / `updateOrganization` / `quotaPercent` | 私有前端内无调用、无测试使用，不是服务端 HTTP API 删除 |

公开页面和兼容页页脚不再指向已归档旧单仓，统一链接实际 Server / Docs 仓库。
架构文档如实记录仍挂载的内嵌管理页；Admin 当前网段说明不再声称 CGNAT-only。

## Why

只测试旧预检会让“测试通过”与真实权限、CSRF、事务额度路径脱节。
密钥额度测试改走实际 HTTP → 人类会话 / CSRF → 写事务，覆盖有效、已过期、
已消费单次、已用可复用密钥，以及满额拒绝、删除后再创建和无限套餐。
Free 的服务 API 禁用不放宽；测试使用合法人类会话，不通过改变套餐凑通过。
成员加入仍由现有注册事务与开放注册集成回归覆盖；开租户保留最终人数检查。

CI 增加固定版本的 `U1000,SA4006` 检查；两个前端的严格未使用项检查纳入现有
typecheck / build。浏览器脚本补充明确 npm 入口，防止今后被文件扫描误判为垃圾。

## Compatibility impact

不修改 HTTP / gRPC 字段、官方 Tailscale 协议、客户端类型、套餐额度、数据库
结构或任何已发布迁移；不迁移 / 删除生产用户、网络、设备或会话。
共享接口仅移除未调用的私有方法，现有 Server 实现和跨租户分享回归仍验证。

以下内容明确保留，不用清理名义取消能力或破坏升级：

- 后续 2026-10-16 已按 [ADR-0049](adr/ADR-0049-retire-embedded-console.md)删除 `/console/*`
  完整页面和表单，仅保留书签迁移 / 旧写 410。内嵌 `/admin/*` 不在此次用户中心退役范围内。
- 旧账户地址的薄适配、旧租户登录跳转、`network-check.py` 的 410 拒绝规则、
  重置码退役响应和旧凭据清理 SQL，均是兼容或安全边界，不是旧业务复活。
- `MemoryStore` 是持久实现的测试对照和内嵌公共能力；`Agent.netmapStats` 是
  真实异步应用回归的锁内观测点，不因生产入口不调用就删除。
- `CleanState`、`ExpireNodeTx`、`DefaultUser` 在本仓生产 / 测试根不可达，但属于
  已导出的 Go 表面；仓内扫描不能证明外部使用者不存在，本轮不做无公告破坏性删除。
- 前端只在本文件使用的导出类型、`import(...).DERPNode` 等类型引用以及由 Admin
  引用的 Web 浏览器模块不属于未使用运行时代码。
- 完整 Staticcheck 仍有上游弃用提示和历史风格提示；未为消除告警改写 Noise、
  MapResponse / Capabilities 或密码学测试。CI 只为本轮明确的无用项建立门禁。

## Security impact

仅删除不可达实现，额度和注册授权仍以当前事务为权威；不绕过会话撤销、权限、
CSRF、租户边界、审计或保留网段检查。浏览器验收使用隔离测试状态，不修改正式站。
没有读取、打印或提交真实令牌、私钥、证书包、状态备份或诊断转储。

## Tests

执行目录分别为对应仓库根目录；浏览器前置条件和命令见 Web / Admin README。

```sh
# xunara-server
go build ./...
go vet ./...
go test ./... -count=1 -timeout=15m
go test -race ./... -count=1 -timeout=30m
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 -checks=U1000,SA4006 ./...

# xunara-server/integration/sharing
go test -race . -count=1 -timeout=4m

# xunara-relay
go build ./... && go vet ./... && go test ./... -count=1
go test -race ./... -count=1

# xunara-web 与 xunara-admin 分别执行
npm test && npm run build

# xunara-web
npm run test:network

# xunara-deploy
python3 nginx/smoke.py
```

本地最终结果：构建 / vet / Go 全量常规测试和全量 race、无用项检查、共享模块
race、中继 build / vet / test / race 均通过。主模块 control 竞态包耗时
802.113 秒，identity 141.514 秒；未沿用默认十分钟超时或旧提交结果。
Web 501、Admin 61 项单测及严格类型 / 构建通过；Shell 17 项、两种共享入口各
17 阶段浏览器、103 阶段管理 / 网络浏览器、21 阶段 nginx 集成通过，JS 错误为零。

补充的 25 阶段认证 / 密码恢复、7 阶段独立平台账户与 6 阶段设备分享浏览器均
通过。中继安装器在一次性 Docker 中验证真实二进制 / TLS、私有文件、身份保留
升级、CA 回退和无效配置；CDN / systemd / 控制面响应仍是明确夹具。

`scripts/verify-dns-ownership.py` 使用本机官方 Tailscale 1.102.2、两个隔离
userspace-networking 客户端与真实 Relay，完成 API 启用 MagicDNS、同名保护、
设备更名、内部 A / PTR、WireGuard ICMP 和重启保持地址 / 名称；未改宿主机 DNS。
这不等于所有操作系统或宿主机解析器验收，开发验证脚本也不是公开下发的检查器。

独立前端清理已推送 Web `7042bbc` 与 Admin `cbaeb6a`，对应 GitHub CI 均成功。
Server 本次提交另触发 CI，以该提交的运行结果为准，不复用上一版 CI 状态。

本轮是源码清理，不自动覆盖现有线上产物；无迁移、无新功能发布承诺。
