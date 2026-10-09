# 网络控制台：权限、DNS 与私有中继

本说明是产品 API 的实现边界；使用步骤见
[用户手册](https://github.com/xunara-net/xunara-docs/blob/main/docs/user/network-console.md)。
前端为独立 xunara-web，Core 不依赖 Vue、可视化布局或网页身份。决策见
[ADR-0018](adr/ADR-0018-network-console.md) 与 [ADR-0019](adr/ADR-0019-managed-relay-map.md)。

## 权限数据流

规则编辑 / 图示 / 组 / HuJSON → 同一 `policy.Document` → 原有 Compiler →
自检与变更预览 → 持久版本事务 → 实际 PacketFilter / 标准 MapResponse。
模拟与矩阵复用目标设备实际编译的过滤规则，解释引用被测试的规则，不读取前端草稿
中的旧索引。单次矩阵最多 12 × 12；Web 按 8 × 8 分别翻来源/目标页并可搜索。

未托管时保留部署文件和旧默认互通语义；首次发布记录原配置为版本 0，之后数据库
独占权威，文件修改不能覆盖。默认隔离必须显式发布无允许规则，不靠移除文件恢复。
历史读取最近 50 个版本，恢复会发布新版本，绝不覆盖旧版本或改迁移编号。

策略拒绝重复键、未知字段、错误字段大小写、过大内容与失败/未执行的自检。
高级 SSH、应用 Grants、测试、设备能力和不同目标端口集合不能被图形编辑静默删除
或扩大；无法无损编辑的规则使用高级模式。配置关系图不是实时连接遥测。

## API

以下均为同源租户产品 API，完整请求/返回以对应实现和测试为准。

| 路径 | 操作与定义 |
|---|---|
| `/api/v2/policy/configuration` | GET / PUT 配置与版本；`control/api_network_policy.go` |
| `/api/v2/policy/validate` | POST 编译、自检与预览；不会下发 |
| `/api/v2/policy/history` | GET 不可变历史 |
| `/api/v2/policy/simulate`、`/api/v2/policy/matrix` | POST 当前或草稿的指定设备、协议、端口检查 |
| `/api/v2/dns/configuration` | GET / PUT MagicDNS、解析器、搜索域、split；`control/network_configuration.go` |
| `/api/v2/dns/records`、`/api/v2/dns/records/{id}` | GET / POST / PUT / DELETE A / AAAA；`control/api_network_dns.go` |
| `/api/v2/relays/enrolled`、`/api/v2/relays/enroll-tokens` | GET 本租户记录/额度、签发接入令牌；`control/relay_api.go` |
| `/api/v2/derp` | GET 客户端实际下发地图；`control/api_v2_derp.go` |

配置发布要求当前 `revision` 和 `base_hash`，记录更新使用记录版本，删除要求
`If-Match`。过期版本 409，不能连续重试覆盖；存储错误 503，不能伪装成空列表/互通。
旧 DNS 删除仅保留薄兼容适配，仍经过记录保护与相同写入门禁。

网络写入要求 owner/admin、套餐 Entitlement；Cookie 会话还要求 `X-CSRF-Token`，
服务密钥还要求 write Scope 与 API 授权。策略和 DNS 同事务复查持久凭据/角色，
提交配置、历史、审计、配置通知；策略发布同时撤销旧 SSH check 批准。
更新前端按钮状态不能代替后端校验，普通成员只读。不扩大 Human / Machine / Service 信任。

## DNS 与地图

DNS 只管理官方客户端实际支持的 A / AAAA 地址记录；设备自动名、服务、ACME 与
其他类型受保护。配置域名仍由部署维护，不隐式更名设备；不提供未实现的 DoH/DoT。
托管后清空配置发明确空 DNSConfig，删除最后一个中继发明确空 DERPMap，不能用
“nil 表示不变”留下旧客户端配置。静态公共地图与私有地区以不可变快照合并。

只有当前租户启用、健康、心跳在三分钟内且被 DERPPolicy 允许的私有/组织节点才加入
地图；公开接入记录不自动广播给所有租户。地区 0 的旧记录不推断 TLS 信任或地区。
中继上报真实编号 / pin，托管 CLI 自动设置持久租户准入，官方 DERP TLS 客户端验证
该 pin；公网可达性、STUN 开放和实际设备通信仍需要部署实测。

## 迁移与验收

state 只追加 v20（配置/历史与记录版本）和 v21（中继地区/pin），identity 保持 v13。
旧 DNS、设备、会话和中继凭据保留；旧二进制拒绝新 schema。回退必须在维护窗口
同时恢复升级前完整一致性状态和旧产物，恢复业务后禁止用旧快照覆盖新写入。

验证入口：`control/network_console_test.go`、`control/managed_derp_test.go`、
`state/sqlite_network_migration_test.go`、`networkconfig/store_test.go`、
`policy/managed_test.go`；在本仓库执行 build/vet/test/race。真实 Noise 流验证 DNS / ACL
更新，官方 derphttp 客户端验证 TLS pin。跨实例故障保留有效快照并重试刷新，不承诺
零传播延迟。权限允许不等于服务监听、防火墙放行或实时连接可达。
