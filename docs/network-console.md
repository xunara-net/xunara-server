# 网络控制台：权限、DNS、地址与中继

本说明是产品 API 的实现边界；使用步骤见
[用户手册](https://github.com/xunara-net/xunara-docs/blob/main/docs/user/network-console.md)。
前端为独立 xunara-web，Core 不依赖 Vue、可视化布局或网页身份。决策见
[ADR-0018](adr/ADR-0018-network-console.md)、[ADR-0019](adr/ADR-0019-managed-relay-map.md)
与 [ADR-0020](adr/ADR-0020-relay-configuration-history.md)、[ADR-0021](adr/ADR-0021-relay-runtime-execution.md)、
[ADR-0022](adr/ADR-0022-address-management-and-external-relays.md)。

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
| `/api/v2/relays/{id}`、`/api/v2/relays/{id}/history` | GET 当前配置 / 历史、PATCH 修改或恢复、DELETE 版本保护删除；`control/relay_configuration.go`、`networkconfig/relay.go` |
| `/api/platform/v1/organizations/{orgID}/relays/{relayID}` 及 `/history` | 独立平台凭据；同一版本与历史事务；`control/platform_relays.go` |
| `/api/v2/derp` | GET 客户端实际下发地图；`control/api_v2_derp.go` |
| `/api/v2/network/addresses`、`/validate` | GET 实际/期望网段，PUT 带版本保存，POST 仅校验预览；`control/address_management.go` |
| `/api/v2/machines/{ref}/ipv4` | PUT 带旧 IP 基准显式修改单设备地址；`networkconfig/addresses.go`、`state/addresses.go` |
| `/api/v2/derp/configuration`、`/history` | GET / PUT 非托管地图与 GET 版本历史；`control/external_derp.go` |
| `/api/v2/derp/import-official` | POST 固定官方 HTTPS 地图预览，不自动保存；`control/external_derp.go` |

配置发布要求当前 `revision` 和 `base_hash`，记录更新使用记录版本，删除要求
`If-Match`。过期版本 409，不能连续重试覆盖；存储错误 503，不能伪装成空列表/互通。
旧 DNS 删除仅保留薄兼容适配，仍经过记录保护与相同写入门禁。

网络写入要求 owner/admin、套餐 Entitlement；Cookie 会话还要求 `X-CSRF-Token`，
服务密钥还要求 write Scope 与 API 授权。策略和 DNS 同事务复查持久凭据/角色，
提交配置、历史、审计、配置通知；策略发布同时撤销旧 SSH check 批准。
更新前端按钮状态不能代替后端校验，普通成员只读。不扩大 Human / Machine / Service 信任。

## 中继配置与历史

PATCH 正文要求 `config_version` 为读取的当前正整数版本，并提供要改的
`desired_state`、`bandwidth_limit`、`region_name` 中至少一个。恢复只提交
`config_version` 与 `restore_from`，不得混入配置字段；恢复生成新版本，不回退版本号。
DELETE 要求 `If-Match: <当前版本>`，也接受完整双引号包裹的版本。不接受通配符。
缺少版本返回 428 `RELAY_VERSION_REQUIRED`，过期返回 409 `RELAY_CONFIG_CHANGED`。

只接受 online / maintenance / disabled / revoked，带宽为 -1、0 或可安全表示的
正整数；地区名称最长 128 字节，不接受控制字符。旧客户端需刷新/升级，不提供
读取当前版本后自动覆盖的兼容旁路。已撤销身份不能被修改或恢复为启用状态。

历史首项为最新版本，最多返回 50 项；字段为 `config_version`、`desired_state`、
`bandwidth_limit`、`region_name`、`actor`、`created`。首次编辑保存原始快照；其时间
是快照采集时间，不伪造早期操作时间。更早但未被记录的旧部署变更不能追溯。
删除中继会删除其恢复历史，但保留审计；历史不能重建服务凭据或恢复遥测。

用户与平台写入均将配置、历史、审计和配置通知一起提交；用户事务再次验证持久
凭据和角色。平台列表与历史读故障失败关闭。Cookie 写入仍需 CSRF，服务密钥仍
需 API Entitlement 与 write 范围。没有新增迁移或套餐特判。

保存是期望配置，不是执行回执。新版 Relay 实际热更每连接限速、维护拒新、停用
断连/恢复及终态撤销，再通过心跳自报执行结果。两个后台分开展示期望版本和报告，
旧版无报告时为未知，失联报告为旧回执。身份撤销没有停机 ACK，不能用历史报告
证明已经断开。具体可选字段及缓存语义以
[Relay 契约](https://github.com/xunara-net/xunara-relay/blob/main/docs/relay-protocol.md#5-运行时执行与回执可选兼容扩展)为准。
报告变化、遥测与服务审计同事务，存储故障返回 503 而不是无效服务凭据。

## DNS 与地图

DNS 只管理官方客户端实际支持的 A / AAAA 地址记录；设备自动名、服务、ACME 与
其他类型受保护。注册/更名与记录/服务写入共用事务型归属检查；新设备名冲突时分配
稳定后缀，既有记录不被覆盖。配置域名仍由部署维护，不隐式更名旧设备；首次绑定
后不能在线改域名，不提供未实现的 DoH/DoT。升级先执行
[DNS 名称只读预检](dns-name-ownership.md)，发现旧碰撞需人工审查。
托管后清空配置发明确空 DNSConfig，删除最后一个中继发明确空 DERPMap，不能用
“nil 表示不变”留下旧客户端配置。静态公共地图与私有地区以不可变快照合并。

只有当前租户启用、健康、心跳在三分钟内且被 DERPPolicy 允许的私有/组织节点才加入
地图；公开接入记录不自动广播给所有租户。地区 0 的旧记录不推断 TLS 信任或地区。
中继上报真实编号 / pin，托管 CLI 自动设置持久租户准入，官方 DERP TLS 客户端验证
该 pin；公网可达性、STUN 开放和实际设备通信仍需要部署实测。

## 网段与单设备 IP

自定义 IPv4 不再局限于 `100.64.0.0/10` 或 /16～/28，合法私有或公网单播
范围均经过保留/冲突检查；例如 `10.0.0.0/8`、`172.16.0.0/12`、
`192.168.50.0/24`。默认仍是 CGNAT；非标准范围明示实验性客户端兼容风险，
允许配置不意味着获得公网 IP 所有权或保证所有官方客户端功能可用。
不允许非法、系统/客户端内部、分享、部署保留及其他租户的现有/历史预留。
/30 及更大池排除网络/广播地址，/31 和 /32 主机池分别有 2 和 1 个地址；
容量不足拒绝注册，不回退旧池。自动分配与手动修改共用边界，不改写既有设备。
决策见 [ADR-0023](adr/ADR-0023-flexible-ipv4-allocation.md)，仅替代 ADR-0022 的
强制 CGNAT 范围部分，不改变其余地址与中继决策。

Free 的 `AllowCustomCIDR` 为 false；固定分配范围内的 IP 修改与网段能力分开，
仍需网络管理员及写入门禁。IPv6 当前由系统分配，不能在此界面手工改写。
预览不写状态，保存网段仅改变后续分配；已有设备不会批量断连或重编号。
设备详情修改要求旧 IP 基准、地址未被占用并属于实际范围，失败保留草稿。
标准自身/peer 地址更新沿用原 Mapper 与通知；心跳的旧副本不再覆盖地址列。
按 IP 写的 ACL、自定义 DNS、应用或外部配置须由管理员显式同步，不能盲目替换。

节点库保存实际范围与来源版本，分配在事务内读取。平台库先持久提交期望范围与
新旧预留，再应用节点库；不是跨库原子事务。故障时返回失败，GET 标注 pending，
现有实际范围保持，后台及重启重试收敛，不能假报已生效。
地址、审计与配置通知同事务，角色/凭据在事务内复核；配置来源不依赖进程缓存。

历史网段及补录的旧节点 /32 保守保留，删除/归档租户也不自动回收。尚未实现安全
回收与批量迁移工作流；池空间不足须运维审查，不直接删预留或旧设备绕过冲突。
升级发现既有设备与另一租户分配冲突时失败关闭，需要先审查，不自动更改生产 IP。

## 默认、非托管与托管中继

用户中心默认打开「可用中继」，展示实际部署/外部/托管来源及端口。非托管地图
单独管理，可手工新增多节点地区或从固定官方 HTTPS 源导入草稿，确认后发布。
导入不带凭据、不跟随重定向，有 context、超时与大小上限；不提供任意 URL 抓取。
版本冲突保留草稿，恢复历史生成新版本；删除仅撤回本租户地图，不控制外部服务。

地区编号不能覆盖部署地图或任何托管记录，离线/维护节点的编号也受保护；反向
接入检查与令牌消费在同一事务。合并保留部署字段、完整节点/TLS 字段和 DERPPolicy，
不自动把公开注册记录广播到其他租户。没有心跳的外部节点不伪造在线或执行回执。
固定官方地图导入不承诺公共服务器一定接纳本平台节点，仍须独立测试外部服务。

预编译程序及校验方法以
[Relay 下载说明](https://github.com/xunara-net/xunara-relay/blob/main/docs/precompiled-release.md)
为准；Web 固定到真实预览发布，不按浏览器系统自动误选服务器架构，不包含凭据。
交叉编译与校验和不等于全 OS 现场验收、独立签名或自动升级。

## 迁移与验收

state 只追加 v20（配置/历史与记录版本）、v21（中继地区/pin）、v22（执行回执与接收时间）、
v23（持久分配范围及 IP 唯一性）、v24（分配 DNS 名称及租户域名绑定），平台 plans
保持 v4（预留/版本日志），identity 保持 v13。
旧 DNS、设备、会话和中继凭据保留；旧二进制拒绝新 schema。回退必须在维护窗口
同时恢复升级前完整一致性状态和旧产物，恢复业务后禁止用旧快照覆盖新写入。

验证入口：`control/network_console_test.go`、`control/managed_derp_test.go`、
`state/sqlite_network_migration_test.go`、`networkconfig/store_test.go`、
`policy/managed_test.go`；在本仓库执行 build/vet/test/race。真实 Noise 流验证 DNS / ACL
更新，官方 derphttp 客户端验证 TLS pin。跨实例故障保留有效快照并重试刷新，不承诺
零传播延迟。权限允许不等于服务监听、防火墙放行或实时连接可达。

本切片还验证 `control/address_management_test.go`、`control/external_derp_test.go`、
`state/addresses_test.go`、`networkconfig/addresses_test.go` 与 `netspace/client_test.go`，
包括实际/期望收敛、两连接抢占、审计回滚、地址自身/peer 下发、外部导入/碰撞/隔离。
