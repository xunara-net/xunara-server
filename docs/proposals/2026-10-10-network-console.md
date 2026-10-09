# 网络控制台持久配置与可视化权限提案

- 日期：2026-10-10
- 依赖顺序：xunara-server → xunara-web → xunara-deploy / xunara-docs
- 任务：https://github.com/xunara-net/xunara-web/issues/1

## 问题与数据流

现有用户页面只能读取文件策略、删除 DNS、读取中继；手机菜单占据正文前方。
本任务交付可操作的网络管理，不能以表单保存或模拟图代替实际控制面生效。

可视化规则和高级 HuJSON → 同一个 `policy.Document` → 现有 Compiler →
校验 / 真实设备模拟 / Diff → 带期望版本的发布 → 持久配置和审计事务 →
不可变运行快照 → 既有 MapResponse 的 DNS / PacketFilter 更新。

## 决策

新增平台 `networkconfig` 模块，复用每租户 SQLite 连接池。state 仅追加 v20
配置头与历史表；平台模块实现 CAS、审计、配置 revision 和 SSH check 撤销的
原子提交。Identity 提供事务内人类会话 / owner 或 admin 复核，不把 Machine
身份当作管理身份。浏览器写入要求 Human Session 和会话绑定 CSRF；Service
写入必须持有 write Scope、有效 API Key、可写所有者角色及 API Entitlement，
在事务内重查撤销/过期/角色和 Scope，不让 API 权限反向成为 Human 身份。

文件 ACL 与启动 DNS 是未托管配置的唯一来源，第一次发布将它们导入 revision 0；
此后数据库为唯一权威，文件 watcher 不得覆盖 Web 发布。坏配置拒绝启动或保持
上个有效快照，不回退为 allow-all。版本恢复是发布新版本，不能删除配置头。
旧数据库的无策略默认保持兼容；UI 明确提示完全互通，不伪装零信任。

DNS 支持全球解析器、搜索域、split DNS、MagicDNS 开关及 A / AAAA 自定义记录。
只读网络域名，避免隐式改名和证书变化。官方 v1.104.0 `node_backend.go` 只消费
ExtraRecords 的地址类型，不能提供会被客户端忽略的 TXT / CNAME 编辑假功能；
客户端 ACME TXT 通道保持不变。机器/证书记录在用户编辑器中受保护。

中继沿用已评审的租户注册/心跳 API，新增独立用户页面；公共下发地图与私有托管
记录分开，心跳不是连接质量或实际中继路径。一次性 token 只在内存短暂显示。

## 风险与验收

v20 使旧二进制拒绝较新状态；维护窗口内回退必须二进制加一致性状态配套，
开放公网后禁止覆盖旧快照。验证 CAS 跨连接竞争、写失败全回滚、权限撤销、
重启/多实例同步、真实 netmap 更新、导入不丢字段、版本恢复、模拟/矩阵与 Compiler
结果一致、手机抽屉导航/首屏操作及秘密清除。完整 build / vet / test / race、
前端类型/单测/构建和隔离浏览器验证全部完成后方可发布。

参考：[官方 Grants](https://tailscale.com/docs/reference/syntax/grants)、
[官方 DNS](https://tailscale.com/docs/reference/dns-in-tailscale)；协议行为以锁定
`tailscale.com v1.104.0` 的 `tailcfg.DNSConfig` 与客户端实现为准。
