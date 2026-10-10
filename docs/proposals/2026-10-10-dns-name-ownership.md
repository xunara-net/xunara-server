# Architecture Change Proposal：租户 DNS 名称的原子归属

- 日期：2026-10-10
- 范围：Server / Docs
- 前置：ADR-0018；state v23 / identity v13 / plans v4
- 跟踪：[任务 #7](https://github.com/xunara-net/xunara-server/issues/7)

## 问题与已核对链路

DNS 管理写入检查设备和服务名，但注册、密钥轮换、MapRequest 更名、原生客户端
心跳反向写入没有同事务保护。服务发布的前置读取也不能排除另一连接在提交前注册
同名设备。上游客户端优先查询 ExtraRecords，重复名称可能使设备名解析到错误地址。

已核对 Tailscale v1.104.0 的 tailcfg.Node.Name、dnsname.SanitizeHostname 与
net/dns/resolver；Headscale 的 Node.GivenName、NodeStore 名称碰撞测试。协议允许
控制面分配 DNS 名称，机器自报 Hostinfo.Hostname 不应被当作名称所有权。

来源：[Tailscale Node](https://github.com/tailscale/tailscale/blob/v1.104.0/tailcfg/tailcfg.go)、
[官方名称解析](https://github.com/tailscale/tailscale/blob/v1.104.0/net/dns/resolver/tsdns.go)、
[Headscale 名称模型](https://github.com/juanfont/headscale/blob/main/hscontrol/types/node.go)。

## 决策提案

1. 追加 state v24，持久化节点分配的 DNS label 与已绑定的租户域名；保留机器自报
   Hostname，FQDN 优先使用分配名。合法、无冲突的既有名称不变，IP/身份不变。
2. 注册和机器更名在同一节点事务内检查设备、服务和自定义记录。新名称碰撞时
   自动分配含节点 ID 的稳定后缀，重报相同主机名和密钥轮换不反复加后缀。
   域名大小写与尾点规范化；分配后仍使用官方 Node.Name，不增加协议字段。
3. DNS 记录与服务写入在各自写事务内复核反向归属，关闭前置检查与写入的竞态。
   SQLite 使用既有 immediate 事务，MemoryStore 使用同一个锁；查询故障失败关闭。
4. 初次绑定域名同事务补录旧设备名称。发现旧重复或与服务/记录碰撞时拒绝绑定，
   不静默改写既有名称、记录或 IP。绑定后不同实例必须使用相同域名；在线改域名
   不在本次实现，避免旧实例继续发布不同命名空间。尚未启用域名可后续首次绑定。
5. 保留旧 UpdateNode 作为通用事实更新入口，委托同一个持久写入实现；新增指针型
   更新用于获得实际分配名，注册、轮换和心跳不能把未提交或旧别名发给客户端。
   删除重复的服务名称前置扫描，不保留两套不同的冲突判断。
6. 共享投影沿用来源的分配名，本地/外来设备与共享服务的已有冲突判断统一尾点。
   复杂共享投影的全局持久名称预留不由本次局部事务保护宣称完成。

## 验收与边界

两种 Store 的名称碰撞、规范化、长名称、保留记录、子域与 ACME、不变重报、
删除释放、读取故障、跨连接竞争和真实 v23 升级/重启；Noise 注册/更名/轮换与
DNS/服务 API 的双向保护。全量 build/vet/test/race、现有真实 API 浏览器回归。
不能将隔离 Go 测试或 Linux 实测称为 Windows/macOS/Android/iOS DNS 验收。

升级前做完整一致性备份与冲突预检；旧二进制拒绝 v24。未恢复服务且无新写入时
可成套恢复旧状态与旧产物，恢复业务后不得用旧快照覆盖新数据。不改变套餐门禁、
管理 API 字段、官方协议、ACL 语义或 DNS 解析器配置。注册/登录审计事务、旧数据
人工消歧、用户手工指定设备别名和全 OS DNS 验收仍为独立后续任务。
