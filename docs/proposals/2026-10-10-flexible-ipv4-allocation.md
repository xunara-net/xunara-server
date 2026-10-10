# Architecture Change Proposal：放开自定义 IPv4 分配范围

- 日期：2026-10-10
- 范围：Server / Web / Admin / Docs
- 跟踪：[跨仓任务 #6](https://github.com/xunara-net/xunara-server/issues/6)
- 前置：ADR-0005、ADR-0022；state v23 / plans v4 / identity v13

## 背景与已核对数据流

用户要求「不要限制网段」。现有用户和平台写入最终都进入 netspace，分别存在
CGNAT-only 与 /16～/28 人工限制；设备修改 IPv4 也单独检查 CGNAT。
自动分配器从持久实际范围读取，旧设备和历史租户范围仍保留，不应为放开表单
丢弃这些保护。地址池块数量的搜索上限是资源保护，不是自定义 CIDR 长度限制。

核对了依赖 Tailscale v1.104.0 的 tsaddr、controlclient、ipnlocal：协议携带节点
单地址，不意味着非 CGNAT 在所有系统和功能中都受支持。客户端 IP 分类、地址
转换及路由仍有标准范围假设。Headscale 上游配置也允许非标准前缀，但明确警告
不支持。因此不能把允许保存 RFC1918 表述为全平台官方兼容。

来源：[Tailscale tsaddr](https://github.com/tailscale/tailscale/blob/v1.104.0/net/tsaddr/tsaddr.go)、
[Tailscale 保留地址](https://tailscale.com/docs/reference/reserved-ip-addresses)、
[Headscale FAQ](https://headscale.net/stable/about/faq/)。

## 决策提案

1. 移除自定义 IPv4 的 CGNAT-only 和 /16～/28 限制，允许合法私有、公网单播
   CIDR 及 /31、/32 主机池。不改变默认 CGNAT、IPv6、套餐定义或官方 wire。
   非标准范围在用户和超管入口明示实验性兼容风险；保存仍须预览/确认。
2. 保留非法/保留地址、客户端内部/分享地址、部署保留、其他租户与历史预留
   检查。公网地址不表示获得该地址所有权；用户须避免局域网和互联网路由冲突。
3. /30 及更大池排除网络/广播地址，/31 和 /32 按单地址池使用全部地址。
   自动与手动 IPv4 共用规则；小池耗尽返回错误，不回退旧池、不越界、不重复。
   两种状态存储保持一致，SQLite 分配计数保持持久和单调；不枚举整个大网段。
4. 自动租户块支持非 CGNAT 与更小块，但保留最多 65536 个候选块的搜索上限，
   并在移位前验证长度，避免 /32 或大池导致整数溢出/拒绝服务。
5. 角色、Entitlement、CSRF、CAS、审计、通知及跨库收敛保持原链路；既有 IP
   不自动改写。仅放开合法地址，不取消权限或安全隔离。

## 验收与恢复

增加私有/公网、大/小前缀、/31 /32 容量与耗尽、手动 IP、旧设备保留、重启、
租户冲突、保留地址与官方 MapResponse/DNS/过滤器测试；Go 全量 build/vet/test/race，
Web/Admin 单测构建与真实 API 手机浏览器验收。不将这些测试冒充各 OS 的实测。

无数据库迁移或 API 字段变更。上线不更改生产网段、IP、套餐或中继；新写非标准
网段后旧版不能编辑该网段，回退前需评估，不能恢复旧快照覆盖运行中的新数据。
