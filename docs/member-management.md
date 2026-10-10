# 成员修改与权限安全

## 当前交付

Owner 可以在用户中心「成员与权限」修改现有 owner/admin/member；admin 和 member
不能管理他人或提升自己。Viewer、Network Admin 和设备 Resource Scope 仍待实现，
不通过添加下拉选项伪造后端能力。管理角色不替代 ACL，也不会自动让机器受信任。

新 Web 对角色变更先确认，发送列表中的原始版本。其他管理员修改后返回冲突，保留
已确认前的显示状态并暂停写入；必须手动刷新列表、重新选择和确认，不自动覆盖或
重试。读取失败不是零成员；缺少版本的旧服务端仍能显示列表，但不能使用新版角色
编辑器。自己降权后重新加载会话，移除成员管理控件。

## 数据流与实现入口

JSON 与兼容 HTML 共享 [成员写入入口](../control/member_updates.go)及
[Identity 事务](../identity/sqlite_member.go)，使用明确字段补丁，不拿完整旧 User
覆盖未提交字段。事务重新验证会话或服务 API key 的归属/期限/撤销/写范围和当前
owner；读取目标事实、比较版本、检查最后 owner，再同时提交更新与必需审计。
无变更请求也重新验证发起身份，但不产生假的变更审计。写入零行或审计插入零行
同样失败，不把“没有 SQL 错误”当作成功。

[管理响应](../control/api_handlers.go)新增 `updatedAt`，PATCH 可提交
`expectedUpdatedAt`，保留完整纳秒精度；旧调用未提供版本仍使用事务授权和 owner
保护，但不具备客户端 CAS 保证。资料更新和角色更新共享目标版本；不要用浏览器
Date 转为毫秒或自动换用新版本重放旧决定。

[CLI](../cmd/xunara/user.go)在可信状态目录上使用独立操作者入口，共用字段补丁、
owner 不变量和事务审计。HTTP 不能选择这个入口。旧内部 UpdateUser 保留为同一
实现的薄适配，已有时间戳时检查完整快照版本，第三方旧资料同步不能恢复旧角色。
创建时间不作为可编辑资料。低层删除在其事务内复用最后 owner 检查，不能与另一
连接降权组合移除全部 owner；正常删除/降权不能用外部 SQL 绕过。

业务错误使用 `MEMBER_CHANGED`、`LAST_OWNER`、`MEMBER_WRITE_FORBIDDEN` 等稳定前缀；
目标读取或必需审计故障返回 503，不解释成 404 或空列表，错误正文不返回底层原因。
同一账号的服务 key 只收窄权限，不能放大当前人类角色。邮件属性不用于身份合并。

## 数据库、升级与边界

本切片无新增表或迁移，state v24、identity v13、plans v4 保持；管理 API 字段仅
追加，官方 wire、节点身份、ACL、套餐与地址分配规则不变。Go Store 接口增加方法，
外部自定义持久实现需要同步实现接口。不影响 Headscale，也不引入 Headscale 表依赖。

**没有因此自动升级调试站。** 若从仍使用 state v23 的旧产物升级到本提交，仍必须
完成前一 DNS 切片的[逐租户只读预检与维护备份](dns-name-ownership.md)，不能因为
本切片无迁移就跳过累积升级流程。状态已经迁移或恢复业务写入后，不可用旧快照
覆盖后续数据；不要把低层 owner 保护称为完整账户注销或安全恢复。

尚未完成：Viewer/Network Admin/Resource Scope、所有其他写入口的事务门禁、平台
删除/撤销的整体原子审计、删除后的跨库资源与账户生命周期、第三方首次建号事务、
多实例实时下发、2FA、邮箱验证/找回及订阅支付。详见
[ADR-0025](adr/ADR-0025-atomic-member-updates.md)和
[Proposal](proposals/atomic-member-updates.md)。

## 隔离验证

前置条件：服务端声明的 Go 版本；在 `xunara-server` 执行。测试使用临时数据库，
两个独立连接，不访问调试站。文件权限故障测试需要正常 `umask 022`；测试状态目录
仍为私有临时目录，不用于生产凭据配置。

```sh
umask 022
go build ./...
go vet ./...
go test ./... -count=1
go test -race ./... -count=1 -timeout=20m
```

新测试覆盖版本 ABA、旧完整快照、会话/服务 key 撤销/过期/异主/降权、租户边界、
重复/无变更、字段保留、读故障、SQL 失败/忽略、审计回滚、跨连接 CAS，以及四种
owner 移除竞争。浏览器入口与前置条件以
[组合脚本](https://github.com/xunara-net/xunara-admin/blob/main/scripts/browser-smoke.cjs)
为准；新增真实角色发布、过期确认、手机刷新、所有权交接和缺版本禁写，不用展示
夹具的成功响应冒充真实授权结果。官方客户端回归入口见前述 DNS 验收文档。
