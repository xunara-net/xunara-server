# Proposal：成员修改与所有者不变量的原子保护

日期：2026-10-11。范围：现有 owner/admin/member，不新增角色或改变客户端协议。

## 问题与数据流

现有 JSON、兼容 HTML 和本地 CLI 先读取完整 User，再独立检查其他 owner，最后
UpdateUser 并在提交后追加审计。两个实例同时降权可以各自看到另一 owner；旧页面
或第三方属性同步的完整快照还能覆盖更新后的角色。平台删除也在事务外检查 owner。

## 方案

1. Identity 提供字段补丁式成员更新。JSON/HTML 共用同一事务，重新验证持久会话
   或服务 API key 的归属、期限、撤销与 write 范围，再检查当前 owner 权限。
2. 同事务读取目标最新事实、检查可选 expectedUpdatedAt、保护最后 owner，并提交
   变更及必需审计。审计失败不能留下新角色；不变更时也重新检查发起凭据。
3. 用户列表返回 updatedAt。Web 与兼容表单发送原始版本，冲突要求刷新、重新确认，
   不自动覆盖、重试或假装成功。旧 API 未发送版本仍可用，但不提供页面 CAS 保证。
4. 本地 CLI 通过独立的可信磁盘操作者入口复用补丁、owner 保护与原子审计；HTTP
   不能选择这个入口。旧完整 User 更新保留为薄适配，已有时间戳作为版本条件。
5. 旧低层删除也在数据库事务内保护最后 owner，消除与降权之间的检查/删除竞争。
   不把这个修复描述为完整账户注销、跨库资源清理或平台审计已全部原子化。

## 兼容、安全与边界

不修改表结构或已发布迁移；state v24、identity v13、plans v4 保持。管理 API 新增
updatedAt 响应及可选 expectedUpdatedAt 请求；官方 wire、节点注册/审批、ACL、套餐
和设备地址不变。人类会话与服务身份分开验证；API key 不能放大其 owner 的权限。
未知角色不获得写权限，存储错误不解释成账户消失或名称空闲，凭据不进入日志。

Viewer、Network Admin、Member 设备 Resource Scope、平台操作者人身份、删除后的
全资源生命周期、注册/登录整体审计与多实例实时下发仍需后续切片，不添加伪入口。

## 验收计划

覆盖跨 SQLite 连接并发降权/删除、过期页面、撤销/过期/异主会话与服务 key、角色
降权后旧凭据、审计/查询/写入故障回滚、无变化请求和部分字段保留。执行完整 Go
build/vet/test/race、Web 单测与构建、真实 API 手机浏览器及官方客户端兼容回归。

参考：规格 §32 的 RBAC/Resource Scope；
[Tailscale 管理角色](https://tailscale.com/docs/reference/user-roles)区分管理权限与网络
ACL。Xunara 继续使用自己的多 owner 产品规则，不复制上游单 owner 或角色授权语义。
