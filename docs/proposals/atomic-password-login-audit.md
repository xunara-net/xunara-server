# Proposal：密码登录会话与成功审计原子提交

日期：2026-10-11。范围只覆盖本地密码登录，不扩展 OIDC、Passkey 或完整登录记录。

## 问题与数据流

JSON 与兼容 HTML 已共用 signInWithPassword；慢哈希校验后，CreateLocalSession
在租户身份事务中复核密码并创建会话，但登录成功和会话创建审计在事务外调用。
审计失败时仍能签发 Cookie；触发器忽略会话插入时也可能返回未持久化的凭据。

## 方案

1. 保持 AccountStore 方法和 HTTP 契约不变；CreateLocalSession 在已有事务内
   提交会话、login.succeeded 和 session.created 两项必需审计。
2. 使用既有 insertIdentityAudit，审计 SQL 错误或零行写入都回滚；共用
   createSession 也校验恰好插入一行，不把 SQL 无错误当作持久化成功。
3. 删除控制层重复的成功审计。失败登录的既有尽力审计及限流预算不变。
4. 成功日志仅记录 user ID、provider 和 session ID，不存登录名、密码、
   密码 hash、token 或 token hash。提交失败返回空 Session/token，不改旧 Cookie。

## 边界与兼容

不修改表结构、已发布迁移、官方协议、地址、套餐或 Headscale 依赖。
底层 CreateSession 是通用会话存储操作，不冒充完成密码认证；测试预置会话
使用它，真实密码登录回归仍使用 CreateLocalSession。此变化为后者新增必需
成功审计，存储故障会导致 503 而不是半成功。

成功 OIDC/Passkey 的整体事务、失败日志可靠投递、IP/User-Agent 登录记录、
账户恢复和 2FA 是独立后续任务，不能把两项事件称为完整登录历史产品。

## 验收与上线

真实 SQLite 注入两项审计各自的 ABORT/IGNORE、会话 IGNORE，检查零新会话/
成功事件与恢复；验证两个 HTTP 入口均保留旧 Cookie、503 且不泄露错误详情。
跨连接并发登录检查每个成功会话恰好两项审计，继续覆盖改密竞争和取消。
执行完整 Go build/vet/test/race、既有手机浏览器与官方客户端回归。

部署包含累计 DNS state v24：先逐租户只读名称检查，再维护停写一致性备份，
验证当前数据、配置和中继未变后恢复业务；不恢复旧快照覆盖新写入。

参考：[SQLite 事务](https://www.sqlite.org/lang_transaction.html)、
[database/sql Tx](https://pkg.go.dev/database/sql#Tx)。
