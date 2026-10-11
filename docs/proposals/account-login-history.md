# Proposal：独立登录记录与最近活动

- 日期：2026-10-11
- 状态：Accepted，实施与验证中
- 范围：Server → Web → Docs / Deploy

## 问题

安全中心目前仅将过期 / 已撤销 Session 当作历史，清理后即丢失；最后活动字段
没有生产写入，页面也没有来源 IP 或浏览器信息。不能把这些缺失包装成完整登录记录。

## 决策与边界

1. 追加 identity v18：Session 保存首次来源 IP / 有界 User-Agent；另建不含
   token / token hash 的成功登录记录。原 Session 事实回填为“旧记录”，来源未知，
   不追溯伪造浏览器或地点。轮换是单独类型，继承来源，不算一次新认证。
2. 所有人类会话创建共用已有身份事务：密码、注册 / 邀请、owner 认领、第三方、
   Passkey 均显式传入来源值。绑定不建会话、不产生成功登录；不改机器 / 服务身份。
   来源取现有受信代理规则，规范化 IP；UA 去控制字符并按 UTF-8 边界限长，属于
   客户端自报信息，不能作为身份、设备信任、地理定位或授权依据。
3. SQLite AFTER INSERT / UPDATE 触发器在同一写事务记录 / 同步会话事实；
   检查必要写入确实影响一行，故障或 RAISE(IGNORE) 不能签发遗漏历史的凭据，
   也不能让撤销与记录不同步。记录与 Session 清理解耦，删除用户时原子删除记录，
   包括未启用外键的连接。保留策略目前与账号生命周期绑定，不宣称自动限期清理。
4. Cookie、Bearer 人类会话和 gRPC 共用带 context 的使用方法；最近活动只记录
   已验证的有效会话，持久单调、每分钟至多更新一次，不滑动延长有效期，不使用
   本机 map 限流。读取 / 活动写入故障失败关闭并保留 Cookie，匿名和 API Key 不写人类记录。
5. 只读分页接口仅当前人类 Session 可访问本人记录；按不可变时间 / 公共 ID
   keyset 分页，默认 20、最多 100，所有查询强制 user 与租户边界。ID / cursor
   不是凭据；不提供可选 user_id 扩权。错误独立展示，不变成空历史。
6. Web 安全中心将浏览器 / 系统、来源 IP、登录和最近活动展示为手机卡片；
   替换误导性的过期会话历史，增加独立记录分页、刷新、轮换 / 旧记录说明。
   不调用外部地理定位，不声称失败登录历史、完整 2FA、多实例部署验收或所有功能完成。

## 验证与升级

测试追加迁移、原会话凭据 / 时间保持、故障 / 忽略写入回滚、所有撤销途径同步、
轮换、GC 后历史、删用户、重启 / 两连接、单调节流、context 取消、代理伪造、
租户 / 用户 / Service 隔离、分页与畸形响应、手机布局及真实隔离 HTTPS。
全量 Go build / vet / test / race，前端类型 / 单测 / 构建，CI 全绿后才发布。
升级需停止全部旧控制面、成套私有备份 / 恢复；不混版本滚动运行。
公网验证只用匿名 / 授权平台只读操作，不登录或改动原用户。

## 依据

- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)：
  生命周期记录与凭据分离，来源属性不能替代认证。
- [OWASP Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)：
  将客户端数据视为不可信，限制敏感信息并防止控制字符注入。
- [SQLite trigger](https://www.sqlite.org/lang_createtrigger.html) 与
  [changes()](https://www.sqlite.org/c3ref/changes.html)：AFTER 写入与事务失败语义，
  触发器内检查本次必要写入，不能假设外层 RowsAffected 包含嵌套操作。
