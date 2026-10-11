# 本人登录记录与会话活动

决策见 [ADR-0032](adr/ADR-0032-account-login-history.md)。这是成功认证与会话生命周期
记录，不是失败登录、组网设备在线记录、地理定位或完整 MFA。

## API 与权限

- `GET /api/v1/account/login-history?limit=20&cursor=<公共游标>`：只接受本租户
  当前 Human Session，本人记录，不接受 `user_id`。服务 API Key、平台令牌或
  MachineKey 不能读取；普通成员和 Free 不受额外套餐限制。
- `limit` 默认 20，范围 1–100；`cursor` 来自上页的 `next_cursor`，末页为空。
  按不可变的创建时间 / 公共 ID 降序分页，新记录不会挤动旧页。重复 / 未知参数、
  非法编码 / 游标或大小返回 400。写操作仍沿用原会话撤销接口和 CSRF。
- 结果为 `records`、`next_cursor`、`current_session_id` 与 `generated_at`。
  记录含公共 `id`、`auth_method`、`kind`（login / rotation / legacy）、
  `created_at`、`expires_at`、`status`（active / revoked / expired），以及
  已记录时的 `last_seen_at`、`client_ip`、`user_agent`、`revoked_at`、`revoked_reason`。
  公共 ID / 游标不是凭据，响应不含 token、token hash、密码或外部身份 subject。
- 既有 `GET /api/v1/account/sessions` 保留契约并补可选来源 / 最近活动；旧前端
  可以忽略新字段。数据响应 `no-store`，列表故障返回明确错误，不返回假空列表。
  临时认证 / 活动写故障返回 503 并保留 Cookie，不当作退出登录。

## 数据与真实性

Identity v18 只追加 Session 来源列和独立记录表 / 触发器。迁移只复制仍有所属
用户的现存 Session 事实，标记为 legacy；过去已清理的记录无法恢复，来源未知。
所有新会话入口显式采集 HTTP 来源，AFTER 写入检查记录确实影响一行；故障或
忽略写入会回滚当前事务，不能返回缺少记录的新凭据。

撤销、改密、平台重置、禁用、解绑与轮换在原事务同步记录；轮换继承首次来源，
不是新的成功认证。过期 Session 清理不删除记录；账号删除在事务中明确删除
Session 和记录，连接未开启外键也不能留下这两类私人数据，忽略删除会回滚。
记录目前随账号保留，**没有自动限期清理 / 导出策略**，运营者应将此纳入隐私和
备份保留管理，不能把“分页 20 条”当成存储仅 20 条。

IP 只使用连接地址或现有显式受信代理规则认可的最后一跳；不默认接受转发头。
UA 去除控制 / 格式字符，按 UTF-8 边界限为 512 字节；它可被客户端自报 / 伪造，
仅作为显示线索，不授予设备信任或权限。未调用地理查询，也不能由 IP 猜城市。

Cookie、人类 Bearer 和 gRPC 共用 context 验证 / 使用路径；数据库条件保障活动
单调与每分钟至多一次持久更新，重启 / 多连接不依赖本机 map。不滑动延长过期，
不保证实时在线；匿名、机器和服务 Key 不写人类 Session 活动。

## 验证与升级

执行目录：`xunara-server`；Go 版本以 `go.mod` 为准。

```sh
go build ./... && go vet ./... && go test ./... -count=1
go test -race ./... -count=1 -timeout=20m
```

真实旧产物升级 / 成套回退：需 Node 22（内置 SQLite），`SMOKE_PREVIOUS_XUNARAD`
指向已发布 identity v17 产物，`SMOKE_XUNARAD` 指向本版。两个路径都是程序路径，
不是凭据；脚本只创建随机的临时隔离状态，不能改为指向部署目录。

```sh
SMOKE_PREVIOUS_XUNARAD=/path/to/released-v17/xunarad \
SMOKE_XUNARAD=/path/to/current/xunarad node scripts/login-history-upgrade-smoke.cjs
```

浏览器回归入口在
[Admin HTTPS 夹具](https://github.com/xunara-net/xunara-admin/blob/main/scripts/authentication-browser-smoke.cjs)
和[跨模块夹具](https://github.com/xunara-net/xunara-admin/blob/main/scripts/browser-smoke.cjs)，
共享 [Web 登录记录测试](https://github.com/xunara-net/xunara-web/blob/main/scripts/login-history-browser-smoke.cjs)。
密码 / 第三方 / Passkey / 注册 / 初始化的来源及隔离、生命周期、故障和忽略回滚
以 identity / control 专项测试为准；浏览器分页样本明确为隔离数据库测试种子，
不能用样本数声称完成了同等数量的真实认证。

上线前停止全部旧控制面、成套备份状态 / 密封密钥 / 配置 / 产物，CI 全绿后更新。
新 schema 不与旧实例滚动混用；回退完整旧状态与旧产物，恢复公开写入后不允许
直接覆盖旧快照。原账号 / token / 过期时间 / 设备 / 网络 / 套餐保持；state / plans
未追加迁移，官方 Tailscale 协议不变。
