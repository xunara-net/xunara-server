# 本人账户安全资料导出

决策见 [ADR-0033](adr/ADR-0033-account-security-export.md)，任务见
[Server #16](https://github.com/xunara-net/xunara-server/issues/16)。仅导出当前租户
本人的安全资料，不是数据库、凭据或全部网络备份，不代表完整个人数据导出已完成。

## 使用与接口

用户控制台「个人设置」的「个人数据导出」默认折叠。选择格式、可选登录记录
日期范围，确认私人文件的保管责任后下载；未保存的页面草稿不包含在内。

`POST /api/v1/account/export` 只接受本租户有效 Human Session 与对应
`X-CSRF-Token`，Cookie / 人类 Bearer 均可；Free / 普通成员没有附加套餐限制。
平台令牌、Service API Key、MachineKey 或匿名不能代为导出。必须使用
`application/json` 请求体，不接受 query、目标用户、租户、路径或下载 URL。

请求字段：

- `format`：`json` 或 `csv`，必须提供。
- `from`、`until`：可选 RFC3339 时间（含时区），按登录记录创建时间采用
  半开区间 `[from, until)`。非空区间必须递增，时间应能无溢出地表示为正 Unix
  纳秒。控制台按浏览器时区转换日期，并将结束当天完整包含在区间内。

JSON 的 schema_version 为 1、scope 为 account-security：本人已保存的资料、
联系邮箱未验证事实、本地密码是否存在、第三方绑定展示属性、通行密钥名称 /
创建 / 使用时间、活动会话及成功登录记录。没有密码、哈希、token、CSRF、外部
subject / token、Passkey credential / public key、配置 secret 或管理员禁用原因。
本地密码存在不意味着当前部署允许密码登录，第三方属性不意味着其应用仍启用。

时间筛选仅作用于登录历史；资料、绑定、通行密钥及活动会话仍是同一次身份事务
的快照。所有记录类型保留，legacy 不猜来源，rotation 不冒充一次新认证。
状态以准备快照时刻为准，最近活动不是实时在线证明。

CSV scope 为 login-history，只包含成功记录的公共标识、登录方式 / 类型、创建 /
有效期 / 最近活动、状态 / 撤销及首次 IP / UA。时间列使用 UTC，中文表头和
UTF-8 BOM；不含其他人、设备、路由、ACL 或 DNS。CSV 为人查看，危险公式 /
控制前导文本加可见「文本：」前缀，分隔符 / 引号用标准编码器处理。原文本
请使用 JSON；不保证任意表格软件、再保存或用户删掉前缀后的安全。

## 限额、完整性与错误

- 每个集合最多 5000 条，读取期间累计文本最多 8 MiB，最终文件最多 8 MiB。
  超限返回 413，整份拒绝，不返回截断文件；缩小历史日期范围后重试，其他
  集合仍超限时联系管理员。分页首屏不是全部记录，空历史区间也不隐藏资料。
- 每用户 15 分钟最多 5 次准入，每 IP 最多 20 次；429 附 Retry-After。取消、
  准备故障或超限请求也可能消耗准入次数，不保证取消可以退回配额。
- 事务复核发起会话 / 启用用户，使用同一连接读所有白名单数据；获取锁后再次
  检查有效期。成功准备与必需审计一起提交，失败或忽略写入不返回任何快照。
  共用 SQLite 限流写入同样检查确实影响一行，忽略消耗不能绕过准入。
- `account.export_prepared` 表示快照准备成功，只记范围与数量，不记私人内容；
  它不表示浏览器已保存。编码超限、客户端取消或网络错误仍可能已有准备审计。
- 完整编码之后才发 attachment / Content-Length / no-store / nosniff / sandbox；
  没有公开导出 URL、服务端缓存文件或异步下载任务。读取或审计故障返回 503，
  不伪装成空数据，不清除尚有效 Cookie。
- 前端请求和响应读取均有超时，检查实际解压后大小、文件类型 / 固定生成名及
  JSON 白名单 / 本人标识。失败、取消、响应异常或离页不发下载，不自动重试；
  Blob URL 及时撤销，不在浏览器持久存储中保存私人文件或内容。

## 验证与兼容

执行目录 `xunara-server`，Go 版本以 go.mod 为准：

```sh
go build ./... && go vet ./... && go test ./... -count=1 -timeout=15m
go test -race ./... -count=1 -timeout=20m
go test ./identity ./control ./state -run 'AccountExport|LoginHistory|Rate' -count=1
```

前端命令在 `xunara-web` 执行（Node 版本以仓库说明为准）：

```sh
npm ci
npm test
npm run build
```

真实下载 / 手机 / 故障 / 取消及现有认证回归共享
[Web 浏览器切片](https://github.com/xunara-net/xunara-web/blob/main/scripts/account-export-browser-smoke.cjs)，
运行入口与前置条件以
[Admin 集成验收](https://github.com/xunara-net/xunara-admin#浏览器集成验收)为准。
测试规模种子不是相同数量的真实认证，原站检查不得导出真实用户私人资料。

真实已发布身份 v18 的隔离升级 / 同 schema 旧产物读取 / 成套恢复：需 Node 22
内置 SQLite，两个环境路径分别指向已发布和当前二进制，脚本仅创建临时状态。
在 `xunara-server` 执行，不把状态目录改到实际部署位置：

```sh
SMOKE_PREVIOUS_IDENTITY=18 SMOKE_PREVIOUS_XUNARAD=/path/to/released-v18/xunarad \
SMOKE_XUNARAD=/path/to/current/xunarad node scripts/login-history-upgrade-smoke.cjs
```

无新迁移：identity v18 / state v24 / plans v4 保持，不修改官方 Tailscale wire、
Headscale、套餐、机器 / 服务信任或会话有效期。先发布支持新接口的服务端，再
升级 Web；新 Web 遇到旧服务端 404 明示升级，不生成虚假文件。维护升级仍需
停止写入、成套私有备份和 CI 全绿；公开受理业务后不以旧快照覆盖新数据。

本功能不改变历史保留 / 删除规则，用户保存的文件与运营者备份仍含私人数据。
设备 / 网络 / 策略 / DNS / 路由导出、完整注销、失败登录、自动保留、邮件、2FA
和支付仍需独立开发，不将这个账户安全切片宣称为所有个人 / 网络数据导出完成。

参考：[Go 事务](https://go.dev/doc/database/execute-transactions)、
[标准 CSV](https://pkg.go.dev/encoding/csv)、
[OWASP CSV Injection](https://community.owasp.org/attacks/CSV_Injection)。
