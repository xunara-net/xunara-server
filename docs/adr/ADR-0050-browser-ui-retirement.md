# ADR-0050：所有浏览器页面迁出 Core，彻底删除旧前端

- 日期：2026-10-16
- 状态：已接受，取代 ADR-0003、ADR-0049 关于保留独立 HTML 页面的决定

## What changed

删除 Core 内全部 Go HTML 模板、内嵌平台后台、浏览器登录/注册/初始化表单、
设备与 SSH 批准表单、WebAuthn 浏览器脚本、旧页脚、CSS、HTML 翻译和服务端时间格式化。
移除只供这些页面使用的处理器和辅助函数，不保留一套“精简备用界面”。
旧内嵌后台专属的 PlanRegistry 会话实现也删除；已发布迁移和历史表不改写，
现行平台管理员身份、通行密钥与持久会话仍由独立平台认证模块负责。

独立 Web 新增初始化、设备批准、SSH 批准、共享设备账户登录和认证错误页面。
pending、批准、拒绝、过期、未知、未登录、只读和读取故障均由同一前端展示。
旧 `/console/*` 只保留固定书签迁移，不是备用 UI；`/ui/prefs` 只跳转新版设置。
`-console-timezone` 仅为现有部署保留参数兼容，显示时间由浏览器格式化。

新增人类浏览器 JSON 面：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET / POST | `/api/v1/auth/setup` | 读取初始化状态 / 提交一次性服务端证明 |
| GET | `/api/v1/browser/device-authorizations/{id}` | 当前租户持久设备授权详情，不返回机器密钥 |
| POST | 上述路径加 `/approve` 或 `/deny` | 复用既有设备审批事务 |
| GET | `/api/v1/browser/ssh-checks/{id}` | 持久 SSH 检查详情 |
| POST | 上述路径加 `/approve` 或 `/deny` | 明确确认单次 SSH 检查 |
| GET | `/api/v1/browser/device-flows/{flowID}` | 共享入口账户选择状态，只在受信入口 Host 开放 |
| POST | 上述路径加 `/login` | 验证账户后绑定精确机器/节点对，仍需单独审批 |

仅 GET 初始化状态可下发 CSRF 证明，不下发一次性初始化令牌。所有新写面使用
JSON 正文与 `X-CSRF-Token`，不从 query 读取凭据。设备/SSH 浏览器 API
只接受 Human Session，拒绝 Service API Key；原有已发布 v1/v2 服务 API 不变。
设备/SSH 详情读取区分持久记录不存在与存储失败，失败关闭而非伪装成空数据。

## Why

线上 `Xunara 87f70d5` 来自当前二进制的独立授权模板，不是缓存，也不是上次
已删除的 `/console`。仅清除完整控制台仍会在客户端授权、错误页和后台露出旧界面，
并留下两份表单与安全处理器。UI 必须只有独立 Web/admin 一份权威实现。

## Compatibility impact

官方客户端的 `AuthURL`、`/register/{id}`、`/device/{flowID}`、
`/ssh/check/{id}` 浏览器 URL 保持不变，由 nginx 向新 Web 返回 SPA；
租户 API、Cookie 和 OAuth/OIDC 回调继续隔离。TS2021、Noise、RegisterResponse、
Map、DNS、DERP、SSH hold/poll 等协议字段与状态机均不修改。
审批不是登录，也不等于设备在线或 SSH 连接已建立。

旧 `POST /login|setup|signup|logout`、根路径 passkey 别名、设备/SSH 表单以及
内嵌后台表单明确 410，不能兼容执行。Core 直连页面路径明确
`503 WEB_UI_REQUIRED`；浏览器必须使用同源 Web 入口。受信反代的 HTTPS
配置需同步更新，不能仅替换 Web 文件；HTTP 凭据与批准请求仍不能明文升级。

无数据库迁移，不删除或移动用户、设备、授权、套餐或中继。回滚恢复应用文件与
nginx 配置，不恢复或覆盖正在使用的状态库。升级可短暂进入维护窗口，必须配套发布
server、Web 与路由，避免旧浏览器表单继续提交。

## Security impact

- 旧表单不解析正文、不签发/清除 Cookie、不修改账户、授权或审计。
- 共享设备入口不会采用浏览器已有的入口管理员会话；仍需独立验证目标账户。
- 页面详情不返回 MachineKey/NodeKey，不把登录成功当作机器可信。
- 回调错误只带固定原因码跳转新错误页，不传播授权码、令牌或提供方原始错误。
- 写入结果未知时，前端关闭重复提交，要求重新读取持久状态，不自动重试批准。
- API 错误保留 401/403/404/409/410/503，不能误报登录失效或审批成功。
- 本地登录和注册要求严格 `application/json`，拒绝普通跨站表单可构造的
  `text/plain` JSON、URL 编码和 multipart 正文；只依赖 CORS 不足以保护匿名登录。

## Tests

Core 无模板源码保护、旧表单零副作用、初始化并发/回滚/限流、设备与 SSH 的
Human/Service 边界、CSRF、不可变重放和存储故障测试；原有官方客户端
Noise/注册/Map/SSH 与分享集成继续运行。浏览器隔离夹具验证真实初始化、
两租户共享设备账户登录与审批、拒绝/过期/未知/错误结果和 320–1440px 布局。
真实 nginx 验证 SPA 与 JSON 分流、旧表单不转发、TLS 和明文失败关闭。
