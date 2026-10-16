# 浏览器旧实现清理清单（2026-10-16）

## 范围与权威实现

本次按“路由 → 处理器 → 身份/授权存储 → 调用方 → 测试 → 部署”核查运行仓库，
对全部 Go 源码扫描内嵌 HTML / 脚本 / 旧模板标记，并核对 Web/admin 路由与 nginx
转发。不是声称审计过每个核心协议算法；未借界面清理修改协议、机器归属或既有数据。
工作目录根部的旧单仓 README 已明确“停止开发、仅留历史”；它不参与新仓构建或部署，
历史归档、Git 历史和原始输入不擅自删除。

| 原实现 | 处理 |
| --- | --- |
| `control/public.go` | 删除首页、登录、注册、初始化模板与旧页脚 |
| `control/pages.go` | 删除设备/SSH 表单、结果和错误模板 |
| `control/admin_pages.go` | 删除内嵌后台模板、样式、表单 |
| `control/admin.go` | 只留平台业务共用辅助与旧路由拒绝，不留表单处理 |
| `control/admin_sessions.go` | 删除旧内嵌后台专用会话实现；现行平台认证独立保留 |
| `control/passkey_browser.go` | 删除内嵌 WebAuthn 脚本；只用独立前端认证器逻辑 |
| `page_style.go`、`page_i18n*.go`、`public_i18n_zh.go` | 删除旧 CSS、HTML 翻译和显示辅助 |
| `login.go`、`signup.go`、`setup.go` | 删除 HTML 适配；保留并复用持久身份、限流和原子提交 |
| `register.go`、`sshcheck.go` | 保留官方客户端协议与授权事务，删除 HTML 表单适配 |
| `native_browser.go` | JSON 账户选择；共享入口管理员 Cookie 不代替目标账户验证 |
| nginx 根/租户授权转发 | 改为独立 SPA；浏览器 JSON API 仍代理 Core |
| nginx 旧 POST 与后台表单 | 410，不能靠有效 Cookie 恢复旧逻辑 |
| 旧 HTML 测试/浏览器夹具 | 删除纯模板快照；安全断言迁移真实 JSON API，不伪造重定向 |

## 不应误删的边界

- 客户端给出的 `/register/{id}`、`/device/{flowID}`、`/ssh/check/{id}`
  是浏览器协议入口；保留 URL，只更换渲染者。
- `/api/v1`、`/api/v2`、gRPC、OAuth/OIDC 回调、TS2021、Noise、
  DERP 和 SSH 长轮询不是旧前端。
- 既有 v1 API 的兼容适配不是 HTML 模板；本次不擅自破坏已发布 API。
- 本地登录/注册的媒体类型是安全例外：现在严格要求 JSON；已构造真实普通表单
  JSON 正文，先复现旧入口签发 Cookie，再验证 415、无 Cookie、无新会话。
- Rust 客户端的兼容夹具仍使用 `Server.SetAddressPrefix`，已核对跨仓调用并保留，
  不能因其在服务端主程序内暂未调用就当作旧 UI 删除。
- 已发布迁移中的旧表结构不改写、不 DROP；旧 HTML 管理 Cookie 不迁移成现行平台身份。
- `form.key` 仍签名匿名 JSON 请求的 CSRF 证明，不是保留旧表单。
- 外部 OIDC/OAuth2 测试提供方的授权页面是隔离测试夹具，不作为产品页面发布。
- 旧发布版升级测试为读取真实历史数据保留旧请求，是兼容性测试，不是运行入口。
- `/console/*` 与 `/ui/prefs` 仅固定目标书签迁移；无任意 query 转发或页面兜底。

## 防回归

`TestCoreHasNoEmbeddedBrowserFrontend` 阻止控制面重新出现旧模板/样式/脚本。
服务端覆盖旧 POST 零副作用、Human/Service 隔离、CSRF、持久审批、不可变重放、
初始化并发/回滚/故障恢复。Web 严格校验 JSON，读取失败不启用确认按钮，
写入结果未知必须显式刷新，不自动重试。

隔离浏览器直接连接真实 daemon，验证两租户共享设备登录、设备和 SSH 审批、
初始化及移动端布局；只读展示和未知结果场景使用明确的局部响应故障夹具。
官方客户端与 Noise 测试另行验证真实协议，不能用 UI 夹具替代协议集成。
发布前运行 nginx 的真实 TLS/Host/方法/路由测试；生产仅做未登录和只读验收，
不借上线测试批准、移动或删除用户设备。
