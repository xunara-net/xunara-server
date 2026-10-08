# ADR-0003：服务端与 Web UI 分离

- 状态：Accepted（迁移中）
- 日期：2026-10-09

## 背景

旧版把用户控制台与平台后台以服务端渲染页面内嵌在 `control/` 中。多仓库规范
要求 UI 属于 `xunara-web` / `xunara-admin`，服务端只提供 API。

## 决策

1. 新增 JSON 认证面 `/api/v1/auth/*`（session / providers / login / signup /
   logout），与 HTML 登录共享同一份会话存储、限流桶与审计；
2. 新增 `/api/v1/capabilities`、`/api/v1/plan`，前端据此渲染能力与升级提示；
3. 产品前端使用既有 `/api/v2/*` 读取设备、DNS、DERP、策略、审计、共享等数据；
4. 服务端**保留**设备授权流程必需的浏览器页面（`/login`、`/signup`、`/setup`、
   `/register/{authID}`、`/ssh/check/*`），因为 Tailscale 客户端会把用户直接
   带到这些 URL；
5. 旧控制台页面（`/console/*`）在 xunara-web 达到功能对等前保留在同一二进制
   中，标记为过渡实现；对等后删除，删除时同步发布迁移说明。

## 影响

- 前端不再需要服务端模板，可独立发布（Vite 构建产物由部署层或服务端静态
  托管）。
- 会话仍由服务端持有，前端不接触任何管理凭据。
