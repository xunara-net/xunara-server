# ADR-0001：采用 GitHub Organization 多仓库治理

- 状态：Accepted
- 日期：2026-10-09

## 背景

项目此前是单一仓库（`xunara-net/xunara`），同时包含控制面、产品 API、内嵌
Web 控制台、DERP 中继、部署脚本与文档。需求（长期规范与 GitHub 补充规范）
要求服务端、Web、Admin、Relay、Deploy、Docs 按产品边界拆分，并保持依赖方向
单向：`web/admin/client → server`、`relay → server`。

## 决策

在 `github.com/xunara-net` 组织下建立职责明确的仓库：

```text
xunara-server   xunara-web   xunara-admin
xunara-relay    xunara-deploy   xunara-docs
```

依赖方向固定为：

```text
xunara-sdk（未来） → xunara-server
xunara-web / xunara-admin / xunara-client → Xunara Core API
xunara-relay → 注册与配置来自 xunara-server，数据面独立
```

禁止循环依赖；前端不得直接访问控制面内部状态或 Headscale 数据库。

## 影响

- 兼容性：协议与数据格式不变，官方客户端无感知。
- 安全：Secret 只存在于各仓库自身的配置机制中，前端不再持有任何管理凭据。
- 迁移：旧仓库保留历史，README 指向新仓库；`xunara-server` 由原仓库历史
  延续（模块路径改为 `github.com/xunara-net/xunara-server`）。
