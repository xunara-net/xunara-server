# Proposal：原生 OAuth 2.0 人类登录适配器

日期：2026-10-11。范围：GitHub、GitLab、Gitea 与可配置的标准 OAuth2 提供方。

## 问题与数据流

已有 `IdentityProvider`、持久 `AuthTransaction`、账户绑定和邀请完成事务，但部署入口只能直接配置 OIDC。不能把没有 ID Token 的 OAuth2 提供方伪装成 OIDC，也不能另建用户、会话或设备授权缓存。

采用 `授权码 + S256 PKCE → 服务端 POST 换令牌 → 固定当前用户接口（Bearer header）→ (provider_id, immutable subject) → 现有原子完成事务`。OAuth2 适配器只认证外部人类账户；角色、套餐、邀请、租户和设备审批由现有业务层决定。OIDC 继续执行 nonce、签名、issuer、audience、时间与 JWKS 校验；这些不是无 ID Token 的 OAuth2 声称拥有的能力。

## 设计

- 新增静态 OAuth2 配置列表；单租户通过非秘密 JSON 文件，组织配置按租户分别提供列表。秘密只引用环境变量或权限受限的密钥文件，不出现在命令行、URL 或日志。
- GitHub 使用固定官方端点；GitLab/Gitea 支持管理员明确指定的自建实例。通用提供方必须显式配置授权、令牌、当前用户端点和不可变 subject 字段，且支持 S256。已配置端点只允许 HTTPS 或本地回环 HTTP，无 userinfo、query、fragment；不接受来自浏览器的端点或回调。
- 不支持 implicit/password grant、关闭 PKCE、令牌 query、任意 profile claims→角色映射、邮箱匹配、外部 access/refresh token 持久化。固定客户端认证方式，不自动尝试第二次交换；所有后端 HTTP 有 context、timeout、响应大小限制，不跟随重定向。
- 普通 OAuth2 的 email 未经 OIDC 验证，也不能隐式生成 ACL 使用的本地 login name。新账户采用 provider ID 与不可变 subject 摘要形成独立本地名称；已绑定用户的名称和旧 OIDC 路径不改，不泄漏 raw subject。
- OAuth2 回调固定为本租户 `/oauth2/callback/<provider-id>`；旧 `/oidc/callback/` 保持兼容。拒绝重复/保留 provider ID，防止配置覆盖导致身份混淆。
- API 能力正确区分 `auth.oauth2` 与 `auth.oidc`，页面复用通用第三方按钮。未配置应用不得显示虚假的可用入口。
- 不改数据库 schema、迁移、套餐默认值及官方客户端协议。既有 OIDC、密码、passkey、网络与设备继续回归。

## 验收与交付顺序

先服务端适配器/配置/HTTP 安全测试，再用户端用语与浏览器真实 OAuth2 夹具，最后文档、构建、全量普通和竞态测试。跨仓库顺序：server → web/admin → docs。隔离夹具必须覆盖 PKCE/state、错误响应、无秘密 query/日志、重放、浏览器绑定、邀请准入、同邮箱不合并、同 subject 不同提供方、绑定与最后登录方法保护。

公网验收另需真实应用登记、密钥和 HTTPS。LinuxDO 未核实 S256 支持；QQ/微信的原生流程及安全传递方式未完成评审，不能写成已接入，可由经过审核的 OIDC broker 接入。此提案不交付生产提供方凭证、不更改管理员或网络数据。

## 上游依据

- [OAuth2 安全最佳实践 RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
- [GitHub OAuth apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)、[当前用户 API](https://docs.github.com/en/rest/users/users#get-the-authenticated-user)
- [GitLab OAuth2](https://docs.gitlab.com/api/oauth2/)、[当前用户 API](https://docs.gitlab.com/api/users/#retrieve-the-current-user)
- [Gitea OAuth2](https://docs.gitea.com/development/oauth2-provider/)、[API](https://docs.gitea.com/api/1.25/)
- [LinuxDO Connect 官方说明](https://wiki.linux.do/Community/LinuxDoConnect)（未声明 PKCE，不据此承诺兼容）。
