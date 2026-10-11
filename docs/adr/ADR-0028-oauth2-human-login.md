# ADR-0028：复用持久认证链的原生 OAuth2 登录

状态：Accepted。依据：[Proposal](../proposals/oauth2-human-login.md)。

OAuth2 授权本身不是已验证的 OIDC 身份令牌。使用 S256 授权码交换和提供方固定的当前用户接口，取不可变账户 ID，不取邮箱、昵称或客户端传入的 subject。GitHub/GitLab/Gitea 使用评审后的端点和最小资料 scope，通用适配器只支持同样的安全协议能力。

复用 `IdentityProvider` 和租户内持久认证事务，所有绑定、邀请、配额、Session、审计都经现有原子完成事务，不开第二套状态机，不自动批准 Machine。provider ID 在租户中唯一且配置后不能随意用于另一个发行方；更换发行方必须使用新的 ID。

OAuth2 email 未经 OIDC 校验，除了不能合并身份，也不能隐式成为 ACL 的本地登录名称。只对新 OAuth2 账户使用 provider ID 与不可变 subject 的摘要作为名称，展示资料仍分开保存；不重命名既有用户或改变旧 OIDC 行为。

固定客户端认证方式（POST 正文或 Basic header），令牌只经 Bearer header 读取资料，不存储 access/refresh token，不跟随后端重定向，返回错误不携带提供方正文和请求 URL。回调使用服务器配置的精确允许地址，并与持久事务交叉核验。

不改 schema、已发布迁移和官方客户端协议。新增 OAuth2 配置与能力是向后兼容扩展，既有 OIDC callback 路径不改。真实公网接入需另行配置应用与 HTTPS；未评审的国内扫码提供方及不支持 S256 的提供方不得通过关闭安全检查接入。
