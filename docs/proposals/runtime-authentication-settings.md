# Proposal：持久注册策略与第三方登录管理

- 日期：2026-10-11
- 状态：Accepted，实施与验证中
- 范围：xunara-server → xunara-web / xunara-admin → xunara-docs / xunara-deploy

## 问题与数据流

当前成员邀请要求部署配置为 `registration=invite`，而自助开户入口必须为
`open`；这使入口网络无法邀请同事。第三方身份适配器、绑定与回调已经存在，
但配置只来自部署文件，所有者和平台管理员不能在页面管理。

现有链路为：提供方 Registry → 持久 AuthTransaction → 适配器验证 →
事务型账户绑定 / 邀请兑换 / Session。配置管理必须复用该链路，不引入第二套登录。

## 决策

1. 分开租户成员加入策略与平台创建独立网络的公开注册开关。前者由租户所有者
   或平台管理员修改；后者仅平台管理员修改。开户入口禁止匿名加入共享网络，
   但可显式使用邀请码加入。邀请码不进入 URL。
2. Identity 追加迁移：单租户认证配置版本和认证事务的配置版本。配置、审计和
   旧待完成事务失效原子提交；写入重新核验当前所有者 Session，跨实例用 CAS。
3. 首次无持久配置时沿用部署配置。运行时配置只覆盖成员策略、公开开户开关和
   新增提供方；部署提供方保留来源标识，可禁用但不能被另一身份域覆盖。
4. 新增提供方 ID、协议、issuer / endpoint、subject 字段和 client ID 不可重用或
   修改；变更身份域必须创建新 ID。可以改显示名称、启停和轮换密钥。
5. Client secret 仅经受保护的 POST/PUT 请求提交、AES-GCM 密封后持久化；密封
   密钥使用状态目录独立 0600 文件。API 只返回是否配置，不能读取文件或环境变量。
6. 运行时提供方使用专门 HTTPS 出站客户端：禁止环境代理、HTTP 重定向、内网 /
   环回 / 元数据地址；每次 DNS 解析和实际连接校验地址，防止 DNS 重绑定。
   保留部署文件对受信运维配置的兼容，不允许 Web 关闭验证。
7. 配置在认证请求中刷新，数据库故障失败关闭；已有身份绑定、会话、邀请历史
   和设备不删除。禁用最后一种可用登录方式必须拒绝，避免锁死已有账户。
8. Web 增加网络登录设置及邀请/绑定页直达入口；Admin 增加按租户管理页。
   手机侧边抽屉与现有设计一致，密钥不进入浏览器持久存储。

## 兼容性、安全与验证

不修改 TS2021、Noise、MapRequest/MapResponse、设备信任或套餐设备配额。
Human、Machine、Service 身份保持独立；外部身份键始终为 `(provider_id, subject)`。
新增 API，不删除旧 API。迁移只追加，恢复需同时保护数据库与密封密钥。

验证：权限/CSRF、CAS、审计回滚、跨实例刷新、重启持久化、身份域不可覆盖、
最后登录方式、密钥不回显、SSRF/重绑定、旧事务失效、邀请与公开开户隔离；
Go build/vet/test/full race，两个前端 typecheck/test/build 与手机浏览器联调。
实际第三方登录仍需要用户自行申请提供方应用，不能伪造或预置凭据。

## 上游依据

- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)：精确回调、PKCE、禁止开放重定向。
- [go-oidc ClientContext](https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc#ClientContext)：出站客户端注入。
- 实现 API 以本仓库 `identity/provider.go`、`identity/oidc.go`、`identity/oauth2.go`、
  `identity/sqlite_account_identities.go` 为准，不另造协议字段。
