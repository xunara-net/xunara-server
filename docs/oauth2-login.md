# 原生 OAuth 2.0 第三方登录

决策：[ADR-0028](adr/ADR-0028-oauth2-human-login.md)。跟踪：[issue #11](https://github.com/xunara-net/xunara-server/issues/11)。

## 能做什么

正式 Web/Admin 现在有 [登录与注册管理](authentication-settings.md)：所有者管理
当前网络，平台管理员按租户配置，运行时 secret 加密持久保存且不可读回。
以下文件方式仍供受信部署初始化使用，不是唯一配置入口；其 private/loopback
运维配置不能经 Web 绕过运行时的公网 HTTPS 和 SSRF 防护。

配置后，正式登录页展示对应第三方按钮；「安全中心」可显式绑定、解绑；受邀人可以通过第三方授权加入当前网络，无须另设密码。共用持久认证事务、邀请、成员额度、会话与审计，不改变角色或设备审批。陌生 OAuth2 账号不能绕过 invite/closed；没有配置应用时不显示假的登录入口。

| 类型 | 适配方式 | 身份键/默认权限 |
|---|---|---|
| `github` | GitHub.com 授权码 + S256，固定官方端点 | 当前用户数字 `id`；`read:user`，不请求仓库/私有邮箱权限 |
| `gitlab` | GitLab.com 或自建实例，支持部署子路径 | 当前用户数字 `id`；`read_user` |
| `gitea` | 自建 Gitea，要求 1.23+ 的细粒度 scope 与 S256 支持 | 当前用户数字 `id`；`read:user` |
| `generic` | 管理员审核的标准 OAuth2，固定三个端点和顶层不可变身份字段 | 字符串或正整数 subject；必须支持 S256 与 Bearer 资料请求 |

OAuth2 不要求存在 ID Token，身份来自提供方受保护的当前用户接口，不从浏览器提供的 email、subject 或 claims 获取。OIDC 继续使用已验证的 ID Token、nonce、issuer、audience、签名、时限和 JWKS。Google/Microsoft 等具有 OIDC 的服务仍使用现有 OIDC 配置，不以绕开 ID Token 验证代替。

同邮箱不同账户不合并，同 subject 不同 provider 不混淆；整数 ID 不经过浮点解析。昵称、登录名、邮箱只是展示属性。原始 `site_admin`、groups、api_key 等资料不映射到角色或持久化。外部 access/refresh token 只在后端换码及资料请求期间使用，不存入 Session、数据库或浏览器。

新 OAuth2 账户的本地登录名采用 provider ID 与不可变 subject 的摘要，不让未验证邮箱成为 ACL 名称，也不公开 raw subject。已绑定账户和历史 OIDC 用户不被重命名；昵称仍是可读的展示名。

## 单租户配置

前置条件：构建当前服务端和 Web、更新同源 nginx 配置、准备真实 HTTPS 域名，并在提供方登记应用。执行目录 `xunara-server`。复制[非秘密示例](examples/oauth2.json)，填入真实 client ID（不是 secret）；GitHub Callback URL 精确登记：

```text
https://app.example.com/oauth2/callback/github
```

配置文件为非空 JSON 数组，最多 16 个提供方。每项只选 `client_secret_env` 或 `client_secret_file` 之一；文件须为绝对路径、非符号链接的普通文件，权限严格 `0600`。路径可写入 JSON，密钥值不可以。未知字段、明文 `client_secret`、缺失秘密、重复/保留 ID 或跨租户回调均拒绝启动。

以下在 **Bash** 中执行，不把秘密放入历史或 argv。先编辑非秘密配置中的 client ID，替换为实际登记域名；HTTPS 反代须预先指向本机 8080：

```bash
go build -o xunarad ./cmd/xunarad
cp docs/examples/oauth2.json /tmp/xunara-oauth2.json
# 先编辑 /tmp/xunara-oauth2.json 的非秘密应用资料。
set +x
IFS= read -r -s -p 'GitHub Client Secret: ' XUNARA_GITHUB_CLIENT_SECRET
printf '\n'
export XUNARA_GITHUB_CLIENT_SECRET
./xunarad -listen 127.0.0.1:8080 -server-url https://app.example.com \
  -state-dir /var/lib/xunara -oauth2-config /tmp/xunara-oauth2.json \
  -allow-local-login -trusted-proxy
unset XUNARA_GITHUB_CLIENT_SECRET
```

`-allow-local-login` 保留密码和首次 owner 初始化；配置任意外部提供方后，不带此开关则不提供密码入口。新部署仍需一次性 `/setup`，不能让首个第三方登录自动成为 owner。生产 systemd 使用既有 `EnvironmentFile`（`0600`）或私密文件引用。没有可信反向代理时不用 `-trusted-proxy`。

GitLab 列表项使用 `type: "gitlab"`（默认 GitLab.com），自建设置 `base_url`。Gitea 必须配置 `base_url`。不要为了“能登录”请求 `api`、`repo`、写权限或管理员 scope；默认只需资料。GitHub Enterprise 未经此切片验证，不冒充 GitHub.com 预设。

## 多租户与通用提供方

`-org-config` 每个组织的 `oauth2` 使用同样数组，分别配置本租户应用/回调/秘密。不能同时传单租户 `-oauth2-config`。组织示意片段（其余字段沿用已有配置）：

```json
{
  "oauth2": [
    {"id":"github", "type":"github", "client_id":"registered-client-id", "client_secret_file":"/etc/xunara/github.secret"},
    {"id":"company-gitea", "type":"gitea", "base_url":"https://git.example.com/team", "client_id":"registered-client-id", "client_secret_env":"XUNARA_GITEA_CLIENT_SECRET"}
  ],
  "allow_local_login": true
}
```

通用适配器显式设置 `auth_url`、`token_url`、`userinfo_url`、`subject_field`；可设置 `name_field`、`username_field`、`email_field` 和 `scopes`。只支持 JSON 顶层身份字段，不执行脚本或角色映射。`auth_style` 只支持 `client_secret_post`（默认，正文不是 query）或 `client_secret_basic`；内置预设固定 POST 正文，不自动重复交换探测认证方式。

端点/回调只允许 HTTPS（夹具允许回环 HTTP），禁止 credentials、query、fragment。回调必须精确等于本租户 `server_url` 下 `/oauth2/callback/<id>`，预设不能覆盖端点/身份字段。state、S256、浏览器绑定、事务时限/单次消费、同一绑定发起会话及提交前准入复核不可关闭。provider ID 是主键的一部分；换发行方须使用新 ID，不能复用旧 ID 连接另一用户库。

请求有 context、10 秒单请求超时与控制面整体超时；资料限 1 MiB，非法 JSON/subject 拒绝，不跟随令牌/资料重定向。秘密只经 POST 正文、Basic 或 Bearer header。提供方错误正文、请求 URL 和令牌不向日志/浏览器透传。

自动创建的 managed tailnet 暂无 IdP 编辑或全平台账户映射；第三方直接自动开通独立租户仍未完成。LinuxDO 官方说明尚未确认 S256；QQ/微信扫码与安全换码未评审，不能通过关闭 PKCE 或秘密拼 URL 接入。可另外通过经过审核的 OIDC broker 接入，不宣称本次直接实现这些提供方。

## 兼容与验收

保持 state v24 / identity v14 / plans v4，无新迁移。旧 `/oidc/callback/` 保留，新增 `/oauth2/callback/` 同源反代与开发代理；登录页是 SPA，不按查询参数切换旧页面。新增 `auth.oauth2` / `auth.external`，只在实际启用 OIDC/密码时声明其能力；不改 Tailscale Capabilities 或其他官方协议。接口和配置以 [账户实现](../control/api_account_identities.go)、[加载器](../cmd/xunarad/oauth2.go) 为准。

执行目录 `xunara-server`，Go 版本满足 `go.mod`：

```sh
go build ./...
go vet ./...
go test ./... -count=1 -timeout=20m
go test -race ./... -count=1 -timeout=20m
```

浏览器说明见 [Admin 验收](https://github.com/xunara-net/xunara-admin/blob/main/README.md#浏览器集成验收)。夹具同时运行真实 OIDC/JWKS 和无 ID Token 的 OAuth2 授权码/令牌/资料服务，覆盖邀请、绑定、同会话、state/PKCE、重放、资料错误、最后登录方法、来源会话撤销和手机宽度。它不接公网，不能替代真实应用和 HTTPS 验收。

上游：[GitHub](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)、[GitLab](https://docs.gitlab.com/api/oauth2/)、[Gitea](https://docs.gitea.com/development/oauth2-provider/)、[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)。
