# MagicDNS、第三方账号绑定与邀请加入

## 给用户的操作说明

### MagicDNS

进入「DNS」。网络还没有域名时，所有者或管理员点击「启用 MagicDNS」，确认后系统为本网络分配独立内部域名并保存。免费套餐也能启用设备名称解析。

设备短名称和完整名称都可用于本网络访问；客户端需要接受网络 DNS。已有设备无需重新注册，IP、分配名、访问规则和设备密钥不变。页面「设备名称」列出实际名称；重名使用持久分配的后缀。

首次内部域名不可直接更名。关闭/开启 MagicDNS 开关不移除域名，也不重置客户端身份。自定义 A/AAAA 记录、解析器、搜索域和分流 DNS 仍受自定义 DNS Entitlement 控制。此功能不是公网 DNS 服务，不自动提供公网 HTTPS 证书。

### 第三方账号

原生 GitHub/GitLab/Gitea/通用 S256 OAuth2 也使用本节同一绑定、邀请和会话机制，
无需改用另一套账户。其端点配置与非 OIDC 的验证边界见 [OAuth2 手册](oauth2-login.md)。

进入「安全中心 → 第三方账号绑定」，选择部署管理员已经配置的提供方，完成提供方授权后回到本账户。绑定不会创建第二个成员，不会因为邮箱相同合并账户，也不改变角色或批准设备。

绑定需要当前人类登录与 CSRF，并在回调时保持同一浏览器、同一发起会话。退出登录、切换账户、提供方拒绝、回放或绑定到另一个账户都会失败。

解绑前必须保留一种**当前部署仍可使用**的登录方式：可用密码、启用的通行密钥或其他已配置外部身份。解绑会退出该提供方来源的控制台会话；当前登录也被退出时，页面返回登录。已连接设备和 API key 不受影响。

没有配置提供方时页面明确提示管理员配置，不提供虚假的授权按钮。提供方停用后其既有绑定仍可查看、管理，但不被计为可用恢复方法。外部 subject 不暴露在页面或管理 URL。

### 邀请成员

所有者在「成员」创建一次性邀请，选择成员或管理员角色和有效期。分别发送网络的注册页面地址和邀请码；邀请码不能拼在网址上，也不会再次查询显示。

受邀人打开该网络注册地址，输入邀请码，可以设置密码注册，也可以选择已配置的 OIDC 账号加入。OIDC-only 网络也支持邀请注册。提供方授权成功后仍会重新检查邀请的撤销/过期/已用状态及实际成员额度；授权期间撤销的邀请不能继续建号。

普通 OIDC 登录不能绕过 invite/closed 注册策略。已有绑定可继续登录，邀请不能用来更改已有账户角色。open 普通租户仍允许额度内新成员注册；独立租户开通入口继续拒绝隐式共享成员。

## 配置与 API

提供方配置以 [CLI](../cmd/xunarad/main.go) 和 [组织配置](../cmd/xunarad/orgconfig.go) 为准：固定 issuer、client ID 和回调 allowlist；client secret 只通过环境或私密配置文件，不进入 URL、参数和日志。公网提供方验收需要合规的固定回调与 HTTPS，不把本地测试发行方当成生产配置。

所有 API 字段以实现为准：

- [DNS 初始化和配置](../control/network_configuration.go)：首次初始化使用当前版本与配置指纹，持久命名空间、历史、审计和通知同事务提交；并发冲突不会自动重试覆盖。
- [账户身份接口](../control/api_account_identities.go)：人类会话专用列表、绑定开始及解绑；Service API Key 不能代替人类身份。
- [OIDC 回调](../control/login.go)、[原子认证事务](../identity/sqlite_account_identities.go)：复用已有 state/nonce/PKCE、发行方/受众/签名/时限和 JWKS 校验；绑定、注册、登录按持久用途区分。
- [邀请接口](../control/api_member_invites.go)：所有者专用，邀请码仅在创建响应和注册 POST 正文中出现；认证事务只保存邀请码哈希。

## 升级和兼容

追加 **identity v14** 的三个认证事务引用字段，历史事务默认保持普通登录用途。state v24、plans v4 不变。未指定部署域名时，启动与 DNS 只读检查恢复数据库中的命名空间；明确指定不同域名仍拒绝。尚未初始化的网络升级时不会自动启用，必须由网络管理员确认。

既有密码与外部绑定、会话、邀请、IP、设备名称和套餐配置保留。新变化是未知 OIDC 身份也遵守 invite/closed 门禁。已发布迁移不改写；旧二进制不能直接读取 identity v14，回退必须使用维护窗口中的完整旧状态备份。

## 验收命令

执行目录：`xunara-server`；Go 版本满足 `go.mod`。

```sh
go build ./...
go vet ./...
go test ./... -count=1
go test -race ./... -count=1 -timeout=20m
```

官方 Linux 客户端隔离验收要求本机已安装 `tailscale`、`tailscaled`，先构建控制面和兄弟仓库中继，不使用生产状态目录或主机 DNS。执行目录仍为 `xunara-server`：

```sh
go build -o /tmp/xunara-onboarding-server ./cmd/xunarad
(cd ../xunara-relay && go build -o /tmp/xunara-onboarding-relay ./cmd/xunara-relay)
python3 scripts/verify-dns-ownership.py \
  --server-binary /tmp/xunara-onboarding-server \
  --relay-binary /tmp/xunara-onboarding-relay --initialize-domain
```

浏览器运行说明见 [超管仓库验收](https://github.com/xunara-net/xunara-admin/blob/main/README.md#浏览器集成验收)。该夹具通过真实 RSA/JWKS/PKCE 验证邀请加入、绑定、同一发起会话、解绑、最后登录方法保护以及 320/390/768 宽度；不接入公网发行方。

本次不交付邮箱邀请投递、全局账户跨租户加入、邮箱验证/找回、2FA、任意域名迁移或全操作系统 DNS 接管验收。决策见 [ADR-0027](adr/ADR-0027-account-onboarding-and-magicdns.md)，跟踪见 [issue #10](https://github.com/xunara-net/xunara-server/issues/10)。
