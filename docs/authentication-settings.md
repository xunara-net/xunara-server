# 登录与注册的运行时管理

决策：[ADR-0029](adr/ADR-0029-runtime-authentication-settings.md)，
跨仓库任务：[issue #12](https://github.com/xunara-net/xunara-server/issues/12)。

## 页面入口与职责

- Web：侧边栏「登录与注册」(`/authentication`)，仅当前网络所有者可管理。
  成员邀请和安全中心的第三方绑定卡片也提供直达入口；普通成员/管理员只能
  管理自己的绑定，不能修改整个网络的登录应用。
- Admin：「登录与注册」(`/admin/authentication`)，选择租户后管理该租户。
  「租户与网络」列表提供「登录配置」直达入口。
- 配置实时持久保存，无需编辑文件或重启。首次没有运行时配置时沿用部署值；
  部署文件仍是初始化与受信运维配置，不再是唯一管理入口。

## 两种注册不能混淆

**成员加入方式**：关闭、邀请加入、开放加入。开放加入只授予普通成员；
邀请加入按一次性邀请授予 member/admin，不授予 owner。所有方式在后端继续
检查成员 Entitlement，Free 的单成员额度不会因开启邀请而绕过。

**独立网络公开开户**：仅在 `self_service` 入口租户存在，仅平台管理员可以启停。
关闭不会关闭已有租户或成员登录；调整成员邀请不会影响公开开户。入口租户
不允许匿名加入共享网络，只能使用明确的成员邀请。

成员邀请页面的注册地址为 `/register?mode=invite`，只携带非敏感的入口选择。
**邀请码另行输入，不能拼在地址里**；后端再次验证当前准入方式及邀请。
关闭邀请保留历史；重开后尚未使用且未到期的邀请仍有效。需要永久撤销时，
在成员页面明确撤销邀请码。

## 配置第三方应用

1. 选择 GitHub、GitLab、Gitea、OIDC 或支持 S256 的通用 OAuth2。
2. 填写唯一提供方 ID，页面按服务端真实控制地址显示固定回调。
3. 在提供方申请应用，精确登记回调，再输入 Client ID 和 Client Secret。
   OIDC 公共客户端可不配置 secret；OAuth2 必须配置服务端 secret。
4. 先保存停用配置，核对 issuer / endpoint / scope，再启用。未申请真实应用的
   配置不是一次真实第三方登录验收；自签站点可能被公网提供方拒绝。
5. 现有成员到「安全中心」显式绑定。邮箱相同不合并账户，登录不会审批设备。

通用 OAuth2 需固定授权、换码和当前用户资料端点，提供稳定 subject 字段；
不能将浏览器传入的邮箱/角色当成身份，不能关闭 PKCE。
详细协议与提供方版本边界见 [OAuth2 手册](oauth2-login.md)。

提供方 ID、协议、Client ID、issuer、端点与 subject 映射不可修改；切换身份域
必须创建新的 ID。运行时提供方可以修改按钮名称、启停、轮换密钥或归档。
归档清除保存的 secret，保留身份记录并永久保留 ID，不会使旧绑定指向新的 IdP。
运行时配置上限为 16 条（包括归档记录），是有界资源保护，不是套餐判断。

部署提供方标记「部署配置」，可在页面启停，不能在此改变其密钥/身份域或覆盖 ID。
第三方账号绑定与应用配置是两个入口：个人绑定不应向用户索取整个应用的密钥。

## 安全和一致性

- Secret 只通过受保护的 JSON 正文提交；不读取请求指定的环境变量或文件。
  API 不返回明文或密封值；前端请求结束/离开页面即清除输入，不写浏览器存储。
- AES-GCM 密封使用状态目录中的 `authentication_secret.key`（0600）。
  备份必须同时保护数据库和此密钥；丢失密钥会失败关闭，不会退回空 secret 登录。
- 运行时只支持公网 HTTPS，包括回调。禁用环境代理和 HTTP 重定向；出站连接
  每次解析并检查地址，连接校验后的 IP、按原主机名验证 TLS，拒绝内网、环回、
  元数据及转换地址。响应体有界。受信部署文件的已有运维配置保持兼容。
- 配置用版本 CAS；冲突返回 409，不覆盖其他管理员的修改。写事务重新验证 owner
  Session/角色；配置、审计、旧待完成第三方事务取消只有一个提交点。
- 发起、兑换、成员注册和解绑会核验配置版本。请求读配置故障返回 503，不将故障
  当成未配置或开放注册。各实例在认证请求刷新持久版本，重启恢复配置。
- 停用/归档不能让已有账户失去最后一种可用登录方式。已有 Session、设备及
  外部绑定不自动撤销；新的授权需重新发起。设备审批与服务身份保持独立。

## API 契约

Tenant：`/api/v1/authentication`；要求有效 owner **人类 Session**，写请求携带
`X-CSRF-Token`，服务 API Key 不得替代。

Platform：`/api/platform/v1/organizations/{orgID}/authentication`；要求平台 Bearer。
租户 Session 不得调用跨租户接口。

| 方法/后缀 | 用途 |
|---|---|
| `GET /settings` | 版本、成员注册策略、公开开户权限、提供方非敏感配置、固定控制地址 |
| `PATCH /settings` | `revision` + `registration`；平台入口可提交 `public_signup_enabled` |
| `POST /providers` | `revision` + 应用配置；secret 只写不读 |
| `PATCH /providers/{providerID}` | `revision` + 名称、`enabled`、新 secret；拒绝不可变字段 |
| `DELETE /providers/{providerID}` | `If-Match` 版本（含首次版本 0）；归档，不删身份记录 |

字段以 `control/api_authentication_settings.go` 为准。公开提供方接口另外声明
`member_registration` / `member_invitations`，与原有 `registration`（公开入口）分开。
旧字段、登录和回调接口保留，不改 Tailscale 协议。

## 升级与验证

需要 Identity v15，仅追加迁移；state/plans 迁移不变。先升级 server，再升级 Web/Admin。
正常恢复只回退程序需理解旧版本不认识运行时设置；要完整维护回退，停服务后恢复
匹配的程序、数据库快照与密封密钥。业务开放后不能用过期快照覆盖新增账户。

服务端仓库根目录，Go 工具链已安装：

```sh
go build ./... && go vet ./... && go test ./... -count=1
go test -race ./... -count=1 -timeout=20m
```

浏览器隔离验收命令见 [xunara-admin](https://github.com/xunara-net/xunara-admin#浏览器集成验收)。
它使用临时 HTTPS 租户、真实管理/邀请/开户 API、手机弹窗与跨租户/CAS 校验；
不连接公网 IdP。运行时 OAuth2 绑定/回调另由 Go 隔离夹具验证，真实公共应用仍需运营验收。
