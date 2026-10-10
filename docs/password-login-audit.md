# 密码登录与成功审计

JSON 与兼容 HTML 共享密码登录业务；慢哈希通过后在租户身份事务内再次核对
原密码，创建会话、登录成功和会话创建事件，全部提交后才返回 Cookie。
会话或任一必需审计 SQL 失败/零行写入都会回滚，返回脱敏 503 并保留旧 Cookie。
密码错误仍为 401，限流仍为 429，限流预算不随身份事务回滚。

事件只绑定人类用户、local 提供方和会话 ID，不保存登录名或任何凭据值。
两个入口不会重复记录成功事件；已有会话不因新登录失败而被撤销。
这是审计一致性切片，不是包含 IP、地点、User-Agent 的完整登录历史或 2FA。

实现以 [密码入口](../control/password_login.go)、
[身份事务](../identity/sqlite_account.go)、
[会话插入](../identity/sqlite_session.go)、
[审计助手](../identity/sqlite_registration.go)为准。
决策见 [ADR-0026](adr/ADR-0026-atomic-password-login-audit.md)。

## 兼容

AccountStore 签名与 HTTP 载荷不变；CreateLocalSession 新增必需成功审计。
通用 CreateSession 是存储操作，不代表验证密码，仍供独立认证流程及测试使用。
本切片不改迁移、官方客户端协议、地址、ACL 或套餐；最新代码包含先前 DNS v24，
从 v23 部署仍须遵守 [只读预检与一致性备份](dns-name-ownership.md)。

## 验证入口

执行目录：xunara-server 仓库根目录；Go 版本满足 go.mod，使用正常 umask 022
运行包含文件权限场景的测试；测试状态由私有临时目录承载，无生产账号依赖。

```sh
umask 022
go test ./identity ./control -run 'PasswordSession|PasswordAdmission|PasswordLoginAudits|Account' -count=1
go build ./... && go vet ./... && go test ./... -count=1
go test -race ./... -count=1 -timeout=20m
```
