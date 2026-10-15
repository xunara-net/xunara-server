# 注册入口、多网段与本地网络保护

## 注册成功但进不去 / 主站不能登录

一个免费账号拥有一个独立租户，不是入口站成员。旧的 IP 型泛域名会在公网 IP
改变后失效，入口单域证书也不能覆盖所有租户主机。

在已有 `self_service` 配置中增加 `console_url`，值必须等于入口组织
`server_url` 的规范 origin（包含真实公网端口，不带路径、query 或 fragment）：

```json
{
  "site": "portal",
  "domain_suffix": "tailnet.example.com",
  "scheme": "https",
  "port": "9090",
  "plan": "free",
  "console_url": "https://app.example.com:9090"
}
```

此处是 `self_service` 对象，不是整个组织配置文件。需要新版 Server、Web
和部署仓库 nginx 模板一起升级。浏览器新入口是
`https://app.example.com:9090/login`；注册直接进入同源专属控制台。
普通用户名与密码自动定位账户，不要求填写网络标识或选择登录范围。
旧 `/t/<org>/login` 书签、退出登录和会话过期都回到统一入口，不固定旧租户；
共享入口通行密钥先填写用户名，再验证已绑定的密钥。已有用户不需要重新注册或重置密码。

浏览器同源入口使用租户路径 Cookie，不能拿入口 owner 的 Cookie 登录别的网络。
运行时 OAuth/OIDC 配置页面显示新入口下的回调地址，需同步到第三方应用的精确
redirect allowlist；已有部署提供方仍使用其部署配置的回调。

`organization.url` 保持官方客户端 login-server；新 `organization.console_url`
只用于网页。**不要把带 `/t/…` 的控制台网址当成官方客户端的 login-server。**
独立客户端的主机仍需要泛解析与覆盖该主机的正式证书；没有这些不能宣称客户端接入已修复。

## 多个 IPv4 池

「我的网络 → 修改分配网段」保留一个默认池，可附加最多 32 个互不重叠的 IPv4 池。
数量边界用于限制配置处理成本，不限制合法 CIDR 的前缀长度；/31、/32 仍可用。
套餐需包含自定义 CIDR entitlement，Free 默认不开放该能力。

- 新设备自动从默认池分配；设备详情可手动把单台 IPv4 改到附加池。
- 先预览再确认保存，两个步骤使用同一配置版本和 CSRF；并发变更必须重新读取。
- 删除池只关闭未来地址使用，已有 IP 保留；历史地址继续为原租户预留。
- 设备地址仍作为标准 Node Addresses/AllowedIPs 下发，不把整个池冒充子网路由。
- 跨池访问不会自动被隔离。按池 CIDR 在「访问权限」配置 ACL/Grants；
  子网路由批准也不等于访问授权。这不是二层 VLAN 或广播域模拟。

接口以 `control/address_management.go`、`state/addresses.go` 为准。

## DNS 冲突：避免接入后把本地软件源变成黑洞

`100.100.100.100` 不是整个 Tailscale 分配网段，而是客户端固定内部服务地址。
IPv6 对应 `fd7a:115c:a1e0::53`；控制面不能通过 DNSConfig 随意更换它。
参见 [Quad100](https://tailscale.com/docs/reference/quad100) 与
[resolv.conf 行为](https://tailscale.com/docs/reference/faq/dns-resolv-conf)。

Linux「添加设备」默认开启「接入前检查本地网段冲突」，使用 Shell、curl、awk、
iproute2、mktemp、timeout 等常见工具，不依赖 Python 或 iproute2 JSON。
命令先从当前受信站点下载 `/network-check.sh` 公开只读检查器，检查本地
接口地址/所有表中的非默认路由；冲突或读取失败时不执行后续安装和 `tailscale up`。
检查器不接收账户密钥，不变更本机网络，不自动关闭 DNS 或制造一个自定义 Quad100。

这能防止已知本地网段与当前池、固定 DNS 地址重叠时继续接管；不能保证发现
未配置显式路由的公网/外部软件源，也不覆盖其他系统或连接后新增路由。
已发生黑洞时先在受影响机器执行 `sudo tailscale down`，确认本地 DNS/路由恢复后再排查。
仅添加 `--accept-dns=false` 不能承诺解决目的 IP 冲突；可重新规划池/本地网络，
或按[官方 userspace 模式](https://tailscale.com/kb/1112/userspace-networking)另行实测。

## 升级

State v25 / Plans v5 只追加迁移。停旧实例并完整备份；先部署 Server，再部署
Web 和 nginx，保持当前正式证书、中继证书及全部 Noise 密钥。
不能新旧程序混写；公开写入恢复后不能用升级前快照覆盖新注册和新设备。
