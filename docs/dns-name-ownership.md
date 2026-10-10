# DNS 名称管理与升级检查

## 用户能感受到的变化

- 两台设备都叫 `laptop` 可以正常接入，不再发布同一个 MagicDNS 名称。
- `nas` 已被自定义记录或服务占用时，新设备获得如 `nas-12` 的分配名。
  原记录和服务仍指向原地址，机器自报名称不被改写；设备实际 FQDN 以 API 为准。
- 客户端更名沿用同一个冲突检查；反复心跳、同名重报和密钥轮换不会反复加后缀。
- 管理记录和机器 DNS/服务发布不能覆盖设备分配名，失败保留原配置。
- 删除设备或记录后可重新使用空出的名称；不会自动移除仍保留的关联 DNS 记录。

官方 Node.Name 和 DNSConfig 下发语义不变。内部实现以
[Store](../state/store.go)、[归属规则](../state/dns_names.go)及
[SQLite 事务](../state/sqlite_dns_names.go)为准。决策见
[ADR-0024](adr/ADR-0024-dns-name-ownership.md)。

## 升级前只读预检

前置：在 `xunara-server` 源码根目录，Go 版本满足 `go.mod`；具有目标状态目录
的读取权限。分别设置每个租户的真实状态目录和该租户当前配置的 DNS 域名。
未启用 MagicDNS 域名时显式设置 `XUNARA_DNS_DOMAIN=''`，不要猜测域名。

```sh
# 执行目录：xunara-server；两个变量需事先设置为目标租户的真实值。
: "${XUNARA_STATE_DIR:?请设置目标租户的状态目录}"
: "${XUNARA_DNS_DOMAIN?请设置当前域名，未启用时设为空字符串}"
go run ./cmd/xunara dns check \
  -state-dir "$XUNARA_STATE_DIR" -domain "$XUNARA_DNS_DOMAIN"
```

只读检查 v23/v24，不迁移库、不改 IP/身份/记录。成功输出
`DNS name ownership check passed (read-only; no migrations applied)`。
发现碰撞、坏名称、读取失败或与已绑定域名不一致时返回非零。

冲突须先在旧版中人工审查：确认设备/服务/记录实际用途，再通过已授权入口更名或
编辑冲突配置，重新预检。不要直接删除设备或数据库表来“修复”，不要把已有 DNS
记录自动替换成设备 IP；ACL、证书、应用和外部配置的关联需要独立确认。

## 迁移和回退边界

state 只追加 v24；identity v13 和 plans v4 不变。启动在同事务内校验归属并补录
旧名称，旧无冲突 FQDN 不变。失败不会部分补录，也不会静默重编号或给旧设备换名。
已启用域名首次绑定后拒绝不同域名或空域名实例；通过 DNS 页面关闭 MagicDNS
解析开关仍是原功能，与移除部署域名不同。未绑定域名的部署可后续首次启用域名。

逐租户预检后，维护窗口停止控制面写入，完整备份状态目录、平台库、配置和产物；
不得只复制活跃 WAL 数据库的主文件。更新、启动、核对版本和原数据后再恢复访问。
启动迁移与域名绑定是两个阶段：即使绑定失败，schema 也可能已升级至 v24。
旧二进制不能直接打开新库，失败时须在未恢复业务、无新写入前成套还原备份。
业务恢复后不能用旧快照覆盖新数据，应保留当前状态并前滚修复。

本轮开发验证不等于已经升级调试站或正式生产。上线以实际部署记录为准。

## 可重复的隔离验证

前置：执行目录 `xunara-server`；本机有官方 Linux `tailscale`/`tailscaled`，并
支持 `tailscale dns query --json`；相邻 `xunara-relay` 源码和满足模块要求的 Go。
测试自行启动两个 userspace 客户端、控制面及本地 TLS DERP/STUN，使用临时状态、
私有 socket 和 0600 密钥文件，结束清理自己启动的进程，不改宿主 DNS/现有 daemon。

```sh
# 执行目录：xunara-server；不需要生产账号或平台令牌。
validation_dir=$(mktemp -d)
chmod 700 "$validation_dir"
go build -o "$validation_dir/xunarad" ./cmd/xunarad
(cd ../xunara-relay && go build -o "$validation_dir/xunara-relay" ./cmd/xunara-relay)
python3 scripts/verify-dns-ownership.py \
  --server-binary "$validation_dir/xunarad" \
  --relay-binary "$validation_dir/xunara-relay"
```

脚本验证真实同名注册、保护管理记录、在线更名、官方内部 A/PTR 查询、按新名称的
WireGuard ICMP 和控制面重启。测试使用 `--accept-dns=false` 防止更改宿主解析器；
不将内部 forwarder 查询冒充宿主 OS DNS 接管或 Windows/macOS/Android/iOS 实测。
本轮实测客户端为 Linux 1.102.2；并发及真实 v23 升级故障回归见
[状态测试](../state/dns_names_test.go)和[Noise/API 测试](../control/dns_names_test.go)。

用户手工指定别名、域名更换、复杂共享投影的持久全局预留、全 OS DNS、注册审计
整体原子性仍为后续任务，不在此文宣称完成。
