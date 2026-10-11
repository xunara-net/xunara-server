# 核心设备接入、连接报告与中继检测

## 添加设备

「设备 → 添加设备」读取本租户 overview 的接入地址，Linux 支持官方 curl 安装
或仅登录；MagicDNS、接收路由、子网/出口和名称勾选生成参数。子网/出口权限与
路由上限读取 Entitlement，服务端继续强制注册/批准配额。Windows/macOS 有命令
与官方下载，手机有自定义服务器地址，不执行 Linux 命令。无 Auth Key、平台
Token、重置已有配置或自动批准；路由仍需 IP 转发、批准、ACL 和防火墙。

## 只读设备报告

`GET /api/v1/machines/{ref}/connection`（numeric/stable ID），本租户 read scope/
Human Session，no-store；缺设备 404、未登录 401、scope 不足 403。
白名单含控制面在线/最后联系/读取时间、HomeDERP/客户端首选区域、当前地图及来源、
UDP/IPv6/NAT/端口映射 null/bool、候选端点和客户端 DERP 探测毫秒值。
端点最多 32、服务器最多 32、延迟最多 128，明确总数/截断与稳定排序。

未知报告、无平台地图、策略关闭和未选择归属分别展示。不序列化原始 Hostinfo、
机器/节点/Disco 密钥、日志/推送标识。HomeDERP 不是实际流量路径；报告缓存无
独立检测时间，读取时间不是更新时间，探测不是应用 RTT。用客户端
`tailscale status`/`tailscale ping` 核实真实路径。

## 私有中继健康

`POST /api/v2/relays/{id}/health`，空 JSON。本租户已登记节点，owner/admin 或
既有 write API scope，Human CSRF，服务 API Entitlement；缺节点 404、撤销 409，
每用户每分钟 12 次，429 带 Retry-After。目标仅登记 HTTPS 主机/端口/pin，固定
`/derp/probe`，8 秒总超时、4 秒握手/响应头、16 KiB 头、4 KiB 有界响应读取。
全部 DNS 地址必须公网并固定拨号，禁代理/重定向，TLS 复用官方 tlsdial。

响应含 relayId、configVersion、checkedAt、perspective=control-plane、status、固定
code、tlsVerified、httpStatus 与成功延迟。reachable 必须 TLS 成功且 HTTP 200；
blocked/unreachable 不是健康成功。必需 relay.health_checked 审计失败返回 503，
不泄露底层错误/凭据。不覆写心跳、LastSeen、配置、回执、身份或地图；Web 防双击、
显式重试，更新/删除节点后丢弃旧配置结果。它不是 STUN/准入/端到端可达保证。

## 验证与边界

MapRequest 持久报告读取、缺值/单位/白名单/截断、快照并发/read scope/租户隔离；
真实 TLS/pin/坏证书/取消/无重定向/防 SSRF、CSRF/限流/租户、审计 ABORT/IGNORE
失败及原状态保持。Go 全量 build/vet/test/race，Web 类型/单测/构建、隔离手机
Chromium 回归。无迁移或 Tailscale wire 改动，原 Noise/Map/DNS/DERP 回归继续执行。
安装器以 [relay 手册](https://github.com/xunara-net/xunara-relay/blob/main/docs/private-relay-install.md)为准；
全架构/发行版现场运行、实时路径遥测、自动升级与故障转移不在已验证范围。
