# ADR-0036：参数化接入与分层中继健康

状态：接受。Proposal 见[私有中继安装与健康](../proposals/2026-10-12-private-relay-install-and-health.md)。

## 决策

Web 从本租户真实地址和 Entitlement 生成官方客户端接入命令，不注入 Auth Key
或自动批准。relay 仓库维护固定版预编译安装器、先校验再提权、专用低权限服务、
隐藏/私有文件令牌、进程专用 CA 与身份保留升级。

健康分为本机监听/TLS、控制面到登记节点 TLS/HTTP、客户端报告与真实数据面。
主动检测仅本租户节点，管理员/write scope、Human CSRF、持久限流、必需审计；
审计未落盘不能成功。公网验证全部解析 IP、固定拨号，禁代理/重定向，复用官方
CA/CertName/pin。结果不修改心跳/配置，Web 丢弃已更新配置的旧结果。

## 影响

不改官方 DERP/STUN、注册/心跳字段、迁移或套餐名称规则；不提供自动修复/故障
转移或 STUN/端到端保证。Linux systemd 安装不冒充全 OS 服务安装，校验和不是
独立签名。契约见[核心手册](../device-core.md)，安装见
[relay 手册](https://github.com/xunara-net/xunara-relay/blob/main/docs/private-relay-install.md)。
