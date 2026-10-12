# Proposal：每台设备的密钥有效期设置

日期：2026-10-13。任务 [Server #20](https://github.com/xunara-net/xunara-server/issues/20)。

## 数据流与决策

Web 列表/详情共用「有效期设置」弹窗 → 租户 lifecycle 快照及 CSRF → 管理员写
接口 → 数据库写锁、持久权限及身份/有效期 CAS → 仅 expiry 更新、必需审计与
配置通知同事务 → 原有 Map 下发 KeyExpiry。保留旧立即过期接口作为同一实现的适配。

有效设备可设置 1/7/30/90/180 天或未来 180 天内的指定时间、关闭过期、立即过期。
相对天数在服务器事务内计时；指定时间以 RFC3339 UTC 保存。已过期设备只能显式
临时续期 30 分钟，随后在窗口内重新认证或管理有效期。冲突、权限撤销、未知结果
必须重新读取并确认，不自动重试，不让客户端恢复管理员已撤销的授权。

核对官方[Key expiry](https://tailscale.com/docs/features/access-control/key-expiry)：
零有效期表示不自动过期，过期设备临时延长固定 30 分钟。官方 1～180 天设置是
网络默认认证周期；本次指定日期是 Xunara 的单设备管理能力，不宣称官方具有
同样的日期选择器。暂不改网络默认周期、新设备注册或合法重新认证的既有策略。
已核对锁定 SDK v1.104.0 的 ipnlocal/expiry.go 与 local.go：官方客户端根据
SelfNode/Peers KeyExpiry 及 ControlTime 执行到期计时，不增加私有 wire 字段。

## 安全与验证

无迁移，不改 MachineKey/NodeKey、归属、IP、路由、标签、额度或人类 Session。
永不过期有明确风险提示；临时恢复有独立确认。新增权限/CSRF、时间/形状校验、
时间流逝边界、跨连接 CAS、必需写入 IGNORE/ABORT 回滚、持久角色撤销、重启
读回及真实 Noise Map 回归。Web 测试时区/非法日期、响应确认、移动端、过期
恢复与失败后重新确认。全量 build/vet/test/race 与隔离浏览器通过后再安全发布。
