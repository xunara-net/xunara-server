# ADR-0038：设备过期与预授权接入的事务闭环

状态：接受（2026-10-12）。任务 [Server #19](https://github.com/xunara-net/xunara-server/issues/19)，
实施前[Proposal](../proposals/2026-10-12-device-expiry-and-token-enrollment.md)。

## 决策

手动过期绑定设备身份及有效期摘要；只更新 expiry，不删除机器/地址、不释放额度。
管理员持久凭据/角色、CAS、必需审计及通知同事务；冲突和未知结果须重新确认。
注册公钥补充及客户端缩短 expiry 不再用整行旧快照覆盖管理事实。

添加设备使用独立 Machine Auth Key，不使用平台/Human/Service 凭据。普通短期
一次性签发、节点创建/轮换、配额、消费及审计各自同事务，共用现有 DNS/地址及
轮换逻辑，非法持久标签拒绝授权。旧 v1/HTML 只作适配，不混用非原子业务实现。
浏览器审批的新建配额也下沉同一数据库写锁，防止混合入口超额；历史审批的
授权状态/审计事务不在本次全面重构范围，不能以此宣称整套审批已原子化。

复制命令仅隐藏输入与 file:，秘密不进 argv/URL/日志。Linux 密钥脚本只供显式
私有下载，关闭跟踪、私有权限及退出清理；手机不伪造 CLI 支持。

## 影响

无迁移、无官方 wire、无 Headscale 内部依赖或 plan-name 分支。Free 10 设备保持，
满额已有机器轮换不误计新设备。v1 Cookie 写加入 CSRF/持久授权及 API Entitlement
服务检查；公开响应形状保持。测试与现场边界见[契约手册](../device-enrollment.md)。

本地完整 Go build/vet/test/race、Web 396/Admin 51 单测与构建及 95 阶段隔离
浏览器通过，页面 JS 错误为零；真实 Linux 软件包安装和 Windows/macOS 现场
运行不冒充已验证，正式站写入不作为测试夹具。

## 后续交互调整（2026-10-12）

按用户明确要求，[简化接入 Proposal](../proposals/2026-10-12-simplified-device-enrollment.md)
替代本 ADR 中复制命令仅隐藏输入/file: 与设备私有下载的交互决策：Web 显式
勾选 Token 后直接生成含设备 Auth Key 的短命令，单一复制，高级参数折叠。
必须明确承认终端历史/argv/剪贴板暴露风险，默认短期一次性密钥并清除页面
秘密；不再声称该模式不会泄露到进程参数。其余后端事务、授权、隔离、额度、
审计、官方兼容决策保持不变，不影响私有中继安装流程。
