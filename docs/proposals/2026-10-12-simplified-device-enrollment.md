# Proposal：官方风格的简洁设备接入

状态：按用户明确要求实施（2026-10-12）。

## 范围

只调整 Web 添加设备交互与客户端命令，不改认证 API、机器身份、事务、额度、
审计、数据库或官方 wire。参考官方 Linux 安装与 auth-key CLI 文档以及锁定的
Tailscale v1.104.0 `up.go`，不假称访问了需登录的官方控制台。

默认浏览器接入；选择平台后复制一个完整命令。显式勾选 Token 后，粘贴设备
Auth Key 或生成现有 API 支持的短期一次性密钥，直接写入 `--auth-key`。
不再单独复制 Token、隐藏输入、多平台临时密钥脚本或下载私有设备接入文件。
高级参数折叠，按客户端默认值省略无效冗余参数；Linux 安装阶段保留 pipefail，
安装/下载失败不得继续携带密钥运行接入命令。

## 安全取舍

用户明确选择的含 Token 命令会进入剪贴板，执行时也可能进入 shell history、
进程参数、审计/终端录屏；不能再宣称 argv/历史无密钥。这是 ADR-0038 中仅
隐藏输入/file: 的交互决策变更，不改变其后端事务决策。页面简短提示这些风险，
默认签发 15 分钟一次性设备密钥，不使用平台或 API Token，不拼进 URL/query，
不持久化至浏览器，关闭/离页/切到浏览器或手机清除本页密钥。不自动签发、
自动重试或撤销未使用密钥。复制及错误提示不回显真实密钥到应用日志。

## 验证

命令模式/平台默认值/注入/权限与额度、真实 Linux shell mock 安装及失败阻断、
单一复制包含正确设备密钥、移动折叠/滚动/宽度、关闭清理及权限读取失败关闭。
全量前端类型/单测/构建与隔离真实 API 浏览器回归；生产仅更新静态 Web，保护
正式证书、其他租户 SNI、原人类数据和默认 Relay，不用生产账户或设备试写。

参考：[Linux 安装](https://tailscale.com/docs/install/linux)、
[CLI](https://tailscale.com/docs/reference/tailscale-cli)、
[密钥泄露风险](https://tailscale.com/docs/features/access-control/auth-keys/how-to/secure-auth-keys)。
