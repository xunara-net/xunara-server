# ADR-0002：官方 Tailscale 客户端兼容是不可修改的红线

- 状态：Accepted
- 日期：2026-10-09

## 背景

Xunara 的产品能力（多租户、套餐、可视化权限、Web 控制台）都必须建立在
「官方 Tailscale 客户端能正常加入 Tailnet」之上。协议兼容层一旦被产品需求
改写，所有官方客户端都会失效。

## 决策

以下协议面 **只允许为修复兼容性问题而修改**，且必须附带兼容性测试：

```text
TS2021、Noise、MapRequest、MapResponse、NodeKey、MachineKey、DiscoKey、
Register、Poll、DNS、DERP、Capabilities、FeatureQuery
```

产品功能一律通过 Core API 与产品层实现：

- 产品权限 → `policy` 编译 → 控制面 NetMap；
- 套餐配额 → 资源创建点闸门；
- Web UI → Core API。

## 影响

- 任何带宽、限速、审计与可视化需求不得在协议层做特判。
- 协议层变更需要 `go test ./control/...` 全量通过，并新增针对性兼容测试。
