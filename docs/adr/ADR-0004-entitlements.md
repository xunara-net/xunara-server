# ADR-0004：套餐能力通过 Entitlement 强制，而不是散落的 if

- 状态：Accepted
- 日期：2026-10-09

## 背景

如果业务代码到处写 `if plan == "pro"`，新增套餐就必须修改程序逻辑，也会在
审计、迁移与测试中产生分叉。

## 决策

- `plan.Plan` 是唯一的套餐数据模型（配额 + 能力开关 + 价格元数据）；
- `control.PlanRegistry` 只负责「租户 → 套餐」分配与目录持久化；
- 配额在资源创建点检查（设备、密钥、成员、路由、API Key、审计），返回稳定
  错误码前缀；
- 未配置套餐的部署使用 `plan.UnlimitedPlan()`，闸门全部 no-op；
- 降级不删除任何既有资源：超出配额进入 Over Limit 状态，由用户自行收敛。

## 影响

- 新增套餐 = 新增一条 `plan.Plan` 数据（`-plans` 文件或平台 API），不需要
  改代码。
- 前端通过 `/api/v1/plan` 与 `/api/v1/capabilities` 渲染配额与升级提示。
