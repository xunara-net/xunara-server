# AI 开发规则（xunara-server）

> 本文档是仓库级约束。完整规范见
> [xunara-docs/AI_DEVELOPMENT.md](https://github.com/xunara-net/xunara-docs/blob/main/AI_DEVELOPMENT.md)。

## 必须遵守

1. **官方 Tailscale 客户端兼容优先。** 不得为任何产品功能修改
   TS2021 / Noise / MapRequest / MapResponse / NodeKey / MachineKey /
   DiscoKey / Register / Poll / DNS / DERP / Capabilities / FeatureQuery 的
   兼容语义。
2. **身份分离。** Human / Machine / Service 身份不得互相推导；外部身份键
   只能是 `(provider_id, subject)`，邮箱只是属性。
3. **租户隔离。** User / Machine / Node / Route / ACL / Grant / AuthKey /
   APIKey / DERP / Share / Audit 都必须带租户边界。
4. **Secret 不进 URL、argv、日志。** 使用环境变量或密钥文件。
5. **Core 不依赖 WebUI。** 服务端只提供 API；页面属于 xunara-web /
   xunara-admin 仓库。
6. **最小修改。** 优先定位—分析—最小修复—测试，禁止无必要的大规模重构。
   涉及数据库、认证流程、网络分配、策略引擎、计费与租户模型的结构性变更
   必须先写 ADR（`docs/adr/`）。
7. **已发布的迁移条目永不修改。** 数据库迁移只能追加新版本。

## 每次提交必须说明

```text
What changed / Why / Compatibility impact / Security impact / Tests
```

## 测试要求

```bash
go build ./...
go test ./...
go vet ./...
```

涉及并发、Session、Identity、控制面时额外运行 `go test -race ./...`。
