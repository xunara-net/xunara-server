# 托管私有中继自动下发提案

注册/心跳目前只有管理记录，没有进入客户端 DERPMap。新增可选注册字段
`region_id` / `cert_name`，新 Relay 从自己的 map 提交地区与证书 pin；旧记录
地区 0 仅展示，不猜 TLS 信任。state 追加 v21 字段及非零地区唯一索引。

仅将本租户 online、健康且三分钟内有心跳的私有/组织中继合并到静态地图。
保留 DERPPolicy；地区冲突拒绝注册，不覆盖平台区域。使用标准 CertName，
自签名仅接受 SHA-256 pin，不设 InsecureForTests。托管 Relay 自动使用自己
租户的 /derp/admit，避免成为开放代理。地图变更通过标准流式 MapResponse 下发。

测试静态地图不变、租户边界、坏 pin/地区冲突、TLS/准入、超时/禁用/删除摘除、
流式更新和重启。心跳不代表真实路径。旧二进制拒绝 v21；维护回退需配套一致性
备份，恢复公网后不覆盖旧快照。参考锁定的 Tailscale `tailcfg/derpmap.go`、
`derp/derphttp` 证书校验与 Headscale mapper，不改 wire 类型或其语义。
