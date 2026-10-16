package control

import "github.com/xunara-net/xunara-server/state"

// 设备概览共用展示名，不因客户端尚未上报主机名而丢失节点标识。
func nodeDisplayHostname(node state.Node) string {
	if node.Hostname != "" {
		return node.Hostname
	}
	if node.Hostinfo != nil && node.Hostinfo.Hostname != "" {
		return node.Hostinfo.Hostname
	}
	return node.StableID
}
