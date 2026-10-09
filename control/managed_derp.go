package control

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/state"
)

type derpMapSnapshot struct {
	Map         *tailcfg.DERPMap
	Fingerprint string
}

// 仅合并当前租户的托管中继，不把注册记录升级成跨租户共享基础设施。
func (server *Server) refreshRelayMap(ctx context.Context) error {
	server.relayMapMu.Lock()
	defer server.relayMapMu.Unlock()
	sqlite, ok := server.store.(*state.SQLiteStore)
	if !ok {
		return fmt.Errorf("managed relay map requires a durable store")
	}
	rows, err := sqlite.DB().QueryContext(ctx, "SELECT id, region_id, hostname, region_code, region_name, derp_port, stun_port, cert_name, desired_state, healthy, last_seen, visibility FROM relays ORDER BY region_id")
	if err != nil {
		return err
	}
	defer rows.Close()
	served := server.derpMap
	if served != nil {
		served = served.Clone()
	}
	hasManaged := false
	now := time.Now()
	for rows.Next() {
		var relay state.Relay
		var healthy bool
		var lastSeen *int64
		if err := rows.Scan(&relay.ID, &relay.RegionID, &relay.HostName, &relay.RegionCode, &relay.RegionName, &relay.DERPPort, &relay.STUNPort, &relay.CertName, &relay.DesiredState, &healthy, &lastSeen, &relay.Visibility); err != nil {
			return err
		}
		if relay.RegionID <= 0 {
			continue
		}
		if relay.Visibility == state.RelayVisibilityPublic {
			continue
		}
		if !state.ValidRelayVisibility(relay.Visibility) || relay.RegionID > 65535 || !validRelayHostname(relay.HostName) || !validRelayPort(relay.DERPPort) || !validRelayPort(relay.STUNPort) || relay.CertName != "" && !validRelayCertPin(relay.CertName) {
			return fmt.Errorf("managed relay %s has invalid map configuration", relay.ID)
		}
		hasManaged = true
		if server.derpPolicy.Mode == DERPPolicyNone || server.derpPolicy.Mode == DERPPolicyRegions && !slices.Contains(server.derpPolicy.Regions, relay.RegionID) || relay.DesiredState != state.RelayStateOnline || !healthy || lastSeen == nil || now.Sub(time.Unix(0, *lastSeen)) > relayOnlineWindow {
			continue
		}
		if served == nil {
			served = &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}
		}
		if served.Regions == nil {
			served.Regions = make(map[tailcfg.DERPRegionID]*tailcfg.DERPRegion)
		}
		regionID := tailcfg.DERPRegionID(relay.RegionID)
		if _, exists := served.Regions[regionID]; exists {
			return fmt.Errorf("managed relay region %d conflicts with deployment map", relay.RegionID)
		}
		served.Regions[regionID] = &tailcfg.DERPRegion{
			RegionID: regionID, RegionCode: relay.RegionCode, RegionName: relay.RegionName,
			Nodes: []*tailcfg.DERPNode{{Name: "xunara-" + strconv.Itoa(relay.RegionID), RegionID: regionID, HostName: relay.HostName, DERPPort: relay.DERPPort, STUNPort: relay.STUNPort, CertName: relay.CertName}},
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	previous := server.managedDERP.Load()
	if served == nil && (hasManaged || previous != nil && previous.Map != nil) {
		// nil 在增量中表示不变；删除最后一台时必须发送明确的空地图。
		served = &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}
	}
	encoded, _ := json.Marshal(served)
	fingerprint := string(encoded)
	if previous == nil || previous.Fingerprint != fingerprint {
		server.managedDERP.Store(&derpMapSnapshot{Map: served, Fingerprint: fingerprint})
		server.notifyWatchers()
	}
	return nil
}

func (server *Server) refreshRelayMapAfterChange(ctx context.Context) {
	if err := server.refreshRelayMap(ctx); err != nil {
		server.log.Error("relay map refresh failed; durable change will be retried", "err", err)
	}
}
