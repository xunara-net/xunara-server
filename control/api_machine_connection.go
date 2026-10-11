package control

import (
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

const machineConnectionEndpointLimit = 32
const machineConnectionLatencyLimit = 128

type machineRelayServer struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	DERPPort int    `json:"derpPort"`
	STUNPort int    `json:"stunPort"`
	STUNOnly bool   `json:"stunOnly"`
}

type machineRelayRegion struct {
	ID               tailcfg.DERPRegionID `json:"id"`
	Code             string               `json:"code"`
	Name             string               `json:"name"`
	Source           string               `json:"source"`
	Advertised       bool                 `json:"advertised"`
	Servers          []machineRelayServer `json:"servers"`
	ServersTruncated bool                 `json:"serversTruncated"`
}

type machineRelayLatency struct {
	RegionID      tailcfg.DERPRegionID `json:"regionId"`
	Code          string               `json:"code"`
	Name          string               `json:"name"`
	AddressFamily string               `json:"addressFamily"`
	Milliseconds  float64              `json:"milliseconds"`
}

type machineNetworkReport struct {
	LinkType              string `json:"linkType"`
	UDP                   *bool  `json:"udp"`
	IPv6                  *bool  `json:"ipv6"`
	MappingVariesByDestIP *bool  `json:"mappingVariesByDestIP"`
	UPnP                  *bool  `json:"upnp"`
	PMP                   *bool  `json:"pmp"`
	PCP                   *bool  `json:"pcp"`
}

type machineConnectionView struct {
	StableID                 string                `json:"stableId"`
	GeneratedAt              time.Time             `json:"generatedAt"`
	ControlOnline            bool                  `json:"controlOnline"`
	LastControlSeenAt        *time.Time            `json:"lastControlSeenAt"`
	ReportAvailable          bool                  `json:"reportAvailable"`
	MapConfigured            bool                  `json:"mapConfigured"`
	PolicyMode               string                `json:"policyMode"`
	HomeRegion               *machineRelayRegion   `json:"homeRegion"`
	ReportedRegionID         tailcfg.DERPRegionID  `json:"reportedRegionId"`
	ReportedRegionAdvertised bool                  `json:"reportedRegionAdvertised"`
	Network                  *machineNetworkReport `json:"network"`
	Endpoints                []string              `json:"endpoints"`
	EndpointCount            int                   `json:"endpointCount"`
	EndpointsTruncated       bool                  `json:"endpointsTruncated"`
	Latencies                []machineRelayLatency `json:"latencies"`
	LatenciesTruncated       bool                  `json:"latenciesTruncated"`
}

func reportedBool(value opt.Bool) *bool {
	known, reported := value.Get()
	if !reported {
		return nil
	}
	return &known
}

// 只读取已存在的节点报告；HomeDERP 与控制面在线都不是实际点对点流量证明。
func (server *Server) machineConnectionView(node state.Node) machineConnectionView {
	served := server.derpMap
	var sources map[tailcfg.DERPRegionID]string
	// 地图和来源必须取自同一不可变快照，避免热更新期间拼出错误的中继归属。
	if snapshot := server.managedDERP.Load(); snapshot != nil {
		served, sources = snapshot.Map, snapshot.Sources
	}
	mode := string(server.derpPolicy.Mode)
	if mode == "" {
		mode = "inherit"
	}
	view := machineConnectionView{
		StableID: node.StableID, GeneratedAt: time.Now().UTC(), ControlOnline: server.isOnline(node.ID),
		MapConfigured: served != nil, PolicyMode: mode, Endpoints: []string{}, Latencies: []machineRelayLatency{},
	}
	if node.LastSeen != nil {
		lastSeen := *node.LastSeen
		view.LastControlSeenAt = &lastSeen
	}
	regionAt := func(identifier tailcfg.DERPRegionID) *tailcfg.DERPRegion {
		if served == nil || identifier <= 0 {
			return nil
		}
		return served.Regions[identifier]
	}
	if node.HomeDERP > 0 {
		home := &machineRelayRegion{ID: node.HomeDERP, Servers: []machineRelayServer{}}
		if region := regionAt(node.HomeDERP); region != nil {
			home.Code, home.Name, home.Advertised, home.Source = region.RegionCode, region.RegionName, true, "deployment"
			if source := sources[node.HomeDERP]; source != "" {
				home.Source = source
			}
			for _, relay := range region.Nodes {
				if relay == nil || relay.HostName == "" {
					continue
				}
				if len(home.Servers) == machineConnectionEndpointLimit {
					home.ServersTruncated = true
					break
				}
				derpPort, stunPort := relay.DERPPort, relay.STUNPort
				if derpPort == 0 && !relay.STUNOnly {
					derpPort = 443
				}
				if stunPort == 0 {
					stunPort = 3478
				}
				home.Servers = append(home.Servers, machineRelayServer{relay.Name, relay.HostName, derpPort, stunPort, relay.STUNOnly})
			}
			slices.SortFunc(home.Servers, func(first, second machineRelayServer) int {
				if compared := strings.Compare(first.Hostname, second.Hostname); compared != 0 {
					return compared
				}
				return strings.Compare(first.Name, second.Name)
			})
		}
		view.HomeRegion = home
	}
	for _, endpoint := range node.Endpoints {
		if !endpoint.IsValid() {
			continue
		}
		view.EndpointCount++
		if len(view.Endpoints) < machineConnectionEndpointLimit {
			view.Endpoints = append(view.Endpoints, endpoint.String())
		}
	}
	slices.Sort(view.Endpoints)
	view.EndpointsTruncated = view.EndpointCount > len(view.Endpoints)
	if node.Hostinfo == nil || node.Hostinfo.NetInfo == nil {
		return view
	}
	report := node.Hostinfo.NetInfo
	view.ReportAvailable = true
	view.Network = &machineNetworkReport{UDP: reportedBool(report.WorkingUDP), IPv6: reportedBool(report.WorkingIPv6),
		MappingVariesByDestIP: reportedBool(report.MappingVariesByDestIP), UPnP: reportedBool(report.UPnP), PMP: reportedBool(report.PMP), PCP: reportedBool(report.PCP)}
	switch report.LinkType {
	case "wired", "wifi", "mobile":
		view.Network.LinkType = report.LinkType
	}
	if report.PreferredDERP > 0 {
		view.ReportedRegionID = report.PreferredDERP
		view.ReportedRegionAdvertised = regionAt(report.PreferredDERP) != nil
	}
	// 上游键为 regionID-v4/v6、值为秒；不暴露旧 host:port 键或未下发区域。
	for measurement, seconds := range report.DERPLatency {
		identifier, family, found := strings.Cut(measurement, "-")
		if !found || (family != "v4" && family != "v6") || seconds < 0 || seconds > 3600 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
			continue
		}
		parsed, err := strconv.ParseInt(identifier, 10, 64)
		if err != nil || identifier != strconv.FormatInt(parsed, 10) {
			continue
		}
		region := regionAt(tailcfg.DERPRegionID(parsed))
		if region == nil {
			continue
		}
		view.Latencies = append(view.Latencies, machineRelayLatency{tailcfg.DERPRegionID(parsed), region.RegionCode,
			region.RegionName, "ip" + family, math.Round(seconds*100000) / 100})
	}
	slices.SortFunc(view.Latencies, func(first, second machineRelayLatency) int {
		if first.RegionID < second.RegionID {
			return -1
		}
		if first.RegionID > second.RegionID {
			return 1
		}
		return strings.Compare(first.AddressFamily, second.AddressFamily)
	})
	if len(view.Latencies) > machineConnectionLatencyLimit {
		view.Latencies = view.Latencies[:machineConnectionLatencyLimit]
		view.LatenciesTruncated = true
	}
	return view
}

func (server *Server) handleAPIMachineConnection(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if _, allowed := server.requireScope(writer, request, identity.ScopeRead); !allowed {
		return
	}
	node, found := server.lookupAPINode(chi.URLParam(request, "ref"))
	if !found {
		writeAPIError(writer, http.StatusNotFound, "machine not found")
		return
	}
	writeJSON(writer, http.StatusOK, server.machineConnectionView(node))
}
