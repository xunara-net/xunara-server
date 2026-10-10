package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"tailscale.com/tailcfg"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/networkconfig"
)

const officialDERPMapURL = "https://controlplane.tailscale.com/derpmap/default"
const externalDERPMaxBytes = 2 << 20

var errDERPRegionConflict = errors.New("DERP region is reserved by another map source")

func emptyExternalDERPMap() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}
}

// validateExternalDERPMap 保留上游完整字段，禁止测试用 TLS 绕过及无效端口。
func validateExternalDERPMap(value *tailcfg.DERPMap) error {
	if value == nil || value.Regions == nil || len(value.Regions) > 128 {
		return errors.New("a DERP map with up to 128 regions is required")
	}
	names := make(map[string]bool)
	for identifier, region := range value.Regions {
		if !identifier.IsValid() || region == nil || region.RegionID != identifier || len(region.Nodes) == 0 || len(region.Nodes) > 16 || len(region.RegionCode) > 64 || len(region.RegionName) > 128 {
			return errors.New("each region needs a matching positive ID and one to sixteen nodes")
		}
		for _, node := range region.Nodes {
			if node == nil || node.RegionID != identifier || node.Name == "" || len(node.Name) > 128 || names[node.Name] || !validRelayHostname(node.HostName) || node.InsecureForTests || node.STUNTestIP != "" {
				return errors.New("each node needs a unique name, matching region and a valid TLS hostname; test overrides are forbidden")
			}
			names[node.Name] = true
			if node.DERPPort < 0 || node.DERPPort > 65535 || node.STUNPort < -1 || node.STUNPort > 65535 {
				return errors.New("DERP port must be 0..65535; STUN port must be -1..65535")
			}
			if node.CertName != "" && !validRelayCertPin(node.CertName) && !validRelayHostname(node.CertName) {
				return errors.New("TLS certificate name must be a hostname or a SHA-256 raw certificate pin")
			}
			for _, entry := range []struct {
				address string
				ipv4    bool
			}{{node.IPv4, true}, {node.IPv6, false}} {
				if entry.address == "" || entry.address == "none" {
					continue
				}
				address, err := netip.ParseAddr(entry.address)
				if err != nil || address.Is4() != entry.ipv4 || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
					return errors.New("forced node addresses must have the correct IP family or be 'none'")
				}
			}
		}
	}
	if value.HomeParams != nil {
		for identifier, score := range value.HomeParams.RegionScore {
			if value.Regions[identifier] == nil || score <= 0 || math.IsNaN(score) || math.IsInf(score, 0) {
				return errors.New("home scores require existing regions and finite positive values")
			}
		}
	}
	return nil
}

func decodeExternalDERPMap(reader io.Reader) (*tailcfg.DERPMap, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var value tailcfg.DERPMap
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("DERP map must be a single JSON document")
	}
	return &value, validateExternalDERPMap(&value)
}

func (server *Server) externalDERPConfiguration(ctx context.Context) (networkconfig.Document, *tailcfg.DERPMap, error) {
	document, found, err := server.networkConfig.Get(ctx, networkconfig.DERP)
	if err != nil || !found {
		return document, emptyExternalDERPMap(), err
	}
	value, err := decodeExternalDERPMap(strings.NewReader(document.Content))
	return document, value, err
}

func (server *Server) externalDERPView(request *http.Request) (map[string]any, error) {
	document, value, err := server.externalDERPConfiguration(request.Context())
	if err != nil {
		return nil, err
	}
	applied := document.Revision == 0
	if snapshot := server.managedDERP.Load(); snapshot != nil {
		applied = snapshot.ExternalRevision == document.Revision
	}
	return map[string]any{"revision": document.Revision, "map": value, "applied": applied,
		"csrf_token": csrfTokenFor(server.accountSessionToken(request)), "official_url": officialDERPMapURL}, nil
}

func (server *Server) handleAPIExternalDERPConfiguration(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireScope(writer, request, identity.ScopeRead); !ok {
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	view, err := server.externalDERPView(request)
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, view)
}

// checkExternalDERPRegions 在发布事务内检查所有托管记录，包括离线、维护中的节点。
func (server *Server) checkExternalDERPRegions(ctx context.Context, transaction *sql.Tx, value *tailcfg.DERPMap) error {
	for identifier := range value.Regions {
		if server.cfg.DERPMap != nil && server.cfg.DERPMap.Regions[identifier] != nil {
			return errDERPRegionConflict
		}
		var occupied bool
		if err := transaction.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM relays WHERE region_id=?)", identifier).Scan(&occupied); err != nil {
			return err
		}
		if occupied {
			return errDERPRegionConflict
		}
	}
	return nil
}

func checkEnrolledExternalDERPRegion(ctx context.Context, transaction *sql.Tx, identifier tailcfg.DERPRegionID) error {
	if identifier == 0 {
		return nil
	}
	var content string
	err := transaction.QueryRowContext(ctx, "SELECT content FROM network_documents WHERE kind=?", networkconfig.DERP).Scan(&content)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	value, err := decodeExternalDERPMap(strings.NewReader(content))
	if err != nil {
		return err
	}
	if value.Regions[identifier] != nil {
		return errDERPRegionConflict
	}
	return nil
}

func (server *Server) handleAPISaveExternalDERP(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireNetworkWriter(writer, request)
	if !ok {
		return
	}
	var body struct {
		Revision    *uint64          `json:"revision"`
		Map         *tailcfg.DERPMap `json:"map"`
		RestoreFrom *uint64          `json:"restore_from"`
	}
	if !decodeAPIBody(writer, request, &body) {
		return
	}
	if body.Revision == nil || body.Map != nil && body.RestoreFrom != nil {
		writeAPIError(writer, http.StatusBadRequest, "DERP_MAP_INVALID: expected revision and one map or history version are required")
		return
	}
	if body.RestoreFrom != nil {
		document, err := server.networkConfig.Version(request.Context(), networkconfig.DERP, *body.RestoreFrom)
		if err != nil {
			server.writeNetworkError(writer, err)
			return
		}
		body.Map, err = decodeExternalDERPMap(strings.NewReader(document.Content))
		if err != nil {
			server.writeNetworkError(writer, err)
			return
		}
	}
	if err := validateExternalDERPMap(body.Map); err != nil {
		writeAPIError(writer, http.StatusBadRequest, "DERP_MAP_INVALID: "+err.Error())
		return
	}
	content, err := json.Marshal(body.Map)
	if err != nil || len(content) > externalDERPMaxBytes {
		writeAPIError(writer, http.StatusBadRequest, "DERP_MAP_INVALID: map is too large")
		return
	}
	server.networkMu.Lock()
	defer server.networkMu.Unlock()
	_, err = server.networkConfig.SaveChecked(request.Context(), networkconfig.DERP, string(content), `{"Regions":{}}`, *body.Revision, networkWriter(principal), func(ctx context.Context, transaction *sql.Tx) error {
		return server.checkExternalDERPRegions(ctx, transaction, body.Map)
	})
	if errors.Is(err, errDERPRegionConflict) {
		writeAPIError(writer, http.StatusConflict, "DERP_REGION_CONFLICT: default or managed relay already uses this region ID")
		return
	}
	if err == nil {
		err = server.refreshRelayMap(request.Context())
	}
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	view, err := server.externalDERPView(request)
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, view)
}

func (server *Server) handleAPIExternalDERPHistory(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireScope(writer, request, identity.ScopeRead); !ok {
		return
	}
	documents, err := server.networkConfig.History(request.Context(), networkconfig.DERP)
	if err != nil {
		server.writeNetworkError(writer, err)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, map[string]any{"items": documents})
}

// 只访问固定官方 HTTPS 源，不接受用户 URL，也不跟随重定向；不附带任何身份凭据。
func fetchOfficialDERPMap(ctx context.Context, transport http.RoundTripper) (*tailcfg.DERPMap, error) {
	client := &http.Client{Timeout: 12 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, officialDERPMapURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("official DERP map could not be fetched")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("official DERP map returned HTTP %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, externalDERPMaxBytes+1))
	if err != nil || len(content) > externalDERPMaxBytes {
		return nil, errors.New("official DERP map response is incomplete or too large")
	}
	return decodeExternalDERPMap(strings.NewReader(string(content)))
}

func (server *Server) handleAPIImportOfficialDERP(writer http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireNetworkWriter(writer, request); !ok {
		return
	}
	value, err := fetchOfficialDERPMap(request.Context(), nil)
	if err != nil {
		writeAPIError(writer, http.StatusBadGateway, "DERP_IMPORT_FAILED: official map unavailable; existing relays are unchanged")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"map": value, "source": officialDERPMapURL})
}
