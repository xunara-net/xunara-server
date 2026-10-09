package control

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// Xunara Relay control protocol (HTTP side).
//
// The contract is frozen in xunara-relay/docs/relay-protocol.md: a relay
// exchanges a one-time enrollment token for a long-lived identity, then reports
// status on heartbeats and receives its desired configuration in the answer.
// The relay's data plane never depends on this API; the control plane never
// proxies user traffic (supplement sections 74-75).
//
// Two surfaces live here:
//
//   - POST /api/relay/v1/{enroll,heartbeat}: the protocol itself. It is
//     authenticated by the relay's own credential, not by a session, because a
//     relay is a service identity (AGENTS.md section 5).
//   - /api/v2/relays/*: the operator surface for issuing enrollment tokens and
//     steering enrolled relays.
const (
	relayEnrollPath    = "/api/relay/v1/enroll"
	relayHeartbeatPath = "/api/relay/v1/heartbeat"
)

// Enrollment tokens are bounded so a leaked token is not a permanent key.
const (
	defaultRelayEnrollmentTTL = 24 * time.Hour
	maxRelayEnrollmentTTL     = 30 * 24 * time.Hour
)

// relayOnlineWindow is how long after its last heartbeat a relay still counts
// as online. The relay's default heartbeat interval is one minute, so this
// tolerates two missed reports before a relay looks down.
const relayOnlineWindow = 3 * time.Minute

// Bound untrusted relay-provided text so a hostile relay cannot grow the
// database or the console with unbounded strings.
const (
	maxRelayNameBytes    = 128
	maxRelayHostnameByte = 253
	maxRelayVersionBytes = 64
	maxRelayBodyBytes    = 64 << 10
)

// relayEnrollRequest is the body of POST /api/relay/v1/enroll.
//
// Unknown fields are accepted on purpose: a newer relay must be able to talk
// to an older control plane (relay-protocol.md section 4).
type relayEnrollRequest struct {
	Name       string `json:"name"`
	RegionCode string `json:"region_code"`
	RegionName string `json:"region_name"`
	RegionID   int    `json:"region_id,omitempty"`
	CertName   string `json:"cert_name,omitempty"`
	HostName   string `json:"hostname"`
	NodeKey    string `json:"node_key"`
	Version    string `json:"version"`
	DERPPort   int    `json:"derp_port"`
	STUNPort   int    `json:"stun_port"`
	Visibility string `json:"visibility"`
}

// relayEnrollResponse is the identity a relay stores (0600) and reuses.
type relayEnrollResponse struct {
	RelayID    string `json:"relay_id"`
	RelayToken string `json:"relay_token"`
	ControlURL string `json:"control_url"`
	Name       string `json:"name,omitempty"`
}

// relayHeartbeatRequest is the body of POST /api/relay/v1/heartbeat.
type relayHeartbeatRequest struct {
	Version          string `json:"version"`
	Healthy          bool   `json:"healthy"`
	UptimeSeconds    int64  `json:"uptime_seconds"`
	ConnectedClients int    `json:"connected_clients"`
	BytesIn          int64  `json:"bytes_in"`
	BytesOut         int64  `json:"bytes_out"`
}

// relayRemoteConfig is the answer to a heartbeat: the desired state of the
// relay. ConfigVersion is a string because the protocol treats it as an opaque
// token the relay compares for equality.
type relayRemoteConfig struct {
	DesiredState   string `json:"desired_state"`
	ConfigVersion  string `json:"config_version"`
	BandwidthLimit int64  `json:"bandwidth_limit"`
	RegionName     string `json:"region_name,omitempty"`
}

// writeRelayError answers with the protocol's error shape: relay clients read
// code and message, and the code is what automation matches on.
func writeRelayError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"code": code, "message": message})
}

// handleRelayEnroll implements POST /api/relay/v1/enroll.
func (s *Server) handleRelayEnroll(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok || !state.ValidRelayEnrollmentSecret(token) {
		writeRelayError(w, http.StatusUnauthorized, "RELAY_TOKEN_INVALID", "enrollment token is missing or malformed")
		return
	}
	record, err := s.store.LookupRelayEnrollmentToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, state.ErrRelayNotFound) {
			writeRelayError(w, http.StatusUnauthorized, "RELAY_TOKEN_INVALID", "enrollment token is unknown")
		} else {
			s.log.Error("reading a relay enrollment credential", "err", err)
			writeRelayError(w, http.StatusServiceUnavailable, "RELAY_INTERNAL", "the control plane could not complete enrollment")
		}
		return
	}

	var req relayEnrollRequest
	if !decodeRelayBody(w, r, &req) {
		return
	}
	relay, ok := s.validatedRelayFromRequest(w, req, record)
	if !ok {
		return
	}

	id, err := state.NewRelayID()
	if err != nil {
		s.log.Error("generating a relay id", "err", err)
		writeRelayError(w, http.StatusInternalServerError, "RELAY_INTERNAL", "the control plane could not complete enrollment")
		return
	}
	secret, err := state.NewRelayTokenSecret()
	if err != nil {
		s.log.Error("generating a relay token", "err", err)
		writeRelayError(w, http.StatusInternalServerError, "RELAY_INTERNAL", "the control plane could not complete enrollment")
		return
	}
	relay.ID = id
	relay.CreatedBy = "enrollment-token:" + record.ID
	// 套餐给出额度，存储在事务内读取实际用量，拒绝或故障时不消费操作员的令牌。
	entitlement := s.Plan()
	if _, err := s.store.EnrollRelay(r.Context(), token, relay, secret, entitlement.MaxRelays); err != nil {
		switch {
		case errors.Is(err, state.ErrRelayEnrollmentConsumed), errors.Is(err, state.ErrRelayAlreadyEnrolled):
			writeRelayError(w, http.StatusConflict, "RELAY_ALREADY_ENROLLED", "enrollment token or relay identity has already been used")
		case errors.Is(err, state.ErrRelayEnrollmentExpired):
			writeRelayError(w, http.StatusGone, "RELAY_ENROLLMENT_EXPIRED", "enrollment token has expired")
		case errors.Is(err, state.ErrRelayNotFound):
			writeRelayError(w, http.StatusUnauthorized, "RELAY_TOKEN_INVALID", "enrollment token is unknown")
		case errors.Is(err, state.ErrRelayLimitReached):
			writeRelayError(w, http.StatusForbidden, "RELAY_LIMIT_REACHED",
				fmt.Sprintf("the current plan allows %s relays", entitlement.RelayAllowance()))
		default:
			s.log.Error("committing relay enrollment", "err", err)
			writeRelayError(w, http.StatusServiceUnavailable, "RELAY_INTERNAL", "the control plane could not complete enrollment")
		}
		return
	}

	// The detail names the relay and its region, never the token.
	s.audit("relay:"+id, identity.AuditRelayEnrolled, "relay:"+id,
		fmt.Sprintf("enrolled from %s (region %s)", relay.HostName, relay.RegionCode))
	s.log.Info("relay enrolled",
		"relay", id, "hostname", relay.HostName, "region", relay.RegionCode, "visibility", relay.Visibility)
	s.refreshRelayMapAfterChange(r.Context())

	writeJSON(w, http.StatusOK, relayEnrollResponse{
		RelayID:    id,
		RelayToken: secret,
		ControlURL: s.cfg.ServerURL,
		Name:       relay.Name,
	})
}

// validatedRelayFromRequest turns a validated request into a relay value. It
// writes the protocol error and reports false when the request is invalid.
func (s *Server) validatedRelayFromRequest(w http.ResponseWriter, req relayEnrollRequest, record state.RelayEnrollmentToken) (state.Relay, bool) {
	if req.RegionID < 0 || req.RegionID > 65535 || req.CertName != "" && !validRelayCertPin(req.CertName) {
		writeRelayError(w, http.StatusBadRequest, "RELAY_REQUEST_INVALID", "region_id must be 0..65535 and cert_name must be a SHA-256 certificate pin")
		return state.Relay{}, false
	}
	if req.RegionID != 0 {
		var publicKey key.NodePublic
		if publicKey.UnmarshalText([]byte(req.NodeKey)) != nil || publicKey.IsZero() {
			writeRelayError(w, http.StatusBadRequest, "RELAY_REQUEST_INVALID", "managed map requires a valid DERP public key")
			return state.Relay{}, false
		}
		if s.cfg.DERPMap != nil && s.cfg.DERPMap.Regions[tailcfg.DERPRegionID(req.RegionID)] != nil {
			writeRelayError(w, http.StatusConflict, "RELAY_REGION_CONFLICT", "region ID is reserved by the deployment map; choose another region ID")
			return state.Relay{}, false
		}
		for _, existing := range s.store.ListRelays() {
			if existing.RegionID == req.RegionID {
				writeRelayError(w, http.StatusConflict, "RELAY_REGION_CONFLICT", "region ID is already enrolled; choose another region ID")
				return state.Relay{}, false
			}
		}
	}
	host := strings.TrimSpace(req.HostName)
	if !validRelayHostname(host) {
		writeRelayError(w, http.StatusBadRequest, "RELAY_REQUEST_INVALID", "hostname must be a DNS name or IP address without a scheme")
		return state.Relay{}, false
	}
	nodeKey := strings.TrimSpace(req.NodeKey)
	if !strings.HasPrefix(nodeKey, "nodekey:") || len(nodeKey) > 128 {
		writeRelayError(w, http.StatusBadRequest, "RELAY_REQUEST_INVALID", "node_key must be a DERP node public key")
		return state.Relay{}, false
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = host
	}
	if len(name) > maxRelayNameBytes {
		writeRelayError(w, http.StatusBadRequest, "RELAY_REQUEST_INVALID", "name is too long")
		return state.Relay{}, false
	}
	if len(req.Version) > maxRelayVersionBytes {
		writeRelayError(w, http.StatusBadRequest, "RELAY_REQUEST_INVALID", "version is too long")
		return state.Relay{}, false
	}
	if len(req.RegionCode) > maxRelayVersionBytes || len(req.RegionName) > maxRelayNameBytes {
		writeRelayError(w, http.StatusBadRequest, "RELAY_REQUEST_INVALID", "region code or name is too long")
		return state.Relay{}, false
	}
	visibility := strings.TrimSpace(req.Visibility)
	if visibility == "" {
		// The operator's token may pin the visibility; otherwise a relay is
		// private until an operator publishes it.
		visibility = record.Visibility
	}
	if visibility == "" {
		visibility = state.RelayVisibilityPrivate
	}
	if !state.ValidRelayVisibility(visibility) {
		writeRelayError(w, http.StatusBadRequest, "RELAY_REQUEST_INVALID", "visibility is not supported")
		return state.Relay{}, false
	}
	// 接入凭据只授权签发时指定的范围，服务身份不能自行升级为公共中继。
	if record.Visibility != "" && visibility != record.Visibility {
		writeRelayError(w, http.StatusForbidden, "RELAY_VISIBILITY_FORBIDDEN", "visibility must match the enrollment token")
		return state.Relay{}, false
	}
	if !validRelayPort(req.DERPPort) || !validRelayPort(req.STUNPort) {
		writeRelayError(w, http.StatusBadRequest, "RELAY_REQUEST_INVALID", "ports must be between 0 and 65535")
		return state.Relay{}, false
	}
	if existing, ok := s.store.RelayByNodeKey(nodeKey); ok {
		writeRelayError(w, http.StatusConflict, "RELAY_ALREADY_ENROLLED",
			"this node key is already enrolled as relay "+existing.ID)
		return state.Relay{}, false
	}

	return state.Relay{
		Name: name, HostName: host,
		RegionID: req.RegionID, CertName: req.CertName,
		RegionCode: strings.TrimSpace(req.RegionCode), RegionName: strings.TrimSpace(req.RegionName),
		NodeKey: nodeKey, Version: req.Version,
		DERPPort: req.DERPPort, STUNPort: req.STUNPort,
		Visibility: visibility, DesiredState: state.RelayStateOnline,
	}, true
}

func validRelayCertPin(value string) bool {
	pin, found := strings.CutPrefix(value, "sha256-raw:")
	if !found || len(pin) != 64 {
		return false
	}
	_, err := hex.DecodeString(pin)
	return err == nil
}

// handleRelayHeartbeat implements POST /api/relay/v1/heartbeat.
func (s *Server) handleRelayHeartbeat(w http.ResponseWriter, r *http.Request) {
	token, ok := bearerToken(r)
	if !ok || !state.ValidRelayToken(token) {
		writeRelayError(w, http.StatusUnauthorized, "RELAY_TOKEN_INVALID", "relay token is missing or malformed")
		return
	}
	relay, ok := s.store.RelayByToken(token)
	if !ok {
		writeRelayError(w, http.StatusUnauthorized, "RELAY_TOKEN_INVALID", "relay token is unknown")
		return
	}
	// A revoked relay must stop serving; the data plane is already refusing
	// clients, and the heartbeat is where it learns why.
	if relay.DesiredState == state.RelayStateRevoked {
		writeRelayError(w, http.StatusForbidden, "RELAY_REVOKED", "this relay has been revoked")
		return
	}

	var status relayHeartbeatRequest
	if !decodeRelayBody(w, r, &status) {
		return
	}
	if status.UptimeSeconds < 0 || status.ConnectedClients < 0 || status.BytesIn < 0 || status.BytesOut < 0 {
		writeRelayError(w, http.StatusBadRequest, "RELAY_REQUEST_INVALID", "counters must not be negative")
		return
	}

	if err := s.store.UpdateRelayHeartbeat(relay.ID, state.RelayHeartbeat{
		Version:          status.Version,
		Healthy:          status.Healthy,
		UptimeSeconds:    status.UptimeSeconds,
		ConnectedClients: status.ConnectedClients,
		BytesIn:          status.BytesIn,
		BytesOut:         status.BytesOut,
	}); err != nil {
		if errors.Is(err, state.ErrRelayNotFound) {
			writeRelayError(w, http.StatusUnauthorized, "RELAY_TOKEN_INVALID", "relay token is unknown")
			return
		}
		s.log.Error("recording a relay heartbeat", "relay", relay.ID, "err", err)
		writeRelayError(w, http.StatusInternalServerError, "RELAY_INTERNAL", "the control plane could not record the heartbeat")
		return
	}

	relay, ok = s.store.RelayByID(relay.ID)
	if !ok {
		writeRelayError(w, http.StatusUnauthorized, "RELAY_TOKEN_INVALID", "relay token is unknown")
		return
	}
	s.refreshRelayMapAfterChange(r.Context())
	writeJSON(w, http.StatusOK, relayRemoteConfig{
		DesiredState:   relay.DesiredState,
		ConfigVersion:  strconv.FormatUint(relay.ConfigVersion, 10),
		BandwidthLimit: relay.BandwidthLimit,
		RegionName:     relay.RegionName,
	})
}

// decodeRelayBody decodes a bounded JSON body, tolerating unknown fields.
func decodeRelayBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRelayBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeRelayError(w, http.StatusBadRequest, "RELAY_REQUEST_INVALID", "invalid JSON body")
		return false
	}
	return true
}

// validRelayHostname accepts a DNS name or IP address a client could dial.
func validRelayHostname(host string) bool {
	if host == "" || len(host) > maxRelayHostnameByte {
		return false
	}
	if strings.ContainsAny(host, "/ \t\r\n?#@") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	// A DNS name: at least one dot or a single label, labels bounded to 63
	// characters by DNS itself.
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, character := range label {
			if character != '-' && !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') {
				return false
			}
		}
	}
	return true
}

func validRelayPort(port int) bool { return port >= 0 && port <= 65535 }

// relayView is the JSON shape of an enrolled relay.
type relayView struct {
	RegionID         int    `json:"regionId"`
	CertName         string `json:"certName,omitempty"`
	ID               string `json:"id"`
	Name             string `json:"name"`
	Hostname         string `json:"hostname,omitempty"`
	RegionCode       string `json:"regionCode,omitempty"`
	RegionName       string `json:"regionName,omitempty"`
	NodeKey          string `json:"nodeKey,omitempty"`
	Version          string `json:"version,omitempty"`
	DERPPort         int    `json:"derpPort,omitempty"`
	STUNPort         int    `json:"stunPort,omitempty"`
	Visibility       string `json:"visibility"`
	DesiredState     string `json:"desiredState"`
	ConfigVersion    uint64 `json:"configVersion"`
	BandwidthLimit   int64  `json:"bandwidthLimit"`
	Healthy          bool   `json:"healthy"`
	Online           bool   `json:"online"`
	UptimeSeconds    int64  `json:"uptimeSeconds,omitempty"`
	ConnectedClients int    `json:"connectedClients,omitempty"`
	BytesIn          int64  `json:"bytesIn,omitempty"`
	BytesOut         int64  `json:"bytesOut,omitempty"`
	CreatedAt        string `json:"createdAt,omitempty"`
	LastSeen         string `json:"lastSeen,omitempty"`
	CreatedBy        string `json:"createdBy,omitempty"`
}

// relayViewFor renders one relay. The DERP node key is a public key: it is
// what clients pin, not a secret.
func relayViewFor(relay state.Relay, now time.Time) relayView {
	view := relayView{
		RegionID: relay.RegionID, CertName: relay.CertName,
		ID: relay.ID, Name: relay.Name, Hostname: relay.HostName,
		RegionCode: relay.RegionCode, RegionName: relay.RegionName,
		NodeKey: relay.NodeKey, Version: relay.Version,
		DERPPort: relay.DERPPort, STUNPort: relay.STUNPort,
		Visibility: relay.Visibility, DesiredState: relay.DesiredState,
		ConfigVersion: relay.ConfigVersion, BandwidthLimit: relay.BandwidthLimit,
		Healthy: relay.Healthy, UptimeSeconds: relay.UptimeSeconds,
		ConnectedClients: relay.ConnectedClients,
		BytesIn:          relay.BytesIn, BytesOut: relay.BytesOut,
		CreatedBy: relay.CreatedBy,
	}
	if !relay.Created.IsZero() {
		view.CreatedAt = relay.Created.UTC().Format(time.RFC3339)
	}
	if !relay.LastSeen.IsZero() {
		view.LastSeen = relay.LastSeen.UTC().Format(time.RFC3339)
		view.Online = relay.DesiredState == state.RelayStateOnline &&
			now.Sub(relay.LastSeen) <= relayOnlineWindow
	}
	return view
}

// relayViews renders every relay of this organization.
func (s *Server) relayViews() []relayView {
	now := time.Now().UTC()
	relays := s.store.ListRelays()
	out := make([]relayView, 0, len(relays))
	for _, relay := range relays {
		out = append(out, relayViewFor(relay, now))
	}
	return out
}

// relayEnrollTokenView is the JSON shape of an enrollment token. The secret is
// never part of it: it exists only in the answer that created it.
type relayEnrollTokenView struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Visibility string `json:"visibility"`
	ExpiresAt  string `json:"expiresAt,omitempty"`
	UsedAt     string `json:"usedAt,omitempty"`
	CreatedAt  string `json:"createdAt,omitempty"`
	CreatedBy  string `json:"createdBy,omitempty"`
	Used       bool   `json:"used"`
	Expired    bool   `json:"expired"`
}

func relayEnrollTokenViewFor(tok state.RelayEnrollmentToken, now time.Time) relayEnrollTokenView {
	view := relayEnrollTokenView{
		ID: tok.ID, Name: tok.Name, Visibility: tok.Visibility,
		CreatedBy: tok.CreatedBy, Used: tok.Used(), Expired: tok.Expired(now),
	}
	if !tok.Expiry.IsZero() {
		view.ExpiresAt = tok.Expiry.UTC().Format(time.RFC3339)
	}
	if !tok.UsedAt.IsZero() {
		view.UsedAt = tok.UsedAt.UTC().Format(time.RFC3339)
	}
	if !tok.Created.IsZero() {
		view.CreatedAt = tok.Created.UTC().Format(time.RFC3339)
	}
	return view
}

// createRelayEnrollmentToken issues a one-time token and returns its secret.
// It is the single code path behind the console API and the platform API, so
// the two surfaces cannot drift.
func (s *Server) createRelayEnrollmentToken(name, visibility string, ttl time.Duration, createdBy string) (state.RelayEnrollmentToken, string, error) {
	name = strings.TrimSpace(name)
	if len(name) > maxRelayNameBytes {
		return state.RelayEnrollmentToken{}, "", errors.New("name is too long")
	}
	if visibility == "" {
		visibility = state.RelayVisibilityPrivate
	}
	if !state.ValidRelayVisibility(visibility) {
		return state.RelayEnrollmentToken{}, "", errors.New("visibility is not supported")
	}
	if ttl <= 0 {
		ttl = defaultRelayEnrollmentTTL
	}
	if ttl > maxRelayEnrollmentTTL {
		return state.RelayEnrollmentToken{}, "", errors.New("ttl exceeds 30 days")
	}
	if p := s.Plan(); !p.AllowsRelays(len(s.store.ListRelays())) {
		return state.RelayEnrollmentToken{}, "", errRelayLimitReached
	}

	id, err := state.NewRelayEnrollmentTokenID()
	if err != nil {
		return state.RelayEnrollmentToken{}, "", err
	}
	secret, err := state.NewRelayEnrollmentTokenSecret()
	if err != nil {
		return state.RelayEnrollmentToken{}, "", err
	}

	tok := state.RelayEnrollmentToken{
		ID: id, Name: name, Visibility: visibility,
		Expiry:    time.Now().UTC().Add(ttl),
		CreatedBy: createdBy,
	}
	if err := s.store.CreateRelayEnrollmentToken(tok, secret); err != nil {
		return state.RelayEnrollmentToken{}, "", err
	}
	stored, ok := s.store.RelayEnrollmentTokenByID(id)
	if !ok {
		stored = tok
	}
	return stored, secret, nil
}

// errRelayLimitReached is the service-level form of RELAY_LIMIT_REACHED.
var errRelayLimitReached = errors.New("the current plan does not allow another relay")

// apiRelayEnrollTokenCreateRequest is the body of POST
// /api/v2/relays/enroll-tokens.
type apiRelayEnrollTokenCreateRequest struct {
	Name string `json:"name"`
	// Visibility pins what the relay may request; empty means private.
	Visibility string `json:"visibility"`
	// TTLSeconds bounds the token's life; empty means 24 hours.
	TTLSeconds int64 `json:"ttl_seconds"`
}

// handleAPIV2RelaysEnrolled implements GET /api/v2/relays/enrolled.
func (s *Server) handleAPIV2RelaysEnrolled(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	store, ok := s.store.(*state.SQLiteStore)
	if !ok {
		s.writeNetworkError(w, errors.New("relay management requires a durable store"))
		return
	}
	relays, err := store.ListRelaysContext(r.Context())
	if err != nil {
		s.writeNetworkError(w, err)
		return
	}
	views := make([]relayView, 0, len(relays))
	for _, relay := range relays {
		views = append(views, relayViewFor(relay, time.Now()))
	}
	used, limit := len(views), s.Plan().MaxRelays
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"items":       views,
		"used":        used,
		"limit":       limit,
		"csrf_token":  csrfTokenFor(s.accountSessionToken(r)),
		"control_url": s.cfg.ServerURL,
	})
}

// handleAPIV2Relay implements GET /api/v2/relays/{id}.
func (s *Server) handleAPIV2Relay(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	relay, ok := s.store.RelayByID(chi.URLParam(r, "id"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "relay not found")
		return
	}
	writeJSON(w, http.StatusOK, relayViewFor(relay, time.Now().UTC()))
}

// handleAPIV2CreateRelayEnrollToken implements POST
// /api/v2/relays/enroll-tokens. The secret is returned once and never stored
// in plaintext, so a lost token must be replaced rather than re-read.
func (s *Server) handleAPIV2CreateRelayEnrollToken(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNetworkWriter(w, r)
	if !ok {
		return
	}
	var req apiRelayEnrollTokenCreateRequest
	if !decodeAPIBody(w, r, &req) {
		return
	}
	if req.Visibility == state.RelayVisibilityPublic {
		writeAPIError(w, http.StatusForbidden, "public relay enrollment requires platform administration")
		return
	}

	tok, secret, err := s.createRelayEnrollmentToken(req.Name, req.Visibility, time.Duration(req.TTLSeconds)*time.Second, principal.actor())
	if err != nil {
		switch {
		case errors.Is(err, errRelayLimitReached):
			writeAPIError(w, http.StatusForbidden, err.Error())
		default:
			writeAPIError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	s.audit(principal.actor(), identity.AuditRelayEnrollTokenCreated, "relay-token:"+tok.ID,
		"created an enrollment token for a "+tok.Visibility+" relay")
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": secret,
		"item":  relayEnrollTokenViewFor(tok, time.Now().UTC()),
	})
}

// handleAPIV2RelayEnrollTokens implements GET /api/v2/relays/enroll-tokens.
func (s *Server) handleAPIV2RelayEnrollTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, identity.ScopeRead); !ok {
		return
	}
	now := time.Now().UTC()
	store, ok := s.store.(*state.SQLiteStore)
	if !ok {
		s.writeNetworkError(w, errors.New("relay management requires a durable store"))
		return
	}
	tokens, err := store.ListRelayEnrollmentTokensContext(r.Context())
	if err != nil {
		s.writeNetworkError(w, err)
		return
	}
	items := make([]relayEnrollTokenView, 0, len(tokens))
	for _, tok := range tokens {
		items = append(items, relayEnrollTokenViewFor(tok, now))
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// handleAPIV2DeleteRelayEnrollToken implements DELETE
// /api/v2/relays/enroll-tokens/{id}.
func (s *Server) handleAPIV2DeleteRelayEnrollToken(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNetworkWriter(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	if _, exists := s.store.RelayEnrollmentTokenByID(id); !exists {
		writeAPIError(w, http.StatusNotFound, "enrollment token not found")
		return
	}
	if err := s.store.DeleteRelayEnrollmentToken(id); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "could not revoke the enrollment token")
		return
	}
	s.audit(principal.actor(), identity.AuditRelayEnrollTokenRevoked, "relay-token:"+id, "revoked an enrollment token")
	s.log.Info("relay enrollment token revoked", "token", id, "actor", principal.actor())
	w.WriteHeader(http.StatusNoContent)
}

// apiRelayConfigRequest is the body of PATCH /api/v2/relays/{id}. Pointer
// fields distinguish "leave alone" from "set to zero".
type apiRelayConfigRequest struct {
	DesiredState   string  `json:"desired_state"`
	BandwidthLimit *int64  `json:"bandwidth_limit"`
	RegionName     *string `json:"region_name"`
}

// handleAPIV2UpdateRelay implements PATCH /api/v2/relays/{id}.
func (s *Server) handleAPIV2UpdateRelay(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNetworkWriter(w, r)
	if !ok {
		return
	}
	var req apiRelayConfigRequest
	if !decodeAPIBody(w, r, &req) {
		return
	}
	if req.DesiredState != "" && !state.ValidRelayState(req.DesiredState) {
		writeAPIError(w, http.StatusBadRequest, "desired_state must be online, maintenance, disabled or revoked")
		return
	}
	if req.BandwidthLimit != nil && *req.BandwidthLimit < -1 {
		writeAPIError(w, http.StatusBadRequest, "bandwidth_limit must be -1, 0 or a positive byte rate")
		return
	}
	if req.RegionName != nil && len(*req.RegionName) > maxRelayNameBytes {
		writeAPIError(w, http.StatusBadRequest, "region_name is too long")
		return
	}

	id := chi.URLParam(r, "id")
	relay, err := s.store.UpdateRelayConfig(id, state.RelayConfigUpdate{
		DesiredState:   req.DesiredState,
		BandwidthLimit: req.BandwidthLimit,
		RegionName:     req.RegionName,
	})
	if err != nil {
		if errors.Is(err, state.ErrRelayNotFound) {
			writeAPIError(w, http.StatusNotFound, "relay not found")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "could not update the relay")
		return
	}

	s.audit(principal.actor(), identity.AuditRelayUpdated, "relay:"+id,
		"desired state "+relay.DesiredState)
	s.log.Info("relay updated", "relay", id, "state", relay.DesiredState, "actor", principal.actor())
	s.refreshRelayMapAfterChange(r.Context())
	writeJSON(w, http.StatusOK, relayViewFor(relay, time.Now().UTC()))
}

// handleAPIV2DeleteRelay implements DELETE /api/v2/relays/{id}. Deleting a
// relay removes its credential; a relay that heartbeats afterwards is rejected.
func (s *Server) handleAPIV2DeleteRelay(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireNetworkWriter(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	relay, exists := s.store.RelayByID(id)
	if !exists {
		writeAPIError(w, http.StatusNotFound, "relay not found")
		return
	}
	if err := s.store.DeleteRelay(id); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "could not delete the relay")
		return
	}
	s.audit(principal.actor(), identity.AuditRelayDeleted, "relay:"+id, "deleted relay "+relay.Name)
	s.log.Info("relay deleted", "relay", id, "actor", principal.actor())
	s.refreshRelayMapAfterChange(r.Context())
	w.WriteHeader(http.StatusNoContent)
}
