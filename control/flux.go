package control

// This file implements Xunara Flux v1: file transfers between xunara-agent
// nodes, relayed by the control plane (PROJECT_SPEC section 25).
//
// The control plane stores metadata and opaque ciphertext only: the sender
// encrypts for the recipient (X25519 + HKDF + AES-256-GCM), so file content
// and keys never reach this process. A transfer moves only when both sides
// act: the sender offers, the recipient accepts and later confirms; every
// transition is conditional in the store, so a replayed request cannot skip a
// step.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

// Flux defaults. The size ceiling keeps the control plane's SQLite database
// and content directory bounded; deployments can lower them, not raise the
// hard cap (Flux refuses larger files rather than becoming a bulk data path).
const (
	// DefaultFluxMaxSize bounds one transfer's plaintext size.
	DefaultFluxMaxSize = 8 << 20
	// MaxFluxSize is the hard ceiling a configuration cannot exceed.
	MaxFluxSize = 64 << 20
	// DefaultFluxTTL bounds how long a transfer may stay active.
	DefaultFluxTTL = time.Hour
	// MaxFluxTTL bounds a configured TTL.
	MaxFluxTTL = 24 * time.Hour
	// DefaultFluxMaxActivePerNode bounds active transfers one node takes part
	// in, in either role.
	DefaultFluxMaxActivePerNode = 32
	// DefaultFluxMaxActiveTotal bounds active transfers per organization.
	DefaultFluxMaxActiveTotal = 1024
	// DefaultFluxMaxStoredBytes bounds the plaintext size of stored content.
	DefaultFluxMaxStoredBytes = 1 << 30

	// fluxOverhead reserves room in the stored ciphertext for the sender's
	// ephemeral public key, nonce and AEAD tag (section 25.2).
	fluxOverhead = 64
	// fluxNameLimit bounds the proposed file name.
	fluxNameLimit = 128
	// fluxReasonLimit mirrors state.FluxReasonLimit for request validation.
	fluxReasonLimit = state.FluxReasonLimit

	// fluxTerminalRetention keeps finished transfers readable for a day so
	// both sides can learn the outcome, then the janitor prunes them.
	fluxTerminalRetention = 24 * time.Hour
)

// FluxConfig configures Xunara Flux. Nil uses the defaults; Disabled turns the
// feature off (every flux endpoint answers 404).
type FluxConfig struct {
	// Disabled turns file transfer off entirely.
	Disabled bool
	// MaxSize bounds one transfer's plaintext size. Zero uses
	// [DefaultFluxMaxSize]; values above [MaxFluxSize] are rejected.
	MaxSize int64
	// TTL bounds how long an active transfer may live. Zero uses
	// [DefaultFluxTTL]; values above [MaxFluxTTL] are rejected.
	TTL time.Duration
	// Quotas bounds stored transfers. Zero fields use the defaults.
	Quotas state.FluxQuotas
	// Dir overrides where ciphertext is stored. Empty uses <StateDir>/flux.
	Dir string
}

// fluxServer is the normalized Flux configuration; nil on a Server means the
// feature is disabled.
type fluxServer struct {
	dir     string
	maxSize int64
	ttl     time.Duration
	quotas  state.FluxQuotas
}

// newFluxServer validates cfg and prepares the content directory. A nil
// configuration (or Disabled) leaves the feature off; a configuration that
// cannot work stops the server instead of being silently disabled, which
// would leave operators guessing why transfers fail.
func newFluxServer(stateDir string, cfg *FluxConfig) (*fluxServer, error) {
	if cfg == nil || cfg.Disabled {
		return nil, nil
	}
	fl := &fluxServer{
		maxSize: cfg.MaxSize,
		ttl:     cfg.TTL,
		quotas:  cfg.Quotas,
	}
	if fl.maxSize == 0 {
		fl.maxSize = DefaultFluxMaxSize
	}
	if fl.maxSize < 1 || fl.maxSize > MaxFluxSize {
		return nil, fmt.Errorf("control: flux max size %d is outside 1..%d", cfg.MaxSize, MaxFluxSize)
	}
	if fl.ttl == 0 {
		fl.ttl = DefaultFluxTTL
	}
	if fl.ttl < time.Minute || fl.ttl > MaxFluxTTL {
		return nil, fmt.Errorf("control: flux TTL %v is outside 1m..%v", cfg.TTL, MaxFluxTTL)
	}
	if fl.quotas.MaxActivePerNode == 0 {
		fl.quotas.MaxActivePerNode = DefaultFluxMaxActivePerNode
	}
	if fl.quotas.MaxActiveTotal == 0 {
		fl.quotas.MaxActiveTotal = DefaultFluxMaxActiveTotal
	}
	if fl.quotas.MaxStoredBytes == 0 {
		fl.quotas.MaxStoredBytes = DefaultFluxMaxStoredBytes
	}
	if fl.quotas.MaxActivePerNode < 1 || fl.quotas.MaxActiveTotal < 1 || fl.quotas.MaxStoredBytes < 1 {
		return nil, fmt.Errorf("control: flux quotas must be positive")
	}

	fl.dir = cfg.Dir
	if fl.dir == "" {
		fl.dir = filepath.Join(stateDir, "flux")
	}
	if err := os.MkdirAll(fl.dir, 0o700); err != nil {
		return nil, fmt.Errorf("control: creating flux content directory: %w", err)
	}
	return fl, nil
}

// fluxOverheadBytes is how much larger than the plaintext the stored
// ciphertext may be; anything larger is rejected before it is read.
func (fl *fluxServer) contentLimit(size int64) int64 { return size + fluxOverhead }

// contentPath resolves the ciphertext file of a transfer. Transfer IDs are
// server-generated ("fx_" + hex); the check is defence in depth against a
// future ID source ever becoming client-controlled.
func (fl *fluxServer) contentPath(id string) (string, error) {
	rest, ok := strings.CutPrefix(id, "fx_")
	if !ok || rest == "" || len(rest) != 32 {
		return "", fmt.Errorf("control: invalid flux transfer id %q", id)
	}
	if _, err := hex.DecodeString(rest); err != nil {
		return "", fmt.Errorf("control: invalid flux transfer id %q", id)
	}
	return filepath.Join(fl.dir, id+".bin"), nil
}

// removeContent deletes a transfer's ciphertext, ignoring a missing file.
func (fl *fluxServer) removeContent(id string) {
	path, err := fl.contentPath(id)
	if err != nil {
		return
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		// The caller logs; the store still stops serving the transfer.
		_ = err
	}
}

// writeContent stores ciphertext atomically: a temp file in the same
// directory is renamed into place, so a crash cannot leave a partial file
// visible under the transfer ID.
func (fl *fluxServer) writeContent(id string, src io.Reader, limit int64) (int64, error) {
	path, err := fl.contentPath(id)
	if err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(fl.dir, ".upload-*")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return 0, err
	}
	written, err := io.Copy(tmp, io.LimitReader(src, limit+1))
	if err != nil {
		tmp.Close()
		return 0, err
	}
	if written > limit {
		tmp.Close()
		return 0, errFluxTooLarge
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return 0, err
	}
	tmpName = ""
	return written, nil
}

// errFluxTooLarge reports a body past the transfer's content limit.
var errFluxTooLarge = errors.New("control: flux content exceeds the declared size")

// fluxTransferView is the JSON shape of a transfer on the agent API.
// RecipientKey is the recipient's per-transfer public key, which is public by
// design; content and any private key never appear here.
type fluxTransferView struct {
	ID                string    `json:"id"`
	Direction         string    `json:"direction"`
	State             string    `json:"state"`
	Name              string    `json:"name"`
	Size              int64     `json:"size"`
	SHA256            string    `json:"sha256"`
	SenderNodeID      string    `json:"senderNodeId"`
	SenderHostname    string    `json:"senderHostname"`
	RecipientNodeID   string    `json:"recipientNodeId"`
	RecipientHostname string    `json:"recipientHostname"`
	RecipientKey      string    `json:"recipientKey,omitempty"`
	Reason            string    `json:"reason,omitempty"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
	ExpiresAt         time.Time `json:"expiresAt"`
}

// fluxView renders a stored transfer for the caller.
func (s *Server) fluxView(t state.FluxTransfer, viewer state.NodeID) fluxTransferView {
	direction := "received"
	if t.SenderNode == viewer {
		direction = "sent"
	}
	view := fluxTransferView{
		ID:        t.ID,
		Direction: direction,
		State:     string(t.State),
		Name:      t.Name,
		Size:      t.Size,
		SHA256:    t.SHA256,
		Reason:    t.Reason,
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
		ExpiresAt: t.ExpiresAt,
	}
	if sender, ok := s.store.GetNodeByID(t.SenderNode); ok {
		view.SenderNodeID = sender.StableID
		view.SenderHostname = sender.Hostname
	}
	if recipient, ok := s.store.GetNodeByID(t.RecipientNode); ok {
		view.RecipientNodeID = recipient.StableID
		view.RecipientHostname = recipient.Hostname
	}
	if len(t.RecipientKey) > 0 {
		view.RecipientKey = base64.StdEncoding.EncodeToString(t.RecipientKey)
	}
	return view
}

// authenticateFlux authenticates an agent request through the header pair the
// binary endpoints use (a GET or PUT has no JSON body to carry them).
func (s *Server) authenticateFlux(req *http.Request) (state.Node, error) {
	body := agentRequest{
		MachineKey: req.Header.Get("X-Xunara-Machine-Key"),
		NodeKey:    req.Header.Get("X-Xunara-Node-Key"),
	}
	node, _, err := s.authenticateAgent(req, body)
	return node, err
}

// decodeFluxBody decodes an optional JSON payload; an empty body is fine for
// endpoints that take no fields.
func decodeFluxBody(w http.ResponseWriter, req *http.Request, out any) bool {
	if req.Body == nil || req.ContentLength == 0 {
		return true
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 8<<10)).Decode(out); err != nil && !errors.Is(err, io.EOF) {
		httpError(w, NewHTTPError(http.StatusBadRequest, "invalid JSON body", nil))
		return false
	}
	return true
}

// fluxError maps store errors onto the agent API's status codes: a transfer
// the caller is not part of is a 404 (IDs do not leak), a state conflict is a
// 409, a quota breach is a 429.
func (s *Server) fluxError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, state.ErrFluxTransferNotFound):
		httpError(w, NewHTTPError(http.StatusNotFound, "transfer not found", nil))
	case errors.Is(err, state.ErrFluxTransferState):
		httpError(w, NewHTTPError(http.StatusConflict, "transfer is not in a state that allows this", nil))
	case errors.Is(err, state.ErrFluxQuota):
		httpError(w, NewHTTPError(http.StatusTooManyRequests, "flux quota exceeded", nil))
	default:
		s.log.Error("flux transfer", "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
	}
}

// validateFluxName normalizes the proposed file name. It becomes a path
// component on the receiving side, so path separators and control characters
// are rejected here (the CLI applies the same rule before sending).
func validateFluxName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	switch {
	case name == "":
		return "", errors.New("a file name is required")
	case name == "." || name == "..":
		return "", errors.New("the file name is not a valid basename")
	case utf8.RuneCountInString(name) > fluxNameLimit:
		return "", fmt.Errorf("the file name is longer than %d characters", fluxNameLimit)
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '/' || r == '\\' {
			return "", errors.New("the file name must be a basename without control characters")
		}
	}
	return name, nil
}

// validateFluxSHA256 checks the plaintext digest the sender declares; the
// recipient verifies it after decryption, and the control plane only stores it.
func validateFluxSHA256(raw string) (string, error) {
	sum := strings.ToLower(strings.TrimSpace(raw))
	if len(sum) != 64 {
		return "", errors.New("sha256 must be 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(sum); err != nil {
		return "", errors.New("sha256 must be 64 hexadecimal characters")
	}
	return sum, nil
}

// validateFluxReason bounds the peer-visible explanation of a denial or
// failure: printable ASCII, so it cannot smuggle control sequences into a
// terminal or log line.
func validateFluxReason(raw string) (string, error) {
	reason := strings.TrimSpace(raw)
	if utf8.RuneCountInString(reason) > fluxReasonLimit {
		return "", fmt.Errorf("reason is longer than %d characters", fluxReasonLimit)
	}
	for _, r := range reason {
		if r < 0x20 || r > 0x7e {
			return "", errors.New("reason must be printable ASCII")
		}
	}
	return reason, nil
}

// handleFluxCreate implements POST /api/agent/v1/flux/transfers:
// the sender offers a file to another node.
func (s *Server) handleFluxCreate(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateFlux(req)
	if err != nil {
		httpError(w, err)
		return
	}

	var body struct {
		Recipient string `json:"recipient"`
		Name      string `json:"name"`
		Size      int64  `json:"size"`
		SHA256    string `json:"sha256"`
	}
	if !decodeFluxBody(w, req, &body) {
		return
	}

	recipient, ok := s.store.GetNodeByStableID(strings.TrimSpace(body.Recipient))
	if !ok {
		// Hostnames are not unique, so the API takes the stable ID; the CLI
		// resolves a hostname through the netmap.
		httpError(w, NewHTTPError(http.StatusBadRequest, "unknown recipient node", nil))
		return
	}
	if recipient.ID == node.ID {
		httpError(w, NewHTTPError(http.StatusBadRequest, "a node cannot send a file to itself", nil))
		return
	}
	name, err := validateFluxName(body.Name)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), nil))
		return
	}
	if body.Size < 0 || body.Size > s.flux.maxSize {
		httpError(w, NewHTTPError(http.StatusRequestEntityTooLarge,
			fmt.Sprintf("file size must be between 0 and %d bytes", s.flux.maxSize), nil))
		return
	}
	sha, err := validateFluxSHA256(body.SHA256)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), nil))
		return
	}

	transfer := state.FluxTransfer{
		SenderNode:    node.ID,
		RecipientNode: recipient.ID,
		Name:          name,
		Size:          body.Size,
		SHA256:        sha,
		ExpiresAt:     time.Now().Add(s.flux.ttl),
	}
	if err := s.store.CreateFluxTransfer(&transfer, s.flux.quotas); err != nil {
		s.fluxError(w, err)
		return
	}

	s.audit(nodeActor(node), identity.AuditFluxOffered, "flux:"+transfer.ID,
		fmt.Sprintf("offered %s (%d bytes) to %s", transfer.Name, transfer.Size, recipient.StableID))
	writeJSON(w, http.StatusCreated, s.fluxView(transfer, node.ID))
}

// handleFluxList implements GET /api/agent/v1/flux/transfers.
func (s *Server) handleFluxList(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateFlux(req)
	if err != nil {
		httpError(w, err)
		return
	}

	transfers := s.store.ListFluxTransfers(node.ID)
	views := make([]fluxTransferView, 0, len(transfers))
	for _, t := range transfers {
		views = append(views, s.fluxView(t, node.ID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"transfers": views})
}

// fluxTransition wraps the four single-step transitions that share a handler
// shape: resolve the transfer, act, audit, delete content when the transfer
// becomes terminal, and answer with the updated view.
func (s *Server) fluxTransition(w http.ResponseWriter, node state.Node, id, action string,
	step func(id string, actor state.NodeID) (state.FluxTransfer, error), audit string) {

	transfer, err := step(id, node.ID)
	if err != nil {
		s.fluxError(w, err)
		return
	}
	if !transfer.State.Active() {
		s.flux.removeContent(transfer.ID)
	}
	s.audit(nodeActor(node), audit, "flux:"+transfer.ID,
		fmt.Sprintf("%s %s (%d bytes)", action, transfer.Name, transfer.Size))
	writeJSON(w, http.StatusOK, s.fluxView(transfer, node.ID))
}

// handleFluxAccept implements POST /api/agent/v1/flux/transfers/{id}/accept.
func (s *Server) handleFluxAccept(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateFlux(req)
	if err != nil {
		httpError(w, err)
		return
	}
	var body struct {
		PublicKey string `json:"publicKey"`
	}
	if !decodeFluxBody(w, req, &body) {
		return
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body.PublicKey))
	if err != nil || len(key) != 32 {
		httpError(w, NewHTTPError(http.StatusBadRequest, "publicKey must be a base64 X25519 public key", nil))
		return
	}
	s.fluxTransition(w, node, chi.URLParam(req, "id"), "accepted",
		func(id string, actor state.NodeID) (state.FluxTransfer, error) {
			return s.store.AcceptFluxTransfer(id, actor, key)
		}, identity.AuditFluxAccepted)
}

// handleFluxDeny implements POST /api/agent/v1/flux/transfers/{id}/deny.
func (s *Server) handleFluxDeny(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateFlux(req)
	if err != nil {
		httpError(w, err)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if !decodeFluxBody(w, req, &body) {
		return
	}
	reason, err := validateFluxReason(body.Reason)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), nil))
		return
	}
	s.fluxTransition(w, node, chi.URLParam(req, "id"), "denied",
		func(id string, actor state.NodeID) (state.FluxTransfer, error) {
			return s.store.DenyFluxTransfer(id, actor, reason)
		}, identity.AuditFluxDenied)
}

// handleFluxCancel implements POST /api/agent/v1/flux/transfers/{id}/cancel.
func (s *Server) handleFluxCancel(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateFlux(req)
	if err != nil {
		httpError(w, err)
		return
	}
	s.fluxTransition(w, node, chi.URLParam(req, "id"), "cancelled",
		func(id string, actor state.NodeID) (state.FluxTransfer, error) {
			return s.store.CancelFluxTransfer(id, actor)
		}, identity.AuditFluxCancelled)
}

// handleFluxComplete implements POST
// /api/agent/v1/flux/transfers/{id}/complete: the recipient confirmed the
// decrypted content.
func (s *Server) handleFluxComplete(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateFlux(req)
	if err != nil {
		httpError(w, err)
		return
	}
	s.fluxTransition(w, node, chi.URLParam(req, "id"), "completed",
		func(id string, actor state.NodeID) (state.FluxTransfer, error) {
			return s.store.CompleteFluxTransfer(id, actor)
		}, identity.AuditFluxCompleted)
}

// handleFluxFail implements POST /api/agent/v1/flux/transfers/{id}/fail: the
// recipient could not decrypt or verify the content.
func (s *Server) handleFluxFail(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateFlux(req)
	if err != nil {
		httpError(w, err)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if !decodeFluxBody(w, req, &body) {
		return
	}
	reason, err := validateFluxReason(body.Reason)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusBadRequest, err.Error(), nil))
		return
	}
	s.fluxTransition(w, node, chi.URLParam(req, "id"), "failed",
		func(id string, actor state.NodeID) (state.FluxTransfer, error) {
			return s.store.FailFluxTransfer(id, actor, reason)
		}, identity.AuditFluxFailed)
}

// handleFluxUpload implements PUT /api/agent/v1/flux/transfers/{id}/content.
// The body is opaque ciphertext; the server bounds it by the declared plaintext
// size and stores it atomically.
func (s *Server) handleFluxUpload(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateFlux(req)
	if err != nil {
		httpError(w, err)
		return
	}
	id := chi.URLParam(req, "id")

	transfer, ok := s.store.GetFluxTransfer(id)
	if !ok || transfer.SenderNode != node.ID {
		httpError(w, NewHTTPError(http.StatusNotFound, "transfer not found", nil))
		return
	}
	if transfer.State != state.FluxAccepted {
		httpError(w, NewHTTPError(http.StatusConflict, "transfer is not in a state that allows this", nil))
		return
	}
	limit := s.flux.contentLimit(transfer.Size)
	if req.ContentLength > limit {
		httpError(w, NewHTTPError(http.StatusRequestEntityTooLarge, "content exceeds the declared size", nil))
		return
	}

	if _, err := s.flux.writeContent(id, req.Body, limit); err != nil {
		if errors.Is(err, errFluxTooLarge) {
			s.flux.removeContent(id)
			httpError(w, NewHTTPError(http.StatusRequestEntityTooLarge, "content exceeds the declared size", nil))
			return
		}
		s.log.Error("storing flux content", "transfer", id, "err", err)
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}

	updated, err := s.store.UploadFluxTransfer(id, node.ID)
	if err != nil {
		// Another instance (or a replayed request) already moved the
		// transfer; the file just written must not replace the winner's.
		s.flux.removeContent(id)
		s.fluxError(w, err)
		return
	}
	s.audit(nodeActor(node), identity.AuditFluxUploaded, "flux:"+updated.ID,
		fmt.Sprintf("uploaded %s (%d bytes)", updated.Name, updated.Size))
	writeJSON(w, http.StatusOK, s.fluxView(updated, node.ID))
}

// handleFluxDownload implements GET
// /api/agent/v1/flux/transfers/{id}/content: the recipient streams the
// ciphertext. A download may be retried until the transfer leaves "uploaded".
func (s *Server) handleFluxDownload(w http.ResponseWriter, req *http.Request) {
	node, err := s.authenticateFlux(req)
	if err != nil {
		httpError(w, err)
		return
	}
	id := chi.URLParam(req, "id")

	transfer, ok := s.store.GetFluxTransfer(id)
	if !ok || transfer.RecipientNode != node.ID {
		httpError(w, NewHTTPError(http.StatusNotFound, "transfer not found", nil))
		return
	}
	if transfer.State != state.FluxUploaded {
		httpError(w, NewHTTPError(http.StatusConflict, "transfer content is not available", nil))
		return
	}
	path, err := s.flux.contentPath(transfer.ID)
	if err != nil {
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}
	file, err := os.Open(path)
	if err != nil {
		s.log.Error("reading flux content", "transfer", transfer.ID, "err", err)
		httpError(w, NewHTTPError(http.StatusNotFound, "transfer content is missing", nil))
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		httpError(w, NewHTTPError(http.StatusInternalServerError, "internal error", nil))
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, req, "", info.ModTime(), file)
}
