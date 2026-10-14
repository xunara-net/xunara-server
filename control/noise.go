package control

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/http2"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	// ts2021UpgradePath is the path the server listens on for the TS2021
	// control protocol upgrade.
	ts2021UpgradePath = "/ts2021"

	// earlyPayloadMagic is the first 5 bytes the server sends over Noise before
	// the HTTP/2 stream starts: a marker that cannot be mistaken for an HTTP/2
	// frame, followed by a 4-byte big-endian length, followed by a JSON
	// [tailcfg.EarlyNoise]. See tailscale/control/controlhttp.
	earlyPayloadMagic = "\xff\xff\xffTS"

	// noiseBodyLimit caps request bodies on the Noise router. The Noise
	// handshake accepts any machine key without checking registration, so all
	// endpoints behind it are reachable without credentials; the limit prevents
	// unauthenticated OOM via unbounded reads. No legitimate request
	// ([tailcfg.RegisterRequest], [tailcfg.MapRequest], ...) comes close.
	noiseBodyLimit int64 = 1 << 20 // 1 MiB
)

// errUnsupportedClientVersion is returned when a client's capability version is
// below [MinSupportedCapabilityVersion].
var errUnsupportedClientVersion = errors.New("unsupported client version")

// noiseServer is the per-connection state of a TS2021 session.
type noiseServer struct {
	server *Server

	conn       *controlbase.Conn
	machineKey key.MachinePublic

	// challenge is a fresh per-connection challenge the client must answer by
	// proving possession of its node key.
	challenge key.ChallengePrivate
	clientIP  string
}

// handleNoiseUpgrade implements /ts2021: it hijacks the HTTP connection,
// completes the Noise handshake, and then serves the machine-control API over
// HTTP/2 on the encrypted connection.
func (s *Server) handleNoiseUpgrade(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Upgrade") == "" {
		// The client did not request a protocol upgrade. This typically means a
		// reverse proxy in front of Xunara is not passing WebSocket/upgrade
		// requests through.
		s.log.Warn("TS2021 request without Upgrade header; a reverse proxy may be stripping it",
			"remote", req.RemoteAddr)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	ns := &noiseServer{
		server:    s,
		challenge: key.NewChallenge(),
		clientIP:  s.clientIP(req),
	}

	conn, err := controlhttpserver.AcceptHTTP(req.Context(), w, req, s.noiseKey, ns.earlyNoise)
	if err != nil {
		// AcceptHTTP always writes an HTTP response itself; nothing more to do.
		s.log.Warn("noise upgrade failed", "remote", req.RemoteAddr, "err", err)
		return
	}
	defer conn.Close()

	ns.conn = conn
	ns.machineKey = conn.Peer()

	handler := ns.router()
	if dispatch := s.noiseDispatch.Load(); dispatch != nil {
		handler = dispatch.Handler(ns)
	}
	base := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{BaseConfig: base})
}

// earlyNoise writes the early payload the client reads immediately after the
// handshake: the version-gated [tailcfg.EarlyNoise] carrying the node-key
// challenge.
func (ns *noiseServer) earlyNoise(protocolVersion int, w io.Writer) error {
	if !isSupportedVersion(tailcfg.CapabilityVersion(protocolVersion)) {
		return fmt.Errorf("%w: %d", errUnsupportedClientVersion, protocolVersion)
	}

	payload, err := json.Marshal(&tailcfg.EarlyNoise{
		NodeKeyChallenge: ns.challenge.Public(),
	})
	if err != nil {
		return err
	}

	var magic [5]byte
	copy(magic[:], earlyPayloadMagic)

	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))

	if _, err := w.Write(magic[:]); err != nil {
		return err
	}
	if _, err := w.Write(length[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)

	return err
}

// router is the HTTP/2 API served *inside* a Noise session. Only machine
// control endpoints live here.
func (ns *noiseServer) router() http.Handler {
	r := chi.NewRouter()

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			req.Body = http.MaxBytesReader(w, req.Body, noiseBodyLimit)
			next.ServeHTTP(w, req)
		})
	})

	r.Route("/machine", func(r chi.Router) {
		r.Post("/register", ns.handleRegister)
		r.Post("/map", ns.handleMap)
		r.Post("/set-dns", ns.handleSetDNS)
		r.Post("/feature/query", ns.handleFeatureQuery)
		r.Post("/audit-log", ns.handleAuditLog)
		r.Post("/update-health", ns.handleUpdateHealth)
		r.Get("/whoami", ns.handleWhoami)
		r.Patch("/set-device-attr", ns.handleSetDeviceAttrs)
		r.Post("/id-token", ns.handleIDToken)
		r.Get("/ssh/action/{srcNodeID}/to/{dstNodeID}", ns.handleSSHAction)

		// Tailnet lock (TKA). The official client issues all of these as GET
		// requests with a JSON body; the paths mirror upstream.
		r.Route("/tka", func(r chi.Router) {
			r.Get("/init/begin", ns.handleTKAInitBegin)
			r.Get("/init/finish", ns.handleTKAInitFinish)
			r.Get("/bootstrap", ns.handleTKABootstrap)
			r.Get("/sync/offer", ns.handleTKASyncOffer)
			r.Get("/sync/send", ns.handleTKASyncSend)
			r.Get("/disable", ns.handleTKADisable)
			r.Get("/sign", ns.handleTKASign)
			r.Get("/affected-sigs", ns.handleTKAAffectedSigs)
		})
	})

	return r
}

// rejectUnsupported writes a 400 and reports true when a client's capability
// version is below the floor. It is the single chokepoint for version gating
// inside a Noise session.
func (ns *noiseServer) rejectUnsupported(w http.ResponseWriter, version tailcfg.CapabilityVersion, nkey key.NodePublic) bool {
	if isSupportedVersion(version) {
		return false
	}

	ns.server.log.Warn("rejecting unsupported client",
		"min_cap_ver", int(MinSupportedCapabilityVersion),
		"client_cap_ver", int(version),
		"node.key", nkey.ShortString(),
		"machine.key", ns.machineKey.ShortString())

	http.Error(w, errUnsupportedClientVersion.Error(), http.StatusBadRequest)

	return true
}
