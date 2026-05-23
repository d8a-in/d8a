// Package server contains the d8a-server HTTP runtime.
//
// In OSS / standalone mode it serves MCP traffic over a local HTTP endpoint;
// in paid mode (added later) it also dials out to the d8a.in control plane.
// This package owns the lifecycle: listen, serve, drain on shutdown.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// DefaultListenAddr is the default HTTP listen address.
//
// We deliberately bind to loopback only by default so a fresh install
// never accidentally exposes itself to the network. Operators who need
// to listen on a routable interface must opt in via configuration.
// (See README design notes: safe-by-default.)
const DefaultListenAddr = "127.0.0.1:8443"

// Config holds the user-facing server configuration. New fields here
// should also be reachable via the FileConfig + flags in cmd/server.
type Config struct {
	// ListenAddr is the address the HTTP server binds to.
	// Empty string falls back to DefaultListenAddr.
	ListenAddr string

	// Audience is the canonical URL of this d8a-server instance.
	// Bearer tokens presented by clients must be bound to this
	// audience (RFC 8707) to be accepted.
	Audience string

	// AllowedOrigins is the allow-list for the HTTP `Origin` header
	// (DNS-rebinding defense). Empty allow-list with a request that
	// carries any non-empty Origin is denied with 403.
	AllowedOrigins []string

	// Validator authenticates Bearer tokens presented at /mcp.
	// Required when the /mcp endpoint is exposed; if nil, /mcp will
	// uniformly return 401 (the safe failure mode).
	Validator Validator
}

// Server is the d8a-server runtime. Construct with New, then call Run.
type Server struct {
	cfg  Config
	log  *slog.Logger
	http *http.Server
}

// New constructs a Server. Defaults are applied to cfg before use.
func New(cfg Config, log *slog.Logger) *Server {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}

	s := &Server{cfg: cfg, log: log}

	mux := http.NewServeMux()
	s.routes(mux)

	s.http = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return s
}

// routes registers HTTP routes on mux.
//
// /healthz is a public liveness probe — no auth, no middleware. /mcp
// is the placeholder for the MCP Streamable HTTP endpoint, guarded by
// the full middleware stack so M2's behavior can be exercised before
// any MCP logic exists. Middleware order is intentional: cheapest
// rejections first.
func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	mcp := Chain(
		http.HandlerFunc(s.handleMCPPlaceholder),
		RequireOrigin(s.cfg.AllowedOrigins, s.log),
		ParseProtocolVersion(),
		RequireAuth(s.cfg.Validator, s.cfg.Audience, s.log),
	)
	mux.Handle("POST /mcp", mcp)
	mux.Handle("GET /mcp", mcp)
}

// handleHealthz is a basic liveness probe — proves the process is up
// and serving. Real readiness (e.g. MCP runners ready) will live at a
// different endpoint later.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// handleMCPPlaceholder runs after the middleware stack has accepted a
// request. M3 will replace it with the real initialize handshake.
// For now it returns 501 with a small JSON body that echoes the
// resolved identity and protocol version, so a hands-on smoke test
// can verify each middleware did its job.
func (s *Server) handleMCPPlaceholder(w http.ResponseWriter, r *http.Request) {
	id, _ := IdentityFromContext(r.Context())
	v, _ := ProtocolVersionFromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":           "mcp endpoint not yet implemented",
		"note":            "initialize handshake lands in milestone 3",
		"subject":         id.Subject,
		"protocolVersion": v,
	})
}

// shutdownTimeout caps how long graceful shutdown is allowed to wait
// for in-flight requests to finish before being forcibly closed.
const shutdownTimeout = 10 * time.Second

// Run starts the HTTP server and blocks until either ctx is canceled
// (triggering a graceful shutdown) or the listener errors. It returns
// the first error encountered, or nil on a clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	s.log.Info("listening", "addr", s.cfg.ListenAddr)

	// ListenAndServe blocks; run it on a goroutine so we can also wait
	// on ctx in this function. The buffered channel reports the listener
	// error (or nil if Shutdown closed it normally).
	serveErr := make(chan error, 1)
	go func() {
		err := s.http.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		// Listener exited on its own (e.g. bind error).
		return err
	case <-ctx.Done():
		s.log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			return err
		}
		// Drain the serve goroutine to ensure a clean exit.
		return <-serveErr
	}
}
