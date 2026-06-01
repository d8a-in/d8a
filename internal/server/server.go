// Package server contains the d8a-server HTTP runtime.
//
// In OSS / standalone mode it serves MCP traffic over a local HTTP endpoint;
// in paid mode (added later) it also dials out to the d8a.in control plane.
// This package owns the lifecycle: listen, serve, drain on shutdown.
package server

import (
	"context"
	"errors"
	"fmt"
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

	// ServerVersion is reported as serverInfo.version in MCP
	// initialize responses. cmd/server wires this in from
	// internal/core so the server package stays free of the
	// dependency.
	ServerVersion string

	// Sessions is the SessionStore implementation. If nil, an
	// InMemorySessionStore is constructed in New.
	Sessions SessionStore

	// Runner is the legacy / test path: a single Runner shared by
	// every request. Mutually exclusive with Backend — set one or
	// the other. Tests typically set this to a pre-built fake or
	// StdioRunner.
	Runner Runner

	// Backend describes how to spawn backing-MCP subprocesses on
	// demand. When set, Run constructs a RunnerPool from it and
	// dispatches requests through the pool (mutually exclusive
	// with Runner).
	Backend *Backend

	// BackendShareSafe controls pool behavior when Backend is set:
	// true (default) means one Runner serves every identity;
	// false means each identity gets its own Runner. See
	// brainstorming #112/#113.
	BackendShareSafe bool

	// Catalog filters what each authenticated identity can see and
	// do at the MCP protocol layer (initialize capabilities,
	// tools/list, tools/call, resources/*, prompts/*). nil = no
	// catalog configured → permissive mode (back-compat with the
	// pre-M6 behavior).
	Catalog *Catalog

	// IdleTimeout controls how long a session can go without
	// activity before the background GC removes it. The zero value
	// applies a sensible default (DefaultIdleTimeout); set to a
	// negative duration to disable the GC entirely (sessions live
	// forever — only suitable for short-lived test processes).
	IdleTimeout time.Duration

	// SweepInterval is how often the GC goroutine wakes to check
	// for expired sessions. The zero value applies a sensible
	// default (DefaultSweepInterval).
	SweepInterval time.Duration

	// RateLimit configures per-identity request rate limiting at
	// the /mcp endpoint. Zero RequestsPerSecond disables limiting
	// — see brainstorming #103 for the design.
	RateLimit RateLimit

	// PoolIdleTimeout controls how long a per-identity backing
	// Runner can sit unused in the pool before being stopped and
	// reaped. Only meaningful in isolate mode (the shared runner
	// is never evicted). Zero applies a default of 15 minutes; a
	// negative value disables pool eviction.
	PoolIdleTimeout time.Duration
}

// DefaultPoolIdleTimeout is the per-identity pool-eviction default
// applied when Config.PoolIdleTimeout is zero. 15 minutes is long
// enough that a user idle-thinking between tool calls doesn't pay
// for re-spawning every time, short enough that a one-off connector
// doesn't keep a subprocess alive for hours.
const DefaultPoolIdleTimeout = 15 * time.Minute

// DefaultIdleTimeout is the session-GC idle threshold applied when
// Config.IdleTimeout is zero. Half an hour balances "drop forgotten
// browser tabs" against "don't kick an active assistant mid-task."
const DefaultIdleTimeout = 30 * time.Minute

// DefaultSweepInterval is how often the GC goroutine scans the
// session store when Config.SweepInterval is zero. One minute is
// fine-grained enough that the actual idle window is close to
// IdleTimeout without burning CPU on idle servers.
const DefaultSweepInterval = 1 * time.Minute

// Server is the d8a-server runtime. Construct with New, then call Run.
type Server struct {
	cfg      Config
	log      *slog.Logger
	http     *http.Server
	sessions SessionStore

	// runner is the live backing MCP from the legacy path, populated
	// by Run after a successful Start. nil when no runner is
	// configured.
	runner Runner

	// pool is the multi-instance backing-MCP pool from the Backend
	// path. nil when no Backend was configured. Mutually exclusive
	// with runner.
	pool *RunnerPool

	// backendCaps is what the backing MCP advertised during its own
	// initialize. Returned in d8a-server's initialize response so
	// upstream MCP clients see the underlying capabilities. In pool
	// mode it's the union (single-backend pools advertise the same
	// caps for every instance).
	backendCaps ServerCapabilities

	// catalog filters per-identity what each session sees and can
	// call. nil = no catalog → permissive mode.
	catalog *Catalog

	// limiter throttles per identity. nil = rate limiting disabled.
	limiter *RateLimiter
}

// New constructs a Server. Defaults are applied to cfg before use.
func New(cfg Config, log *slog.Logger) *Server {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}

	s := &Server{
		cfg:      cfg,
		log:      log,
		sessions: cfg.Sessions,
		catalog:  cfg.Catalog,
		limiter:  NewRateLimiter(cfg.RateLimit),
	}
	if s.sessions == nil {
		s.sessions = NewInMemorySessionStore()
	}

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
// /healthz is an unauthenticated liveness probe. /mcp (POST/GET/DELETE)
// is the MCP Streamable HTTP endpoint, guarded by the full middleware
// chain. Middleware order is intentional: cheapest rejections first
// (Origin, then protocol version, then bearer validation).
func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	mcpChain := func(h http.HandlerFunc) http.Handler {
		return Chain(
			h,
			RequireOrigin(s.cfg.AllowedOrigins, s.log),
			ParseProtocolVersion(),
			RequireAuth(s.cfg.Validator, s.cfg.Audience, s.log),
			RequireRateLimit(s.limiter, s.log),
		)
	}
	mux.Handle("POST /mcp", mcpChain(s.handleMCPPost))
	mux.Handle("GET /mcp", mcpChain(s.handleMCPGet))
	mux.Handle("DELETE /mcp", mcpChain(s.handleMCPDelete))
}

// idleAndSweep resolves Config.IdleTimeout / Config.SweepInterval
// into their effective values, applying defaults for zero and
// returning (0, 0) when GC is explicitly disabled (IdleTimeout < 0).
func (s *Server) idleAndSweep() (idle, sweep time.Duration) {
	idle = s.cfg.IdleTimeout
	switch {
	case idle < 0:
		return 0, 0 // GC disabled
	case idle == 0:
		idle = DefaultIdleTimeout
	}
	sweep = s.cfg.SweepInterval
	if sweep <= 0 {
		sweep = DefaultSweepInterval
	}
	return idle, sweep
}

// runSessionGC periodically sweeps three idle-data stores at a
// single cadence: the SessionStore for expired sessions, the rate
// limiter for unused buckets, and the runner pool for cold
// per-identity backing MCPs. One ticker, three jobs.
//
// Exits when ctx is canceled. Each job is bypassed cleanly when
// its corresponding feature is disabled / nil.
func (s *Server) runSessionGC(ctx context.Context, idle, sweep time.Duration) {
	poolIdle := s.poolIdleTimeout()
	s.log.Info("background GC enabled",
		"session_idle_timeout", idle,
		"sweep_interval", sweep,
		"rate_limiter_active", s.limiter != nil,
		"pool_idle_timeout", poolIdle)
	ticker := time.NewTicker(sweep)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if n := s.sessions.ExpireBefore(now.Add(-idle)); n > 0 {
				s.log.Info("expired idle sessions",
					"count", n, "idle_timeout", idle)
			}
			if s.limiter != nil {
				if n := s.limiter.Cleanup(now.Add(-s.cfg.RateLimit.EvictAfter)); n > 0 {
					s.log.Debug("evicted idle rate-limit buckets", "count", n)
				}
			}
			if s.pool != nil && poolIdle > 0 {
				if n := s.pool.EvictIdle(now.Add(-poolIdle)); n > 0 {
					s.log.Info("evicted idle pool runners",
						"count", n, "idle_timeout", poolIdle)
				}
			}
		}
	}
}

// poolIdleTimeout resolves Config.PoolIdleTimeout into its effective
// value. Zero → DefaultPoolIdleTimeout; negative → 0 (disabled).
func (s *Server) poolIdleTimeout() time.Duration {
	t := s.cfg.PoolIdleTimeout
	switch {
	case t < 0:
		return 0
	case t == 0:
		return DefaultPoolIdleTimeout
	default:
		return t
	}
}

// handleHealthz is a basic liveness probe — proves the process is up
// and serving. Real readiness (e.g. MCP runners ready) will live at a
// different endpoint later.
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// shutdownTimeout caps how long graceful shutdown is allowed to wait
// for in-flight requests to finish before being forcibly closed.
const shutdownTimeout = 10 * time.Second

// Run starts the HTTP server and blocks until either ctx is canceled
// (triggering a graceful shutdown) or the listener errors.
//
// If a Runner is configured, Run starts it *before* listening so we
// never accept traffic against a backend that's not ready, caches its
// capabilities, and stops it *after* HTTP has drained so in-flight
// requests are not abruptly cut off.
func (s *Server) Run(ctx context.Context) error {
	switch {
	case s.cfg.Runner != nil && s.cfg.Backend != nil:
		return fmt.Errorf("Config.Runner and Config.Backend are mutually exclusive")
	case s.cfg.Runner != nil:
		s.runner = s.cfg.Runner
		s.log.Info("starting backing MCP (singleton)")
		caps, err := s.runner.Start(ctx)
		if err != nil {
			return fmt.Errorf("backing mcp start: %w", err)
		}
		s.backendCaps = caps
		defer func() {
			if err := s.runner.Stop(); err != nil {
				s.log.Warn("backing mcp stop", "err", err)
			}
		}()
	case s.cfg.Backend != nil:
		s.pool = NewRunnerPool(*s.cfg.Backend, s.cfg.BackendShareSafe, s.log)
		s.log.Info("starting backing MCP pool",
			"share_safe", s.cfg.BackendShareSafe)
		if err := s.pool.Start(ctx); err != nil {
			return fmt.Errorf("backing mcp pool start: %w", err)
		}
		s.backendCaps = s.pool.Caps()
		defer func() {
			if err := s.pool.Close(); err != nil {
				s.log.Warn("backing mcp pool stop", "err", err)
			}
		}()
	}

	// Start the session-GC goroutine unless explicitly disabled
	// (Config.IdleTimeout < 0). It exits when ctx is canceled, just
	// before HTTP shutdown begins — sessions outliving the server
	// process don't matter, so no separate shutdown coordination
	// is needed.
	idleTimeout, sweepInterval := s.idleAndSweep()
	if idleTimeout > 0 {
		go s.runSessionGC(ctx, idleTimeout, sweepInterval)
	}

	s.log.Info("listening", "addr", s.cfg.ListenAddr)

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
		return err
	case <-ctx.Done():
		s.log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return <-serveErr
	}
}
