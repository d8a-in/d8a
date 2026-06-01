// Command d8a-server hosts MCP servers and exposes them over HTTP.
//
// In OSS / standalone mode it serves MCPs over a local HTTP endpoint
// gated by scoped API keys. In paid mode it additionally connects
// outbound to the d8a.in control plane for identity, signed policy,
// audit metadata, and rendezvous.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"d8a.in/d8a/internal/core"
	"d8a.in/d8a/internal/server"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	configPath := flag.String("config", "", "path to JSON config file (required to enable /mcp endpoint)")
	listen := flag.String("listen", "", "HTTP listen address; overrides config")
	hashToken := flag.String("hash-token", "", "print SHA-256 hex of the given token (for generating apiKeys[].tokenHashHex) and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(core.Version)
		return
	}
	if *hashToken != "" {
		fmt.Println(server.HashToken(*hashToken))
		return
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	log.Info("d8a-server starting", "version", core.Version)

	fc := server.FileConfig{}
	if *configPath != "" {
		loaded, err := server.LoadFileConfig(*configPath)
		if err != nil {
			log.Error("config load failed", "err", err)
			os.Exit(1)
		}
		fc = loaded
	}
	if *listen != "" {
		fc.Listen = *listen
	}
	if fc.Listen == "" {
		fc.Listen = server.DefaultListenAddr
	}

	validator, err := server.NewAPIKeyValidator(fc.APIKeys)
	if err != nil {
		log.Error("invalid api keys", "err", err)
		os.Exit(1)
	}

	cfg := server.Config{
		ListenAddr:     fc.Listen,
		Audience:       fc.Audience,
		AllowedOrigins: fc.AllowedOrigins,
		Validator:      validator,
		ServerVersion:  core.Version,
		Catalog:        server.NewCatalog(fc.Capabilities),
		IdleTimeout:    time.Duration(fc.IdleTimeoutSeconds) * time.Second,
		SweepInterval:  time.Duration(fc.SweepIntervalSeconds) * time.Second,
	}
	if fc.RateLimit != nil {
		cfg.RateLimit = server.RateLimit{
			RequestsPerSecond: fc.RateLimit.RequestsPerSecond,
			Burst:             fc.RateLimit.Burst,
			EvictAfter:        time.Duration(fc.RateLimit.EvictAfterSeconds) * time.Second,
		}
		log.Info("rate limit configured",
			"rps", cfg.RateLimit.RequestsPerSecond,
			"burst", cfg.RateLimit.Burst)
	}
	if cfg.Catalog != nil {
		log.Info("capability catalog loaded", "bundles", len(fc.Capabilities))
	} else {
		log.Info("no capability catalog configured — permissive mode")
	}

	if fc.Backend != nil {
		// Log the resolved command + args at startup so the
		// operator's audit trail records exactly what was spawned.
		// (SEP-1024 / brainstorming #121: explicit consent surface.)
		log.Info("backing mcp configured",
			"command", fc.Backend.Command,
			"args", fc.Backend.Args,
			"isolate", fc.Backend.Isolate)

		var envSlice []string
		if len(fc.Backend.Env) > 0 {
			keys := make([]string, 0, len(fc.Backend.Env))
			for k := range fc.Backend.Env {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				envSlice = append(envSlice, k+"="+fc.Backend.Env[k])
			}
		} else {
			// Empty (not nil) so the StdioRunner factory doesn't
			// inherit d8a-server's environment.
			envSlice = []string{}
		}

		if fc.Backend.Sandbox != nil && fc.Backend.Sandbox.Disabled {
			log.Warn("backing mcp sandbox DISABLED — running without containment")
		} else {
			log.Info("backing mcp sandbox enabled",
				"network", coalesce(fc.Backend.Sandbox, "host"))
		}

		// Use the pool path (Config.Backend) so identities can be
		// isolated when fc.Backend.Isolate is true. shareSafe is
		// the inverse of Isolate.
		cfg.Backend = &server.Backend{
			Command: fc.Backend.Command,
			Args:    fc.Backend.Args,
			Env:     envSlice,
			Sandbox: fc.Backend.Sandbox,
			ClientInfo: server.Implementation{
				Name:    "d8a-server",
				Title:   "d8a Server",
				Version: core.Version,
			},
			Log: log,
		}
		cfg.BackendShareSafe = !fc.Backend.Isolate
	}

	// Catch SIGINT (Ctrl-C) and SIGTERM (systemd / kill) so the
	// server can drain in-flight requests on shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(cfg, log)
	if err := srv.Run(ctx); err != nil {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
	log.Info("d8a-server stopped cleanly")
}

// coalesce returns the policy's Network field, or fallback if the
// policy is nil or the field is empty.
func coalesce(p *server.SandboxPolicy, fallback string) string {
	if p == nil || p.Network == "" {
		return fallback
	}
	return p.Network
}
