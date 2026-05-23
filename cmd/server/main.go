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
	"syscall"

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
