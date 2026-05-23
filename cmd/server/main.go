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
	listen := flag.String("listen", server.DefaultListenAddr, "HTTP listen address")
	flag.Parse()

	if *showVersion {
		fmt.Println(core.Version)
		return
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	log.Info("d8a-server starting", "version", core.Version)

	// Catch SIGINT (Ctrl-C) and SIGTERM (systemd/`kill`) so the
	// server can drain in-flight requests on shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(server.Config{ListenAddr: *listen}, log)
	if err := srv.Run(ctx); err != nil {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
	log.Info("d8a-server stopped cleanly")
}
