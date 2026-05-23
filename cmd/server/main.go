// Command d8a-server hosts MCP servers and exposes them over HTTP.
//
// In OSS / standalone mode it serves MCPs over a local HTTP endpoint
// gated by scoped API keys. In paid mode it additionally connects
// outbound to the d8a.in control plane for identity, signed policy,
// audit metadata, and rendezvous.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"d8a.in/d8a/internal/core"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(core.Version)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	logger.Info("d8a-server starting", "version", core.Version)

	// TODO: load config, start HTTP server, load MCP runners.
}
