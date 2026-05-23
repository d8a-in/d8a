// Command d8a-client connects an AI client (Claude, Codex, …) to a d8a-server.
//
// Two build modes (Go build tags, added later):
//   - headless: CLI/daemon for SSH, containers, CI; no display deps.
//   - gui:      Fyne-based system-tray agent for desktops.
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
	logger.Info("d8a-client starting", "version", core.Version)

	// TODO: load config, connect to server, expose local MCP endpoint.
}
