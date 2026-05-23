# d8a

A blind MCP gateway: connect your team's AI to internal services without exposing data or credentials to anyone outside your network.

**Status:** Early scaffold. Not yet usable.

## Components

- **`d8a-server`** — hosts MCPs and serves them over HTTP. Runs inside the customer's network.
- **`d8a-client`** — connects an AI client (Claude, Codex, …) to a `d8a-server`. Headless (SSH/LXC/CI) and GUI (desktop) builds from one codebase via Go build tags.

## Build

Requires **Go 1.26+**.

```bash
make build      # builds both binaries into ./bin/
make test       # runs tests
make fmt vet    # formatting + static checks
```

Or directly:

```bash
go build ./...
go run ./cmd/server --version
go run ./cmd/client --version
```

## License

[Apache-2.0](LICENSE).
