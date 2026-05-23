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

## License & Model

d8a is intentionally **permissive open source** ([Apache-2.0](LICENSE)). We chose permissive licensing over source-available alternatives (BSL, Elastic License, SSPL, AGPL) for three reasons:

- **The moat lives in the architecture, not the license.** Paid d8a.in features — secure tunnel, control plane, signed policy distribution, multi-connector fleets, threat-rule intelligence — are closed source and live in a separate repository. The open-source server and client deliver a complete, useful, self-hostable product on a trusted network *on their own*; the paid layer adds secure-remote access, scale, and central governance.
- **Trust is a feature.** For a security product, "you can read every line of code that touches your data" is a stronger guarantee than any vendor promise. Permissive licensing preserves that without legal asterisks.
- **Adoption matters more than defending against forks.** Our wedge user is a developer self-hosting on a trusted network; we want as few barriers as possible.

Want the paid features? See [d8a.in](https://d8a.in).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All commits must be DCO-signed (`git commit -s`).
