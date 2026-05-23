package server

import (
	"context"
	"encoding/json"
)

// Runner is a long-lived bridge to one backing MCP server.
//
// Implementations may be subprocess (stdio), remote HTTP, WASM, etc.
// — only the runner cares which. All methods MUST be goroutine-safe;
// the dispatch layer calls them concurrently from many in-flight
// client requests.
//
// Lifecycle: Start once at d8a-server startup (performs the backing
// MCP's initialize handshake and returns its advertised capabilities),
// then Call/Notify freely until Stop.
type Runner interface {
	// Start launches the backing MCP and performs its initialize/
	// initialized handshake. The returned ServerCapabilities is what
	// the backing MCP advertised — the dispatch layer will (later)
	// filter this through the catalog and identity scopes before
	// surfacing it to upstream clients.
	Start(ctx context.Context) (ServerCapabilities, error)

	// Call sends a JSON-RPC request and returns either the raw result
	// JSON or a JSON-RPC error. Concurrent callers are serialized on
	// the underlying transport with internal id remapping, so a
	// caller never sees another caller's response.
	Call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, *JSONRPCError)

	// Notify sends a JSON-RPC notification (no response expected).
	Notify(ctx context.Context, method string, params json.RawMessage) error

	// Stop terminates the backing MCP cleanly (close stdin per the
	// MCP stdio shutdown spec, then wait, then SIGKILL on stuck
	// processes).
	Stop() error
}
