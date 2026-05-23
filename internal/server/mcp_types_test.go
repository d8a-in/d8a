package server

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestInitializeParamsAlwaysIncludesCapabilities guards against a
// subtle Go JSON encoding pitfall: `,omitempty` on a map field will
// drop the key entirely for an empty (but non-nil) map. The MCP spec
// requires the `capabilities` field on initialize *even when empty*,
// and strict backing MCPs reject the handshake without it. This test
// is the canary.
func TestInitializeParamsAlwaysIncludesCapabilities(t *testing.T) {
	params := InitializeParams{
		ProtocolVersion: "2025-11-25",
		Capabilities:    ClientCapabilities{}, // empty but non-nil
		ClientInfo:      Implementation{Name: "x", Version: "0"},
	}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"capabilities":{}`) {
		t.Fatalf("expected empty capabilities object in JSON; got: %s", raw)
	}

	// And also when the map is nil — same outcome (empty object), so a
	// caller that forgets to initialize the map still gets a spec-
	// compliant on-the-wire message.
	params2 := InitializeParams{
		ProtocolVersion: "2025-11-25",
		ClientInfo:      Implementation{Name: "x", Version: "0"},
	}
	raw2, _ := json.Marshal(params2)
	if !strings.Contains(string(raw2), `"capabilities":`) {
		t.Fatalf("nil capabilities map should still serialize the key; got: %s", raw2)
	}
}
