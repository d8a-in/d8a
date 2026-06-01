package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ----- POST /mcp helpers -----

// mcpPost performs an authorized POST /mcp request with the given
// body and optional session id. It returns the raw HTTP response so
// callers can inspect status, headers, and body.
func mcpPost(t *testing.T, base, token, sessionID, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("MCP-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

// initializeSession performs a successful initialize and returns the
// MCP-Session-Id header from the response.
func initializeSession(t *testing.T, base, token string) string {
	t.Helper()
	body := `{
		"jsonrpc":"2.0","id":1,"method":"initialize",
		"params":{
			"protocolVersion":"2025-11-25",
			"capabilities":{},
			"clientInfo":{"name":"test-client","version":"0.0.1"}
		}
	}`
	resp := mcpPost(t, base, token, "", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("initialize status = %d, body = %s", resp.StatusCode, raw)
	}
	sid := resp.Header.Get("MCP-Session-Id")
	if sid == "" {
		t.Fatal("initialize did not return MCP-Session-Id")
	}
	return sid
}

func decodeRPC(t *testing.T, body io.Reader) JSONRPCMessage {
	t.Helper()
	var m JSONRPCMessage
	if err := json.NewDecoder(body).Decode(&m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return m
}

// ----- initialize -----

func TestInitialize_Success(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	body := `{"jsonrpc":"2.0","id":42,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"0"}}}`
	resp := mcpPost(t, base, "secret", "", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("MCP-Session-Id") == "" {
		t.Error("MCP-Session-Id header missing")
	}

	msg := decodeRPC(t, resp.Body)
	if string(msg.ID) != "42" {
		t.Errorf("response id = %s, want 42", msg.ID)
	}
	if msg.Error != nil {
		t.Fatalf("unexpected error: %+v", msg.Error)
	}

	var result InitializeResult
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.ProtocolVersion != "2025-11-25" {
		t.Errorf("ProtocolVersion = %q", result.ProtocolVersion)
	}
	if result.ServerInfo.Name != "d8a-server" {
		t.Errorf("ServerInfo.Name = %q", result.ServerInfo.Name)
	}
	// M3 announces an empty capability set — verify it's an empty
	// object (not missing, not null).
	if result.Capabilities == nil {
		t.Errorf("Capabilities is nil; want empty object")
	}
}

func TestInitialize_NegotiatesUnknownVersionToPreferred(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01","capabilities":{},"clientInfo":{"name":"c","version":"0"}}}`
	resp := mcpPost(t, base, "secret", "", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	msg := decodeRPC(t, resp.Body)
	var result InitializeResult
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.ProtocolVersion != preferredProtocolVersion {
		t.Errorf("ProtocolVersion = %q, want %q", result.ProtocolVersion, preferredProtocolVersion)
	}
}

func TestInitialize_BadJSON(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	resp := mcpPost(t, base, "secret", "", `{not json`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (JSON-RPC error in body)", resp.StatusCode)
	}
	msg := decodeRPC(t, resp.Body)
	if msg.Error == nil || msg.Error.Code != ErrCodeParseError {
		t.Fatalf("Error = %+v, want code %d", msg.Error, ErrCodeParseError)
	}
}

func TestInitialize_BadEnvelope(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	// Well-formed JSON, wrong jsonrpc version.
	resp := mcpPost(t, base, "secret", "", `{"jsonrpc":"1.0","id":1,"method":"initialize"}`)
	defer resp.Body.Close()

	msg := decodeRPC(t, resp.Body)
	if msg.Error == nil || msg.Error.Code != ErrCodeInvalidRequest {
		t.Fatalf("Error = %+v, want code %d", msg.Error, ErrCodeInvalidRequest)
	}
}

// ----- session handling -----

func TestPing_RequiresSession(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	// Skip initialize — try ping without a session id.
	resp := mcpPost(t, base, "secret", "", `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	msg := decodeRPC(t, resp.Body)
	if msg.Error == nil || msg.Error.Code != ErrCodeInvalidRequest {
		t.Fatalf("Error = %+v, want code %d", msg.Error, ErrCodeInvalidRequest)
	}
}

func TestPing_UnknownSession(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	resp := mcpPost(t, base, "secret", "session-that-never-existed", `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestPing_Success(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	sid := initializeSession(t, base, "secret")

	resp := mcpPost(t, base, "secret", sid, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	msg := decodeRPC(t, resp.Body)
	if msg.Error != nil {
		t.Fatalf("Error = %+v", msg.Error)
	}
	if string(msg.ID) != "2" {
		t.Errorf("response id = %s, want 2", msg.ID)
	}
}

func TestNotificationInitialized_Accepted(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	sid := initializeSession(t, base, "secret")

	resp := mcpPost(t, base, "secret", sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	// Body MUST be empty per spec.
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("body = %q, want empty", body)
	}
}

func TestUnknownMethod_ReturnsMethodNotFound(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	sid := initializeSession(t, base, "secret")

	resp := mcpPost(t, base, "secret", sid, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	defer resp.Body.Close()

	msg := decodeRPC(t, resp.Body)
	if msg.Error == nil || msg.Error.Code != ErrCodeMethodNotFound {
		t.Fatalf("Error = %+v, want code %d", msg.Error, ErrCodeMethodNotFound)
	}
}

// ----- cross-identity hijack defense (brainstorming #120) -----

func TestSession_RejectsCrossIdentityAccess(t *testing.T) {
	// Two API keys for two different subjects, both bound to the same
	// audience. A session issued to alice MUST NOT be usable by bob,
	// even though bob's token is otherwise valid.
	const audience = "http://aud.example/mcp"
	aliceKey := APIKey{TokenHashHex: HashToken("alice-secret"), Audience: audience, Subject: "alice"}
	bobKey := APIKey{TokenHashHex: HashToken("bob-secret"), Audience: audience, Subject: "bob"}
	v, err := NewAPIKeyValidator([]APIKey{aliceKey, bobKey})
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	base, teardown := startTestServer(t, testServerOpts{
		validator: v,
		audience:  audience,
	})
	defer teardown()

	sid := initializeSession(t, base, "alice-secret")

	// Bob now tries to use Alice's session id with bob's token.
	resp := mcpPost(t, base, "bob-secret", sid, `{"jsonrpc":"2.0","id":99,"method":"ping"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

// ----- GET and DELETE -----

func TestGetMCP_Returns405(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	req, _ := http.NewRequest(http.MethodGet, base+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 (no SSE stream offered)", resp.StatusCode)
	}
}

func TestDeleteMCP_TerminatesSession(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	sid := initializeSession(t, base, "secret")

	req, _ := http.NewRequest(http.MethodDelete, base+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	req.Header.Set("MCP-Session-Id", sid)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", resp.StatusCode)
	}

	// A subsequent ping with that session must now 404.
	pingResp := mcpPost(t, base, "secret", sid, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	defer pingResp.Body.Close()
	if pingResp.StatusCode != http.StatusNotFound {
		t.Fatalf("post-delete ping status = %d, want 404", pingResp.StatusCode)
	}
}

func TestDeleteMCP_RequiresSessionHeader(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	req, _ := http.NewRequest(http.MethodDelete, base+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// ----- backend forwarding (M4) -----

// mcpTestOptsWithBackend returns test options including a real
// StdioRunner backed by the test-helper fake MCP. The harness's
// teardown will Stop the runner via Server.Run's deferred cleanup.
func mcpTestOptsWithBackend(t *testing.T) testServerOpts {
	t.Helper()
	opts := mcpTestOpts(t)
	opts.runner = NewStdioRunner(fakeMCPCmd(t),
		Implementation{Name: "d8a-server-test", Version: "0"},
		newRunnerLogger())
	return opts
}

func TestInitialize_AdvertisesBackendCapabilities(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOptsWithBackend(t))
	defer teardown()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`
	resp := mcpPost(t, base, "secret", "", body)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	msg := decodeRPC(t, resp.Body)
	var result InitializeResult
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The fake MCP advertises {"tools":{}}; we should pass that
	// through into our own initialize response.
	if _, ok := result.Capabilities["tools"]; !ok {
		t.Fatalf("Capabilities = %v, want tools key (forwarded from backend)", result.Capabilities)
	}
}

func TestToolsList_ForwardedToBackend(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOptsWithBackend(t))
	defer teardown()

	sid := initializeSession(t, base, "secret")

	resp := mcpPost(t, base, "secret", sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	msg := decodeRPC(t, resp.Body)
	if msg.Error != nil {
		t.Fatalf("Error = %+v", msg.Error)
	}
	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Permissive mode (no catalog on these opts) → the backend's
	// full tool list comes through verbatim. The fake now exposes
	// echo + secret-tool; we check both are present.
	names := map[string]bool{}
	for _, tool := range result.Tools {
		names[tool.Name] = true
	}
	if !names["echo"] || !names["secret-tool"] {
		t.Fatalf("tools/list missing expected tools; got %+v", result.Tools)
	}
}

func TestToolsCall_ForwardedAndPreservesResult(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOptsWithBackend(t))
	defer teardown()

	sid := initializeSession(t, base, "secret")

	// The fake echoes params back as "content". Send a distinctive
	// payload and confirm we receive it verbatim.
	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"x":42}}}`
	resp := mcpPost(t, base, "secret", sid, body)
	defer resp.Body.Close()

	msg := decodeRPC(t, resp.Body)
	if msg.Error != nil {
		t.Fatalf("Error = %+v", msg.Error)
	}
	var result struct {
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(result.Content) != `{"name":"echo","arguments":{"x":42}}` {
		t.Fatalf("content = %s, want params echoed back verbatim", result.Content)
	}
}

func TestBackendError_ForwardedAsJSONRPCError(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOptsWithBackend(t))
	defer teardown()

	sid := initializeSession(t, base, "secret")

	resp := mcpPost(t, base, "secret", sid, `{"jsonrpc":"2.0","id":4,"method":"boom"}`)
	defer resp.Body.Close()

	msg := decodeRPC(t, resp.Body)
	if msg.Error == nil {
		t.Fatal("expected error from backing boom method")
	}
	if msg.Error.Code != -32000 {
		t.Errorf("Code = %d, want -32000 (backend's error code preserved)", msg.Error.Code)
	}
}

func TestMethodNotFound_WithoutBackend(t *testing.T) {
	// No backend → unknown methods return our own method-not-found,
	// not a forwarded error.
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	sid := initializeSession(t, base, "secret")
	resp := mcpPost(t, base, "secret", sid, `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	defer resp.Body.Close()

	msg := decodeRPC(t, resp.Body)
	if msg.Error == nil || msg.Error.Code != ErrCodeMethodNotFound {
		t.Fatalf("Error = %+v, want code %d", msg.Error, ErrCodeMethodNotFound)
	}
}

// ----- catalog / curated capabilities (M6) -----

// mcpTestOptsWithCatalog returns opts with the fake-MCP backend AND
// a validator whose key has the given scopes. Catalog grants "echo"
// to scope "demo:basic" and nothing else.
func mcpTestOptsWithCatalog(t *testing.T, scopes []string) testServerOpts {
	t.Helper()
	const audience = "http://aud.example/mcp"
	v, err := NewAPIKeyValidator([]APIKey{{
		TokenHashHex: HashToken("secret"),
		Audience:     audience,
		Subject:      "alice",
		Scopes:       scopes,
	}})
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	return testServerOpts{
		validator: v,
		audience:  audience,
		runner: NewStdioRunner(fakeMCPCmd(t),
			Implementation{Name: "d8a-server-test", Version: "0"},
			newRunnerLogger()),
		catalog: NewCatalog(map[string]CapabilityBundle{
			"demo:basic": {Tools: []string{"echo"}}, // grants "echo" only
			"demo:full":  {Tools: []string{"*"}},    // wildcard
		}),
	}
}

func TestCatalog_InitializeFiltersUnentitledCapabilities(t *testing.T) {
	// Identity has zero scopes → no tools granted → the backend
	// announces "tools" but our initialize response must NOT.
	base, teardown := startTestServer(t, mcpTestOptsWithCatalog(t, nil))
	defer teardown()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}`
	resp := mcpPost(t, base, "secret", "", body)
	defer resp.Body.Close()

	msg := decodeRPC(t, resp.Body)
	var result InitializeResult
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := result.Capabilities["tools"]; ok {
		t.Fatalf("identity with no scopes should not see 'tools' capability; got %v", result.Capabilities)
	}
}

func TestCatalog_InitializeKeepsEntitledCapabilities(t *testing.T) {
	// Identity granted "demo:basic" → tools key remains.
	base, teardown := startTestServer(t, mcpTestOptsWithCatalog(t, []string{"demo:basic"}))
	defer teardown()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}`
	resp := mcpPost(t, base, "secret", "", body)
	defer resp.Body.Close()

	msg := decodeRPC(t, resp.Body)
	var result InitializeResult
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := result.Capabilities["tools"]; !ok {
		t.Fatalf("identity with demo:basic should see 'tools' capability; got %v", result.Capabilities)
	}
}

func TestCatalog_ToolsListDropsUnentitled(t *testing.T) {
	// "demo:basic" grants only "echo"; the fake MCP also exposes
	// "secret-tool"; tools/list MUST hide secret-tool.
	base, teardown := startTestServer(t, mcpTestOptsWithCatalog(t, []string{"demo:basic"}))
	defer teardown()

	sid := initializeSession(t, base, "secret")
	resp := mcpPost(t, base, "secret", sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	defer resp.Body.Close()

	msg := decodeRPC(t, resp.Body)
	if msg.Error != nil {
		t.Fatalf("Error = %+v", msg.Error)
	}
	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, tool := range result.Tools {
		if tool.Name == "secret-tool" {
			t.Fatalf("'secret-tool' leaked through tools/list under demo:basic; got %+v", result.Tools)
		}
	}
	if len(result.Tools) != 1 || result.Tools[0].Name != "echo" {
		t.Fatalf("expected exactly [echo]; got %+v", result.Tools)
	}
}

func TestCatalog_ToolsCallBlocksUnentitled(t *testing.T) {
	// Direct call to "secret-tool" must be rejected even though the
	// backing MCP would handle it — the PEP refuses before the
	// request leaves our process.
	base, teardown := startTestServer(t, mcpTestOptsWithCatalog(t, []string{"demo:basic"}))
	defer teardown()

	sid := initializeSession(t, base, "secret")
	body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"secret-tool","arguments":{}}}`
	resp := mcpPost(t, base, "secret", sid, body)
	defer resp.Body.Close()

	msg := decodeRPC(t, resp.Body)
	if msg.Error == nil || msg.Error.Code != ErrCodeMethodNotFound {
		t.Fatalf("expected method-not-found denial; got %+v", msg.Error)
	}
}

func TestCatalog_ToolsCallAllowsEntitled(t *testing.T) {
	// "echo" is granted; tools/call with name=echo must succeed.
	base, teardown := startTestServer(t, mcpTestOptsWithCatalog(t, []string{"demo:basic"}))
	defer teardown()

	sid := initializeSession(t, base, "secret")
	body := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}`
	resp := mcpPost(t, base, "secret", sid, body)
	defer resp.Body.Close()

	msg := decodeRPC(t, resp.Body)
	if msg.Error != nil {
		t.Fatalf("entitled call rejected: %+v", msg.Error)
	}
}

func TestCatalog_WildcardScopeGrantsEverything(t *testing.T) {
	// demo:full → ["*"] → every tool reachable.
	base, teardown := startTestServer(t, mcpTestOptsWithCatalog(t, []string{"demo:full"}))
	defer teardown()

	sid := initializeSession(t, base, "secret")

	// Both tools should appear in tools/list.
	resp := mcpPost(t, base, "secret", sid, `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`)
	msg := decodeRPC(t, resp.Body)
	resp.Body.Close()
	var listed struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	_ = json.Unmarshal(msg.Result, &listed)
	if len(listed.Tools) != 2 {
		t.Fatalf("wildcard scope should list both tools; got %+v", listed.Tools)
	}

	// And secret-tool should be callable.
	resp = mcpPost(t, base, "secret", sid,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"secret-tool","arguments":{}}}`)
	msg = decodeRPC(t, resp.Body)
	resp.Body.Close()
	if msg.Error != nil {
		t.Fatalf("wildcard scope blocked secret-tool: %+v", msg.Error)
	}
}

// ----- rate limiting (M9) -----

func TestRateLimit_ThrottlesAfterBurstExhausted(t *testing.T) {
	// burst=2: the first two POSTs to /mcp succeed (auth + bearer
	// + a JSON-RPC error from the parse path is fine — the rate
	// limit is what we care about), the third should be 429.
	opts := mcpTestOpts(t)
	opts.rateLimit = RateLimit{
		RequestsPerSecond: 0.01, // refill so slow it's effectively unrefilled within the test
		Burst:             2,
	}
	base, teardown := startTestServer(t, opts)
	defer teardown()

	// Use a body that bypasses the JSON-RPC initialize path — the
	// rate limiter runs as middleware *before* the handler. Even an
	// invalid body counts against the token bucket because the
	// middleware fires first.
	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	// First two: should NOT be 429.
	for i := 0; i < 2; i++ {
		resp := mcpPost(t, base, "secret", "ignored-session", body)
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			t.Fatalf("request #%d unexpectedly 429 (burst should permit 2)", i+1)
		}
		resp.Body.Close()
	}

	// Third: must be 429 with retry-after.
	resp := mcpPost(t, base, "secret", "ignored-session", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 once burst is exhausted", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("expected Retry-After header on 429")
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestRateLimit_IsPerIdentity(t *testing.T) {
	// Two API keys, two subjects. Alice exhausts her bucket; Bob's
	// independent bucket should still permit a request.
	const audience = "http://aud.example/mcp"
	v, err := NewAPIKeyValidator([]APIKey{
		{TokenHashHex: HashToken("alice-key"), Audience: audience, Subject: "alice"},
		{TokenHashHex: HashToken("bob-key"), Audience: audience, Subject: "bob"},
	})
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	base, teardown := startTestServer(t, testServerOpts{
		validator: v,
		audience:  audience,
		rateLimit: RateLimit{RequestsPerSecond: 0.01, Burst: 1},
	})
	defer teardown()

	body := `{"jsonrpc":"2.0","id":1,"method":"ping"}`

	// Alice's first request consumes her token; second is 429.
	r1 := mcpPost(t, base, "alice-key", "sid", body)
	r1.Body.Close()
	r2 := mcpPost(t, base, "alice-key", "sid", body)
	if r2.StatusCode != http.StatusTooManyRequests {
		r2.Body.Close()
		t.Fatalf("alice's second call = %d, want 429", r2.StatusCode)
	}
	r2.Body.Close()

	// Bob shares NO state with alice — his first call must succeed.
	rBob := mcpPost(t, base, "bob-key", "sid", body)
	defer rBob.Body.Close()
	if rBob.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("bob throttled by alice's bucket — limiter is leaking across identities")
	}
}

func TestCatalog_PermissiveWhenNoCatalog(t *testing.T) {
	// Regression: pre-M6 behavior — no catalog configured means
	// every authenticated identity has access to every tool the
	// backend exposes. Used by the existing Postgres demo config
	// (and existing tests using mcpTestOptsWithBackend).
	opts := mcpTestOptsWithBackend(t) // no catalog set
	base, teardown := startTestServer(t, opts)
	defer teardown()

	sid := initializeSession(t, base, "secret")
	resp := mcpPost(t, base, "secret", sid, `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)
	defer resp.Body.Close()
	msg := decodeRPC(t, resp.Body)
	var listed struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	_ = json.Unmarshal(msg.Result, &listed)
	if len(listed.Tools) != 2 {
		t.Fatalf("permissive mode should expose both tools; got %+v", listed.Tools)
	}
}
