package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// testServerOpts customizes the test-server harness without making the
// production Config type depend on test concerns.
type testServerOpts struct {
	validator      Validator
	audience       string
	allowedOrigins []string
}

// pickAddr returns a free loopback address. There is a small race
// window between releasing the listener and the server claiming the
// address, but it's acceptable for tests and avoids hard-coding ports.
func pickAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

// startTestServer launches the server in the background and returns
// its base URL and a teardown function that triggers graceful
// shutdown and waits for it to complete.
func startTestServer(t *testing.T, opts testServerOpts) (baseURL string, teardown func()) {
	t.Helper()
	addr := pickAddr(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(Config{
		ListenAddr:     addr,
		Audience:       opts.audience,
		AllowedOrigins: opts.allowedOrigins,
		Validator:      opts.validator,
	}, log)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Run(ctx)
		close(done)
	}()

	// Wait until the server is accepting connections.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return "http://" + addr, func() {
				cancel()
				<-done
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("server did not become ready in time")
	return "", func() {}
}

// ----- /healthz (unauthenticated) -----

func TestHealthzReturnsOK(t *testing.T) {
	base, teardown := startTestServer(t, testServerOpts{})
	defer teardown()

	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := strings.TrimSpace(string(body)); got != "ok" {
		t.Fatalf("body = %q, want %q", got, "ok")
	}
}

func TestHealthzRejectsWrongMethod(t *testing.T) {
	base, teardown := startTestServer(t, testServerOpts{})
	defer teardown()

	req, err := http.NewRequest(http.MethodPost, base+"/healthz", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

// ----- /mcp (gated by the middleware stack) -----

func mcpTestOpts(t *testing.T) testServerOpts {
	t.Helper()
	return testServerOpts{
		validator:      newValidatorWithKey(t, "secret", "http://aud.example/mcp", "alice", []string{"postgres:read"}),
		audience:       "http://aud.example/mcp",
		allowedOrigins: []string{"http://allowed.example"},
	}
}

func TestMCP_RequiresAuth(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	resp, err := http.Get(base + "/mcp")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != `Bearer realm="d8a"` {
		t.Fatalf("WWW-Authenticate = %q, want bearer challenge", got)
	}
}

func TestMCP_RejectsDisallowedOrigin(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	req, _ := http.NewRequest(http.MethodGet, base+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Origin", "http://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestMCP_RejectsBadProtocolVersion(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	req, _ := http.NewRequest(http.MethodGet, base+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("MCP-Protocol-Version", "9999-99-99")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// Once the middleware stack accepts a GET /mcp, the underlying
// handler returns 405 because we don't open an SSE stream here (the
// MCP Streamable HTTP spec explicitly allows this response). This
// test confirms the middleware *runs* to completion — the rejection
// codes for bad origin (above), bad version (above), and missing
// auth (above) are all detected *before* this handler would run.
func TestMCP_GetReturns405AfterMiddleware(t *testing.T) {
	base, teardown := startTestServer(t, mcpTestOpts(t))
	defer teardown()

	req, _ := http.NewRequest(http.MethodGet, base+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	req.Header.Set("Origin", "http://allowed.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405 (no SSE stream offered)", resp.StatusCode)
	}
}
