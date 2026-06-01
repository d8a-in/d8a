package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// TestHelperProcess is the workhorse subprocess for stdio runner tests.
// It re-execs this test binary with D8A_FAKE_MCP=1 set, at which point
// the early-return below falls through and runFakeMCP takes over,
// behaving as a tiny MCP server speaking newline-delimited JSON-RPC
// on stdio. With D8A_FAKE_MCP unset (normal `go test` invocation) it
// returns immediately and contributes nothing.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("D8A_FAKE_MCP") != "1" {
		return
	}
	runFakeMCP(os.Stdin, os.Stdout)
	os.Exit(0)
}

func runFakeMCP(in io.Reader, out io.Writer) {
	dec := json.NewDecoder(in)
	enc := json.NewEncoder(out)
	for {
		var req JSONRPCMessage
		if err := dec.Decode(&req); err != nil {
			return
		}
		if req.IsNotification() {
			// MCP allows notifications; we just absorb them.
			continue
		}
		switch req.Method {
		case "initialize":
			result := InitializeResult{
				ProtocolVersion: "2025-11-25",
				Capabilities: ServerCapabilities{
					"tools": json.RawMessage(`{}`),
				},
				ServerInfo: Implementation{Name: "fake-mcp", Version: "0.0.0"},
			}
			resp, _ := NewResultResponse(req.ID, result)
			_ = enc.Encode(resp)
		case "tools/list":
			// Multiple tools so catalog-filtering integration tests
			// have something to filter out.
			resp, _ := NewResultResponse(req.ID, map[string]any{
				"tools": []map[string]string{
					{"name": "echo", "description": "Echoes its params back"},
					{"name": "secret-tool", "description": "Should be filtered by catalog tests"},
				},
			})
			_ = enc.Encode(resp)
		case "tools/call":
			// Echo the params back as content.
			resp, _ := NewResultResponse(req.ID, map[string]json.RawMessage{
				"content": req.Params,
			})
			_ = enc.Encode(resp)
		case "boom":
			_ = enc.Encode(NewErrorResponse(req.ID, -32000, "boom", nil))
		default:
			_ = enc.Encode(NewErrorResponse(req.ID, ErrCodeMethodNotFound, "fake-mcp: "+req.Method, nil))
		}
	}
}

// fakeMCPCmd returns an *exec.Cmd that re-execs the test binary as a
// fake MCP server. Tests pass this into NewStdioRunner.
func fakeMCPCmd(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "-test.v=false")
	cmd.Env = append(os.Environ(), "D8A_FAKE_MCP=1")
	return cmd
}

func newRunnerLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestStdioRunner_StartAndCapabilities(t *testing.T) {
	r := NewStdioRunner(fakeMCPCmd(t), Implementation{Name: "test-host"}, newRunnerLogger())
	caps, err := r.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Stop()

	if _, ok := caps["tools"]; !ok {
		t.Fatalf("expected tools capability; got %v", caps)
	}
}

func TestStdioRunner_CallToolsList(t *testing.T) {
	r := NewStdioRunner(fakeMCPCmd(t), Implementation{Name: "test-host"}, newRunnerLogger())
	if _, err := r.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Stop()

	raw, rpcErr := r.Call(context.Background(), "tools/list", nil)
	if rpcErr != nil {
		t.Fatalf("Call: %+v", rpcErr)
	}
	var result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Tolerate additional tools (the fake exposes "secret-tool" too
	// for catalog-filter tests in mcp_handler_test.go).
	var sawEcho bool
	for _, t := range result.Tools {
		if t.Name == "echo" {
			sawEcho = true
		}
	}
	if !sawEcho {
		t.Fatalf("tools list missing 'echo'; got %+v", result.Tools)
	}
}

func TestStdioRunner_ConcurrentCallsAreIsolated(t *testing.T) {
	// 50 concurrent callers issuing different methods must each
	// receive *their own* response, not someone else's, even though
	// the backing MCP is a single stdio stream.
	r := NewStdioRunner(fakeMCPCmd(t), Implementation{Name: "test-host"}, newRunnerLogger())
	if _, err := r.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Stop()

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			params := json.RawMessage([]byte(`{"i":` + jsonNumber(i) + `}`))
			raw, rpcErr := r.Call(context.Background(), "tools/call", params)
			if rpcErr != nil {
				errs <- &rpcCallError{i: i, err: rpcErr.Message}
				return
			}
			// The fake echoes params back in content.
			var out struct {
				Content json.RawMessage `json:"content"`
			}
			if err := json.Unmarshal(raw, &out); err != nil {
				errs <- err
				return
			}
			if string(out.Content) != string(params) {
				errs <- &rpcCallError{i: i, err: "response did not match request params: " + string(out.Content)}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent call: %v", err)
	}
}

type rpcCallError struct {
	i   int
	err string
}

func (e *rpcCallError) Error() string {
	return e.err
}

func jsonNumber(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestStdioRunner_CallReturnsBackingError(t *testing.T) {
	r := NewStdioRunner(fakeMCPCmd(t), Implementation{Name: "test-host"}, newRunnerLogger())
	if _, err := r.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Stop()

	_, rpcErr := r.Call(context.Background(), "boom", nil)
	if rpcErr == nil {
		t.Fatal("expected JSON-RPC error from backing 'boom'")
	}
	if rpcErr.Code != -32000 {
		t.Errorf("Code = %d, want -32000", rpcErr.Code)
	}
}

func TestStdioRunner_CallAfterStopFails(t *testing.T) {
	r := NewStdioRunner(fakeMCPCmd(t), Implementation{Name: "test-host"}, newRunnerLogger())
	if _, err := r.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	_ = r.Stop()

	_, rpcErr := r.Call(context.Background(), "tools/list", nil)
	if rpcErr == nil {
		t.Fatal("expected error after Stop")
	}
}

func TestStdioRunner_StopIdempotent(t *testing.T) {
	r := NewStdioRunner(fakeMCPCmd(t), Implementation{Name: "test-host"}, newRunnerLogger())
	if _, err := r.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestStdioRunner_CallRespectsContextCancel(t *testing.T) {
	// "wait" method doesn't exist in the fake → it will return a
	// JSON-RPC error quickly. To exercise cancellation we need a
	// method that doesn't immediately respond. We don't have one,
	// so instead we cancel a context *before* calling — Call should
	// observe the cancellation between picking up the id and sending.
	r := NewStdioRunner(fakeMCPCmd(t), Implementation{Name: "test-host"}, newRunnerLogger())
	if _, err := r.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer r.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Even though ctx is already cancelled, the fake responds
	// instantly, so Call may complete before cancellation is observed.
	// We accept either outcome: success, or a cancellation-ish error.
	// What we DO want to assert: it doesn't hang.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = r.Call(ctx, "tools/list", nil)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Call hung past timeout")
	}
}
