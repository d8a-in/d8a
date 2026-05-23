package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// stdioMaxLine caps how large a single JSON-RPC line from the backing
// MCP may be. 16 MiB is generous for query results and tool outputs;
// streaming for genuinely large payloads is a later milestone.
const stdioMaxLine = 16 << 20 // 16 MiB

// stdioStopGrace is how long Stop waits for the backing MCP to exit
// cleanly after stdin is closed (the MCP stdio shutdown signal)
// before sending SIGKILL.
const stdioStopGrace = 5 * time.Second

// StdioRunner implements Runner by spawning the backing MCP as a
// subprocess and bridging its stdio JSON-RPC stream.
//
// Concurrency:
//   - Writes to the child's stdin are serialized by writeMu.
//   - Pending requests are keyed by a monotonically increasing local
//     id (which we put on the wire); a single reader goroutine
//     demultiplexes responses back to their waiting Call.
//   - The original caller's id (if any) is not exposed to the child
//     because higher layers already do id management.
type StdioRunner struct {
	cmd        *exec.Cmd
	clientInfo Implementation
	log        *slog.Logger

	stdin io.WriteCloser

	writeMu sync.Mutex // serializes writes to stdin

	mu       sync.Mutex // guards nextID, pending, stopped
	nextID   int64
	pending  map[int64]chan json.RawMessage
	stopped  bool
	readDone chan struct{}
}

// NewStdioRunner returns a Runner that will spawn cmd when Start is
// called. cmd is mutated to attach stdio pipes and (if not already
// set) a minimal environment. clientInfo is the {name, version, …}
// the runner advertises to the backing MCP during initialize.
func NewStdioRunner(cmd *exec.Cmd, clientInfo Implementation, log *slog.Logger) *StdioRunner {
	return &StdioRunner{
		cmd:        cmd,
		clientInfo: clientInfo,
		log:        log,
		pending:    make(map[int64]chan json.RawMessage),
		readDone:   make(chan struct{}),
	}
}

// Start launches the backing MCP, performs initialize + initialized,
// and returns the advertised ServerCapabilities.
//
// TODO(security): apply sandboxing primitives here per brainstorming
// #78/#79 — bubblewrap + Landlock + seccomp, plus per-MCP egress
// allowlist. M4 only enforces "minimal environment by default"; the
// hardening lands in a follow-up milestone.
func (r *StdioRunner) Start(ctx context.Context) (ServerCapabilities, error) {
	// Default to an empty environment — the operator must pass in
	// only what's needed via cmd.Env (set by the caller / config).
	if r.cmd.Env == nil {
		r.cmd.Env = []string{}
	}

	stdin, err := r.cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := r.cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	r.stdin = stdin

	// Forward the child's stderr line-by-line to our logger as
	// warnings — it's typically informational/error chatter we want
	// to surface for debugging.
	stderr, err := r.cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	go r.forwardStderr(stderr)

	if err := r.cmd.Start(); err != nil {
		return nil, fmt.Errorf("start: %w", err)
	}
	r.log.Info("backing mcp started",
		"command", r.cmd.Path, "pid", r.cmd.Process.Pid)

	go r.readLoop(stdout)

	// MCP lifecycle: send initialize, wait for response, then send
	// notifications/initialized.
	initParams := InitializeParams{
		ProtocolVersion: "2025-11-25",
		Capabilities:    ClientCapabilities{},
		ClientInfo:      r.clientInfo,
	}
	paramsRaw, err := json.Marshal(initParams)
	if err != nil {
		_ = r.Stop()
		return nil, fmt.Errorf("marshal initialize params: %w", err)
	}

	resultRaw, rpcErr := r.Call(ctx, "initialize", paramsRaw)
	if rpcErr != nil {
		_ = r.Stop()
		return nil, fmt.Errorf("backing mcp initialize failed: %s", rpcErr.Message)
	}
	var result InitializeResult
	if err := json.Unmarshal(resultRaw, &result); err != nil {
		_ = r.Stop()
		return nil, fmt.Errorf("decode initialize result: %w", err)
	}

	if err := r.Notify(ctx, "notifications/initialized", nil); err != nil {
		_ = r.Stop()
		return nil, fmt.Errorf("notifications/initialized: %w", err)
	}

	r.log.Info("backing mcp initialized",
		"protocolVersion", result.ProtocolVersion,
		"server", result.ServerInfo.Name)
	return result.Capabilities, nil
}

func (r *StdioRunner) forwardStderr(rc io.ReadCloser) {
	scanner := bufio.NewScanner(rc)
	for scanner.Scan() {
		r.log.Warn("backing mcp stderr", "line", scanner.Text())
	}
}

// Call implements Runner.Call.
func (r *StdioRunner) Call(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, *JSONRPCError) {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return nil, &JSONRPCError{Code: ErrCodeInternalError, Message: "runner stopped"}
	}
	r.nextID++
	id := r.nextID
	ch := make(chan json.RawMessage, 1)
	r.pending[id] = ch
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		delete(r.pending, id)
		r.mu.Unlock()
	}()

	msg := JSONRPCMessage{
		JSONRPC: jsonrpcVersion,
		ID:      json.RawMessage(strconv.FormatInt(id, 10)),
		Method:  method,
		Params:  params,
	}
	if err := r.writeLine(msg); err != nil {
		return nil, &JSONRPCError{Code: ErrCodeInternalError, Message: err.Error()}
	}

	select {
	case respLine := <-ch:
		var resp JSONRPCMessage
		if err := json.Unmarshal(respLine, &resp); err != nil {
			return nil, &JSONRPCError{Code: ErrCodeInternalError, Message: "malformed response from backing mcp"}
		}
		if resp.Error != nil {
			return nil, resp.Error
		}
		return resp.Result, nil
	case <-ctx.Done():
		return nil, &JSONRPCError{Code: ErrCodeInternalError, Message: ctx.Err().Error()}
	}
}

// Notify implements Runner.Notify.
func (r *StdioRunner) Notify(_ context.Context, method string, params json.RawMessage) error {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return errors.New("runner stopped")
	}
	r.mu.Unlock()

	msg := JSONRPCMessage{
		JSONRPC: jsonrpcVersion,
		Method:  method,
		Params:  params,
	}
	return r.writeLine(msg)
}

// writeLine encodes msg as a single newline-terminated JSON object
// and writes it to stdin under writeMu so concurrent calls don't
// interleave bytes.
func (r *StdioRunner) writeLine(msg JSONRPCMessage) error {
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	if r.stdin == nil {
		return errors.New("runner not started")
	}
	_, err = r.stdin.Write(raw)
	return err
}

// readLoop demultiplexes responses from the backing MCP to their
// waiting Call. Notifications/requests from the server side are
// logged (M4 doesn't yet act on them — M5 will surface progress
// notifications to upstream clients).
func (r *StdioRunner) readLoop(stdout io.ReadCloser) {
	defer close(r.readDone)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), stdioMaxLine)
	for scanner.Scan() {
		line := scanner.Bytes()
		// Demux requires only the id; defer full parsing to the
		// waiter so we don't pay for it inside the read loop.
		var head struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.Unmarshal(line, &head); err != nil {
			r.log.Warn("invalid json from backing mcp", "len", len(line))
			continue
		}
		if len(head.ID) == 0 || string(head.ID) == "null" {
			// Server-side notification or request. Log for now.
			r.log.Info("backing mcp unsolicited message")
			continue
		}
		var id int64
		if err := json.Unmarshal(head.ID, &id); err != nil {
			r.log.Warn("non-integer id from backing mcp (we always send integer ids)",
				"id", string(head.ID))
			continue
		}
		r.mu.Lock()
		ch, ok := r.pending[id]
		r.mu.Unlock()
		if !ok {
			r.log.Warn("response for unknown id", "id", id)
			continue
		}
		// Copy bytes because the scanner reuses its buffer.
		buf := make([]byte, len(line))
		copy(buf, line)
		ch <- buf
	}
	if err := scanner.Err(); err != nil {
		r.log.Warn("read loop ended with error", "err", err)
	}
	// Drain any pending callers with a synthetic error so they don't
	// block forever waiting on a response that will never come.
	r.mu.Lock()
	for id, ch := range r.pending {
		errResp := NewErrorResponse(json.RawMessage(strconv.FormatInt(id, 10)),
			ErrCodeInternalError, "backing mcp closed", nil)
		raw, _ := json.Marshal(errResp)
		select {
		case ch <- raw:
		default:
		}
	}
	r.mu.Unlock()
}

// Stop implements Runner.Stop. Closing stdin is the MCP stdio
// shutdown signal; we then wait for the child to exit. After the
// grace period we SIGKILL.
func (r *StdioRunner) Stop() error {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return nil
	}
	r.stopped = true
	r.mu.Unlock()

	if r.stdin != nil {
		_ = r.stdin.Close()
	}

	// Drain read loop.
	<-r.readDone

	done := make(chan error, 1)
	go func() { done <- r.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			r.log.Info("backing mcp exited with error", "err", err)
		}
		return nil
	case <-time.After(stdioStopGrace):
		if r.cmd.Process != nil {
			_ = r.cmd.Process.Kill()
		}
		<-done
		r.log.Warn("backing mcp force-killed after grace period")
		return errors.New("backing mcp did not exit in time")
	}
}
