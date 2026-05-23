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

// startTestServer launches the server in the background and returns its
// base URL and a teardown function that triggers graceful shutdown and
// waits for it to complete.
func startTestServer(t *testing.T) (baseURL string, teardown func()) {
	t.Helper()
	addr := pickAddr(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(Config{ListenAddr: addr}, log)

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

func TestHealthzReturnsOK(t *testing.T) {
	base, teardown := startTestServer(t)
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
	// The route was registered with the Go 1.22+ method pattern
	// "GET /healthz", so anything else should fall through to the
	// default 405 handler.
	base, teardown := startTestServer(t)
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
