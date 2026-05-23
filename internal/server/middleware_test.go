package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

// ----- extractBearer -----

func TestExtractBearer(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{"empty", "", "", false},
		{"just scheme", "Bearer", "", false},
		{"scheme+space only", "Bearer ", "", false},
		{"good", "Bearer abc123", "abc123", true},
		{"lowercase scheme", "bearer abc123", "abc123", true},
		{"trailing whitespace", "Bearer abc123  ", "abc123", true},
		{"wrong scheme", "Basic abc123", "", false},
		{"prefix without space", "BearerXabc", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := extractBearer(c.header)
			if got != c.want || ok != c.ok {
				t.Fatalf("extractBearer(%q) = (%q,%v), want (%q,%v)",
					c.header, got, ok, c.want, c.ok)
			}
		})
	}
}

// ----- RequireOrigin -----

func TestRequireOrigin_AbsentHeaderAllowed(t *testing.T) {
	h := RequireOrigin([]string{"https://allowed.example"}, discardLogger())(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (absent Origin should pass)", rec.Code)
	}
}

func TestRequireOrigin_AllowedHeaderPasses(t *testing.T) {
	h := RequireOrigin([]string{"https://allowed.example"}, discardLogger())(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "https://allowed.example")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
}

func TestRequireOrigin_DisallowedHeaderForbidden(t *testing.T) {
	h := RequireOrigin([]string{"https://allowed.example"}, discardLogger())(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "https://evil.example")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403", rec.Code)
	}
}

func TestRequireOrigin_EmptyAllowSetRejectsAnyOrigin(t *testing.T) {
	h := RequireOrigin(nil, discardLogger())(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Origin", "https://example.com")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code = %d, want 403 (no allowed origins configured)", rec.Code)
	}
}

// ----- RequireAuth -----

func TestRequireAuth_MissingAuthorization(t *testing.T) {
	v := newValidatorWithKey(t, "secret", "aud", "alice", nil)
	h := RequireAuth(v, "aud", discardLogger())(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer realm="d8a"` {
		t.Fatalf("WWW-Authenticate = %q, want bearer challenge", got)
	}
}

func TestRequireAuth_WrongScheme(t *testing.T) {
	v := newValidatorWithKey(t, "secret", "aud", "alice", nil)
	h := RequireAuth(v, "aud", discardLogger())(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 for non-Bearer scheme", rec.Code)
	}
}

func TestRequireAuth_WrongAudienceRejected(t *testing.T) {
	v := newValidatorWithKey(t, "secret", "https://a.example/mcp", "alice", nil)
	// Server's audience is different from what the key was issued for.
	h := RequireAuth(v, "https://b.example/mcp", discardLogger())(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 (audience mismatch)", rec.Code)
	}
}

func TestRequireAuth_Success_AttachesIdentity(t *testing.T) {
	v := newValidatorWithKey(t, "secret", "aud", "alice", []string{"postgres:read"})

	var captured Identity
	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	h := RequireAuth(v, "aud", discardLogger())(terminal)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if captured.Subject != "alice" {
		t.Errorf("Identity.Subject = %q, want alice", captured.Subject)
	}
	if len(captured.Scopes) != 1 || captured.Scopes[0] != "postgres:read" {
		t.Errorf("Identity.Scopes = %v, want [postgres:read]", captured.Scopes)
	}
}

func TestRequireAuth_NilValidator(t *testing.T) {
	h := RequireAuth(nil, "aud", discardLogger())(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer anything")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401 (misconfigured server should refuse)", rec.Code)
	}
}

// ----- ParseProtocolVersion -----

func TestParseProtocolVersion_AbsentFallsBack(t *testing.T) {
	var seen string
	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = ProtocolVersionFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	h := ParseProtocolVersion()(terminal)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if seen != fallbackProtocolVersion {
		t.Fatalf("ctx version = %q, want %q", seen, fallbackProtocolVersion)
	}
}

func TestParseProtocolVersion_SupportedPasses(t *testing.T) {
	var seen string
	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = ProtocolVersionFromContext(r.Context())
	})
	h := ParseProtocolVersion()(terminal)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	h.ServeHTTP(rec, req)
	if seen != "2025-11-25" {
		t.Fatalf("ctx version = %q, want 2025-11-25", seen)
	}
}

func TestParseProtocolVersion_UnsupportedBadRequest(t *testing.T) {
	h := ParseProtocolVersion()(okHandler())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("MCP-Protocol-Version", "9999-99-99")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
}

// ----- Chain ordering -----

func TestChain_FirstListedIsOutermost(t *testing.T) {
	var log []string
	mk := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				log = append(log, "in:"+name)
				next.ServeHTTP(w, r)
				log = append(log, "out:"+name)
			})
		}
	}
	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		log = append(log, "handler")
		w.WriteHeader(http.StatusOK)
	})

	h := Chain(terminal, mk("a"), mk("b"), mk("c"))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(context.Background())
	h.ServeHTTP(rec, req)

	want := []string{"in:a", "in:b", "in:c", "handler", "out:c", "out:b", "out:a"}
	if len(log) != len(want) {
		t.Fatalf("log = %v, want %v", log, want)
	}
	for i := range want {
		if log[i] != want[i] {
			t.Fatalf("log[%d] = %q, want %q (full: %v)", i, log[i], want[i], log)
		}
	}
}
