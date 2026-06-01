package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// contextKey is unexported so other packages cannot collide with our
// keys when reading the request context.
type contextKey int

const (
	identityKey contextKey = iota
	protocolVersionKey
)

// IdentityFromContext returns the Identity attached by RequireAuth.
// The second return value is false when no Identity was attached.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey).(Identity)
	return id, ok
}

// ProtocolVersionFromContext returns the MCP protocol version parsed
// from the MCP-Protocol-Version header (or the spec-mandated fallback
// when the header is absent). The second value is false when
// ParseProtocolVersion did not run.
func ProtocolVersionFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(protocolVersionKey).(string)
	return v, ok
}

// Middleware is the conventional http.Handler wrapper signature used
// throughout this package.
type Middleware func(http.Handler) http.Handler

// Chain composes middlewares around handler. The first listed
// middleware is *outermost*: it runs first on the way in and last on
// the way out.
func Chain(handler http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		handler = mws[i](handler)
	}
	return handler
}

// RequireOrigin returns middleware that rejects requests whose
// `Origin` header is not in allowed.
//
// Per the MCP Streamable HTTP spec (DNS-rebinding defense), servers
// MUST validate the Origin header when present. Non-browser clients
// (CLIs, Claude Code) typically omit Origin entirely — those requests
// pass through. A non-empty Origin not in the allow-list is a hard
// 403. When allowed is empty, *any* non-empty Origin is rejected,
// which is the safe-by-default posture for a fresh install.
func RequireOrigin(allowed []string, log *slog.Logger) Middleware {
	allowSet := make(map[string]struct{}, len(allowed))
	for _, o := range allowed {
		allowSet[o] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}
			if _, ok := allowSet[origin]; !ok {
				log.Warn("rejecting request with disallowed Origin",
					"origin", origin, "remote", r.RemoteAddr, "path", r.URL.Path)
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuth returns middleware enforcing `Authorization: Bearer
// <token>`. The token is validated against v, bound to the canonical
// audience URL of this server (per RFC 8707).
//
// Failures uniformly produce 401 + `WWW-Authenticate: Bearer
// realm="d8a"` and never echo the presented token or the underlying
// validator error back to the caller, to deny probing.
func RequireAuth(v Validator, audience string, log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v == nil {
				// Server misconfigured. Refuse rather than allow.
				log.Error("RequireAuth invoked with nil Validator", "path", r.URL.Path)
				respondUnauthorized(w)
				return
			}
			token, ok := extractBearer(r.Header.Get("Authorization"))
			if !ok {
				respondUnauthorized(w)
				return
			}
			id, err := v.Validate(r.Context(), token, audience)
			if err != nil {
				log.Info("auth rejected", "remote", r.RemoteAddr, "path", r.URL.Path)
				respondUnauthorized(w)
				return
			}
			ctx := context.WithValue(r.Context(), identityKey, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractBearer returns the token portion of an "Authorization: Bearer
// <token>" header, accepting the scheme case-insensitively per RFC 6750.
// It returns ("", false) for any malformed input.
func extractBearer(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) {
		return "", false
	}
	if !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

func respondUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="d8a"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

// RequireRateLimit returns middleware that consumes one token from
// the rate limiter for the authenticated identity per request. On
// empty bucket the request is rejected with HTTP 429 + a JSON-RPC
// error body (id=null, since rate limiting is decided before parsing
// the request payload).
//
// A nil limiter is a no-op: handlers wired with RequireRateLimit(nil,
// log) behave exactly as if the middleware weren't present, so
// rate limiting can be enabled/disabled by config without a routing
// change.
func RequireRateLimit(l *RateLimiter, log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if l == nil {
				next.ServeHTTP(w, r)
				return
			}
			id, ok := IdentityFromContext(r.Context())
			if !ok || id.Subject == "" {
				// Pre-auth path (or anonymous). Auth middleware
				// should have rejected; if it didn't, we can't
				// rate limit a missing subject — let through.
				next.ServeHTTP(w, r)
				return
			}
			if !l.Allow(time.Now(), id.Subject) {
				log.Info("rate limited",
					"subject", id.Subject, "path", r.URL.Path)
				respondRateLimited(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// respondRateLimited writes the HTTP 429 + JSON-RPC error body that
// represents a throttled request. Retry-After is the conservative
// "try again in a second" value — clients with their own backoff
// will refine.
func respondRateLimited(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(JSONRPCMessage{
		JSONRPC: jsonrpcVersion,
		ID:      json.RawMessage("null"),
		Error: &JSONRPCError{
			Code:    -32000,
			Message: "rate limited",
		},
	})
}

// SupportedProtocolVersions is the set of MCP protocol versions this
// build can serve. The first entry is also our preferred version for
// the initialize handshake (M3).
var SupportedProtocolVersions = []string{
	"2025-11-25",
	"2025-03-26", // also the spec-mandated fallback when header is absent
}

// fallbackProtocolVersion is the version a Streamable HTTP server MUST
// assume when no MCP-Protocol-Version header is present (per the MCP
// Transports spec, for backwards compatibility with older clients
// that pre-date the header).
const fallbackProtocolVersion = "2025-03-26"

// ParseProtocolVersion returns middleware that parses and validates
// the `MCP-Protocol-Version` header, attaching the resolved version
// to the request context. An unsupported version triggers HTTP 400;
// an absent header falls back to the spec-mandated 2025-03-26.
func ParseProtocolVersion() Middleware {
	supported := make(map[string]struct{}, len(SupportedProtocolVersions))
	for _, v := range SupportedProtocolVersions {
		supported[v] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			v := r.Header.Get("MCP-Protocol-Version")
			if v == "" {
				v = fallbackProtocolVersion
			}
			if _, ok := supported[v]; !ok {
				http.Error(w, "unsupported MCP protocol version", http.StatusBadRequest)
				return
			}
			ctx := context.WithValue(r.Context(), protocolVersionKey, v)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
