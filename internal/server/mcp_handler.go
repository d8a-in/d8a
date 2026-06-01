package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// preferredProtocolVersion is the version we return if the client
// asks for something we don't recognize, or didn't ask at all. The
// MCP Lifecycle spec says the server SHOULD respond with the latest
// version it supports in that case.
const preferredProtocolVersion = "2025-11-25"

// maxMCPRequestBody caps how much we read from any /mcp POST. Larger
// bodies are rejected — defense against a runaway or hostile client
// trying to OOM the server.
const maxMCPRequestBody = 4 << 20 // 4 MiB

// handleMCPPost is the POST /mcp handler: it parses a JSON-RPC
// message and dispatches.
//
// Order of concerns:
//  1. read + parse the JSON-RPC envelope (HTTP 200 + JSON-RPC error
//     on parse failures, per JSON-RPC convention)
//  2. `initialize` requests are special-cased: no session ID needed,
//     server issues one in the response
//  3. every other request/notification must reference an existing
//     session that belongs to this authenticated identity
func (s *Server) handleMCPPost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxMCPRequestBody+1))
	if err != nil {
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(nil, ErrCodeParseError, "failed to read body", nil))
		return
	}
	if len(body) > maxMCPRequestBody {
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(nil, ErrCodeInvalidRequest, "request body too large", nil))
		return
	}

	msg, err := DecodeJSONRPC(body)
	if err != nil {
		code := ErrCodeParseError
		if errors.Is(err, ErrJSONRPCInvalidRequest) {
			code = ErrCodeInvalidRequest
		}
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, code, err.Error(), nil))
		return
	}

	// Special-case initialize: no session ID yet.
	if msg.IsRequest() && msg.Method == "initialize" {
		s.handleInitialize(w, r, msg)
		return
	}

	// All other requests/notifications must reference a live session
	// belonging to this identity.
	sessionID := r.Header.Get("MCP-Session-Id")
	if sessionID == "" {
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, ErrCodeInvalidRequest,
			"MCP-Session-Id header required after initialize", nil))
		return
	}
	sess, ok := s.sessions.Get(sessionID)
	if !ok {
		// Per the MCP Streamable HTTP spec, return 404 so the client
		// knows to start a fresh initialize.
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	identity, _ := IdentityFromContext(r.Context())
	if sess.Subject != identity.Subject {
		// Defend against session-id theft / cross-identity hijack
		// (brainstorming #120 — bind session state to user identity).
		http.Error(w, "session does not belong to this identity", http.StatusForbidden)
		return
	}

	switch {
	case msg.IsNotification():
		s.handleNotification(w, r, sess, msg)
	case msg.IsRequest():
		s.handleRequest(w, r, sess, msg)
	default:
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, ErrCodeInvalidRequest,
			"unrecognized JSON-RPC message", nil))
	}
}

// handleInitialize processes the very first request of a session.
// It negotiates the protocol version, mints a session ID, stores
// the session, and returns the InitializeResult.
func (s *Server) handleInitialize(w http.ResponseWriter, r *http.Request, msg JSONRPCMessage) {
	var params InitializeParams
	if len(msg.Params) > 0 {
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, ErrCodeInvalidParams,
				"invalid initialize params", err.Error()))
			return
		}
	}

	negotiated := negotiateProtocolVersion(params.ProtocolVersion)

	identity, _ := IdentityFromContext(r.Context())

	sessionID, err := NewSessionID()
	if err != nil {
		s.log.Error("session id generation failed", "err", err)
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, ErrCodeInternalError,
			"failed to mint session id", nil))
		return
	}
	now := time.Now()
	s.sessions.Create(sessionID, identity.Subject, negotiated, params.ClientInfo, now)

	// Curated capability advertisement (brainstorming #123):
	// announce a capability key only when the authenticated identity
	// has SOMETHING in that category. With no catalog configured
	// (permissive mode) this is a pure passthrough of whatever the
	// backing MCP advertised. With a catalog, scope-less identities
	// see an empty capability set.
	caps := curatedInitCapabilities(s.backendCaps, s.catalog.Resolve(identity.Scopes))
	result := InitializeResult{
		ProtocolVersion: negotiated,
		Capabilities:    caps,
		ServerInfo:      s.serverImpl(),
	}
	resp, err := NewResultResponse(msg.ID, result)
	if err != nil {
		s.log.Error("initialize marshal failed", "err", err)
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, ErrCodeInternalError,
			"failed to marshal result", nil))
		return
	}

	w.Header().Set("MCP-Session-Id", sessionID)
	s.log.Info("session created",
		"session", sessionID,
		"subject", identity.Subject,
		"protocolVersion", negotiated,
		"client", params.ClientInfo.Name)
	writeJSONRPC(w, http.StatusOK, resp)
}

// runnerForRequest returns the Runner that should serve a request
// from the given identity, using the legacy singleton path when
// Config.Runner is set or the pool's per-partition lookup when
// Config.Backend is set. Returns (nil, nil) when neither is
// configured.
func (s *Server) runnerForRequest(ctx context.Context, identity Identity) (Runner, error) {
	if s.runner != nil {
		return s.runner, nil
	}
	if s.pool != nil {
		return s.pool.RunnerFor(ctx, identity)
	}
	return nil, nil
}

// handleNotification handles a JSON-RPC notification (no id, no
// response). The MCP spec says notifications receive HTTP 202
// Accepted with no body.
//
// notifications/initialized is consumed locally to mark the session
// ready. Everything else is forwarded to the backing MCP (if any) so
// it can react to cancellations and any future spec-defined
// notifications without us having to enumerate them.
func (s *Server) handleNotification(w http.ResponseWriter, r *http.Request, sess *Session, msg JSONRPCMessage) {
	now := time.Now()
	s.sessions.Touch(sess.ID, now)
	switch msg.Method {
	case "notifications/initialized":
		s.sessions.MarkInitialized(sess.ID, now)
	default:
		identity, _ := IdentityFromContext(r.Context())
		runner, err := s.runnerForRequest(r.Context(), identity)
		if err != nil {
			s.log.Warn("runner lookup failed for notification",
				"method", msg.Method, "err", err)
		} else if runner != nil {
			if err := runner.Notify(r.Context(), msg.Method, msg.Params); err != nil {
				s.log.Warn("forward notification failed",
					"method", msg.Method, "err", err)
			}
		}
	}
	w.WriteHeader(http.StatusAccepted)
}

// handleRequest handles a JSON-RPC request (has an id, expects a
// response).
//
// ping is handled locally (it's part of the basic protocol, not a
// backend concern). Catalog-filtered methods (tools/*, resources/*,
// prompts/*) go through dedicated forwarders that drop entries the
// identity isn't allowed to see and reject calls to forbidden names
// before they reach the backing MCP. Other methods are forwarded
// generically — they're not currently filterable.
func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request, sess *Session, msg JSONRPCMessage) {
	s.sessions.Touch(sess.ID, time.Now())
	if msg.Method == "ping" {
		resp, _ := NewResultResponse(msg.ID, struct{}{})
		writeJSONRPC(w, http.StatusOK, resp)
		return
	}

	identity, _ := IdentityFromContext(r.Context())
	access := s.catalog.Resolve(identity.Scopes)

	switch msg.Method {
	case "tools/list":
		s.forwardAndFilterList(w, r, sess, msg, "tools", access.AllowsTool)
		return
	case "tools/call":
		s.forwardWithNameGate(w, r, sess, msg, "name", access.AllowsTool)
		return
	case "resources/list":
		s.forwardAndFilterList(w, r, sess, msg, "resources", access.AllowsResource)
		return
	case "resources/read":
		s.forwardWithNameGate(w, r, sess, msg, "uri", access.AllowsResource)
		return
	case "prompts/list":
		s.forwardAndFilterList(w, r, sess, msg, "prompts", access.AllowsPrompt)
		return
	case "prompts/get":
		s.forwardWithNameGate(w, r, sess, msg, "name", access.AllowsPrompt)
		return
	}

	s.forwardGeneric(w, r, msg)
}

// resolveRunner returns the appropriate runner for the request's
// identity and writes a JSON-RPC error to w if none is available
// (returning nil to tell the caller "I already responded, stop").
// Used by every forwarding helper below.
func (s *Server) resolveRunner(w http.ResponseWriter, r *http.Request, msg JSONRPCMessage) Runner {
	identity, _ := IdentityFromContext(r.Context())
	runner, err := s.runnerForRequest(r.Context(), identity)
	if err != nil {
		s.log.Warn("backing mcp unavailable",
			"method", msg.Method, "subject", identity.Subject, "err", err)
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, ErrCodeInternalError,
			"backing mcp unavailable: "+err.Error(), nil))
		return nil
	}
	if runner == nil {
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, ErrCodeMethodNotFound,
			"method not implemented: "+msg.Method, nil))
		return nil
	}
	return runner
}

// forwardGeneric forwards a JSON-RPC request to the backing MCP and
// returns its response verbatim. Used for methods that aren't
// catalog-filtered (completion/*, logging/*, resources/templates/list,
// future protocol additions).
func (s *Server) forwardGeneric(w http.ResponseWriter, r *http.Request, msg JSONRPCMessage) {
	runner := s.resolveRunner(w, r, msg)
	if runner == nil {
		return
	}
	rawResult, rpcErr := runner.Call(r.Context(), msg.Method, msg.Params)
	if rpcErr != nil {
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, rpcErr.Code, rpcErr.Message, rpcErr.Data))
		return
	}
	resp, _ := NewResultResponse(msg.ID, rawResult)
	writeJSONRPC(w, http.StatusOK, resp)
}

// forwardAndFilterList forwards a "*/list" method, then drops any
// items from the result's listKey array whose identifier (name or
// uri) isn't in the allow set. Other response keys (pagination
// cursors, etc.) are preserved untouched.
func (s *Server) forwardAndFilterList(
	w http.ResponseWriter, r *http.Request, _ *Session,
	msg JSONRPCMessage, listKey string, allow func(string) bool,
) {
	runner := s.resolveRunner(w, r, msg)
	if runner == nil {
		return
	}
	rawResult, rpcErr := runner.Call(r.Context(), msg.Method, msg.Params)
	if rpcErr != nil {
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, rpcErr.Code, rpcErr.Message, rpcErr.Data))
		return
	}
	filtered, err := filterListResult(rawResult, listKey, allow)
	if err != nil {
		// Backend returned an unexpected shape — log loudly and
		// pass the raw response through rather than fail the
		// request. Defensive; modern MCPs SHOULD return the
		// documented shape.
		s.log.Warn("list response shape unexpected; forwarding unfiltered",
			"method", msg.Method, "err", err)
		filtered = rawResult
	}
	resp, _ := NewResultResponse(msg.ID, filtered)
	writeJSONRPC(w, http.StatusOK, resp)
}

// forwardWithNameGate inspects the request's params for an
// identifier under paramKey (e.g. "name" for tools/call, "uri" for
// resources/read), refuses the request if the identifier isn't
// allowed, and otherwise forwards verbatim to the backing MCP.
func (s *Server) forwardWithNameGate(
	w http.ResponseWriter, r *http.Request, sess *Session,
	msg JSONRPCMessage, paramKey string, allow func(string) bool,
) {
	runner := s.resolveRunner(w, r, msg)
	if runner == nil {
		return
	}
	var params map[string]json.RawMessage
	if len(msg.Params) > 0 {
		if err := json.Unmarshal(msg.Params, &params); err != nil {
			writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, ErrCodeInvalidParams,
				"invalid params", err.Error()))
			return
		}
	}
	var ident string
	if v, ok := params[paramKey]; ok {
		_ = json.Unmarshal(v, &ident)
	}
	if ident != "" && !allow(ident) {
		s.log.Info("catalog rejected call",
			"method", msg.Method, "identifier", ident, "subject", sess.Subject)
		// -32601 ("method not found") is the spec-conformant code
		// for "you can't reach this." The client shouldn't have
		// surfaced the option in the first place, but a bypassed
		// list (or a client guessing names) deserves a clear deny.
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, ErrCodeMethodNotFound,
			"not permitted: "+msg.Method+" "+ident, nil))
		return
	}
	rawResult, rpcErr := runner.Call(r.Context(), msg.Method, msg.Params)
	if rpcErr != nil {
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, rpcErr.Code, rpcErr.Message, rpcErr.Data))
		return
	}
	resp, _ := NewResultResponse(msg.ID, rawResult)
	writeJSONRPC(w, http.StatusOK, resp)
}

// curatedInitCapabilities returns the capability map d8a-server
// announces in its initialize response, given what the backend
// advertised and what the identity has access to. tools / resources
// / prompts keys are kept only if the identity has SOMETHING in
// that category (or if permissive mode is in effect). Other keys
// (logging, completion, …) pass through verbatim — they're not
// currently catalog-filtered.
func curatedInitCapabilities(backend ServerCapabilities, access EffectiveAccess) ServerCapabilities {
	caps := ServerCapabilities{}
	if backend == nil {
		return caps
	}
	for k, v := range backend {
		switch k {
		case "tools":
			if access.HasAnyTool() {
				caps[k] = v
			}
		case "resources":
			if access.HasAnyResource() {
				caps[k] = v
			}
		case "prompts":
			if access.HasAnyPrompt() {
				caps[k] = v
			}
		default:
			caps[k] = v
		}
	}
	return caps
}

// filterListResult takes a raw JSON-RPC result object like
//
//	{"tools": [{"name": "a", ...}, {"name": "b", ...}], "nextCursor": "..."}
//
// and drops array entries whose "name" (or, if absent, "uri") is
// not in the allow set. Other keys (e.g. pagination cursors) are
// preserved untouched.
func filterListResult(raw json.RawMessage, listKey string, allow func(string) bool) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	list, ok := obj[listKey]
	if !ok {
		return raw, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(list, &items); err != nil {
		return nil, err
	}
	out := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		var named struct {
			Name string `json:"name"`
			URI  string `json:"uri"`
		}
		_ = json.Unmarshal(item, &named)
		ident := named.Name
		if ident == "" {
			ident = named.URI
		}
		if allow(ident) {
			out = append(out, item)
		}
	}
	filteredList, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	obj[listKey] = filteredList
	return json.Marshal(obj)
}

// handleMCPGet responds to GET /mcp. The spec lets us open an SSE
// stream for server-initiated messages — but M3 doesn't initiate
// any, so we return 405 (the spec explicitly allows this).
func (s *Server) handleMCPGet(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "SSE stream not offered at this endpoint", http.StatusMethodNotAllowed)
}

// handleMCPDelete responds to DELETE /mcp — the spec-defined way for
// a client to explicitly terminate its session. We require the
// MCP-Session-Id header, an authenticated identity that owns the
// session, and respond 204 on success.
func (s *Server) handleMCPDelete(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("MCP-Session-Id")
	if sessionID == "" {
		http.Error(w, "MCP-Session-Id header required", http.StatusBadRequest)
		return
	}
	sess, ok := s.sessions.Get(sessionID)
	if !ok {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}
	identity, _ := IdentityFromContext(r.Context())
	if sess.Subject != identity.Subject {
		http.Error(w, "session does not belong to this identity", http.StatusForbidden)
		return
	}
	s.sessions.Delete(sessionID)
	w.WriteHeader(http.StatusNoContent)
}

// writeJSONRPC writes a JSON-RPC message as a single application/json
// HTTP response.
func writeJSONRPC(w http.ResponseWriter, httpStatus int, msg JSONRPCMessage) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(msg)
}

// negotiateProtocolVersion returns the version the server will use
// for this session given what the client requested.
//
// Per the MCP Lifecycle spec, the server responds with the same
// version when it supports the client's request, or another version
// it supports (SHOULD be the latest) when it doesn't. The client is
// then free to disconnect if the offered version is too new/old.
func negotiateProtocolVersion(requested string) string {
	for _, v := range SupportedProtocolVersions {
		if v == requested {
			return v
		}
	}
	return preferredProtocolVersion
}

// serverImpl returns the static {name, version, …} block used in
// initialize responses. ServerVersion is wired in by cmd/server from
// internal/core so this package doesn't have to depend on core.
func (s *Server) serverImpl() Implementation {
	return Implementation{
		Name:        "d8a-server",
		Title:       "d8a Server",
		Version:     s.cfg.ServerVersion,
		Description: "Open-source MCP gateway (blind, customer-hosted)",
	}
}
