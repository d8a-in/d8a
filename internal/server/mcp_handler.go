package server

import (
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

	result := InitializeResult{
		ProtocolVersion: negotiated,
		// M3 announces an empty capability set — no backing MCPs are
		// wrapped yet. M4 will populate this from the curated catalog
		// per brainstorming #123.
		Capabilities: ServerCapabilities{},
		ServerInfo:   s.serverImpl(),
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

// handleNotification handles a JSON-RPC notification (no id, no
// response). The MCP spec says notifications receive HTTP 202
// Accepted with no body.
func (s *Server) handleNotification(w http.ResponseWriter, _ *http.Request, sess *Session, msg JSONRPCMessage) {
	now := time.Now()
	switch msg.Method {
	case "notifications/initialized":
		s.sessions.MarkInitialized(sess.ID, now)
	case "notifications/cancelled":
		// No queued work yet — but we touch the session and accept.
		s.sessions.Touch(sess.ID, now)
	default:
		// Unknown notifications are accepted silently per JSON-RPC
		// convention (notifications never elicit error responses).
		s.sessions.Touch(sess.ID, now)
	}
	w.WriteHeader(http.StatusAccepted)
}

// handleRequest handles a JSON-RPC request (has an id, expects a
// response).
func (s *Server) handleRequest(w http.ResponseWriter, _ *http.Request, sess *Session, msg JSONRPCMessage) {
	s.sessions.Touch(sess.ID, time.Now())
	switch msg.Method {
	case "ping":
		// MCP ping: empty result, used as a keep-alive.
		resp, _ := NewResultResponse(msg.ID, struct{}{})
		writeJSONRPC(w, http.StatusOK, resp)
	default:
		writeJSONRPC(w, http.StatusOK, NewErrorResponse(msg.ID, ErrCodeMethodNotFound,
			"method not implemented: "+msg.Method, nil))
	}
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
