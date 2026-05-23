package server

import (
	"encoding/json"
	"errors"
	"fmt"
)

// JSON-RPC 2.0 standard error codes.
// See https://www.jsonrpc.org/specification#error_object
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603
)

// jsonrpcVersion is the only valid value for the JSON-RPC "jsonrpc"
// field. Constant so every site checks against the same string.
const jsonrpcVersion = "2.0"

// JSONRPCMessage is a single JSON-RPC 2.0 message — request,
// notification, or response. We use one struct with all possible
// fields rather than distinct types so dispatch can branch on
// presence/absence after a single unmarshal.
//
// ID is stored as RawMessage so we faithfully echo whatever the
// client sent (a string id, a number id, or null) without coercing
// it into a Go type that might re-serialize differently.
type JSONRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError is the error object returned in a JSON-RPC response.
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// IsRequest reports whether m looks like a JSON-RPC *request*: a
// method name and a non-null id.
func (m *JSONRPCMessage) IsRequest() bool {
	return m.Method != "" && len(m.ID) > 0 && string(m.ID) != "null"
}

// IsNotification reports whether m looks like a JSON-RPC
// *notification*: a method name and no id (or explicit null).
func (m *JSONRPCMessage) IsNotification() bool {
	return m.Method != "" && (len(m.ID) == 0 || string(m.ID) == "null")
}

// Sentinel errors returned by DecodeJSONRPC so callers can distinguish
// between a malformed JSON body and a well-formed JSON object that
// doesn't satisfy the JSON-RPC 2.0 envelope.
var (
	ErrJSONRPCParse          = errors.New("json parse error")
	ErrJSONRPCInvalidRequest = errors.New("invalid JSON-RPC request envelope")
)

// DecodeJSONRPC parses raw bytes into a JSONRPCMessage and validates
// the JSON-RPC envelope ("jsonrpc": "2.0"). Returns ErrJSONRPCParse
// wrapping the underlying decoder error for malformed JSON, or
// ErrJSONRPCInvalidRequest for well-formed JSON that's the wrong
// shape.
func DecodeJSONRPC(raw []byte) (JSONRPCMessage, error) {
	var m JSONRPCMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, fmt.Errorf("%w: %v", ErrJSONRPCParse, err)
	}
	if m.JSONRPC != jsonrpcVersion {
		return m, ErrJSONRPCInvalidRequest
	}
	return m, nil
}

// NewResultResponse builds a successful JSON-RPC response carrying
// result and echoing the request id.
func NewResultResponse(id json.RawMessage, result any) (JSONRPCMessage, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return JSONRPCMessage{}, err
	}
	return JSONRPCMessage{
		JSONRPC: jsonrpcVersion,
		ID:      id,
		Result:  raw,
	}, nil
}

// NewErrorResponse builds an error JSON-RPC response. An empty id
// becomes JSON null, per the JSON-RPC spec for errors that occur
// before the request id can be parsed.
func NewErrorResponse(id json.RawMessage, code int, message string, data any) JSONRPCMessage {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return JSONRPCMessage{
		JSONRPC: jsonrpcVersion,
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}
