package server

import "encoding/json"

// Implementation is the {name, title, version, description, …} block
// used in `initialize` for both clientInfo and serverInfo.
type Implementation struct {
	Name        string `json:"name"`
	Title       string `json:"title,omitempty"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	WebsiteURL  string `json:"websiteUrl,omitempty"`
}

// ClientCapabilities is the capabilities object a client advertises
// during initialize. The shape is open and evolves with the spec;
// we keep it as a generic JSON object map so the server doesn't have
// to be recompiled when the client adds new capability keys.
type ClientCapabilities map[string]json.RawMessage

// ServerCapabilities is the capabilities object the server returns
// in initialize. M3 announces an empty set (no backing MCPs wrapped
// yet); M4 will populate it based on the catalog filtered by
// admin grants and the identity's scopes (brainstorming #123).
type ServerCapabilities map[string]json.RawMessage

// InitializeParams is the params block of an `initialize` request.
type InitializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities,omitempty"`
	ClientInfo      Implementation     `json:"clientInfo"`
}

// InitializeResult is the result block returned by `initialize`.
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      Implementation     `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitempty"`
}
