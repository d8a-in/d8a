package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// FileConfig is the on-disk JSON shape for a d8a-server instance.
// It is parsed once at startup and translated into a runtime Config.
//
// Unknown fields are rejected (DisallowUnknownFields) so a typo in a
// field name is a loud startup error rather than a silently-ignored
// security-relevant setting.
type FileConfig struct {
	// Listen is the HTTP listen address. Defaults to DefaultListenAddr
	// (127.0.0.1:8443, loopback only) when empty.
	Listen string `json:"listen,omitempty"`

	// Audience is the canonical URL of this d8a-server instance.
	// Bearer tokens presented by clients must be bound to this
	// audience (RFC 8707) to be accepted. Empty audience means
	// "every key matches" — appropriate ONLY for development on a
	// trusted LAN, never for an exposed deployment.
	Audience string `json:"audience"`

	// AllowedOrigins is the allow-list for the HTTP `Origin` header
	// (DNS-rebinding defense per MCP Streamable HTTP). Requests
	// without an Origin header are always allowed; requests with a
	// non-empty Origin not in this list are rejected with 403.
	// Empty list is safe-by-default: any non-empty Origin is denied.
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`

	// APIKeys is the set of API keys this instance accepts. Each
	// entry stores only the SHA-256 hash of its token, never the
	// token itself.
	APIKeys []APIKey `json:"apiKeys,omitempty"`
}

// LoadFileConfig reads a JSON FileConfig from disk.
func LoadFileConfig(path string) (FileConfig, error) {
	var cfg FileConfig
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %q: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("parse config %q: %w", path, err)
	}
	return cfg, nil
}
