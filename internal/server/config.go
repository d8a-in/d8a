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

	// Capabilities maps scope names (used in APIKeys[].Scopes) to
	// the bundle of MCP tool/resource/prompt identifiers each scope
	// grants. When absent / empty, d8a-server runs in "permissive
	// mode" (every authenticated identity has the same access as
	// the backing MCP exposes). When present, identities see only
	// what their resolved scopes grant — see brainstorming #123.
	Capabilities map[string]CapabilityBundle `json:"capabilities,omitempty"`

	// Backend is the optional backing MCP this server proxies for.
	// When set, d8a-server spawns the configured command, performs
	// its initialize handshake at startup, and forwards MCP method
	// calls through it.
	Backend *BackendConfig `json:"backend,omitempty"`
}

// BackendConfig describes the subprocess to spawn as the backing MCP.
//
// SEP-1024 / brainstorming #121: an operator enabling a backing MCP
// MUST see the exact command and args they're about to execute. The
// config file is that consent surface — d8a-server logs the resolved
// command + args at startup so the operator's commit / review
// captures what's running on their box.
type BackendConfig struct {
	// Command is the executable to run (absolute path or PATH-resolved).
	Command string `json:"command"`

	// Args are positional arguments to Command.
	Args []string `json:"args,omitempty"`

	// Env is the environment passed through to the subprocess.
	// Empty / nil means an empty environment (no PATH, no HOME, etc.) —
	// the operator must explicitly enumerate what the MCP needs.
	Env map[string]string `json:"env,omitempty"`

	// Sandbox controls how the subprocess is contained (bubblewrap-
	// based PID/IPC/UTS/filesystem isolation, plus optional network
	// isolation). nil means "sandbox enabled with safe defaults" —
	// see SandboxPolicy. To bypass containment entirely, set
	// {"sandbox": {"disabled": true}} (strongly discouraged).
	Sandbox *SandboxPolicy `json:"sandbox,omitempty"`
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
