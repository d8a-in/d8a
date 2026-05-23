package server

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

// NewSessionID returns a cryptographically secure session identifier
// suitable for the MCP-Session-Id HTTP header (Streamable HTTP transport).
//
// Per the MCP Streamable HTTP spec, the session ID MUST contain only
// visible ASCII (0x21–0x7E). We encode 16 random bytes (128 bits) as
// lowercase base32 with no padding, yielding 26 ASCII characters per
// id — collision-resistant for any realistic deployment.
//
// Per the MCP Security Best Practices, this ID is for *correlation*
// only — it MUST NOT be used for authentication. Callers that store
// session-scoped state SHOULD bind it to the authenticated identity,
// e.g. by keying as `<user_id>:<session_id>`, to defeat hijacking
// attacks where one user guesses or steals another user's session ID.
func NewSessionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])
	return strings.ToLower(enc), nil
}
