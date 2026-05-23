package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

// Identity describes who is making a request after a successful credential
// validation. It travels on the request context (see IdentityFromContext)
// so downstream handlers can authorize and audit consistently.
type Identity struct {
	// Subject is a stable identifier for the caller (e.g. a key ID,
	// username, or future OAuth subject claim). It's what shows up
	// in audit logs.
	Subject string

	// Scopes are the capability scopes this caller has been granted.
	// The /mcp handler (added in M3) uses these as the input to the
	// PDP/PEP authorization step.
	Scopes []string
}

// ErrInvalidToken is returned by Validator when a credential cannot be
// authenticated (missing, malformed, unknown, expired, or bound to a
// different audience). The middleware translates this into a uniform
// 401 response and never leaks the underlying reason — a single
// "invalid" prevents probing of which dimension failed.
var ErrInvalidToken = errors.New("invalid token")

// Validator authenticates a bearer token presented by an MCP client.
//
// audience is the canonical URL of this d8a-server instance (per
// RFC 8707 Resource Indicators). Implementations MUST verify that
// the credential is bound to this audience and reject otherwise, so
// that a token leaked from one d8a-server instance cannot be replayed
// against another. This is the API-key analogue of OAuth's `resource`
// parameter binding.
//
// The interface is designed so an OAuthBearerValidator can replace
// APIKeyValidator later without any wire-format or middleware change.
type Validator interface {
	Validate(ctx context.Context, token, audience string) (Identity, error)
}

// APIKey describes a single API-key configuration entry.
//
// The raw token is never stored — only its SHA-256 hash — so a
// snapshot of the configuration on disk does not leak working
// credentials. The matching is constant-time.
type APIKey struct {
	// TokenHashHex is the lowercase hex-encoded SHA-256 of the raw
	// bearer token a client will present (64 hex chars).
	TokenHashHex string `json:"tokenHashHex"`

	// Audience is the canonical URL this key is valid for. A presented
	// audience must match exactly (case-sensitive).
	Audience string `json:"audience"`

	// Subject is a stable identifier for the key holder, surfaced to
	// audit logs.
	Subject string `json:"subject"`

	// Scopes are the capability scopes granted to this key.
	Scopes []string `json:"scopes"`
}

// APIKeyValidator is a Validator backed by a static list of API keys.
// It uses constant-time comparison so an attacker can't learn anything
// from response timing.
type APIKeyValidator struct {
	keys []APIKey
	// decoded[i] mirrors keys[i].TokenHashHex pre-decoded for speed.
	decoded [][]byte
}

// NewAPIKeyValidator constructs a validator from the given key set.
// Each key's TokenHashHex must decode to a 32-byte (SHA-256) value;
// invalid entries cause an error so misconfigurations fail loudly at
// startup instead of silently rejecting every request.
func NewAPIKeyValidator(keys []APIKey) (*APIKeyValidator, error) {
	decoded := make([][]byte, len(keys))
	for i, k := range keys {
		raw, err := hex.DecodeString(k.TokenHashHex)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("apikey[%d]: invalid tokenHashHex (must be 64 hex chars of SHA-256)", i)
		}
		decoded[i] = raw
	}
	out := make([]APIKey, len(keys))
	copy(out, keys)
	return &APIKeyValidator{keys: out, decoded: decoded}, nil
}

// HashToken returns the lowercase hex-encoded SHA-256 of token.
// Exposed so config generators (and the `--hash-token` flag in
// cmd/server) can produce TokenHashHex values for the config file.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Validate implements Validator. It always iterates the full key set
// regardless of an early match, so response time does not vary with
// where (or whether) a match occurs.
func (v *APIKeyValidator) Validate(_ context.Context, token, audience string) (Identity, error) {
	if token == "" || audience == "" {
		return Identity{}, ErrInvalidToken
	}
	presented := sha256.Sum256([]byte(token))

	var match *APIKey
	for i := range v.keys {
		hashEq := subtle.ConstantTimeCompare(presented[:], v.decoded[i]) == 1
		audEq := subtle.ConstantTimeCompare([]byte(audience), []byte(v.keys[i].Audience)) == 1
		if hashEq && audEq && match == nil {
			match = &v.keys[i]
			// Do not break: keep iterating so timing is uniform.
		}
	}
	if match == nil {
		return Identity{}, ErrInvalidToken
	}
	return Identity{
		Subject: match.Subject,
		Scopes:  append([]string(nil), match.Scopes...),
	}, nil
}
