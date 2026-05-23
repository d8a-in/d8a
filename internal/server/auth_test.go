package server

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestHashTokenStable(t *testing.T) {
	a := HashToken("hello")
	b := HashToken("hello")
	if a != b {
		t.Fatalf("HashToken not stable: %q vs %q", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("HashToken length = %d, want 64", len(a))
	}
	if strings.ToLower(a) != a {
		t.Fatalf("HashToken not lowercase: %q", a)
	}
}

func TestNewAPIKeyValidator_RejectsBadHash(t *testing.T) {
	_, err := NewAPIKeyValidator([]APIKey{{
		TokenHashHex: "not-hex",
		Audience:     "https://example",
	}})
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
	_, err = NewAPIKeyValidator([]APIKey{{
		TokenHashHex: "deadbeef", // valid hex but too short
		Audience:     "https://example",
	}})
	if err == nil {
		t.Fatal("expected error for short hash")
	}
}

func newValidatorWithKey(t *testing.T, token, audience, subject string, scopes []string) Validator {
	t.Helper()
	v, err := NewAPIKeyValidator([]APIKey{{
		TokenHashHex: HashToken(token),
		Audience:     audience,
		Subject:      subject,
		Scopes:       scopes,
	}})
	if err != nil {
		t.Fatalf("NewAPIKeyValidator: %v", err)
	}
	return v
}

func TestAPIKeyValidator_Success(t *testing.T) {
	v := newValidatorWithKey(t, "secret", "https://a.example/mcp", "alice", []string{"postgres:read"})

	id, err := v.Validate(context.Background(), "secret", "https://a.example/mcp")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if id.Subject != "alice" {
		t.Errorf("Subject = %q, want %q", id.Subject, "alice")
	}
	if len(id.Scopes) != 1 || id.Scopes[0] != "postgres:read" {
		t.Errorf("Scopes = %v, want [postgres:read]", id.Scopes)
	}
}

func TestAPIKeyValidator_WrongToken(t *testing.T) {
	v := newValidatorWithKey(t, "secret", "https://a.example/mcp", "alice", nil)
	if _, err := v.Validate(context.Background(), "WRONG", "https://a.example/mcp"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken", err)
	}
}

func TestAPIKeyValidator_WrongAudience(t *testing.T) {
	v := newValidatorWithKey(t, "secret", "https://a.example/mcp", "alice", nil)
	if _, err := v.Validate(context.Background(), "secret", "https://b.example/mcp"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v, want ErrInvalidToken (audience binding)", err)
	}
}

func TestAPIKeyValidator_EmptyInputs(t *testing.T) {
	v := newValidatorWithKey(t, "secret", "https://a.example/mcp", "alice", nil)
	if _, err := v.Validate(context.Background(), "", "https://a.example/mcp"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("empty token: err = %v, want ErrInvalidToken", err)
	}
	if _, err := v.Validate(context.Background(), "secret", ""); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("empty audience: err = %v, want ErrInvalidToken", err)
	}
}

func TestAPIKeyValidator_ScopesAreCopied(t *testing.T) {
	// Mutating the returned scopes must not affect future calls — the
	// stored Identity is not shared.
	v := newValidatorWithKey(t, "secret", "aud", "alice", []string{"a", "b"})

	id1, _ := v.Validate(context.Background(), "secret", "aud")
	id1.Scopes[0] = "MUTATED"
	id2, _ := v.Validate(context.Background(), "secret", "aud")
	if id2.Scopes[0] != "a" {
		t.Fatalf("scopes leaked across calls: %v", id2.Scopes)
	}
}
