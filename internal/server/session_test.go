package server

import (
	"testing"
)

func TestNewSessionID_NonEmpty(t *testing.T) {
	id, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	if id == "" {
		t.Fatal("NewSessionID returned empty string")
	}
}

func TestNewSessionID_VisibleASCII(t *testing.T) {
	// The MCP spec requires session IDs to contain only visible ASCII
	// characters (0x21–0x7E inclusive).
	id, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	for i, r := range id {
		if r < 0x21 || r > 0x7E {
			t.Fatalf("byte %d in %q is not visible ASCII (0x%X)", i, id, r)
		}
	}
}

func TestNewSessionID_UniqueAcrossCalls(t *testing.T) {
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id, err := NewSessionID()
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("collision after %d calls: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

func TestNewSessionID_Length(t *testing.T) {
	id, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	// 16 random bytes → 26 chars of un-padded base32.
	if got := len(id); got != 26 {
		t.Fatalf("len = %d, want 26", got)
	}
}
