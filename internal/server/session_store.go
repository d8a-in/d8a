package server

import (
	"sync"
	"time"
)

// Session is one MCP session: an authenticated client correlated
// with a server-issued session ID. Sessions do NOT carry
// authentication (that's the bearer token's job, per
// brainstorming #120) — they only associate state across the
// request/response stream.
//
// Subject is a snapshot of the authenticated Identity.Subject at
// initialize time, so the handler can defend against session
// hijack by checking that subsequent requests come from the same
// identity.
type Session struct {
	ID              string
	Subject         string
	ProtocolVersion string
	ClientInfo      Implementation
	Initialized     bool
	CreatedAt       time.Time
	LastSeen        time.Time
}

// SessionStore manages MCP sessions. Implementations must be
// goroutine-safe.
//
// Time values are passed in by the caller instead of read from the
// system clock, so tests can drive the store with a fixed clock
// and assert exact timestamp behavior.
type SessionStore interface {
	Create(id, subject, version string, info Implementation, now time.Time) *Session
	Get(id string) (*Session, bool)
	MarkInitialized(id string, now time.Time) bool
	Touch(id string, now time.Time) bool
	Delete(id string) bool

	// ExpireBefore deletes every session whose LastSeen is strictly
	// before t. Returns the number of sessions removed so callers
	// can log / report. Used by Server.Run's periodic GC sweep.
	ExpireBefore(t time.Time) int
}

// InMemorySessionStore is a simple goroutine-safe in-memory store.
// Sessions have no automatic expiry yet — a later milestone will add
// idle timeouts (and, if needed, distribute state across multiple
// server replicas).
type InMemorySessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewInMemorySessionStore constructs an empty store.
func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{sessions: make(map[string]*Session)}
}

// Create stores a new session.
func (s *InMemorySessionStore) Create(id, subject, version string, info Implementation, now time.Time) *Session {
	sess := &Session{
		ID:              id,
		Subject:         subject,
		ProtocolVersion: version,
		ClientInfo:      info,
		CreatedAt:       now,
		LastSeen:        now,
	}
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	// Return a copy so callers can't mutate stored state by accident.
	out := *sess
	return &out
}

// Get returns a copy of the session with the given id, or false.
func (s *InMemorySessionStore) Get(id string) (*Session, bool) {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	out := *sess
	return &out, true
}

// MarkInitialized records that notifications/initialized has been
// received for the session. Returns false if the session is unknown.
func (s *InMemorySessionStore) MarkInitialized(id string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return false
	}
	sess.Initialized = true
	sess.LastSeen = now
	return true
}

// Touch updates LastSeen.
func (s *InMemorySessionStore) Touch(id string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return false
	}
	sess.LastSeen = now
	return true
}

// Delete removes the session. Returns false if it didn't exist.
func (s *InMemorySessionStore) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[id]; !ok {
		return false
	}
	delete(s.sessions, id)
	return true
}

// ExpireBefore implements SessionStore. Iterates under the write
// lock and removes everything older than t.
func (s *InMemorySessionStore) ExpireBefore(t time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	deleted := 0
	for id, sess := range s.sessions {
		if sess.LastSeen.Before(t) {
			delete(s.sessions, id)
			deleted++
		}
	}
	return deleted
}
