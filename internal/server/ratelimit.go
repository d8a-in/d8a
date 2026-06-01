package server

import (
	"math"
	"sync"
	"time"
)

// RateLimit configures per-identity request rate limiting. A token
// bucket is maintained per authenticated Subject; each /mcp request
// consumes one token. When the bucket is empty, the request is
// rejected (the handler returns a JSON-RPC error with a "rate
// limited" message and HTTP 429).
//
// Per brainstorming #103: this protects the backing service from
// being hammered by a runaway / malicious AI client AND bounds the
// blast radius of a stolen API key. One control, two purposes.
//
// Defaults: zero values disable rate limiting. Operators must set
// RequestsPerSecond explicitly to enable it — secure-by-default
// requires opt-in tuning, since the right rate depends on the
// backing MCP's capabilities.
type RateLimit struct {
	// RequestsPerSecond is the sustained refill rate (tokens added
	// per second). Zero disables rate limiting entirely.
	RequestsPerSecond float64

	// Burst is the maximum number of tokens in the bucket — the
	// largest short-window burst the limiter allows. Zero defaults
	// to ceil(RequestsPerSecond * 2): two seconds of headroom.
	Burst float64

	// EvictAfter is how long a limiter for a given Subject can sit
	// idle (no Allow calls) before being garbage-collected. Zero
	// applies a sensible default (DefaultLimiterEviction).
	// Eviction keeps the per-identity map from growing unboundedly
	// as new subjects appear.
	EvictAfter time.Duration
}

// DefaultLimiterEviction is the idle window before a per-identity
// limiter is forgotten. 30 minutes parallels the session GC and
// is short enough that an attacker can't keep a stale bucket
// around indefinitely, long enough that a brief disconnect-and-
// reconnect doesn't reset a user's effective rate.
const DefaultLimiterEviction = 30 * time.Minute

// bucket is a single token-bucket rate limiter. Not exported —
// constructed and managed only by RateLimiter.
type bucket struct {
	rate     float64 // tokens added per second
	capacity float64 // maximum tokens (= burst)

	mu       sync.Mutex
	tokens   float64
	lastFill time.Time
	lastUsed time.Time
}

// allow consumes one token if available. Returns true (allowed)
// when the request is granted, false when the bucket is empty.
// The bucket is refilled inline before the check.
func (b *bucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	elapsed := now.Sub(b.lastFill).Seconds()
	if elapsed > 0 {
		b.tokens = math.Min(b.capacity, b.tokens+elapsed*b.rate)
		b.lastFill = now
	}
	b.lastUsed = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// idleSince reports the time of the most recent successful or
// rejected Allow call. Used by RateLimiter's eviction sweep.
func (b *bucket) idleSince() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastUsed
}

// RateLimiter holds a token-bucket limiter per identity Subject
// and exposes Allow / Cleanup for the request handler and the
// background GC goroutine.
//
// Construct via NewRateLimiter; the zero RateLimit disables
// limiting and NewRateLimiter returns nil in that case (callers
// should compare to nil before invoking).
type RateLimiter struct {
	cfg RateLimit

	mu      sync.Mutex
	buckets map[string]*bucket
}

// NewRateLimiter constructs a RateLimiter from cfg. Returns nil
// when rate limiting is disabled (cfg.RequestsPerSecond <= 0) so
// callers can switch on nil for "limiter not active."
func NewRateLimiter(cfg RateLimit) *RateLimiter {
	if cfg.RequestsPerSecond <= 0 {
		return nil
	}
	if cfg.Burst <= 0 {
		cfg.Burst = math.Ceil(cfg.RequestsPerSecond * 2)
	}
	if cfg.EvictAfter <= 0 {
		cfg.EvictAfter = DefaultLimiterEviction
	}
	return &RateLimiter{
		cfg:     cfg,
		buckets: make(map[string]*bucket),
	}
}

// Allow checks whether a request from subject is permitted at
// time now. Returns true if the bucket has a token to spare; false
// otherwise.
//
// A nil receiver is treated as "rate limiting disabled" and
// always returns true — so handlers can write
// `limiter.Allow(now, subject)` without a separate nil check.
func (l *RateLimiter) Allow(now time.Time, subject string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	b, ok := l.buckets[subject]
	if !ok {
		b = &bucket{
			rate:     l.cfg.RequestsPerSecond,
			capacity: l.cfg.Burst,
			tokens:   l.cfg.Burst, // start full so first request always succeeds
			lastFill: now,
			lastUsed: now,
		}
		l.buckets[subject] = b
	}
	l.mu.Unlock()
	return b.allow(now)
}

// Cleanup deletes buckets that haven't been used since cutoff.
// Returns the count removed. Used by the GC goroutine.
func (l *RateLimiter) Cleanup(cutoff time.Time) int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	removed := 0
	for subject, b := range l.buckets {
		if b.idleSince().Before(cutoff) {
			delete(l.buckets, subject)
			removed++
		}
	}
	return removed
}

// Size returns the number of active per-identity buckets. Exposed
// for observability / tests.
func (l *RateLimiter) Size() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
