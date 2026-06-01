package server

import (
	"sync"
	"testing"
	"time"
)

func TestNewRateLimiter_ZeroRateDisabled(t *testing.T) {
	if l := NewRateLimiter(RateLimit{}); l != nil {
		t.Fatalf("NewRateLimiter(zero) = %v, want nil", l)
	}
	// A nil limiter must always allow — handlers rely on this.
	var nilLimiter *RateLimiter
	if !nilLimiter.Allow(time.Now(), "alice") {
		t.Fatalf("nil limiter must always Allow")
	}
}

func TestRateLimiter_AllowsBurstThenThrottles(t *testing.T) {
	l := NewRateLimiter(RateLimit{
		RequestsPerSecond: 10,
		Burst:             3,
	})
	now := time.Now()
	// Burst of 3 should succeed immediately.
	for i := 0; i < 3; i++ {
		if !l.Allow(now, "alice") {
			t.Fatalf("Allow #%d in burst denied", i+1)
		}
	}
	// 4th should be denied (no tokens left and no time has passed).
	if l.Allow(now, "alice") {
		t.Fatalf("4th request in same instant should be denied")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	l := NewRateLimiter(RateLimit{
		RequestsPerSecond: 10, // 100ms / token
		Burst:             1,
	})
	now := time.Now()
	if !l.Allow(now, "alice") {
		t.Fatalf("first request denied")
	}
	if l.Allow(now, "alice") {
		t.Fatalf("second request at same instant should be denied")
	}
	// 150ms later, the bucket should hold ~1.5 tokens → next call ok.
	if !l.Allow(now.Add(150*time.Millisecond), "alice") {
		t.Fatalf("request after refill window denied")
	}
}

func TestRateLimiter_IsolatesPerSubject(t *testing.T) {
	// alice and bob have independent buckets — alice exhausting hers
	// must not throttle bob.
	l := NewRateLimiter(RateLimit{RequestsPerSecond: 1, Burst: 1})
	now := time.Now()
	if !l.Allow(now, "alice") {
		t.Fatal("alice first call denied")
	}
	if l.Allow(now, "alice") {
		t.Fatal("alice second call (now bucket empty) should be denied")
	}
	if !l.Allow(now, "bob") {
		t.Fatal("bob's independent bucket should still have a token")
	}
}

func TestRateLimiter_BurstDefault(t *testing.T) {
	// Zero Burst should default to ceil(rate * 2).
	l := NewRateLimiter(RateLimit{RequestsPerSecond: 5})
	now := time.Now()
	// 5 rps * 2 = 10 burst → 10 successful calls before denial.
	for i := 0; i < 10; i++ {
		if !l.Allow(now, "alice") {
			t.Fatalf("Allow #%d denied (burst default should be 10 for rate=5)", i+1)
		}
	}
	if l.Allow(now, "alice") {
		t.Fatalf("11th call should be denied")
	}
}

func TestRateLimiter_CleanupRemovesIdleBuckets(t *testing.T) {
	l := NewRateLimiter(RateLimit{RequestsPerSecond: 10, Burst: 5})
	t0 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	l.Allow(t0, "old")
	l.Allow(t0.Add(time.Minute), "fresh")
	if l.Size() != 2 {
		t.Fatalf("Size = %d, want 2", l.Size())
	}

	// Cutoff at t0 + 30s removes "old" (idle since t0) but keeps
	// "fresh" (idle since t0+1m).
	if got := l.Cleanup(t0.Add(30 * time.Second)); got != 1 {
		t.Errorf("Cleanup removed %d, want 1", got)
	}
	if l.Size() != 1 {
		t.Errorf("Size after cleanup = %d, want 1", l.Size())
	}
}

func TestRateLimiter_ConcurrentAllow(t *testing.T) {
	l := NewRateLimiter(RateLimit{RequestsPerSecond: 1_000_000, Burst: 1_000_000})
	now := time.Now()
	const goroutines = 16
	const calls = 500
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			subject := "user-" + string(rune('A'+g%4)) // 4 subjects share, plenty of collisions
			for i := 0; i < calls; i++ {
				l.Allow(now, subject)
			}
		}(g)
	}
	wg.Wait()
}
