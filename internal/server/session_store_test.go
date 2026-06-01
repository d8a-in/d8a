package server

import (
	"sync"
	"testing"
	"time"
)

func TestInMemorySessionStore_CreateAndGet(t *testing.T) {
	store := NewInMemorySessionStore()
	t0 := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	sess := store.Create("sid", "alice", "2025-11-25", Implementation{Name: "c"}, t0)
	if sess.ID != "sid" || sess.Subject != "alice" || !sess.CreatedAt.Equal(t0) {
		t.Fatalf("created session wrong: %+v", sess)
	}

	got, ok := store.Get("sid")
	if !ok {
		t.Fatal("Get returned !ok")
	}
	if got.Subject != "alice" {
		t.Errorf("Subject = %q", got.Subject)
	}
	if got.Initialized {
		t.Errorf("Initialized = true unexpectedly")
	}
}

func TestInMemorySessionStore_GetReturnsCopy(t *testing.T) {
	// Mutating the returned session must not affect stored state —
	// callers can't accidentally corrupt sessions for other goroutines.
	store := NewInMemorySessionStore()
	store.Create("sid", "alice", "v", Implementation{}, time.Now())

	got, _ := store.Get("sid")
	got.Subject = "MUTATED"

	again, _ := store.Get("sid")
	if again.Subject != "alice" {
		t.Fatalf("stored state was mutated: %q", again.Subject)
	}
}

func TestInMemorySessionStore_MarkInitialized(t *testing.T) {
	store := NewInMemorySessionStore()
	t0 := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	store.Create("sid", "alice", "v", Implementation{}, t0)

	t1 := t0.Add(time.Second)
	if !store.MarkInitialized("sid", t1) {
		t.Fatal("MarkInitialized returned false")
	}
	got, _ := store.Get("sid")
	if !got.Initialized {
		t.Errorf("Initialized = false")
	}
	if !got.LastSeen.Equal(t1) {
		t.Errorf("LastSeen = %v, want %v", got.LastSeen, t1)
	}

	if store.MarkInitialized("nope", t1) {
		t.Errorf("MarkInitialized returned true for unknown id")
	}
}

func TestInMemorySessionStore_Touch(t *testing.T) {
	store := NewInMemorySessionStore()
	t0 := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	store.Create("sid", "alice", "v", Implementation{}, t0)

	t1 := t0.Add(time.Minute)
	if !store.Touch("sid", t1) {
		t.Fatal("Touch returned false")
	}
	got, _ := store.Get("sid")
	if !got.LastSeen.Equal(t1) {
		t.Errorf("LastSeen = %v, want %v", got.LastSeen, t1)
	}
}

func TestInMemorySessionStore_Delete(t *testing.T) {
	store := NewInMemorySessionStore()
	store.Create("sid", "alice", "v", Implementation{}, time.Now())

	if !store.Delete("sid") {
		t.Fatal("Delete returned false")
	}
	if _, ok := store.Get("sid"); ok {
		t.Fatal("session still present after Delete")
	}
	if store.Delete("sid") {
		t.Fatal("Delete returned true for already-deleted id")
	}
}

func TestInMemorySessionStore_ExpireBefore(t *testing.T) {
	store := NewInMemorySessionStore()
	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	store.Create("old", "alice", "v", Implementation{}, t0.Add(-2*time.Hour))
	store.Create("medium", "bob", "v", Implementation{}, t0.Add(-30*time.Minute))
	store.Create("fresh", "carol", "v", Implementation{}, t0)

	// Cutoff = 1h ago: only "old" should disappear.
	cutoff := t0.Add(-1 * time.Hour)
	if got := store.ExpireBefore(cutoff); got != 1 {
		t.Errorf("expired = %d, want 1", got)
	}
	for _, name := range []string{"medium", "fresh"} {
		if _, ok := store.Get(name); !ok {
			t.Errorf("session %q wrongly expired", name)
		}
	}
	if _, ok := store.Get("old"); ok {
		t.Errorf("session 'old' should be gone")
	}

	// Bigger cutoff (5m ago) sweeps "medium" but not "fresh".
	if got := store.ExpireBefore(t0.Add(-5 * time.Minute)); got != 1 {
		t.Errorf("second sweep = %d, want 1", got)
	}
	if _, ok := store.Get("medium"); ok {
		t.Errorf("session 'medium' should be gone")
	}
	if _, ok := store.Get("fresh"); !ok {
		t.Errorf("session 'fresh' wrongly expired")
	}
}

func TestInMemorySessionStore_ExpireBeforeOnEmpty(t *testing.T) {
	store := NewInMemorySessionStore()
	if got := store.ExpireBefore(time.Now()); got != 0 {
		t.Errorf("expired = %d on empty store, want 0", got)
	}
}

func TestInMemorySessionStore_ExpireRefreshesOnTouch(t *testing.T) {
	// A session that gets Touch'd between sweep windows must survive.
	store := NewInMemorySessionStore()
	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	store.Create("s", "alice", "v", Implementation{}, t0)
	// Touch advances LastSeen.
	store.Touch("s", t0.Add(30*time.Minute))
	// Sweep cutoff 15m past t0 — would have caught the original
	// session, but Touch made it fresh.
	if got := store.ExpireBefore(t0.Add(15 * time.Minute)); got != 0 {
		t.Errorf("expired = %d, want 0 (Touch should have refreshed)", got)
	}
}

func TestInMemorySessionStore_ConcurrentAccess(t *testing.T) {
	// The store must survive concurrent Create/Get/Touch/Delete
	// without races (run this with `go test -race`).
	store := NewInMemorySessionStore()
	const goroutines = 32
	const iterations = 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			id := "sid-" + string(rune('A'+g))
			now := time.Now()
			for i := 0; i < iterations; i++ {
				store.Create(id, "alice", "v", Implementation{}, now)
				store.Touch(id, now)
				_, _ = store.Get(id)
			}
			store.Delete(id)
		}(g)
	}
	wg.Wait()
}
