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
