package server

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeRunner is an in-process Runner implementation used for
// pool tests. It records Start/Stop/Call so the test can assert on
// lifecycle behavior without spawning real subprocesses.
//
// Each fakeRunner has a unique InstanceID assigned at construction
// — tests check this to prove that two pool partitions actually
// got DIFFERENT underlying Runners (and not the same instance
// accidentally aliased).
type fakeRunner struct {
	id       string
	caps     ServerCapabilities
	startErr error

	mu      sync.Mutex
	started bool
	stopped bool
	calls   []string
}

func (r *fakeRunner) Start(_ context.Context) (ServerCapabilities, error) {
	if r.startErr != nil {
		return nil, r.startErr
	}
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	return r.caps, nil
}

func (r *fakeRunner) Call(_ context.Context, method string, _ json.RawMessage) (json.RawMessage, *JSONRPCError) {
	r.mu.Lock()
	r.calls = append(r.calls, method)
	r.mu.Unlock()
	// Return the instance ID as the result so tests can prove which
	// Runner served the call.
	return json.RawMessage(`"` + r.id + `"`), nil
}

func (r *fakeRunner) Notify(_ context.Context, _ string, _ json.RawMessage) error { return nil }

func (r *fakeRunner) Stop() error {
	r.mu.Lock()
	r.stopped = true
	r.mu.Unlock()
	return nil
}

// fakeBackend is a Backend whose Build returns successive fakeRunners
// numbered 0, 1, 2, … so tests can identify which build call
// produced a given instance.
type fakeBackend struct {
	count int64
	caps  ServerCapabilities
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		caps: ServerCapabilities{"tools": json.RawMessage(`{}`)},
	}
}

// makeBackend returns the production Backend struct configured to
// invoke a closure that builds the next fakeRunner. We do this by
// monkey-patching: keep a counter, expose via a closure-captured
// build method. Since the production Backend type calls
// exec.Command, we don't use it here — instead the test pool is
// constructed via newTestPool below using fakeBackend directly.
func (b *fakeBackend) build() Runner {
	n := atomic.AddInt64(&b.count, 1) - 1
	return &fakeRunner{
		id:   "instance-" + jsonNumber(int(n)),
		caps: b.caps,
	}
}

// testPool wraps a RunnerPool with a fake Build override so tests
// don't have to invoke exec.Command. The override is plumbed by
// replacing pool.backend's Build behavior — which we can't do
// directly because Backend.Build is a method. So this test pool
// uses a wrapper type that swaps the construction path.
//
// We embed RunnerPool's logic by re-implementing the small surface
// the handler uses; that's enough for the behavior we want to test
// without surgery into the unexported pool internals.
type testPool struct {
	fb        *fakeBackend
	shareSafe bool

	mu         sync.Mutex
	instances  map[string]*fakeRunner
	cachedCaps ServerCapabilities
	closed     bool
}

func newTestPool(shareSafe bool) *testPool {
	return &testPool{
		fb:        newFakeBackend(),
		shareSafe: shareSafe,
		instances: make(map[string]*fakeRunner),
	}
}

func (p *testPool) partitionKey(identity Identity) string {
	if p.shareSafe {
		return sharedKey
	}
	return "subj:" + identity.Subject
}

func (p *testPool) Start(ctx context.Context) error {
	r := p.fb.build().(*fakeRunner)
	caps, err := r.Start(ctx)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.cachedCaps = caps
	if p.shareSafe {
		p.instances[sharedKey] = r
	}
	p.mu.Unlock()
	if !p.shareSafe {
		_ = r.Stop()
	}
	return nil
}

func (p *testPool) RunnerFor(ctx context.Context, identity Identity) (*fakeRunner, error) {
	key := p.partitionKey(identity)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("closed")
	}
	r, ok := p.instances[key]
	if !ok {
		r = p.fb.build().(*fakeRunner)
		p.instances[key] = r
		p.mu.Unlock()
		if _, err := r.Start(ctx); err != nil {
			return nil, err
		}
		return r, nil
	}
	p.mu.Unlock()
	return r, nil
}

func (p *testPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.instances)
}

func (p *testPool) Caps() ServerCapabilities {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cachedCaps
}

func (p *testPool) Close() {
	p.mu.Lock()
	p.closed = true
	insts := p.instances
	p.instances = nil
	p.mu.Unlock()
	for _, r := range insts {
		r.Stop()
	}
}

// ----- behavioral tests against testPool -----

func TestPool_ShareSafeOneRunnerServesAll(t *testing.T) {
	p := newTestPool(true)
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	if p.Size() != 1 {
		t.Fatalf("Size after Start = %d, want 1 (shared mode pre-spawns)", p.Size())
	}

	// Both alice and bob get the same runner instance.
	r1, _ := p.RunnerFor(context.Background(), Identity{Subject: "alice"})
	r2, _ := p.RunnerFor(context.Background(), Identity{Subject: "bob"})
	if r1.id != r2.id {
		t.Fatalf("share-safe mode handed out different instances (%s vs %s)", r1.id, r2.id)
	}
	if p.Size() != 1 {
		t.Fatalf("Size after two dispatches = %d, want 1", p.Size())
	}
}

func TestPool_IsolateModeOneRunnerPerIdentity(t *testing.T) {
	p := newTestPool(false)
	if err := p.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()

	// In isolate mode the warmup runner is spawned for caps AND
	// stopped — Size is 0 after Start.
	if p.Size() != 0 {
		t.Fatalf("Size after Start in isolate mode = %d, want 0", p.Size())
	}

	r1, _ := p.RunnerFor(context.Background(), Identity{Subject: "alice"})
	r2, _ := p.RunnerFor(context.Background(), Identity{Subject: "bob"})
	if r1.id == r2.id {
		t.Fatalf("isolate mode handed out the same instance to alice and bob (%s)", r1.id)
	}
	if p.Size() != 2 {
		t.Fatalf("Size after two dispatches = %d, want 2", p.Size())
	}

	// Same identity gets the same runner each time.
	r1b, _ := p.RunnerFor(context.Background(), Identity{Subject: "alice"})
	if r1.id != r1b.id {
		t.Fatalf("same identity got a different instance on second call (%s vs %s)", r1.id, r1b.id)
	}
}

func TestPool_CapsCachedFromWarmup(t *testing.T) {
	// Even in isolate mode, capabilities are cached at Start time
	// (the warmup runner) so initialize responses don't have to
	// spawn anything to know what to advertise.
	for _, shareSafe := range []bool{true, false} {
		p := newTestPool(shareSafe)
		if err := p.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
		caps := p.Caps()
		if _, ok := caps["tools"]; !ok {
			t.Errorf("shareSafe=%v: Caps missing tools key", shareSafe)
		}
		p.Close()
	}
}

// ----- unit tests against the real RunnerPool (no exec) -----

func TestRunnerPool_PartitionKey(t *testing.T) {
	shared := NewRunnerPool(Backend{}, true, newRunnerLogger())
	if k := shared.PartitionKey(Identity{Subject: "alice"}); k != sharedKey {
		t.Errorf("shareSafe partition key = %q, want %q", k, sharedKey)
	}
	isolate := NewRunnerPool(Backend{}, false, newRunnerLogger())
	if k := isolate.PartitionKey(Identity{Subject: "alice"}); k != "subj:alice" {
		t.Errorf("isolate partition key = %q, want subj:alice", k)
	}
}

func TestRunnerPool_SizeOnNilReceiverIsZero(t *testing.T) {
	// nil-receiver safety: handlers should be able to call pool.Size()
	// without checking for nil, simplifying composition.
	var p *RunnerPool
	if got := p.Size(); got != 0 {
		t.Errorf("nil pool Size = %d, want 0", got)
	}
	if got := p.Caps(); got != nil {
		t.Errorf("nil pool Caps = %v, want nil", got)
	}
	if err := p.Close(); err != nil {
		t.Errorf("nil pool Close = %v, want nil", err)
	}
}
