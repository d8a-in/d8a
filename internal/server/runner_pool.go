package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"sync"
)

// Backend is the factory data for spawning a backing MCP. It captures
// everything the RunnerPool needs to build a fresh subprocess on
// demand — command, args, env, sandbox policy — without holding a
// (single-use) *exec.Cmd directly.
//
// The actual subprocess construction happens in Build(), which is
// called once per partition key the pool needs to materialize.
type Backend struct {
	// Command and Args are the subprocess to run (typically the
	// path to npx or the MCP binary).
	Command string
	Args    []string

	// Env is the environment passed through to the subprocess.
	// Empty is honored verbatim — the operator must enumerate what
	// the MCP needs (HOME, PATH, etc.).
	Env []string

	// Sandbox wraps each spawned subprocess in bubblewrap per the
	// configured policy. nil = safe defaults (see SandboxPolicy).
	// {Disabled: true} bypasses the sandbox.
	Sandbox *SandboxPolicy

	// ClientInfo identifies d8a-server to the backing MCP in the
	// initialize handshake.
	ClientInfo Implementation

	// Log is the logger each spawned Runner uses for its own
	// stderr forwarding.
	Log *slog.Logger
}

// Build constructs a fresh Runner (subprocess not yet started). The
// returned Runner is ready for Start(ctx).
func (b *Backend) Build() (Runner, error) {
	cmd := exec.Command(b.Command, b.Args...)
	cmd.Env = b.Env
	wrapped, err := WrapCommand(cmd, b.Sandbox)
	if err != nil {
		return nil, fmt.Errorf("sandbox wrap: %w", err)
	}
	return NewStdioRunner(wrapped, b.ClientInfo, b.Log), nil
}

// RunnerPool manages backing-MCP subprocesses keyed by a partition
// string. Two modes:
//
//   - shareSafe=true: every identity gets the SAME Runner (the
//     pool holds exactly one instance under the key "__shared").
//     Cheapest, appropriate when the backing MCP itself is
//     stateless w.r.t. cross-user data (e.g. a read-only Postgres
//     with shared admin credentials).
//
//   - shareSafe=false: each authenticated identity gets its OWN
//     Runner (partition key = "subj:<Subject>"). Heavier — N
//     MCP subprocesses for N concurrent identities — but the only
//     correct posture when the MCP holds per-user state or needs
//     per-user credentials.
//
// Lifecycle: Start() spawns one Runner up-front to discover the
// backing MCP's capabilities (always — the capabilities are cached
// for every initialize response regardless of mode, so we don't
// have to wait for a real call to learn them). In shareSafe mode
// that Runner becomes the shared instance. In isolate mode it's
// stopped after caps discovery; per-identity Runners spawn lazily
// on first RunnerFor() call.
//
// Close() stops every live Runner in the pool.
type RunnerPool struct {
	backend   Backend
	shareSafe bool
	log       *slog.Logger

	mu         sync.Mutex
	instances  map[string]*pooledInstance
	cachedCaps ServerCapabilities
	closed     bool
}

// pooledInstance holds a Runner that's been spawned for one
// partition key. startOnce guarantees Start runs exactly once even
// with concurrent RunnerFor() callers; startErr captures failure.
type pooledInstance struct {
	runner    Runner
	startOnce sync.Once
	startErr  error
	started   bool
}

// NewRunnerPool constructs a pool for the given backend. shareSafe
// = true means one Runner serves all identities; false means
// per-identity isolation.
func NewRunnerPool(backend Backend, shareSafe bool, log *slog.Logger) *RunnerPool {
	return &RunnerPool{
		backend:   backend,
		shareSafe: shareSafe,
		log:       log,
		instances: make(map[string]*pooledInstance),
	}
}

// sharedKey is the partition key used when shareSafe is true. The
// underscore prefix avoids any collision with a Subject named
// "shared".
const sharedKey = "__shared"

// PartitionKey returns the pool partition key for an identity, given
// the pool's share-safe configuration. Exposed for tests and audit
// logging.
func (p *RunnerPool) PartitionKey(identity Identity) string {
	if p.shareSafe {
		return sharedKey
	}
	return "subj:" + identity.Subject
}

// Start performs the eager capabilities-discovery spawn. Always
// spawns at least one Runner so the cached caps are populated
// before any initialize response goes out — keeps initialize
// snappy regardless of mode.
//
// In shareSafe mode the spawned Runner stays alive (under the
// shared key). In isolate mode it's stopped after caps are learned;
// per-identity Runners spawn lazily.
func (p *RunnerPool) Start(ctx context.Context) error {
	runner, err := p.backend.Build()
	if err != nil {
		return fmt.Errorf("backend build: %w", err)
	}
	caps, err := runner.Start(ctx)
	if err != nil {
		// Cleanly stop the half-started runner before propagating.
		_ = runner.Stop()
		return fmt.Errorf("warmup start: %w", err)
	}

	p.mu.Lock()
	p.cachedCaps = caps
	if p.shareSafe {
		// Keep this runner; it serves everyone.
		inst := &pooledInstance{runner: runner, started: true}
		// Pre-fire startOnce so RunnerFor doesn't try to re-start it.
		inst.startOnce.Do(func() {})
		p.instances[sharedKey] = inst
	}
	p.mu.Unlock()

	if !p.shareSafe {
		// In isolate mode the warmup runner is just for caps;
		// stop it now.
		_ = runner.Stop()
		p.log.Info("backing mcp pool ready (isolate mode; per-identity runners spawn on demand)")
	} else {
		p.log.Info("backing mcp pool ready (shared mode)",
			"capabilities", capKeyList(caps))
	}
	return nil
}

// capKeyList renders a ServerCapabilities map to a slice of keys for
// readable logging without dumping potentially-large per-capability
// payload objects.
func capKeyList(caps ServerCapabilities) []string {
	out := make([]string, 0, len(caps))
	for k := range caps {
		out = append(out, k)
	}
	return out
}

// RunnerFor returns the Runner that should serve the given identity,
// starting it lazily if this is the first request under its
// partition key.
//
// ctx controls the underlying Runner.Start when lazy creation is
// triggered. The handler typically passes its request context, but
// in production you may want to pass the server-lifetime context
// so a fast HTTP-timeout client doesn't cancel a real start.
func (p *RunnerPool) RunnerFor(ctx context.Context, identity Identity) (Runner, error) {
	if p == nil {
		return nil, errors.New("nil runner pool")
	}
	key := p.PartitionKey(identity)

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("runner pool closed")
	}
	inst, ok := p.instances[key]
	if !ok {
		runner, err := p.backend.Build()
		if err != nil {
			p.mu.Unlock()
			return nil, fmt.Errorf("backend build: %w", err)
		}
		inst = &pooledInstance{runner: runner}
		p.instances[key] = inst
		p.log.Info("spawning new backing mcp for partition", "key", key)
	}
	p.mu.Unlock()

	// sync.Once means the FIRST goroutine to reach a fresh inst
	// runs Start; concurrent callers wait for it to finish.
	inst.startOnce.Do(func() {
		if _, err := inst.runner.Start(ctx); err != nil {
			inst.startErr = err
			return
		}
		inst.started = true
	})
	if inst.startErr != nil {
		return nil, inst.startErr
	}
	return inst.runner, nil
}

// Caps returns the cached backing-MCP capabilities. Populated by
// Start; safe to call concurrently.
func (p *RunnerPool) Caps() ServerCapabilities {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cachedCaps
}

// Size returns the number of live partition instances. Useful for
// tests and operability metrics.
func (p *RunnerPool) Size() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.instances)
}

// Close stops every live Runner in the pool. After Close, RunnerFor
// returns an error. Idempotent.
func (p *RunnerPool) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	insts := p.instances
	p.instances = nil
	p.mu.Unlock()

	var firstErr error
	for key, inst := range insts {
		if !inst.started {
			continue
		}
		if err := inst.runner.Stop(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("stop %s: %w", key, err)
		}
	}
	return firstErr
}
