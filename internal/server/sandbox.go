package server

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrSandboxUnavailable is returned by WrapCommand when bwrap is not
// installed on the host (or not on PATH). For a security product the
// safe default is to refuse to launch rather than silently run without
// containment — callers should treat this as a hard configuration
// error, not a recoverable one.
var ErrSandboxUnavailable = errors.New("bubblewrap (bwrap) not available; sandboxing requires it")

// SandboxPolicy declares how a backing MCP subprocess is contained.
//
// Zero value means "sandbox enabled with safe defaults" (PID / IPC /
// UTS namespaces unshared, /proc and /dev replaced with fresh views,
// /tmp and /run mounted as tmpfs, the host filesystem visible only via
// explicit BindReadOnly / BindReadWrite paths, network shared with
// the host — see Network).
//
// Brainstorming references: #78 (sandboxing primitives — bubblewrap)
// and #79 (egress allowlist — partial: Network="none" blocks all
// outbound traffic; granular per-host allowlist is a later milestone).
type SandboxPolicy struct {
	// Network controls the network namespace of the subprocess.
	//
	//   "host" (default) — share the host network namespace. The MCP
	//                      can reach loopback services like a local
	//                      Postgres. External traffic is unrestricted
	//                      at this layer; rely on host-level egress
	//                      controls for that.
	//   "none"           — new network namespace; the subprocess has
	//                      only its own (empty) loopback. Loopback to
	//                      host services is NOT reachable — grant
	//                      access via unix sockets in BindReadWrite.
	Network string `json:"network,omitempty"`

	// BindReadOnly are *additional* absolute paths bind-mounted
	// read-only into the sandbox, on top of the sensible defaults
	// (see defaultROBinds). The MCP can read these but not write
	// them. Use for language runtimes (e.g. ~/.nvm), package caches
	// (e.g. ~/.npm if read-only is enough), application data, etc.
	BindReadOnly []string `json:"bindReadOnly,omitempty"`

	// BindReadWrite are absolute paths bind-mounted read-write into
	// the sandbox. Use sparingly — for unix sockets to allow access
	// (e.g. /var/run/postgresql), or for caches the MCP must update
	// (e.g. ~/.npm). Anything bind-mounted read-write is durable
	// state the MCP can modify, so each entry should be a deliberate
	// trust grant.
	BindReadWrite []string `json:"bindReadWrite,omitempty"`

	// NoDefaults disables the built-in default read-only mounts
	// (/usr, /bin, /sbin, /lib, /lib64, /etc). Almost no MCP will
	// run without them — they hold the dynamic linker, libc, and
	// the shebang resolver (/usr/bin/env). Set this only when you're
	// hand-building a minimal mount layout.
	NoDefaults bool `json:"noDefaults,omitempty"`

	// Disabled bypasses sandboxing entirely. Strongly discouraged in
	// production; intended for debugging or for environments where
	// the MCP supply chain is fully trusted.
	Disabled bool `json:"disabled,omitempty"`
}

// defaultROBinds is the read-only filesystem visible to every sandbox
// unless the policy overrides it. Deliberately spartan: nothing under
// /home, /root, /var/log, /var/lib, etc. is included.
var defaultROBinds = []string{
	"/usr",
	"/bin",
	"/sbin",
	"/lib",
	"/lib64",
	"/etc",
}

// WrapCommand wraps cmd inside a bwrap invocation per policy and
// returns a *new* *exec.Cmd that, when started, runs the original
// program with full namespace + filesystem containment.
//
// Stdin/Stdout/Stderr/Dir are copied to the wrapped cmd so the caller
// can pre-configure them on cmd as if no wrapping were happening.
//
// Environment handling: bwrap is invoked with --clearenv and a
// --setenv for every entry in cmd.Env, so the child sees ONLY what
// the caller put in cmd.Env (no leaks from the d8a-server process).
//
// If policy.Disabled is true, cmd is returned unchanged. If bwrap is
// not available, returns ErrSandboxUnavailable.
func WrapCommand(cmd *exec.Cmd, policy *SandboxPolicy) (*exec.Cmd, error) {
	p := resolveSandboxPolicy(policy)
	if p.Disabled {
		return cmd, nil
	}

	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSandboxUnavailable, err)
	}

	args, err := buildBwrapArgs(p, cmd)
	if err != nil {
		return nil, err
	}

	wrapped := exec.Command(bwrap, args...)
	// Pre-configured I/O on cmd should also apply to the wrapped cmd
	// — the caller doesn't have to know it's nested.
	wrapped.Stdin = cmd.Stdin
	wrapped.Stdout = cmd.Stdout
	wrapped.Stderr = cmd.Stderr
	wrapped.Dir = cmd.Dir
	// Intentionally do NOT propagate cmd.Env onto wrapped.Env: bwrap's
	// own environment is irrelevant once --clearenv runs; the child's
	// env comes from the --setenv args we built above.
	return wrapped, nil
}

// resolveSandboxPolicy returns the effective policy applied to a
// subprocess. nil input is treated as "all defaults."
//
// BindReadOnly is built additively: defaults are prepended unless
// NoDefaults is true. This way a caller who supplies a *single*
// extra read-only path (the common case: nvm/npm dir for an
// npx-based MCP) doesn't accidentally lose /usr, /lib, /etc — which
// would render the sandbox unable to run anything that has a
// shebang or a dynamically linked binary.
func resolveSandboxPolicy(p *SandboxPolicy) SandboxPolicy {
	var out SandboxPolicy
	if p != nil {
		out = *p
	}
	if out.Disabled || out.NoDefaults {
		return out
	}
	merged := make([]string, 0, len(defaultROBinds)+len(out.BindReadOnly))
	merged = append(merged, defaultROBinds...)
	merged = append(merged, out.BindReadOnly...)
	out.BindReadOnly = merged
	return out
}

// buildBwrapArgs renders a SandboxPolicy into the argument list passed
// to bwrap. The final two list elements are always "--" followed by
// the program and its arguments, so the caller doesn't have to wrap
// or quote them.
func buildBwrapArgs(p SandboxPolicy, cmd *exec.Cmd) ([]string, error) {
	args := []string{
		// Namespace unsharing — kernel-level containment.
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--unshare-cgroup-try", // cgroup ns isn't supported on all kernels; try-version is graceful.
		"--die-with-parent",    // kill the sandbox if d8a-server exits.
		"--new-session",        // detach from the terminal session so signals don't leak.

		// Filesystem skeleton inside the sandbox.
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--tmpfs", "/run",

		// Environment: clear everything, then re-add only what the
		// caller explicitly set on cmd.Env. Prevents accidental leak
		// of d8a-server's secrets into the MCP.
		"--clearenv",
	}

	switch p.Network {
	case "", "host":
		// Share host network — no --unshare-net.
	case "none":
		args = append(args, "--unshare-net")
	default:
		return nil, fmt.Errorf("sandbox: unsupported network policy %q (must be \"host\" or \"none\")", p.Network)
	}

	for _, path := range p.BindReadOnly {
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("sandbox: BindReadOnly path must be absolute: %q", path)
		}
		// --ro-bind-try silently skips a missing source path, which
		// is what we want for default mounts that may not exist on
		// every host (e.g. /lib64 on some systems).
		args = append(args, "--ro-bind-try", path, path)
	}
	for _, path := range p.BindReadWrite {
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("sandbox: BindReadWrite path must be absolute: %q", path)
		}
		args = append(args, "--bind-try", path, path)
	}

	for _, kv := range cmd.Env {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			// Skip malformed entries rather than failing the start —
			// a single bad env var shouldn't prevent the sandbox.
			continue
		}
		args = append(args, "--setenv", kv[:i], kv[i+1:])
	}

	args = append(args, "--")
	args = append(args, cmd.Path)
	args = append(args, cmd.Args[1:]...)
	return args, nil
}

// SandboxAvailable reports whether bwrap is installed and usable.
// Useful for startup-time checks and informative error messages.
func SandboxAvailable() bool {
	_, err := exec.LookPath("bwrap")
	return err == nil
}
