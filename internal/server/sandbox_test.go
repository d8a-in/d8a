package server

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// requireBwrap skips the test if bwrap isn't installed *or* can't
// actually unshare in this environment. The latter happens on
// hardened distros that restrict unprivileged user namespaces
// (Ubuntu 24.04 default, GitHub Actions runners, some container
// environments) — bwrap is on PATH but every invocation fails at
// the namespace-setup stage.
//
// We probe with a minimal "unshare and exit 0" invocation so a
// broken environment skips cleanly instead of producing 3+ confusing
// FAIL lines.
func requireBwrap(t *testing.T) {
	t.Helper()
	if !SandboxAvailable() {
		t.Skip("bwrap not installed; skipping integration sandbox test")
	}
	// The probe needs enough of the host visible for `/usr/bin/true`
	// to actually run — that means /usr (for the binary), /lib for
	// libc, /lib64 for the dynamic linker. Match the same shape the
	// real tests use so the probe is a faithful predictor.
	probe := exec.Command("bwrap",
		"--unshare-pid", "--unshare-ipc", "--unshare-uts",
		"--die-with-parent",
		"--proc", "/proc", "--dev", "/dev",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"/usr/bin/true")
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("bwrap installed but cannot unshare in this environment "+
			"(likely apparmor/userns restrictions): %v\noutput: %s", err, out)
	}
}

// ----- pure argument-shape tests (no exec) -----

func TestWrapCommand_DisabledReturnsOriginal(t *testing.T) {
	orig := exec.Command("/bin/echo", "hello")
	wrapped, err := WrapCommand(orig, &SandboxPolicy{Disabled: true})
	if err != nil {
		t.Fatalf("WrapCommand: %v", err)
	}
	if wrapped != orig {
		t.Fatalf("expected the original cmd to pass through when Disabled")
	}
}

func TestWrapCommand_DefaultsIncludeSafeFlags(t *testing.T) {
	requireBwrap(t) // need bwrap on PATH to construct the wrapped cmd
	orig := exec.Command("/bin/echo", "hi")
	wrapped, err := WrapCommand(orig, nil)
	if err != nil {
		t.Fatalf("WrapCommand: %v", err)
	}
	args := strings.Join(wrapped.Args, " ")
	for _, must := range []string{
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--die-with-parent",
		"--clearenv",
		"--proc /proc",
		"--dev /dev",
		"--tmpfs /tmp",
	} {
		if !strings.Contains(args, must) {
			t.Errorf("default bwrap args missing %q\nargs: %s", must, args)
		}
	}
	// Default network is "host" → MUST NOT include --unshare-net.
	if strings.Contains(args, "--unshare-net") {
		t.Errorf("default policy unexpectedly unshared net: %s", args)
	}
}

func TestWrapCommand_NetworkNoneAddsUnshareNet(t *testing.T) {
	requireBwrap(t)
	orig := exec.Command("/bin/echo")
	wrapped, err := WrapCommand(orig, &SandboxPolicy{Network: "none"})
	if err != nil {
		t.Fatalf("WrapCommand: %v", err)
	}
	if !strings.Contains(strings.Join(wrapped.Args, " "), "--unshare-net") {
		t.Errorf("Network=\"none\" should include --unshare-net; args: %v", wrapped.Args)
	}
}

func TestWrapCommand_UnknownNetworkPolicyErrors(t *testing.T) {
	requireBwrap(t)
	_, err := WrapCommand(exec.Command("/bin/echo"), &SandboxPolicy{Network: "bogus"})
	if err == nil || !strings.Contains(err.Error(), "unsupported network policy") {
		t.Fatalf("err = %v, want unsupported-network error", err)
	}
}

func TestWrapCommand_UserBindsAreAdditiveNotReplacing(t *testing.T) {
	// Regression: when a caller supplies a BindReadOnly entry, the
	// built-in defaults (/usr, /bin, /lib, /etc, …) MUST still be
	// applied — otherwise the sandbox loses the shebang resolver
	// and dynamic linker and nothing runs. Caught in real-world
	// integration with the Postgres demo (where adding ~/.nvm
	// inadvertently dropped /usr and broke `#!/usr/bin/env node`).
	requireBwrap(t)
	orig := exec.Command("/bin/echo")
	wrapped, err := WrapCommand(orig, &SandboxPolicy{
		BindReadOnly: []string{"/home/example/.nvm"},
	})
	if err != nil {
		t.Fatalf("WrapCommand: %v", err)
	}
	args := strings.Join(wrapped.Args, " ")
	for _, must := range []string{
		"--ro-bind-try /usr /usr",                             // default
		"--ro-bind-try /etc /etc",                             // default
		"--ro-bind-try /home/example/.nvm /home/example/.nvm", // user-supplied
	} {
		if !strings.Contains(args, must) {
			t.Errorf("expected %q in wrapped args; got:\n%s", must, args)
		}
	}
}

func TestWrapCommand_NoDefaultsSkipsBuiltinBinds(t *testing.T) {
	requireBwrap(t)
	orig := exec.Command("/bin/echo")
	wrapped, err := WrapCommand(orig, &SandboxPolicy{
		NoDefaults:   true,
		BindReadOnly: []string{"/some/explicit/path"},
	})
	if err != nil {
		t.Fatalf("WrapCommand: %v", err)
	}
	args := strings.Join(wrapped.Args, " ")
	if strings.Contains(args, "--ro-bind-try /usr /usr") {
		t.Errorf("NoDefaults should suppress /usr default; got:\n%s", args)
	}
	if !strings.Contains(args, "--ro-bind-try /some/explicit/path /some/explicit/path") {
		t.Errorf("user-supplied path missing")
	}
}

func TestWrapCommand_RejectsRelativePaths(t *testing.T) {
	requireBwrap(t)
	_, err := WrapCommand(exec.Command("/bin/echo"), &SandboxPolicy{
		BindReadOnly: []string{"relative/path"},
	})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("err = %v, want absolute-path error", err)
	}
}

func TestWrapCommand_NoBwrapReturnsSentinel(t *testing.T) {
	if SandboxAvailable() {
		t.Skip("bwrap is installed on this host; cannot test missing-bwrap path here")
	}
	_, err := WrapCommand(exec.Command("/bin/echo"), nil)
	if !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("err = %v, want ErrSandboxUnavailable", err)
	}
}

func TestWrapCommand_PreservesIO(t *testing.T) {
	requireBwrap(t)
	var stdin, stdout, stderr bytes.Buffer
	orig := exec.Command("/bin/echo")
	orig.Stdin = &stdin
	orig.Stdout = &stdout
	orig.Stderr = &stderr
	wrapped, err := WrapCommand(orig, nil)
	if err != nil {
		t.Fatalf("WrapCommand: %v", err)
	}
	if wrapped.Stdin != &stdin {
		t.Error("stdin not propagated")
	}
	if wrapped.Stdout != &stdout {
		t.Error("stdout not propagated")
	}
	if wrapped.Stderr != &stderr {
		t.Error("stderr not propagated")
	}
}

func TestWrapCommand_EnvIsClearedThenSet(t *testing.T) {
	requireBwrap(t)
	orig := exec.Command("/bin/echo")
	orig.Env = []string{"FOO=bar", "BAZ=qux"}
	wrapped, err := WrapCommand(orig, nil)
	if err != nil {
		t.Fatalf("WrapCommand: %v", err)
	}
	args := strings.Join(wrapped.Args, " ")
	if !strings.Contains(args, "--clearenv") {
		t.Errorf("expected --clearenv in args: %v", wrapped.Args)
	}
	if !strings.Contains(args, "--setenv FOO bar") {
		t.Errorf("expected --setenv FOO bar; args: %v", wrapped.Args)
	}
	if !strings.Contains(args, "--setenv BAZ qux") {
		t.Errorf("expected --setenv BAZ qux; args: %v", wrapped.Args)
	}
}

// ----- integration tests: actually exec under the sandbox -----

// runSandboxed executes a `bash -c` script under the given sandbox
// policy and returns stdout and exit-error. Used by the integration
// tests below to assert real containment behavior.
func runSandboxed(t *testing.T, policy *SandboxPolicy, script string, env []string) (string, error) {
	t.Helper()
	cmd := exec.Command("/bin/bash", "-c", script)
	cmd.Env = env
	wrapped, err := WrapCommand(cmd, policy)
	if err != nil {
		t.Fatalf("WrapCommand: %v", err)
	}
	out, err := wrapped.Output()
	return strings.TrimSpace(string(out)), err
}

func TestSandbox_FilesystemHidesUserHome(t *testing.T) {
	requireBwrap(t)
	// With default mounts (no /home in BindReadOnly), files under the
	// user's home directory MUST NOT be visible inside the sandbox.
	out, err := runSandboxed(t, nil, `test -e "$HOME/.bashrc" && echo VISIBLE || echo HIDDEN`,
		[]string{"HOME=/home/" + currentUserDir(t)})
	if err != nil {
		t.Fatalf("run: %v (stderr: ...)", err)
	}
	if out != "HIDDEN" {
		t.Fatalf("$HOME/.bashrc was visible in the sandbox (out=%q); supply-chain containment broken", out)
	}
}

func TestSandbox_FilesystemReadOnly(t *testing.T) {
	requireBwrap(t)
	// /etc is bound read-only by default; the MCP must not be able
	// to modify it even though it can read it.
	out, err := runSandboxed(t, nil,
		`touch /etc/d8a-sandbox-write-test 2>&1 && echo ALLOWED || echo BLOCKED`,
		nil)
	if err != nil {
		// Non-zero exit from touch+error is expected; we still want
		// to inspect the stdout/stderr captured.
		_ = err
	}
	if !strings.Contains(out, "BLOCKED") {
		t.Fatalf("write to /etc was not blocked: out=%q", out)
	}
}

func TestSandbox_NetworkNoneBlocksExternal(t *testing.T) {
	requireBwrap(t)
	// With Network="none" the sandbox has only its own loopback;
	// dialing any external IP must fail at the routing layer with
	// "Network is unreachable" rather than connecting.
	out, _ := runSandboxed(t, &SandboxPolicy{Network: "none"},
		`(exec 3<>/dev/tcp/1.1.1.1/53 && echo LEAKED) 2>&1 | tail -1`,
		nil)
	if !strings.Contains(out, "Network is unreachable") &&
		!strings.Contains(out, "Network unreachable") {
		t.Fatalf("expected network-unreachable when sandboxed; got: %q", out)
	}
}

func TestSandbox_NetworkHostKeepsLoopback(t *testing.T) {
	requireBwrap(t)
	// With default Network="host" the sandbox shares the host's
	// network namespace, so a TCP connect to a host-loopback service
	// (whether or not it has a listener) does NOT get "Network is
	// unreachable" — the kernel attempts the connect and we get a
	// different errno (refused, timed out, etc.) or success.
	out, _ := runSandboxed(t, nil,
		`(exec 3<>/dev/tcp/127.0.0.1/1 && echo CONNECTED) 2>&1 | tail -1`,
		nil)
	if strings.Contains(out, "Network is unreachable") {
		t.Fatalf("default sandbox unexpectedly isolated host network: %q", out)
	}
}

// currentUserDir returns the basename of the current user's home dir,
// e.g. "d8a" for /home/d8a. Used by tests that need a HOME under the
// sandbox.
func currentUserDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("/bin/sh", "-c", "basename $HOME").Output()
	if err != nil {
		t.Fatalf("basename: %v", err)
	}
	return strings.TrimSpace(string(out))
}
