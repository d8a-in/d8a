# Security Policy

Thanks for taking the time to help keep d8a's users safe.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, email **security@d8a.in** with:

- A clear description of the issue and its security impact.
- Steps to reproduce, or a minimal proof-of-concept if you have one.
- The version / commit you tested against (and your operating system /
  bubblewrap version if it's environment-specific).
- Any disclosure timeline constraints you have on your end.

We acknowledge reports within **3 business days** and aim to have a
fix or a published advisory within **30 days** of acknowledgment for
most issues; complex multi-component issues may take longer, and we'll
keep you in the loop. We won't pursue legal action against good-faith
researchers following this process.

If you don't receive an acknowledgment within 3 business days, please
follow up — emails do occasionally end up in spam.

## Supported versions

d8a is pre-1.0 and pre-release; we patch the `main` branch and the
most recent tagged release only. Older releases do not receive
security fixes.

## Threat model

d8a is the connective tissue between an AI client and the customer's
internal services. The architecture is **blind / no-data-access**:
the d8a-server intentionally does not see customer data in clear
form, does not hold customer credentials in its own memory, and runs
the backing MCP subprocess inside a bubblewrap sandbox. Practical
implications:

- **Bearer tokens** presented at `/mcp` are short, audience-bound API
  keys today and will be OAuth 2.1 access tokens with `resource`
  binding (RFC 8707) in connected/paid mode. Cross-server token
  replay is explicitly prevented by audience validation.
- **Sessions** are correlation only — they are *not* used for
  authentication. Every request still re-validates its bearer token.
- **The backing MCP subprocess** runs in its own PID / IPC / UTS
  namespace under bubblewrap, with a minimal filesystem view, no
  inherited environment, and a configurable network policy (`host`
  or `none`). A compromised MCP package cannot reach the user's
  `$HOME`, `/etc/shadow`, or — with `network: "none"` — the
  internet.
- **No token passthrough.** Per the MCP Authorization spec, the
  bearer token a client presents to d8a-server is NEVER forwarded
  to the backing MCP. The backing MCP uses its own configured
  credentials, injected at the last hop.

Out of scope for this policy:
- Vulnerabilities in third-party MCP packages we run as backends
  (please report those upstream; d8a's sandbox is the mitigation
  on our side).
- DoS-of-self on a developer's own machine (e.g., RAM exhaustion
  from a runaway local query).
- Issues that require physical access to a machine running
  d8a-server.

## Disclosure

Once a fix is released and users have had a reasonable window to
upgrade (typically 14 days, longer for issues we believe are widely
exploitable), we publish a GitHub security advisory crediting the
reporter (with their permission). We're happy to coordinate the
timing if you have other downstream consumers to notify.
