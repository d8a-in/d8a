# Contributing to d8a

Thanks for your interest! d8a is Apache-2.0 licensed open source, and we welcome contributions of code, documentation, bug reports, and ideas.

## Developer Certificate of Origin (DCO)

All contributions must be signed off under the [Developer Certificate of Origin (DCO) v1.1](https://developercertificate.org/) — a lightweight attestation that you have the right to submit your contribution under the project's license. No paperwork; just a `Signed-off-by:` trailer on every commit.

The DCO text:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is licensed under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

### How to sign off

Use `git commit --signoff` (or `-s`):

```bash
git commit -s -m "your message"
```

This appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name and email must match your `git config user.name` and `user.email`. Please use your real name — pseudonyms aren't accepted.

CI will reject pull requests containing commits without a valid sign-off.

## Workflow

1. For non-trivial changes, open an issue first so we can discuss the approach.
2. Fork the repo and create a topic branch.
3. Keep commits small, well-described, and DCO-signed.
4. Run `make fmt vet test` before pushing.
5. Open a pull request; CI must pass.

## Code style

- `gofmt`/`goimports`-formatted (`make fmt`).
- `go vet` clean (`make vet`).
- New behavior includes tests where it can be tested without external services.
- Public APIs in `internal/core` and other shared packages get doc comments.

## Security

If you find a security issue, **please do not open a public issue.** Email `security@d8a.in` for coordinated disclosure. A full security policy will be published as the project matures.
