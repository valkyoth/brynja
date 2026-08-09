<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja">Crates.io</a>
  |
  <a href="https://docs.rs/brynja">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md">Release Plan</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md">Threat Model</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/brynja">
    <img src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
  </a>
</p>

# brynja-test-support

`brynja-test-support` is a narrowly scoped, permanently unpublished Brynja
workspace package. In `0.1.0` it provides the RFC 9850 key-log line encoder
used by repository tests. All ten pinned IANA labels and LF, CRLF, and CR line
endings are explicit. Writes preflight the complete line and preserve the
complete output buffer on every capacity or input rejection.

No production package depends on this crate, and workspace policy rejects any
normal, optional, feature, target, or resolved production-graph edge to it. It
does not provide TLS, cryptography, PKI, a platform provider, or a legacy
protocol implementation. Key-log output reveals traffic secrets by design and
is therefore prohibited from every production package and feature.

## Cryptography Verification Status

This repository-only crate does not implement cryptographic or protocol code,
so it has no component status row. Fixtures, vectors, and test harnesses do
not independently verify a component. Only a named independent reviewer and
linked review evidence can change a component's independent-verification
status.

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.10"
```

This package is marked `publish = false` permanently. It is repository-only
test infrastructure and is not part of any crates.io publication set.

The project-wide no-third-party-crates, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
