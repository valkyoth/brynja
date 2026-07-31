<p align="center">
  <b>Security-first, dependency-free, no_std TLS in Rust.</b><br>
  Built in small audited releases with strict modern/legacy protocol isolation.
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
    <img src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja Rust TLS crate overview">
  </a>
</p>

# brynja-interop

`brynja-interop` is a narrowly scoped Brynja workspace package. In `0.1.0` it
establishes a compile-time boundary only; it does not provide a working TLS,
cryptographic, PKI, platform, or legacy-protocol implementation.

## Cryptography Verification Status

This repository-only crate does not implement cryptographic or protocol code,
so it has no component status row. Interoperability and differential-test
results do not independently verify a component. Only a named independent
reviewer and linked review evidence can change a component's
independent-verification status.

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.1"
```

This package is currently marked `publish = false`. Publication requires the
version-specific deliverables, verification, documentation, a current
committed PASS pentest report, and green GitHub checks in the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide no-third-party-crates, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
