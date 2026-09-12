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

# brynja-dtls

DTLS 1.2/1.3 engines. This package currently establishes a compile-time workspace
boundary only; it does not provide the planned implementation.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| DTLS 1.2/1.3 engines | ❌ Not implemented | ❌ No |

There is no named independent cryptographic or protocol review and no FIPS
140-3 validation. A package compiling is not evidence of a working engine.

## Current use

No operational protocol or platform API is available here, so there is no application
integration example yet. To check the package boundary from the repository:

```sh
cargo test --locked -p brynja-dtls
```

For implemented record-envelope parsing and encoding, see
[`brynja-protocol`](https://github.com/valkyoth/brynja/tree/main/crates/brynja-protocol).
That framing utility does not authenticate, encrypt or establish connections.

## Hardware and SIMD

No hardware acceleration or SIMD implementation is exposed here. Future
engines will consume explicitly selected first-party crypto backends; they
must not imply that a CPU feature report authorizes execution.

Published boundary packages do not imply operational implementation. Check the
capability table above before selecting this crate for an application.

[Implementation roadmap](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md)
· [Security policy](https://github.com/valkyoth/brynja/blob/main/SECURITY.md).
MIT OR Apache-2.0.
