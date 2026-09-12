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

# brynja-legacy-ssl2

SSL 2.0 controlled interoperability. This package currently establishes a compile-time workspace
boundary only; it does not provide the planned implementation.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| SSL 2.0 controlled interoperability | ❌ Not implemented | ❌ No |

There is no named independent cryptographic or protocol review and no FIPS
140-3 validation. A package compiling is not evidence of a working engine.

## Current use

No operational protocol or platform API is available here, so there is no application
integration example yet. To check the package boundary from the repository:

```sh
cargo test --locked -p brynja-legacy-ssl2
```

This explicitly isolated legacy boundary must not be used for new deployments
or general network endpoints. It is absent from the modern facade's defaults.
Independent review would not make an obsolete protocol secure. SHA-1 and MD5
are separate implemented leaves; their availability does not implement these
protocol engines.


## Hardware and SIMD

No hardware acceleration or SIMD implementation is exposed here. Future
engines will consume explicitly selected first-party crypto backends; they
must not imply that a CPU feature report authorizes execution.

This package is currently unpublished (`publish = false`). Its boundary is
not a release-readiness or publication claim.

[Implementation roadmap](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md)
· [Security policy](https://github.com/valkyoth/brynja/blob/main/SECURITY.md).
MIT OR Apache-2.0.
