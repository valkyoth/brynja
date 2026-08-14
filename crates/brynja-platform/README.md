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

# brynja-platform

`brynja-platform 0.1.8` repins its exact `brynja-core 0.9.0` dependency. It
remains a compile-time boundary only and does not provide a working TLS,
cryptographic, PKI, platform, or legacy-protocol implementation.

Brynja v0.13.0 freezes provider capabilities, opaque handles, caller limits,
destruction duties, and version-neutral request metadata upstream in
`brynja-core`. Future platform effects implement those upstream contracts
downstream; this crate does not redefine them, register a fallback provider, or
claim entropy, time, storage, path, pending-operation, or FIPS functionality.
Brynja v0.13.1 additionally freezes the upstream CPU-backend evidence, health,
dispatch, quarantine, and policy contract. This platform crate still supplies
no CPU detection or activation evidence and cannot manufacture backend
authority.
Brynja v0.16.0 freezes the upstream pending-operation effect and authoritative
destruction lifecycle. This package supplies no pending provider, external-key
store, accelerator driver, completion assertion, or cleanup implementation.
Brynja v0.17.0 freezes the upstream FIPS-aware provider architecture. This
package cannot classify module services, complete module self-tests, provide
an operational-environment identity, or turn platform evidence into a FIPS
claim; any later implementation must enter through separately reviewed exact
module contracts.

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.20"
```

Version `0.1.8` was published at v0.20.0 after the cumulative pentest,
remediation retest, and hosted checks recorded
`PASS`/`PASS` with zero open findings. It is governed by the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide no-third-party-crates, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
