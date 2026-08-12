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

`brynja-platform 0.1.7` repins its exact `brynja-core 0.8.0` dependency. It
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

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.10"
```

This dependency-only patch is selected for v0.15.0 but remains unpublished
until its cumulative pentest and hosted checks pass. It is versioned `0.1.7`
under the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide no-third-party-crates, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
