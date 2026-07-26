<p align="center">
  <b>Security-first, dependency-free, no_std TLS in Rust.</b><br>
  Built in small audited releases with strict modern/historical protocol isolation.
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

# brynja-historical-ssl3

`brynja-historical-ssl3` is an explicitly historical and insecure SSL 3.0
controlled-interoperability boundary. It must never be used for new deployments
or general network endpoints. In `0.1.0` it establishes a compile-time boundary
only and does not implement SSL 3.0.

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.1"
```

This package is currently marked `publish = false`. Publication requires the
version-specific deliverables, verification, documentation, and exact-commit
pentest in the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide no-third-party-crates, `no_std`, 500-line source-file,
platform-portability, and modern/historical isolation policies apply here.
