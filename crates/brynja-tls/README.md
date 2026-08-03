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

# brynja-tls

`brynja-tls` is Brynja's evergreen modern TLS facade and one-pass
version-selection boundary. Version-specific protocol state remains in
`brynja-tls12`, `brynja-tls13`, and future version-named packages. Version
`0.1.5` only repins its exact v0.9 dependencies; it does not provide a
working TLS implementation.

## Cryptography Verification Status

No protocol code in this crate has been independently reviewed. This component
only moves from ❌ to ✅ when a named independent reviewer signs off and the
evidence is linked from its status entry. Project tests, CI, Kani, Miri,
fuzzing, and pentesting do not by themselves constitute independent
verification.

| Component | Protocol scope | Independently verified |
| --- | --- | --- |
| `brynja-tls` | Modern TLS version routing and policy | ❌ Not verified |

The component is not implemented yet.

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.9"
```

This dependency-only patch is selected for publication with v0.9.0. Pentest
dispositions are complete and require repository-owner retest before green
hosted release checks under the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide no-third-party-crates, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
