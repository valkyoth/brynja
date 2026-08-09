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

# brynja-research-ssl1

`brynja-research-ssl1` is an unpublished reconstruction and
provenance-research boundary. It can never expose a secure transport API,
accept production credentials, or be published by default. In `0.1.0` it
establishes the compile-time boundary only.

## Cryptography Verification Status

No reconstructed SSL 1.0 code in this crate has been independently reviewed.
This component only moves from ❌ to ✅ when a named independent reviewer signs
off and the evidence is linked from its status entry. Project tests, CI, Kani,
Miri, fuzzing, and pentesting do not by themselves constitute independent
verification. Independent verification could never authorize a secure
transport claim for this research crate.

| Component | Protocol scope | Independently verified |
| --- | --- | --- |
| `brynja-research-ssl1` | Unpublished SSL 1.0 provenance reconstruction | ❌ Not verified |

The component is not implemented yet.

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.1"
```

This package is permanently marked `publish = false`. No release-plan milestone
authorizes publication or a secure transport claim.

The project-wide no-third-party-crates, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
