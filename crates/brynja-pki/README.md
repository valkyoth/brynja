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

# brynja-pki

`brynja-pki 0.1.7` repins its exact `brynja-core 0.8.0` dependency. It remains
a compile-time boundary only and does not provide a working TLS,
cryptographic, PKI, platform, or legacy-protocol implementation.

## Cryptography Verification Status

No PKI code in this crate has been independently reviewed. This component only
moves from ❌ to ✅ when a named independent reviewer signs off and the
evidence is linked from its status entry. Project tests, CI, Kani, Miri,
fuzzing, and pentesting do not by themselves constitute independent
verification.

| Component | Cryptographic scope | Independently verified |
| --- | --- | --- |
| `brynja-pki` | ASN.1, DER, X.509, path validation, and revocation | ❌ Not verified |

The component is not implemented yet.

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
