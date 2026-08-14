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

# brynja-tls13

`brynja-tls13` is the version-specific TLS 1.3 stream engine boundary. Version
`0.1.8` consumes the checkpoint-selected shared `brynja-protocol 0.1.0`
record-envelope boundary in the workspace. It still does not provide a working
TLS, cryptographic, PKI, or platform implementation.

## Cryptography Verification Status

No protocol code in this crate has been independently reviewed. This component
only moves from ❌ to ✅ when a named independent reviewer signs off and the
evidence is linked from its status entry. Project tests, CI, Kani, Miri,
fuzzing, and pentesting do not by themselves constitute independent
verification.

| Component | Protocol scope | Independently verified |
| --- | --- | --- |
| `brynja-tls13` | TLS 1.3 stream record and protocol engine | ❌ Not verified |

The component is not implemented yet.

Most application users will eventually depend on the evergreen facade:

```toml
[dependencies]
brynja = "0.20"
```

Version `0.1.8` was published at v0.20.0 after the cumulative pentest,
remediation retest, and hosted checks recorded `PASS`/`PASS`
with zero open findings. It is governed by the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide no-third-party-crates, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
