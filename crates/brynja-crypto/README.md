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

# brynja-crypto

`brynja-crypto` is Brynja's protocol-facing cryptographic provider, policy,
and composition boundary. Future reusable leaf crates own individual hash,
XOF, and MAC families; `brynja-crypto` consumes their exact implementations
and combines them with AEAD, KDF, RSA, ECC, provider, and cryptographic policy
for protocol callers. The
dependency direction is always from `brynja-crypto` to the leaf families, never
back toward TLS or the full cryptographic graph.

In `0.1.1` this package establishes a compile-time boundary only; it does not
provide a working TLS, cryptographic, PKI, platform, or legacy-protocol
implementation.

## Cryptography Verification Status

No cryptographic code in this crate has been independently reviewed. This
component only moves from ❌ to ✅ when a named independent reviewer signs off
and the evidence is linked from its status entry. Project tests, CI, Kani,
Miri, fuzzing, and pentesting do not by themselves constitute independent
verification.

| Component | Cryptographic scope | Independently verified |
| --- | --- | --- |
| `brynja-crypto` | Provider contracts, cryptographic composition, AEADs, KDFs, RSA, and ECC | ❌ Not verified |

The component is not implemented yet.

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.1"
```

This dependency-only patch is selected for the v0.15.0 cumulative checkpoint
because it exact-pins `brynja-core 0.8.0`. The scheduled pentest passed with
zero findings. Publication still requires green hosted checks, the signed
checkpoint tag, and every version-specific gate in the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide first-party-cryptography, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
