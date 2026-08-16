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

The current internal workspace reexports all six complete portable FIPS 180-4
SHA-2 implementations from `brynja-hash-sha2`. Its broader provider effects, AEADs,
KDFs, public-key cryptography, TLS, PKI, platform, and legacy-protocol scope
remain unimplemented.

## Cryptography Verification Status

No cryptographic code in this crate has been independently reviewed. This
component only moves from ❌ to ✅ when a named independent reviewer signs off
and the evidence is linked from its status entry. Project tests, CI, Kani,
Miri, fuzzing, and pentesting do not by themselves constitute independent
verification.

| Component | Cryptographic scope | Independently verified |
| --- | --- | --- |
| `brynja-crypto` | Provider contracts, cryptographic composition, AEADs, KDFs, RSA, and ECC | ❌ Not verified |

All six portable FIPS 180-4 SHA-2 algorithms are usable through this component;
the remaining planned composition layer is not implemented yet. Ordinary SHA-2 states do not
guarantee erasure of secret-input remnants or private internal state; keyed
constructions must use the later hardened secret-owning path.

```rust
let shorter = brynja_crypto::sha224(b"abc").unwrap();
let digest = brynja_crypto::sha256(b"abc").unwrap();
let wider = brynja_crypto::sha384(b"abc").unwrap();
let widest = brynja_crypto::sha512(b"abc").unwrap();
let truncated_224 = brynja_crypto::sha512_224(b"abc").unwrap();
let truncated_256 = brynja_crypto::sha512_256(b"abc").unwrap();
assert_eq!(shorter.as_bytes().len(), 28);
assert_eq!(digest.as_bytes().len(), 32);
assert_eq!(wider.as_bytes().len(), 48);
assert_eq!(widest.as_bytes().len(), 64);
assert_eq!(truncated_224.as_bytes().len(), 28);
assert_eq!(truncated_256.as_bytes().len(), 32);
```

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.20"
```

Version `0.1.2`, exact-pinned to `brynja-core 0.9.0`, was published at
v0.20.0 after the cumulative pentest, remediation retest, and hosted gates
recorded `PASS`/`PASS` with zero open findings under the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide first-party-cryptography, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
