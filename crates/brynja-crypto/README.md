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
SHA-2 byte and canonical arbitrary-bit implementations from
`brynja-hash-sha2`, including distinct hardened secret-bearing states, plus all
six complete portable FIPS 202 SHA-3 and SHAKE ordinary and hardened byte and
arbitrary-bit message functions and arbitrary-bit SHAKE output from
`brynja-hash-sha3`. The same leaf now supplies complete SP 800-185 encodings
and cSHAKE128/cSHAKE256 ordinary and hardened APIs. Its broader provider effects, AEADs,
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

All six SHA-2 algorithms plus all six FIPS 202 functions are usable through
this component; the remaining planned composition layer is not implemented
yet. Ordinary unkeyed hash and XOF states do not guarantee erasure of secret-
input remnants or private internal state. SHA-2 and SHA-3/SHAKE secret-bearing
consumers must use their distinct hardened state APIs with explicit public or
typed-secret output classification.

```rust
let bit_input = brynja_crypto::BitString::new(&[0b0110_0000], 3).unwrap();
let bit_digest = brynja_crypto::sha256_bits(bit_input).unwrap();
let shorter = brynja_crypto::sha224(b"abc").unwrap();
let digest = brynja_crypto::sha256(b"abc").unwrap();
let wider = brynja_crypto::sha384(b"abc").unwrap();
let widest = brynja_crypto::sha512(b"abc").unwrap();
let truncated_224 = brynja_crypto::sha512_224(b"abc").unwrap();
let truncated_256 = brynja_crypto::sha512_256(b"abc").unwrap();
let sha3_224 = brynja_crypto::sha3_224(b"abc").unwrap();
let sha3_256 = brynja_crypto::sha3_256(b"abc").unwrap();
let sha3_384 = brynja_crypto::sha3_384(b"abc").unwrap();
let sha3_512 = brynja_crypto::sha3_512(b"abc").unwrap();
let mut shake128 = [0_u8; 32];
let mut shake256 = [0_u8; 64];
brynja_crypto::shake128(b"abc", &mut shake128).unwrap();
brynja_crypto::shake256(b"abc", &mut shake256).unwrap();
let mut cshake128 = [0_u8; 32];
brynja_crypto::cshake128(&[0, 1, 2, 3], b"", b"Email Signature", &mut cshake128).unwrap();
assert_eq!(shorter.as_bytes().len(), 28);
assert_eq!(&bit_digest.as_bytes()[..4], &[0x1f, 0x77, 0x94, 0xd4]);
assert_eq!(digest.as_bytes().len(), 32);
assert_eq!(wider.as_bytes().len(), 48);
assert_eq!(widest.as_bytes().len(), 64);
assert_eq!(truncated_224.as_bytes().len(), 28);
assert_eq!(truncated_256.as_bytes().len(), 32);
assert_eq!(sha3_224.as_bytes().len(), 28);
assert_eq!(sha3_256.as_bytes().len(), 32);
assert_eq!(sha3_384.as_bytes().len(), 48);
assert_eq!(sha3_512.as_bytes().len(), 64);
assert_eq!(shake128.len(), 32);
assert_eq!(shake256.len(), 64);
assert_eq!(&cshake128[..4], &[0xc1, 0xc3, 0x69, 0x25]);
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
