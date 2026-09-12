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

Brynja's `no_std`, protocol-facing cryptographic composition and policy
boundary. Reusable leaf crates implement algorithms; this crate reexports
their APIs without making each leaf depend on the entire crypto or TLS graph.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| All six named SHA-2 and all six SHA-3/SHAKE functions | ✅ Fully implemented, reexported | ❌ No |
| cSHAKE, KMAC/KMACXOF, TupleHash and ParallelHash families | ✅ Fully implemented, reexported | ❌ No |
| AEAD, KDF, RSA, ECC and executable provider effects | ❌ Not implemented | ❌ No |

Named hashes and SP 800-185 constructions are usable; the broader planned
cryptographic composition layer is not complete. No independent cryptographic
review or FIPS 140-3 validation is claimed.

## Use

The hash/MAC APIs below require this unpublished checkout, not an older
published foundation-only package:

```sh
cargo add brynja-crypto --path /path/to/brynja/crates/brynja-crypto --no-default-features
```

```rust
let digest = brynja_crypto::sha256(b"abc").unwrap();
assert_eq!(digest.as_bytes().len(), 32);
let mut customized = [0; 32];
brynja_crypto::cshake128(&[0, 1, 2, 3], b"", b"Email Signature", &mut customized).unwrap();
assert_eq!(&customized[..4], &[0xc1, 0xc3, 0x69, 0x25]);
```

Use distinct hardened states for confidential data:

```rust
let mut output = [0; 32];
{
    let mut hash = brynja_crypto::HardenedSha256::new();
    hash.update(b"confidential input").unwrap();
    let secret = hash.finalize_secret(&mut output).unwrap();
    assert_eq!(secret.expose().len(), 32);
}
assert_eq!(output, [0; 32]);
```

## Hardware and SIMD

This composition facade defaults to portable APIs and owns no ISA kernels.
Select optional acceleration through the algorithm leaves and CPU authority
crates. x86-64 SHA/AVX2 and AArch64 SHA2/SHA-512/SHA3 support is
algorithm- and API-specific, not a global switch. Features do not authorize
unsupported instructions or silently route secret state through ordinary kernels.

## Boundaries

Ordinary unkeyed hash/XOF states do not guarantee erasure of private input
remnants. Hardened owners clear source-declared internal regions and classify
outputs as public or typed secret; callers retain responsibility for their
buffers and copies. Registers, compiler copies/spills, caches, dumps, swap,
forgotten owners and terminated processes remain outside the guarantee.

General SHA-512/t is a leaf opt-in extension, not a named SHA-2 facade identity.
Legacy SHA-1/MD5 and legacy protocols remain outside this modern composition
graph. `brynja-crypto` is not a replacement TLS engine or certificate validator.

[Facade examples](https://github.com/valkyoth/brynja/tree/main/crates/brynja)
· [Leaf architecture](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).
MIT OR Apache-2.0.
