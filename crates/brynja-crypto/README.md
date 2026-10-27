<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja-crypto">Crates.io</a>
  |
  <a href="https://docs.rs/brynja-crypto">Docs.rs</a>
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
    <img width="840" src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
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
| Modern HMAC over SHA-2/SHA-3 | ✅ Fully implemented portable API; explicit execution qualification separate | ❌ No |
| AEAD, KDF, RSA, ECC and executable provider effects | ❌ Not implemented | ❌ No |

Named hashes and SP 800-185 constructions are usable; the broader planned
cryptographic composition layer is not complete. No independent cryptographic
review or FIPS 140-3 validation is claimed.

## Use

Use a release containing the hash/MAC APIs described here, not an older
foundation-only package.

After this source version is published, install from the registry:

```sh
cargo add brynja-crypto --no-default-features
```

For an unpublished candidate or matching local checkout instead:

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

Modern HMAC is exposed as `brynja_crypto::hmac`, not as ordinary hash aliases:

```rust
use brynja_crypto::hmac::{Hmac, Sha256};
let key = [0x42; 32]; // Example only: generate real unpredictable keys securely.
let mut bytes = [0; 32];
let tag = Hmac::<Sha256>::authenticate(&key, b"message", &mut bytes).unwrap();
let mut verifier = Hmac::<Sha256>::new(&key).unwrap();
verifier.update(b"message").unwrap();
verifier.verify(tag.as_bytes()).unwrap(); // Only a matching tag returns Ok(()).
```

`hmac-hardened-execution` and `hmac-runtime-execution` expose borrowed-authority
execution explicitly; neither enables automatic detection or fallback. Portable
HMAC stays portable when other dependencies enable CPU features. Tag truncation
is preselected, byte-based and at least 128 bits; full general SHA-512/t tags
retain their exact bit width. Use `finalize_secret` for clearing secret output.
These APIs do not promise protected memory; qualification remains pending.

## Hardware and SIMD

This composition facade defaults to portable APIs and owns no ISA kernels.
Select default-off per-family execution/batch features through this facade or
the algorithm leaves. Namespaces `sha2`, `sha3`, `hmac`, `kmac`, `tuplehash` and
`parallelhash` expose the corresponding leaf APIs; `cpu` is an explicit
no_std CPU-authority opt-in, not a hosted detector. See the
[feature and deployment guide](https://github.com/valkyoth/brynja/blob/main/docs/facade-features.md).
x86-64 SHA/AVX2 and AArch64 SHA2/SHA-512/SHA3 support is
algorithm- and API-specific, not a global switch. Features do not authorize
unsupported instructions or silently route secret state through ordinary kernels.

## Boundaries

Ordinary unkeyed hash/XOF states do not guarantee erasure of private input
remnants. Hardened owners clear source-declared internal regions and classify
outputs as public or typed secret; callers retain responsibility for their
buffers and copies. Registers, compiler copies/spills, caches, dumps, swap,
forgotten owners and terminated processes remain outside the guarantee.

General SHA-512/t is an opt-in extension (`general-sha512-t`, under `sha2`),
not a named SHA-2 identity. Namespaces use explicit export lists and facade
feature gates, excluding conformance-only free functions and standalone
`hardened_in_place` modules from namespace roots. Production `in_place` APIs
nested in execution modules remain available. Cargo still unifies leaf features
and reexported types retain their
inherent methods. KMAC conformance methods belong to distinct leaf-only test
types, including execution and scoped owners, not these production aliases.
Hidden cSHAKE composition methods remain available on the reexported types;
they preserve their terminal lifecycle and output classification. This is not
a sandbox; use dependency policy and the separate `brynja-strict`
facade when ordinary-memory APIs must not be selected.
Legacy SHA-1/MD5 and legacy protocols remain outside this modern composition
graph. `brynja-crypto` is not a replacement TLS engine or certificate validator.

[Facade examples](https://github.com/valkyoth/brynja/tree/main/crates/brynja)
· [Leaf architecture](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).
MIT OR Apache-2.0.
