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

# brynja-legacy-md5

First-party, allocation-free `no_std` legacy MD5 for explicit compatibility.

## Cryptography Verification Status

| Hash | Implemented | Independently verified |
| --- | --- | --- |
| MD5 | 🚧 In progress — portable APIs implemented; final acceptance pending | ❌ Not independently verified |

No named independent reviewer has signed off. Project tests, CI, Kani, Miri,
fuzzing and pentesting are not independent cryptographic review. No FIPS
140-3 validation exists. Testing against RFC 1321 does not constitute
certification or restore the security properties broken by collisions.

## Collision-broken legacy algorithm

MD5 is not appropriate for new security designs, collision-resistant hashes,
signatures, certificates or password hashing. A raw digest is not a MAC.
Memory cleanup does not repair the algorithm. This crate is never enabled by
the modern `brynja` facade, TLS, PKIX, FIPS, or a general-purpose hash default.
Later HMAC/HKDF/OpenPGP integrations need separately typed legacy admission.

## Use

The leaf is currently unpublished `0.1.0`; v0.24.19 is an internal repository
milestone, not a crates.io release. Depend directly on this path when testing.

```toml
[dependencies]
brynja-legacy-md5 = { path = "../brynja/crates/brynja-legacy-md5", default-features = false }
```

```rust
use brynja_legacy_md5::{Md5, md5};
let mut hash = Md5::new();
hash.update(b"a")?;
hash.update(b"bc")?;
assert_eq!(hash.finalize(), md5(b"abc")?);
# Ok::<(), brynja_legacy_md5::Md5Error>(())
```

`md5_bits` and `Md5::finalize_bits` take a canonical `BitString`: meaningful
bits occupy the high end of the last byte, unused low bits must be zero.
The bit tail is accepted only by consuming finalization, after any streamed
complete bytes. RFC 1321 encodes the low 64 length bits in little-endian order, including
messages exceeding 2^64 bits. This API checks a u128 bit counter and rejects
lengths beyond u128::MAX; this is a representability limit, not an RFC limit.
Capacity probes and failed updates do not mutate state. Digests are exactly 16 bytes.

## Confidential input and owned cleanup

Use `HardenedMd5`, not an ordinary public-digest API, for confidential input
in an explicitly admitted legacy construction. It is sealed, non-cloneable,
non-formattable, consuming on finalization, and has no reset or snapshot API.

```rust
use brynja_legacy_md5::HardenedMd5;
let mut output = [0_u8; 16];
{
    let digest = HardenedMd5::digest_secret(b"legacy confidential input", &mut output)?;
    // Exposing or copying these bytes remains the caller's responsibility.
    assert_eq!(digest.expose().len(), 16);
}
assert_eq!(output, [0_u8; 16]);
# Ok::<(), brynja_legacy_md5::Md5Error>(())
```

Streaming, arbitrary-bit secret output, and explicit `PublicDeclassification`
are also available. Secret-output failures clear the whole destination, even
when it has the wrong size. Public-output failures leave it unchanged.

Both API profiles share a private owner that clears chaining state, block/
padding storage, length, buffered count and output staging on Drop.
Compression reads its block directly without a separate message schedule.
This uses mandatory `brynja-core` compiler-resistant clearing; the optional
`brynja-sanitization` adapter is not required. Success, consuming errors,
cancellation and recoverable unwinding all destroy that owner. A failed
update retains the unchanged live state until retry or destruction.

No guarantee covers registers, compiler-created copies/spills, caches, moves,
swap, DMA, dumps, `mem::forget`, abort, termination, power loss, or caller-owned
input/output copies. No pinned/locked memory or accelerated execution exists.

## Verification and links

Run `cargo test -p brynja-legacy-md5` and
`python3 scripts/md5/check-md5-differential.py` from the repository root.
The suite includes all seven RFC 1321 appendix A.5 vectors, streaming boundaries, million-byte
input, independent arbitrary-bit differential checks, output failures, unwind,
compile-fail ownership checks and compiler cleanup evidence.

- [Implementation and assurance contract](https://github.com/valkyoth/brynja/blob/main/docs/legacy-md5.md)
- [Roadmap](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md)
- [Security policy](https://github.com/valkyoth/brynja/blob/main/SECURITY.md)

Rust 1.90.0–1.98.1; default validation on 1.98.1. MIT OR Apache-2.0.
