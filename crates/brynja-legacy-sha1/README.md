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

# brynja-legacy-sha1

First-party, allocation-free `no_std` legacy SHA-1 for explicit compatibility.

Default-off `execution` APIs add ordinary public-data SHA/SSE2 and NEON/SHA1
instruction routes for target-specialized binaries, with explicit selection,
streaming, byte/bit one-shot hashing and permanent owner revocation. The separate
host adapter supplies supported AArch64 system authority. Native observations
passed; final release checks remain required and hardened acceleration is not provided. See the
[operational API](https://github.com/valkyoth/brynja/blob/main/docs/legacy-sha1-execution.md).

## Cryptography Verification Status

| Hash | Implemented | Independently verified |
| --- | --- | --- |
| SHA-1 | ✅ Fully implemented | ❌ Not independently verified |
| Opt-in ordinary acceleration | 🚧 In progress; native observations passed, final release checks pending | ❌ Not independently verified |

No named independent reviewer has signed off. Project tests, CI, Kani, Miri,
fuzzing and pentesting are not independent cryptographic review. No FIPS
140-3 validation exists. Testing
against FIPS 180-4 and NIST vectors does not constitute certification.

## Collision-broken legacy algorithm

SHA-1 is not appropriate for new security designs, collision-resistant hashes,
signatures, certificates or password hashing. A raw digest is not a MAC.
Memory cleanup does not repair the algorithm. This crate is never enabled by
the modern `brynja` facade, TLS, PKIX, FIPS, or a general-purpose hash default.
Later HMAC/HKDF/OpenPGP integrations need separately typed legacy admission.

## Use

The leaf is currently unpublished. Depend directly on this checkout path for
explicit legacy compatibility testing.

```toml
[dependencies]
brynja-legacy-sha1 = { path = "../brynja/crates/brynja-legacy-sha1", default-features = false }
```

```rust
use brynja_legacy_sha1::{Sha1, sha1};
let mut hash = Sha1::new();
hash.update(b"a")?;
hash.update(b"bc")?;
assert_eq!(hash.finalize(), sha1(b"abc")?);
# Ok::<(), brynja_legacy_sha1::Sha1Error>(())
```

`sha1_bits` and `Sha1::finalize_bits` take a canonical `BitString`: meaningful
bits occupy the high end of the last byte, unused low bits must be zero.
The bit tail is accepted only by consuming finalization, after any streamed
complete bytes. Messages must contain fewer than 2^64 bits. Capacity probes
and failed updates do not mutate state. Digests are exactly 20 bytes.

## Confidential input and owned cleanup

Use `HardenedSha1`, not an ordinary public-digest API, for confidential input
in an explicitly admitted legacy construction. It is sealed, non-cloneable,
non-formattable, consuming on finalization, and has no reset or snapshot API.

```rust
use brynja_legacy_sha1::HardenedSha1;
let mut output = [0_u8; 20];
{
    let digest = HardenedSha1::digest_secret(b"legacy confidential input", &mut output)?;
    // Exposing or copying these bytes remains the caller's responsibility.
    assert_eq!(digest.expose().len(), 20);
}
assert_eq!(output, [0_u8; 20]);
# Ok::<(), brynja_legacy_sha1::Sha1Error>(())
```

Streaming, arbitrary-bit secret output, and explicit `PublicDeclassification`
are also available. Secret-output failures clear the whole destination, even
when it has the wrong size. Public-output failures leave it unchanged.

Both API profiles share a private owner that clears chaining state, block/
padding storage, schedule, length, buffered count and output staging on Drop.
This uses mandatory `brynja-core` compiler-resistant clearing; the optional
`brynja-sanitization` adapter is not required. Success, consuming errors,
cancellation and recoverable unwinding all destroy that owner. A failed
update retains the unchanged live state until retry or destruction.

Private buffer offset guards are always-on, including optimized builds. An
impossible internal offset panics before a write, not after a fabricated digest.
Safe public input cannot construct such an offset. The consuming workspace
chooses unwind or abort: Brynja's repository profile is not inherited by
dependencies. Aborting does not run Drop. See the
[panic strategy](https://github.com/valkyoth/brynja/blob/main/docs/panic-strategy.md).

No guarantee covers registers, compiler-created copies/spills, caches, moves,
swap, DMA, dumps, `mem::forget`, abort, termination, power loss, or caller-owned
input/output copies. No pinned/locked memory is supplied. Hardened execution remains portable;
ordinary operational routes and separate candidates are described below.

## Verification and links

Run `cargo test -p brynja-legacy-sha1` and
`python3 scripts/sha1/check-sha1-differential.py` from the repository root.
The suite includes 529 official bit vectors, streaming boundaries, million-byte
input, independent arbitrary-bit differential checks, output failures, unwind,
compile-fail ownership checks and compiler cleanup evidence.

- [Implementation and assurance contract](https://github.com/valkyoth/brynja/blob/main/docs/legacy-sha1.md)
- [Roadmap](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md)
- [Security policy](https://github.com/valkyoth/brynja/blob/main/SECURITY.md)

See the workspace toolchain policy for supported Rust versions. MIT OR Apache-2.0.

## Hardware and SIMD

The default-off `execution` feature exposes `execution::Executor` with explicit
portable, prefer and require modes. Target-specialized binaries can execute
x86 SHA/SSE2 or AArch64 SHA1/NEON; borrowed streams support byte updates and
consuming arbitrary-bit finalization. Hosted AArch64 authority is available
through the adapter's separate `runtime-execution` feature. Generic x86 hosted
require mode remains unavailable. These are ordinary, public-data-only routes;
they do not establish hardened cleanup or collision resistance.

The `cpu` feature adds isolated x86/x86_64 SHA and AArch64 SHA1 candidates,
`Sha1BackendSession`, and consuming `AcceleratedSha1` byte/bit streaming APIs.
The original candidate constructors reject ordinary builds before instructions execute. Hardware
schedules/registers/spills are not cleanup-qualified; accelerated types are for
public data only and cannot implement the sealed hardened capability.
`HardenedSha1` remains portable. The separate `brynja-legacy-sha1-std` adapter
retains its default observational API and portable fallback; that API's required
acceleration fails closed. Its separate operational module is described above.
Feature unification can expose CPU types, not mint a platform authority. Dedicated
non-production evidence requires both `cpu-evidence` and the separate
`brynja_sha1_cpu_evidence` cfg; the older shared evidence cfg cannot enable it.
Never persist evidence flags in an application's build environment. A plain
slice does not classify its contents: callers must not pass secrets to the
ordinary accelerated API. Use the sealed hardened API for confidential inputs.
See [acceleration and capture instructions](https://github.com/valkyoth/brynja/blob/main/docs/legacy-sha1-acceleration.md).

Final ordinary/hardened byte/bit and execution-route dispositions are documented in
[legacy final acceptance](https://github.com/valkyoth/brynja/blob/main/docs/legacy-hash-final-acceptance.md).
Fully implemented does not mean collision-resistant, recommended, independently
verified, FIPS validated, or admitted for accelerated execution.
