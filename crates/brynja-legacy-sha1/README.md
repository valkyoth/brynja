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
passed for the released ordinary API. Separate default-off hardened execution
is under qualification. See the
[operational API](https://github.com/valkyoth/brynja/blob/main/docs/legacy-sha1-execution.md).

## Cryptography Verification Status

| Hash | Implemented | Independently verified |
| --- | --- | --- |
| SHA-1 | ✅ Fully implemented | ❌ Not independently verified |
| Opt-in ordinary acceleration | ✅ Opt-in, platform-limited | ❌ Not independently verified |
| Opt-in hardened acceleration | ✅ Opt-in, platform-limited | ❌ Not independently verified |
| Caller-owned portable scoped workspace | 🚧 Implemented; residue qualification pending | ❌ Not independently verified |
| Scoped hardened execution workspace | 🚧 Portable/SHA-NI/Arm routes; residue qualification pending | ❌ Not independently verified |

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
input/output copies. No pinned/locked memory is supplied. `HardenedSha1` remains
portable; the separate opt-in hardened executor is described below.

### Scoped caller-owned storage

`hardened_in_place::Sha1Workspace` keeps active state in borrowed storage. The
handle cannot escape the callback, be reused after finalization, cloned,
formatted or sent/shared across threads. The independent scope guard clears
all six owned regions on return or recoverable unwind, even if the handle is
forgotten. The workspace can then start another fresh computation.

```rust
use brynja_legacy_sha1::hardened_in_place::Sha1Workspace;
let mut workspace = Sha1Workspace::new();
let mut bytes = [0; 20];
let secret = workspace.with(|mut state| {
    state.update(b"legacy input")?;
    state.finalize_secret(&mut bytes)
})?;
assert_eq!(secret.expose().len(), 20);
drop(secret);
assert_eq!(bytes, [0; 20]);
# Ok::<(), brynja_legacy_sha1::Sha1Error>(())
```

`finalize_bits_secret` accepts a final canonical bit string. The corresponding
`finalize_public` and `finalize_bits_public` methods require an explicit
`PublicDeclassification` token. Errors preserve public destinations or clear
every supplied secret-destination byte. Unlike the older by-value state, an
update error clears and terminates the scoped handle (`StateConsumed` thereafter).
There is no length query, preflight oracle, snapshot or in-scope reset.

This additive profile uses portable compression, not optional SHA instructions.
It addresses
source-owned state movement, not complete register/spill/compiler-copy erasure.
Forgetting the separate secret output still prevents that output's own Drop;
abort, caller copies and platform storage remain outside the guarantee. SHA-1
remains collision-broken and inappropriate for new security designs.

With `hardened-execution`, `hardened_execution::in_place::Sha1Workspace`
borrows an existing hardened `Executor`. Select portable, compiled-target or
hosted authority using the existing executor APIs; the workspace never changes
that route. Construction and reuse cannot undo quarantine. This is single-stream
instruction acceleration, not multibuffer SIMD batching.

```rust
# #[cfg(feature = "hardened-execution")]
# fn example() -> Result<(), brynja_legacy_sha1::hardened_execution::Error> {
use brynja_legacy_sha1::hardened_execution::{Executor, in_place::Sha1Workspace};
let executor = Executor::portable(); // or an explicitly selected hardened authority
let mut workspace = Sha1Workspace::new(&executor);
let mut bytes = [0; 20];
let output = workspace.with(|mut state| {
    state.update(b"legacy input")?;
    state.finalize_secret(&mut bytes)
})??;
drop(output);
assert_eq!(bytes, [0; 20]);
# Ok(())
# }
# #[cfg(feature = "hardened-execution")]
# example()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The outer result reports scope admission; the inner value comes from your
callback. Admission failure cannot clear buffers captured only by that callback.
Secret finalization clears buffers once it receives them. Input-length errors
terminate and clear the scoped state without revoking a healthy executor;
backend failures and recoverable callback/operation unwind quarantine it.
Normal cancellation or forgetting a handle still clears storage at scope exit
without revocation. No length/preflight queries are exposed. This does not
extend the guarantee to every register, spill or compiler-created copy, and
abort cannot run cleanup guards.

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

The separate `hardened-execution` feature exposes a secret-bearing
`hardened_execution::Executor`, with portable/prefer/require modes and borrowing
streams. Static x86 SHA/SSE2 and AArch64 NEON/SHA1 use owner-backed schedule and
lane storage with mandatory clearing. Its hosted adapter requires the distinct
`runtime-hardened-execution` feature. Ordinary authority cannot convert to this
authority. Project-owned native correctness evidence covers AMD, Intel, AWS Arm
and Apple M2 Pro; it does not establish migration safety or independent verification.

```rust
# #[cfg(feature = "hardened-execution")]
# fn example() -> Result<(), brynja_legacy_sha1::hardened_execution::Error> {
use brynja_legacy_sha1::hardened_execution::{Executor, Mode};
let owner = Executor::for_compiled_target(Mode::Prefer)?;
let mut bytes = [0u8; 20];
let secret = owner.hash_secret(b"legacy confidential input", &mut bytes)?;
drop(secret);
assert_eq!(bytes, [0; 20]);
# Ok(())
# }
# #[cfg(feature = "hardened-execution")]
# example()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

Byte/bit one-shot hashing, streaming, consuming bit-tail finalization,
explicit public declassification and whole-secret-destination clearing are
supported. See the [hardened contract](https://github.com/valkyoth/brynja/blob/main/docs/legacy-sha1-hardened-execution.md)
for the seven owned regions and platform/cleanup limits.

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
