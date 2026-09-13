# Hardened legacy SHA-1 execution

Status: implementation and development assurance in progress; exceptional owner
pentest/retest and fresh native qualification are required before tagging.
No independent cryptographic review or FIPS validation is claimed.

This is deliberately separate from [ordinary execution](legacy-sha1-execution.md).
The default-off leaf feature `hardened-execution` exposes distinct `Authority`,
`Executor` and borrowing `Stream` types. The hosted adapter's default-off
`runtime-hardened-execution` exposes `select(Mode)` using the same lifetime-wide
AArch64 system feature contract. SHA-1 remains collision-broken legacy
compatibility, never a modern default, raw authentication or password hash.

## Selection and usable APIs

| Selection | Result |
| --- | --- |
| `Executor::portable()` / `Mode::Portable` | Always portable, even in a specialized binary |
| Static `Mode::Require` | x86/x86-64 SHA+SSE2 or little-endian AArch64 NEON+SHA2 required |
| Static `Mode::Prefer` | Portable only when the complete static bundle is absent |
| Hosted AArch64 `Require` / `Prefer` | OS feature authority; no fallback after startup/backend failure |
| Hosted generic x86 | Required fails; preferred selects portable |
| RISC-V / other architectures | Portable only; no invented instruction route |

Static features are a deployment obligation on **every** schedulable CPU, not
just the current CPU. The hosted adapter preserves the existing Linux, Android,
macOS, iOS and Windows [detector/trust table](legacy-sha1-execution.md).
Cached detection is not live revocation. Neither a non-Send owner nor a
successful native run proves arbitrary hotplug or VM migration safety.

```rust
use brynja_legacy_sha1::hardened_execution::{Executor, Mode};

let executor = Executor::for_compiled_target(Mode::Prefer)?;
let mut state = executor.start()?;
state.update(b"legacy confidential ")?;
state.update(b"input")?;
let mut destination = [0u8; 20];
let secret = state.finalize_secret(&mut destination)?;
// Retain the secret owner; explicit exposure/copies are the caller's duty.
assert_eq!(secret.expose().len(), 20);
drop(secret);
assert_eq!(destination, [0; 20]);
# Ok::<(), brynja_legacy_sha1::hardened_execution::Error>(())
```

Byte one-shot `hash_secret` and canonical MSB-first `hash_bits_secret` return
typed, non-cloneable `OwnedSecretRegion`. `finalize_bits_secret` consumes a
bit tail after complete-byte updates. Public counterparts require explicit
`PublicDeclassification`; no implicit ordinary digest import/export exists.
`check_additional_bytes/bits` checks capacity without exposing the current
secret-derived length. Messages remain strictly below 2^64 bits, digests 20 bytes.
`cancel` consumes state. Finalization consumes state on success and error.
Executor revocation affects every borrowing stream and is irreversible.

## Mandatory ownership and cleanup

| Region | Bytes | Owner / lifecycle |
| --- | --- | --- |
| Chaining state | 20 | `Sha1Owner`; Drop, error, unwind |
| Block / padding | 64 | `Sha1Owner`; each compression and destruction |
| Full expanded schedule | 320 | `Sha1Owner`; each compression and destruction |
| Message length | 8 | `Sha1Owner`; destruction |
| Buffered count | 1 | `Sha1Owner`; each compression and destruction |
| Digest staging | 20 | `Sha1Owner`; destruction |
| Vector result staging | 16 | `Scratch`; Drop on successful/failed kernel completion and unwind |

All seven regions use mandatory `brynja-core::clear_owned_region`, the reviewed
compiler-resistant clearing boundary. No feature, optional sanitization adapter
or caller action is needed to clear these inaccessible internal regions.
The kernel schedule and lane stores borrow these owners instead of creating
ordinary local vector arrays. Scalar/vector registers and compiler-created
temporaries are **not** guaranteed erased.

Length rejection precedes state mutation and remains retryable. Backend and
internal invariant failures wipe state and quarantine the owner without silent
portable fallback. Secret destination guards are installed before any platform
callback or state transition: errors and recoverable unwind clear the **entire**
destination, including wrong-size buffers. Public destination errors preserve
the caller's bytes. Borrowing state and authorities are non-Send/non-Sync,
non-Copy/non-Clone/non-Debug; the hardened state capability is sealed.

Cleanup does not guarantee erasure of caller copies, moved/compiler-created
copies, registers, spills, caches, dumps, swap, DMA or platform storage.
`mem::forget`, abort, forced termination and power loss can suppress Drop.
The library does not force its repository panic profile on consumer workspaces.
No locked/pinned memory or deployment certification is supplied.

## Reproducible verification

- `python3 scripts/sha1/check-sha1-hardened.py`: package-external NIST, independent
  bit oracle, typed outputs, ownership rejection, algorithm and cleanup mutants.
- `python3 scripts/sha1/test-sha1-hardened.py`: exact source inventory and drift.
- `python3 scripts/sha1/check-sha1-hardened-codegen.py`: Rust 1.90.0/1.98.1,
  x86-64/AArch64, abort/unwind MIR/LLVM/assembly and actual secret instructions.
- `scripts/sha1/check-sha1-cpu-qemu.sh`: supplemental Arm static/hosted execution.
- Scoped SHA-1 Miri and actual SHA-NI AddressSanitizer are separate local gates.
- `capture-sha1-hardened-native.py`: clean committed AMD, Intel, AWS Arm or Apple
  M2 observations with source hashes, compiler, exact routes, 512 arbitrary
  compression cases, public/secret package tests and compiler cleanup evidence.

Native records are operator-self-attested and require owner review. Historical
ordinary captures cannot qualify these secret kernels. No speedup, timing
resistance, CPU-migration proof, independent review or FIPS certificate is
inferred from functional correctness. Fresh qualification is still pending.
