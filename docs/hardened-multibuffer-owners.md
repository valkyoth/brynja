# Hardened multibuffer hash owners

Status: v0.24.48 in development; narrow and wide SHA-2 CPU/leaf batch APIs implemented,
remaining families, hosted adapters and qualification pending.
The names below are proposed API names until the implementation and downstream
compile tests establish the exact exported surface. Ordinary batch types remain
public-only. Nothing in this document authorizes passing secrets to those types.

The first implemented layer is
`brynja-crypto-cpu::sha256_hardened_batch`, under its separate default-off
`sha256-hardened-batch` feature. Its Authority/Session/Workspace process raw
compression states using distinct AVX2/NEON kernels and clearing packed storage.
They do not perform hash framing or own caller states/blocks. The implemented
`brynja-hash-sha2::hardened_batch` module adds SHA-224/256 framing, eight bounded
optional input/destination slots, clearing workspace and typed borrowed secret
outputs. Enable only `hardened-batch-execution`; it does not enable ordinary
batch execution. `Executor::portable` needs no CPU authority; `with_session`
requires a distinct hardened session, nonzero threshold and Prefer/Require mode.
Required mode demands one eligible full-width group; unequal tails and padding
use the existing hardened scalar compressor. Its rustdoc includes a runnable
secret-output example. The CPU byte-state entry avoids an unowned word array
between packed compression and leaf finalization.

The separate `sha512-hardened-batch` CPU feature now provides
`sha512_hardened_batch::{Authority, Session, Workspace}` with four AVX2 or two
NEON lanes, 128-byte blocks and an owned 80-word packed schedule. The separate
leaf feature `hardened-batch512-execution` exposes `hardened_batch512`: four
bounded slots supporting SHA-384, SHA-512, named /224 and /256, and
`Algorithm::Sha512T(Sha512TBits)` for all 510 valid parameters. It retains the
same clearing, transactional, finite-work and authority contracts as the narrow
leaf. General IV derivation costs one compression per active general slot;
required-route eligibility is checked before derivation. A secret output keeps
the exact parameter identity, including distinctions between named and general
/224 or /256, and masks unused final bits before committing. It never imports
secret bytes through an ordinary digest constructor. Its module rustdoc has a
runnable secret-output example.

Names for Keccak, hosted adapters and ParallelHash remain proposed.
Native qualification is not supplied by local/emulated tests.

## Implementation order and scope

1. Establish distinct packed-storage owners and hardened authority/session paths
   in `brynja-crypto-cpu`, independently for SHA-256, SHA-512 and Keccak. Keep
   ordinary storage/kernels and their public-data assertions out of secret paths.
2. Implement SHA-224/256 hardened leaf batching with separate AVX2 eight-message
   and NEON four-message execution, then the SHA-512 family with AVX2 four-message
   and NEON two-message execution. Include SHA-384, SHA-512, named /224 and /256,
   and every valid general SHA-512/t parameter with its own derived IV.
3. Implement hardened Keccak batching with AVX2 four-state and NEON two-state
   execution. Integrate all eight SHA-3/SHAKE/cSHAKE identities with independent
   rates, suffixes, bit tails, N/S prefixes and finite output requests.
4. Add default-off hosted adapters only after the corresponding hardened leaf
   works without `std`. Never enable ordinary batch features as a shortcut.
5. Integrate eligible ParallelHash leaf batches only after hardened Keccak
   owners, typed outputs and cleanup have passed their dedicated tests. Preserve
   the existing completed-input proof and root-bound leaf tokens.
6. Complete package, mutation, emitted-code, Miri, Kani, sanitizer, native and
   performance evidence separately for every family and backend. Obtain owner
   pentest/retest and run the existing release workflow; do not alter its rules.

All steps belong to this milestone. Incomplete work is reported explicitly;
scalar-only, mock-only or documentation-only progress is not a completed SIMD
profile. If review size requires smaller milestones, retain every dependency
and profile in the plan before proceeding to a dependent capability.

## Public API shape

Each leaf should expose a distinct default-off `hardened-batch-execution` feature
and a `hardened_batch` module (with a separate wide SHA-2 module or named types).
CPU/host feature names must remain distinct from ordinary batch execution.
Existing constructors and facade defaults retain their behavior.

| Type or operation | Required contract |
| --- | --- |
| `Input` | Canonical borrowed bits plus exact algorithm/output identity; borrowed input remains caller-owned, never implicitly declassified |
| `Workspace` | Distinct clearing lane, block, framing and output-metadata owner; no ordinary workspace conversion or borrowed ordinary storage |
| `Executor` | Portable constructor or supplied hardened session plus explicit mode/threshold; no implicit probing or global dispatch |
| `SecretBatchOutput` | Exclusive ownership of the caller-provided destination borrows; exact per-slot identity, no Copy/Clone/Debug/ordinary equality |
| `digest_secret` | Clears every supplied destination on any error, including malformed shape/width and insufficient staging; success transfers clearing duty to the returned owner |
| `digest_public` | Requires an explicit declassification marker; preserves every public destination on failure and clears all staging on every exit |
| `expose(index)` | Explicit shared byte view of a completed secret slot; never an implicit conversion to an ordinary digest |
| `declassify` | Consuming, explicit transfer to a public destination, with private staging and unused capacity cleared |
| `Control` | Caller-selected finite compression/permutation budget and cancellation; checked counters, no refund of completed work |
| `Report` | Actual route/work counts only, never lane contents or keys; batch shape and work are explicitly public metadata |

No secret-producing path may call `Sha512TDigest::from_bytes` or another ordinary
digest importer. A general SHA-512/t secret slot retains its validated parameter
and canonical final-bit mask inside a non-copying output owner. Zero-bit XOF
output remains valid, but does not waive framing, required-route or health checks.
Fixed SHA-3/SHA-2 identities require exact output widths.

Raw owner buffers are private. Authorities, borrowed sessions, unfinished lane
owners and workspaces are not Send/Sync/Copy/Clone/Debug. Ordinary authorities,
sessions, workspaces and public-data markers cannot be converted or relabeled
into their hardened counterparts. Reuse inert algorithm identifiers only where
their dependency does not enable ordinary execution or import an ordinary owner.

Caller-supplied workspace/staging capacities are checked before processing and
never grown implicitly. The leaf remains allocation-free. Output ownership must
not allocate a Vec to hold destination borrows; use a bounded borrowed slot list.
The owner lifetime must prevent caller access until it is dropped or consumed.

## Storage inventory

Every packed aggregate is held in a named, fixed-size clearing owner rather than
an ordinary vector array with a final partial wipe. Destructors use the existing
compiler-resistant clearing primitive; `black_box` alone is not an erasure method.
Checked access rejects bad internal indices instead of clamping or dropping writes.

| Layer | Regions to own and inspect |
| --- | --- |
| SHA-224/256 kernel | Packed initial/current words, input blocks, message schedule, round working state and vector temporaries; all eight slots including unused NEON capacity |
| SHA-512-family kernel | Packed initial/current words, 128-byte blocks, full/ring schedule and round temporaries; all four slots including unused NEON capacity |
| Keccak kernel | Packed lanes, theta column/parity storage, rotation/permutation staging, chi operands and temporary vectors; all four slots including inactive states |
| Leaf framing | Per-lane IV/state, pending input blocks/bits, length counters, cSHAKE encodings and N/S prefix staging, algorithm/t identity, failure/completion latches |
| Output | Uncommitted full and partial bytes, slot lengths/offsets, unused capacity and temporary finalization storage |
| ParallelHash | Leaf chaining values, plan/root binding, order/count state, batch scheduling metadata, root staging and partially completed worker slots |

Register values and compiler-created copies remain disclosed residuals. Minimize
their lifetimes and inspect generated code, without claiming portable Rust can
erase every register/spill/cache copy. Stack moves and partially initialized
construction paths require review; Drop on the final owner is not sufficient
evidence that intermediate source copies were cleared.

## Failure and reuse rules

Acquire an operation guard before any secret-derived mutation. It owns cleanup
until all final checks succeed. Required hardware absence is rejected before
secret processing. With a supplied session, health loss, KAT failure or an
internal invariant violation is terminal; never silently switch to portable.

Ordinary request rejection, insufficient budget and caller cancellation clear
operation-owned storage but do not permanently revoke otherwise healthy reusable
authority. Internal accounting overflow is an invariant failure, not a benign
message-length error. Unwind quarantines the operation's authority and clears
owned storage. Constructors must clear partially initialized secret regions.

Before committing public output, check every width/range, final health and report
counter. The commit must contain no callback, allocation or remaining fallible
operation: one failing lane must not leave other destinations partially updated.
Secret output failure clears whole supplied destinations, not only bytes already
written or the caller's claimed active prefix. Scratch is cleared on success too.

Expose no non-mutating preflight oracle for a private accumulated message length.
Required actual updates/finalization still return checked length errors; this is
not length-hiding cryptography. Public batch shapes, thresholds, progress/work
reports and callbacks remain observable. Users needing traffic-analysis defenses
must pad and control scheduling at the application/deployment layer.

## ParallelHash integration

Only independent leaf messages are eligible for SIMD grouping. KMAC operations
and TupleHash items are not interchangeable with ParallelHash leaves. Preserve
the correct inner SHAKE strength and full 32/64-byte chaining-value width, root
cSHAKE function name, block-size encoding, leaf count and fixed/XOF trailers.

Group at most the admitted workspace capacity; retain scalar tails through a
hardened scalar path. Selection policy must explicitly decide whether an
ineligible tail is allowed under required acceleration; do not claim every leaf
was accelerated when only a full group was. Report performed vector calls,
accelerated leaves and scalar tails separately. Never feed a partial group to an
ordinary permutation just to satisfy a required-route counter.

Completed secret leaf tokens retain the original plan/root identity and index.
The collector rejects foreign, duplicate, missing, reordered or wrong-width
leaves and cannot finalize without exact input completion. Cancellation, failed
worker launch and unwind clear all completed-but-unmerged leaves before return.
Create thread-bound authority inside each worker; do not make sessions Send to
enable parallelism. Only explicitly reviewed completed leaf owners may cross
worker boundaries. SIMD width and worker count are separate public limits.

## Acceptance required before completion

- Positive downstream examples for every constructor, exact bit/byte identity,
  portable/prefer/require route, typed-secret output and explicit declassification.
- Negative compilations for Copy/Clone/Debug/Send/Sync, ordinary substitution,
  owner/session lifetime escape, finalized-state reuse and secret-to-public import.
- Native scalar/SIMD comparisons with lane-distinct random states/messages,
  unequal lengths, inactive slots, every padding boundary and all 510 valid t.
- Direct probes and compiled omission mutants for each owned region on success,
  admission failure, cancellation, exhaustion, health loss, unwind and Drop.
- Mutation of the real SIMD call to no-op, partial write and scalar-only execution:
  output checks alone do not prove acceleration. Compare actual kernel counters.
- Miri for bounded owner/lifecycle paths, Kani for arithmetic/transition invariants,
  native sanitizers with explicit leak policy, and MIR/LLVM/assembly cleanup on
  Rust 1.90.0 and 1.98.1 for x86 Linux, Arm Linux and Apple Arm.
- Native Intel/AMD, AWS Arm and Apple captures plus workload-specific timings.
  Preserve negative speedup findings; do not hardcode a crossover or claim that
  dedicated single-stream instructions and multibuffer SIMD are equivalent.

Fresh evidence must match the actual source/toolchain/profile. Ordinary native
observations remain historical, not proof of hardened cleanup. No independent
cryptographic verification, FIPS validation or military approval is implied.
No memory-locking, dump policy, affinity or process-wide panic mode is forced.
Abort, forced termination and `mem::forget` cannot promise Drop cleanup.
