# Hardened multibuffer hash owners

Status: v0.24.48 in development; narrow and wide SHA-2 CPU/leaf batch APIs implemented,
Keccak CPU/leaf APIs, hosted adapters and scheduled ParallelHash groups implemented;
streaming and threaded groups implemented; complete qualification pending.
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

The default-off `keccak-hardened-batch` CPU feature now exposes the distinct
`keccak_hardened_batch::{Authority, Session, Workspace}` foundation. Four AVX2 or
two NEON states use clearing packed state, columns, deltas and rho/pi/chi staging.
`permute` and `permute_bytes` support word and canonical little-endian byte
states without ordinary packed storage. Both stage all changes until final
health/accounting validation, clear every packed region on exit, and preserve
inactive caller slots. Raw caller state is not owned or erased by this layer.
The raw CPU layer itself does not supply SHA-3 padding, SHAKE squeezing or
cSHAKE encoding.

The separate `brynja-hash-sha3/hardened-batch-execution` feature now exposes
`hardened_batch::{Input, Workspace, Executor, SecretBatchOutput}`. Four optional
borrowed slots support all eight SHA-3/SHAKE/cSHAKE identities, mixed rates,
arbitrary-bit messages and N/S, and finite output (including zero-bit XOF).
Virtual prefix/padding cursors avoid materializing secret cSHAKE prefixes in
ordinary storage. The workspace owns byte states, gathered vector states,
framing encodings/cursors, output offsets, pending-lane flags and distinct
clearing scalar/CPU scratch. Caller-provided output staging is exclusively
borrowed and cleared in full on success, rejection and unwind. Secret output
retains exact per-slot identity and bit count; public commit and consuming
declassification validate every destination before any public write.

Required mode checks eligible full-width groups before reading secret bytes;
the budget counts prefix, padding and squeezing permutations. Unequal tails use
the existing clearing scalar permutation, not ordinary batch storage. Routine
rejection/cancellation preserves reuse, while backend/invariant failures and
unwind revoke the executor. Input lengths, identities and scheduling remain
public metadata. The leaf module rustdoc includes a runnable secret-output
example. These APIs do not enable ordinary batching or ordinary execution.

Three separate default-off `brynja-crypto-cpu-std` features now expose
`sha256_hardened_batch`, `sha512_hardened_batch` and `keccak_hardened_batch`.
Each hosted `Authority::new(Mode)` returns borrowed leaf executors through
`executor(nonzero_threshold)`. These are the exact hardened leaf types, not
ordinary wrappers. Portable never probes; Prefer selects portable only on
initial platform unavailability. KAT/health failures never permit fallback.
AVX2 requires a complete build-wide bundle plus compatible deployment; generic
x86 does not acquire migration authority from CPUID. Little-endian AArch64
uses allowlisted OS NEON feature contracts. Cached detection is not live
revocation or proof of arbitrary hypervisor migration safety.

CPU quarantine revokes existing accelerated borrows and prevents new ones.
Portable selections have no CPU authority; use the portable executor's own
quarantine method for local revocation. Authority/borrow lifetimes and
non-Send/Sync/Copy/Clone/Debug contracts remain enforced.
Native qualification is not supplied by local/emulated tests.

The separate `brynja-hash-parallel/hardened-batch-execution` feature implements
scheduled groups through `execution::batch::{Job, Leaves, Workspace}` and the
clearing SHA-3 batch `Executor`. `Plan::batch(start, count)` selects one to four
contiguous leaves. `Job::execute` computes exact SHAKE128/256 chaining values,
retaining the exact plan object and indices in a non-forgeable affine result.
`Collector::merge_batch` consumes that result, checks all identities, widths and
worker-policy results before absorption, and clears values on success/failure.
`Collector::execute_batched` performs bounded groups in order with one shared
leaf-permutation budget/cancellation control. Root work retains its separate
existing construction/output contract; any failure or unwind cancels the root.

SHA-3 batch reports now include the actual vector-participating slot mask.
Selecting an authority alone does not satisfy RequireAcceleration. Require mode
applies to each group and rejects an incomplete final group; Prefer explicitly
allows clearing scalar tails. Mixed worker policy also permits caller-scheduled
accelerated groups followed by a separate portable tail. Workspace clears all
active and unused CV capacity, nested hash state and staging; completed results
retain exclusive borrows until merge/drop. No ordinary batch owner is involved.
Scheduled tokens cannot complete streaming roots. A distinct
`execution::batch::Stream` now retains exactly 4B caller-owned pending bytes and
a clearing batch workspace, so small updates can fill full SIMD groups. Its
constructor accepts explicit B, root mode, worker executor and StreamConfig.
Byte updates and arbitrary-bit final tails use the same exact SHAKE CV framing;
fixed public/secret destinations and incremental mixed public/secret XOF reads
have the existing transactional/clearing contracts. The internal completion
capability remains private to the streaming module: the new stream independently
checks pending-used == 0 and merged == ceil(total input bits / block bits)
before constructing a root-bound proof. Forgotten readers cannot reopen input.
Cancellation is polled even on calls that only buffer data; reuse one Control
across calls for a cumulative leaf-permutation budget. The complete-input leaf
limit always applies, separately from root construction/output work. Errors and
recoverable unwind cancel the root, pending buffer, hash workspace and counters.
These owners remain thread-bound. The std adapter's separate default-off
`runtime-batch-execution` feature now supplies `execution::batch::Executor`.
Each bounded worker constructs its own hosted/static authority and clearing
workspace. `Leaves::transfer` consumes completed CVs into a separate
`TransferredLeaves` loan: auto-Send, not Sync/Copy/Clone/Debug, without authority,
unfinished sponge or a byte importer. Transfer clears the source and initializes
all destination capacity; merge/drop clears all 256 destination bytes.
`Collector::merge_transferred` retains exact plan identity, indices, worker policy
and deterministic order. Partial/failed work cannot construct a completed token.

The std executor admits 1..=64 simultaneous workers and bounds the complete
input by `max_leaves`. Each group of at most four leaves has its own finite
`max_group_permutations`; this is not a global shared budget and does not count
root construction/output work. Worker width is independent of SIMD width.
Reports sum actual group, vector and scalar work with checked arithmetic.
Storage never grows after initialization. Failed launch, worker panic, cancellation
and backend failure join every started worker, clear unmerged results and cancel
the root. Reversed completion cannot reorder root absorption. No backend failure
is retried through portable execution. Full compiler/package/native qualification
of these new paths remains pending.

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

## Packaged-consumer development acceptance

The standalone checker builds actual `.crate` archives for the eight first-party
dependencies, then resolves an external consumer exclusively against their
extracted contents. It rejects registry/workspace escapes and ordinary batch
features in the hardened-only graph. It never publishes a package or modifies
release-gate rules.

```sh
python3 scripts/cryptography/test-hardened-batch-package.py
python3 scripts/cryptography/check-hardened-batch-package.py --toolchain 1.90.0
python3 scripts/cryptography/check-hardened-batch-package.py --simd
```

`--simd` requires the operator to establish the target's feature bundle: AVX2
on x86-64 or NEON on little-endian AArch64. It forces actual-route tests rather
than accepting an unavailable backend as accelerated evidence. The default is
portable. `--target` selects an installed target and Cargo runner; emulated Arm
execution remains emulation, never native qualification.

The checker runs all six feature-owning crates' shipped library tests/doctests
in debug and release, plus six documented APIs as external-consumer examples.
It pairs every negative compilation with a positive type control and requires
the exact structured rustc error: 129 forbidden ownership traits and sixteen
ordinary-type substitutions or implicit secret-to-public conversions. Completed
ParallelHash transport has a positive Send control; unfinished owners do not.
Eight real cleanup omission mutants must fail executing release tests. SIMD
runs also reject three skipped-dispatch mutations. Restored sources are retested;
missing tests and compilation failures cannot stand in for runtime rejection.
Checker regressions exercise dependency provenance, wrong diagnostics, failed
positive controls, missing runtime tests, restoration and weakened checks.

These checks supplement the prior family-specific mutation campaigns. They do
not replace per-region emitted-code analysis, Kani proofs, fresh platform captures
or the exceptional owner pentest/retest.

## Compiler and bounded-proof development coverage

The narrow and wide SHA-2 leaf workspace inspector checks seven complete byte
regions, the exact nested scalar/CPU owner calls, workspace destruction and
unconditional workspace cleanup at operation-guard entry. MIR binds exact field
and full-slice provenance; LLVM checks ordered region widths and nested calls;
assembly checks surviving calls, including callee-saved x86 GOT-call provenance.
Unknown shapes fail closed. It assumes the reviewed external clearing methods
do not panic; it is not a proof of arbitrary MIR or every upstream caller path.

```sh
python3 scripts/cryptography/test-batch-cleanup-flow.py
python3 scripts/sha2/check-hardened-sha2-batch-codegen.py
python3 scripts/sha2/test-hardened-sha2-batch-codegen.py
python3 scripts/sha3/test-sha3-batch-cleanup-flow.py
python3 scripts/sha3/check-hardened-sha3-batch-codegen.py
python3 scripts/sha3/test-hardened-sha3-batch-codegen.py
python3 scripts/assurance/test-hardened-batch-kani.py
python3 scripts/assurance/check-hardened-batch-kani.py
python3 scripts/assurance/check-parallel-batch-kani.py
```

Compiler coverage passed at Rust 1.90.0 and 1.98.1 for x86-64 Linux, AArch64
Linux and Apple AArch64, with both abort and unwind profiles. Cross-compilation
is not native execution. Each combination rejects 38 altered artifacts. The
inspector also rejects eight actually compiled source regressions (wrong equal-
width field, missing nested clear, destructor clear and operation clear).
Abort-profile inspection does not imply Drop runs after abort.

SHA-3 batch inspection covers all four framing fields in MIR, frame/workspace
destructors and workspace cleanup at operation-guard entry. Its LLVM check follows
workspace-derived addresses through the fully unrolled frame loop: seven byte
regions, all sixteen frame-region clears and the two exact nested owner calls
must cover the entire 5260-byte workspace without gaps or overlap. Assembly
must retain the ordered 25 calls. This is an inspection of the supported compiler
layouts, not a Rust layout ABI or proof of arbitrary iterator MIR. Both compiler
endpoints, all three targets and both panic profiles passed, rejecting 62 altered
artifacts per combination. Nine real compiled source regressions were rejected
on Rust 1.98.1 x86 Linux and Rust 1.90.0 Apple Arm. Twenty-one standalone LLVM
address, extent and control-flow regressions are rejected too.

The standalone Kani driver uses the repository-pinned verifier and appends its
harnesses only to isolated copies of the actual three production Control modules.
It proves arbitrary 64-bit charge/cancellation/error accounting is atomic, with
one callback per charge, and polling preserves the finite budget. All six proofs
passed; nine real-source mutations produce assertion counterexamples. Compiler
errors, empty selection and failed proof runs do not count as proof success.
The existing global harness inventory and release rules are unchanged.

Four additional Kani proofs check the actual ParallelHash batch-range predicate,
scheduled/streaming completion-domain distinction and stream completion predicate.
They cover arbitrary u128 plan/start/merged counts and usize batch counts; stream
completion uses arbitrary u128 input/pending/merged counts at B=1, plus all u16
input bit counts at the non-power-of-two B=3. The oracle uses independently written
subtraction/rounding formulas. Nine compiled source mutants produce assertion
counterexamples, and restored methods pass again. These harnesses inject private
counters (including invalid/unreachable combinations) into real types; the stream
harness deliberately suppresses Drop and does not execute hashing. They therefore
prove the local predicates, not cryptographic state validity, all block sizes,
token provenance, transfer ordering, complete public lifecycle or cleanup.
Insufficient loop-unwinding failures cannot count as mutation counterexamples.

Remaining compiler obligations include secret-output destination iteration,
ParallelHash stream/transport/thread storage and full caller-to-cleanup lifecycle
coverage. Remaining bounded-proof obligations include worker-result transfer and
end-to-end completion-token consumption. These limited checks are
not full multibuffer qualification, proof of crypto kernels, register erasure,
native platform collection or independent review.

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
