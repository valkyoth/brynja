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

The hosted batch tests additionally inject a coordinator-side panic before the
first, second or third worker launch across all four ParallelHash identities.
Already started workers wait on channels until coordinator unwinding disconnects
them, so their real work cannot finish before the injected panic. The Storage
Drop probe records completed worker wrappers and zeroed live slots at destruction;
the caller then checks root cancellation, terminal reuse rejection and secret
destination clearing. This uses synchronization, not elapsed-time assertions.
The twelve cases pass on Rust 1.90.0/1.98.1 and in optimized tests. The threaded
source-mutation campaign now rejects fifteen regressions, including two disabled
cancellation-guard variants and omission of the test-only Drop observer.
Separate pinned nightly-2026-09-11 Miri runs pass all four identities, each
covering the three launch positions (twelve cases total). The earlier fixed-128
run took 291.98 seconds; subsequent fixed-256, XOF-128 and XOF-256 runs took
291.22, 291.92 and 291.25 seconds respectively. The latter three ran concurrently
with isolated build directories and no custom MIRIFLAGS. An initial combined
all-identity invocation timed out and is not counted as passing evidence.

To reproduce one identity without a substring or empty-selection ambiguity:

```sh
cargo +nightly-2026-09-11 miri test --locked --offline --target x86_64-unknown-linux-gnu -p brynja-hash-parallel-std --features runtime-batch-execution --lib execution::batch::worker::tests::coordinator_unwind::coordinator_unwind_fixed256 -- --exact
```

The other exact test-name suffixes are `fixed128`, `xof128` and `xof256`.
Each command must report one passed test; each test internally covers all three
launch positions. These results use Miri's default schedule/seed and do not
establish exhaustive interleaving coverage.

This is runtime evidence for these recoverable-unwind cases, not a general
proof of thread joining, all schedules, native SIMD cleanup or abort behavior.
The observer deliberately records rather than asserts during Drop, avoiding a
second panic that could mask the regression by aborting the process.

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
python3 scripts/cryptography/test-batch-output-flow.py
python3 scripts/cryptography/test-batch-output-assembly.py
python3 scripts/cryptography/check-batch-output-codegen.py
python3 scripts/cryptography/test-batch-output-codegen.py
python3 scripts/parallelhash/test-batch-worker-cleanup.py
python3 scripts/parallelhash/test-batch-worker-assembly.py
python3 scripts/parallelhash/test-batch-worker-lifecycle.py
python3 scripts/parallelhash/test-batch-worker-arguments.py
python3 scripts/parallelhash/test-batch-worker-drop-glue.py
python3 scripts/parallelhash/test-batch-worker-inline.py
python3 scripts/parallelhash/test-batch-worker-provenance.py
python3 scripts/parallelhash/test-batch-worker-scalar.py
python3 scripts/parallelhash/test-batch-worker-machine.py
python3 scripts/parallelhash/test-batch-worker-handoff.py
python3 scripts/parallelhash/test-batch-worker-arm-arguments.py
python3 scripts/parallelhash/test-batch-worker-unwind.py
python3 scripts/parallelhash/test-batch-worker-throwing.py
python3 scripts/parallelhash/test-batch-worker-exception-arguments.py
python3 scripts/parallelhash/check-parallel-batch-cleanup.py
python3 scripts/parallelhash/test-parallel-batch-cleanup.py
python3 scripts/assurance/test-hardened-batch-kani.py
python3 scripts/assurance/check-hardened-batch-kani.py
python3 scripts/assurance/test-parallel-batch-kani.py
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

Secret-output destruction is checked separately by closed LLVM and assembly interpreters.
It explores all absent/empty/nonempty slot combinations: 6,561 for narrow SHA-2
and 81 each for wide SHA-2 and Keccak. Nonempty destination pointers and lengths
remain symbolic; only zero/equality length tests are supported. Every nonempty
destination must clear exactly once at its original length, followed by the
complete identity/bit-count metadata. Unknown instructions, skipped slots,
truncation, early returns and unvisited blocks fail inspection. All twelve
compiler/target/panic combinations passed, as did rejection of 28 synthetic
regressions and sixteen actually compiled source mutations on 1.98.1 x86 Linux
and 1.90.0 Apple Arm. LLVM and assembly independently reject each compiled mutant.

The assembly interpreter follows the emitted x86-64 SysV and AArch64 loops over
the same symbolic shapes. It tracks owner-relative loads, full-width slice
arguments, stack saves/restores, exact direct/indirect clearing targets and ABI
caller-saved clobbers. Exact ordered destination/metadata calls and balanced
callee-saved state are required; unknown instructions and unvisited code fail
closed. Fifty-five synthetic assembly regressions exercise skipped/shortened
clears, bad strides/branches, lost owner pointers, call-clobbered values, wrong
callees, stack corruption and truncating register operations. This is a bounded
interpreter of the observed instruction subset, not a general ISA proof, full
MIR lifecycle proof, linker validation or proof of the callee's internal stores.

ParallelHash inspection binds batch workspace cleanup, transferred leaf storage,
stream cancellation/destruction, reader destruction and the incomplete-operation
guard to their exact owners in MIR. LLVM binds full owned and borrowed extents;
assembly retains the corresponding ordered calls. Each of the twelve compiler
combinations rejects 34 altered artifacts. Thread-worker Storage destruction
has a separate MIR call check and exact LLVM loop check: from a valid Vec's base
to its end, each 256-byte slot is cleared before advancing. It rejects seven
artifact changes on Rust 1.90.0 and eight on 1.98.1, plus sixteen synthetic loop
regressions. Assembly now requires the complete reviewed worker loop, including
empty-length exit, 256-byte scaling/clears/advances, callee-saved pointer/counter
registers, back-edge flags and stack/link restoration. For a valid Vec allocation,
`256 * len <= isize::MAX`; induction on the exact matched countdown covers every
slot without sampling allocation lengths. Unknown instructions, altered loop
bounds, short clears and incomplete function extents fail closed. This recognizes
the observed instruction forms, including CFI-free abort output; it is not a
general machine-code proof or proof that callers supply the promoted Vec fields.
All twelve rows pass and reject eight additional altered assembly artifacts each.
The standalone assembly suite rejects 262 instruction/ABI/boundary regressions.
Fourteen compiled ParallelHash cleanup omissions/shortenings are
rejected on 1.98.1 x86 Linux and 1.90.0 Apple Arm. The shared provenance checker
now rejects 83 malformed artifacts; prior SHA-2/SHA-3 inspectors remain passing.
The three compiled worker-loop mutations must independently fail both LLVM and
assembly inspection; removal of Drop's clear call must fail its MIR check.

A path-sensitive MIR check now follows the worker coordinator's `run_with` local
Storage and Operation owners. It preserves separate lifecycle states at CFG
joins, explores both normal and recoverable-unwind edges, and requires storage
Drop before operation Drop on every such exit after construction. Earlier errors
may precede storage construction but still require the root guard. Only an Ok
result may disarm cancellation; the guard destructor must cancel its exact root
on the incomplete branch. Direct owner moves, overwrites, premature StorageDead,
double drops, unknown calls and removed unwind edges fail inspection.

All twelve compiler/target/panic rows passed, rejecting eleven abort-profile and
23 unwind-profile artifact mutants per row. Eighty-three synthetic lifecycle
regressions are rejected. Five additional real-source mutants (forgotten storage,
forgotten guard, omitted success completion, initially disarmed guard and inverted
cancellation) compile but fail inspection on 1.98.1 x86 Linux and 1.90.0 Apple Arm.
Both full source campaigns now reject nineteen mutants, and restored sources pass.

This establishes local Drop invocation/order, not arbitrary resource/alias flow
or worker joining. It assumes valid Rust references/discriminants and the reviewed
borrow-preserving contracts of the allowed calls. Invalid-enum unreachable sinks,
nonterminating paths, abort and double-panic termination do not supply cleanup
evidence. Callee cleanup and cancellation behavior are separately checked; this
does not prove every borrowed slice retains its original allocation or every
public entry point reaches these owners.

The standalone Storage destructor now has a separate LLVM/assembly argument
check. Its input is the original 24-byte owner; the reviewed compiler layout
loads the Vec base at offset 8 and live-slot length at offset 16 and transfers
both unchanged to the exact qualified clear-loop symbol. The closed machine
forms preserve the platform calling convention without altering either value.
These offsets are compiler-specific evidence, not a stable Rust layout promise.
All twelve existing compiler/target/panic artifacts pass, rejecting thirteen
argument mutants per row. Sixty-two synthetic provenance/ABI/boundary regressions
are rejected. Three further source mutants discard all slots, truncate to one,
or remove the first slot before clearing; each compiles and independently fails
LLVM and assembly inspection. Both full twenty-two-mutant source campaigns pass
on 1.98.1 x86 Linux and 1.90.0 Apple Arm, including restored sources.

Retained Storage drop glue now has a separate closed LLVM interpreter. It follows
the original owner fields, requires exactly one full live-buffer clear invocation
before deallocation, checks base/capacity-derived allocation size and alignment,
and distinguishes normal return from exception resumption. Zero capacity and
positive symbolic capacity are covered, with arbitrary valid live length; this
includes allocated-but-empty storage without sampling a few allocation sizes.
Every emitted block must be visited. A hypothetical exception from clear is
checked for invocation/deallocation ordering only, not successful erasure after
a throwing clear; the erasure claim assumes the qualified non-unwinding clear.
The original machine inspection covers the exact straight-line entry-to-clear
argument prefix. A complementary normal-path check now extends it through
deallocation and both returning epilogues; platform unwind tables remain outside
this check.

Nine retained rows pass (all unwind rows plus 1.90.0 abort), rejecting 150 artifact
mutants across those rows. Three 1.98.1 abort rows fully inline the glue and are
explicitly reported as not emitted, not successful retained-glue checks.
The synthetic suite rejects 61 LLVM and 178 machine-prefix regressions. The three
compiled storage-discard/truncation/removal mutants now independently fail both
LLVM and machine-prefix checks for retained glue as well as the standalone
destructor; both twenty-two-mutant source campaigns pass with restored sources.

`batch_worker_glue_machine.py` recognizes the complete normal instruction paths
of retained Storage glue on the same three targets and compiler endpoints.
After clearing the original live buffer, zero capacity must return without
deallocation; positive capacity must tail-call the LLVM-bound Rust deallocator
with the original allocation base, capacity times 256 bytes and alignment one.
Both paths must restore the reviewed saved registers and frame. The capacity
branch must resolve to the exact returning epilogue, not merely a matching label
name. This assumes a valid immutable Vec header and the reviewed non-unwinding
clearing/deallocator and ABI contracts. It does not establish allocator internals,
CFI restoration or behavior on a hypothetical exception from either callee.

All nine retained rows reject 216 post-clearing artifact mutations which still
pass the original entry-only check. The focused suite rejects 420 instruction,
allocation-ABI and branch regressions. The standalone compiler driver runs this
additional check; no release-gate rule changed. The three fully inlined abort
rows are reported separately and do not count as retained-glue passes.

The actual fully inlined LLVM coordinator now has a post-spawn cleanup
reachability analysis. It extracts branch, switch and invoke successors from
instructions (not predecessor comments), checks phi predecessor-edge
multiplicity, and retains separate possibly-dirty states through loop/branch
joins. Attempting the native thread creation call marks storage possibly dirty;
both successful and failed creation and its unwind edge are covered. Every
subsequent normal return or recoverable-unwind exit must pass the exact Storage
clear symbol or separately qualified retained drop glue. Another spawn attempt
marks storage dirty again. No branch-value pruning hides cleanup obligations.

All twelve compiler/target/panic rows pass, including the three fully-inlined
1.98.1 abort rows. Each unwind row rejects three omitted/replaced cleanup calls;
each abort row rejects two. Thirty synthetic graph/exit/loop/phi regressions are
rejected. The compiled forgotten-Storage mutant independently fails this LLVM
check on 1.98.1 x86 Linux and 1.90.0 Apple Arm, and restored source passes.
That analysis is control-flow/call reachability only: it does not validate inlined cleanup
arguments, arbitrary aliases, worker joining, pre-spawn cleanup, or machine-code
lowering. Nonreturning callees, valid-enum unreachable defaults and infinite paths
are explicitly outside the erasure guarantee. Valid Rust/LLVM and the reviewed
clear/drop-glue contracts remain assumptions; a call is not proof of successful
erasure if those callee contracts are violated.

An additional LLVM analysis now binds inlined clear arguments to the original
memory-backed Storage header. All header-address uses are classified: unknown
uses/escapes fail, field loads/stores have exact types and offsets, and only
reviewed Vec reservation helpers may receive mutable header authority before
spawn. After a native worker-spawn attempt, header writes/reservation/restart
are forbidden. This freezes the original base and live length across worker
execution; backing-buffer contents remain mutable as intended.

Must-equality facts follow stores, loads and predecessor-specific phi inputs.
Joins intersect facts, phis read their inputs simultaneously, re-executed SSA
definitions kill stale iteration facts, and calls are checked only after the
worklist reaches a fixed point. Each post-spawn clear must receive the unchanged
header base/full live length; retained drop glue must receive the original owner.
Reservation invalidates earlier equalities even before spawn. Neither branch
sampling nor an optimistic first loop iteration is accepted as proof.

Ten memory-backed rows pass: 1.90.0 on all three targets and 1.98.1 on x86 Linux,
each under abort/unwind, plus 1.98.1 Arm Linux/Apple under unwind. These reject
80 modified artifacts; 34 synthetic pointer, length,
escape, join and loop regressions are rejected. Fresh 1.98.1 x86 Linux and 1.90.0
Apple Arm campaigns each reject 25 compiled source mutations. The three new
mutations discard, truncate or remove slots in the coordinator after worker
execution; they still pass the separate cleanup-reachability/drop-glue checks
and then independently fail this argument analysis. Restored sources pass.

The earlier four-row Arm skip was too broad: the unwind rows retain the header
and pass the same analysis. Only the two 1.98.1 Arm abort rows fully scalar-replace
it. Those now have a separate allocation-bound argument analysis. It identifies
the original 256-byte-slot `finish_grow` request independently of cleanup calls,
checks the result owner's complete address-use closure, follows its exact base
field, and checks the empty/allocated pointer phi. Zero count must select the
empty branch; the successful allocation path must dominate the allocated input.
The original full slot count and selected base then flow unchanged to each
post-spawn cleanup. Reinitialization after spawning is forbidden, and loop/join
facts converge before cleanup operands are validated.

Both scalar rows pass, rejecting sixteen altered artifacts and 27 synthetic
allocation, extent, escape and loop regressions. All twelve configurations now
pass inlined LLVM argument qualification (96 artifact mutations in total).
Fresh 1.98.1 Arm Linux and Apple Arm source campaigns each reject 28 compiled
mutations, including coordinator slot-discard/truncation/removal under both
unwind and abort; restored sources pass. Fresh compiler-driver runs pass on both
Arm targets. Cross-compilation is not native execution evidence.

These analyses assume valid LLVM/Rust Vec invariants and
the reviewed reservation/clear/drop contracts; they do not prove initial
allocation size against the input plan, allocator internals, worker joins,
arbitrary backing-buffer aliases or machine lowering. Field offsets and the
source-local identity are compiler-specific, not a stable Rust ABI guarantee.

The emitted coordinator assembly now has a separate ordinary-control-flow
cleanup check. A closed x86-64/AArch64 instruction-class parser recognizes direct
branches, tested branches, returning calls, ordinary returns and terminal traps.
Native thread creation marks storage possibly dirty, including creation failure;
every later normal return must pass the exact qualified clear/drop symbol.
States remain separate across merges and repeated-spawn loops. Indirect returning
calls cannot count as cleanup, and indirect jumps, unknown instructions, inline
assembly markers and opaque executable directives are rejected. GOT/PLT and
Mach-O symbol normalization is explicit and assumes correct runtime linking.

All twelve compiler/target/panic rows pass, rejecting four assembly-only mutants
per row (48 total): removal/substitution of each of the two normal/error cleanup
calls, or an early return in its place. The focused suite rejects 67 bypass,
identity, loop and parser regressions. Real compiled forgotten-Storage mutations
also fail the assembly check independently of the already-failing MIR/LLVM;
fresh 1.98.1 x86 Linux/Apple Arm and 1.90.0 Arm Linux source campaigns pass with
restored sources (25, 28 and 25 mutations respectively).
The artifact and compiled forgotten-Storage tests require an actual dirty-return
violation; an unrelated parser rejection cannot satisfy those mutation checks.

This is machine CFG call reachability only, not instruction data-flow semantics
or argument/register/stack correctness. Its ordinary edges do not include LSDA
exception tables or CFI recovery, even when inspecting an unwind-profile build.
Landing pads reachable only through unwinding remain outside this analysis.
Traps, independently identified noreturn callees and infinite paths establish no
erasure. Valid code/ABI, reviewed callee contracts and symbol resolution remain
assumptions. No release gate or production code changed.

An additional local machine handoff check covers eight stack-backed rows: both
panic profiles on all three 1.90.0 targets and 1.98.1 x86 Linux. It identifies
the unique original empty Vec header independently of cleanup arguments and
requires its initialization to dominate worker creation. Stack-pointer changes
on ordinary paths from initialization to cleanup fail closed. For each
post-spawn normal/error cleanup site, a bounded, single-entry, call-free suffix
must load the exact full-width base/live-length fields into the clearing ABI
registers, or form the original header address for retained drop glue. Register
copies are tracked; narrower loads, clobbers and post-spawn entry past setup
cannot establish the argument identity. Pre-spawn empty exits do not count as
post-spawn argument evidence. The four 1.98.1 Arm rows retain some arguments in
registers and use the separate register/spill analysis described below.

All eight supported rows pass and reject 48 assembly-only argument/offset
mutations with unchanged LLVM inputs. The focused suite rejects 62
field/width/branch/frame/ABI regressions. This is a local stack-field-to-call
handoff under the reviewed Vec layout, valid stack ownership, linking and
ordinary-return ABI assumptions. It does not establish preceding memory writes,
header/backing-buffer alias provenance, allocation correctness or exception
recovery. In particular, loading the correct field does not by itself prove that
the field still contains the correct allocation value. The separate LLVM checks
do not turn this limited machine check into a whole-machine provenance proof.

The four 1.98.1 Arm register/spill rows now have an ordinary-machine-path
fixed-point check. It independently identifies the minimum-count selection,
256-byte-slot allocation ABI, zero/nonzero routing, successful allocated-base
load and empty-base initialization. Nonempty paths cannot reach worker creation
without the successful allocation load. Full-width copies, direct stack cells
and tracked stack-address aliases preserve identities; arithmetic, narrow writes,
overlapping scalar/vector stores and ABI caller-clobbers invalidate them. Facts
are intersected at joins and loops, separately before/after spawning, and every
post-spawn normal/error clear must receive the original base/full count. The
allocation call must also receive that count. The analysis does not infer branch
predicates or turn arbitrary expressions into identities.

All four rows pass and reject 64 assembly-only argument/initialization mutants,
with unchanged LLVM. The focused suite rejects 77 root/spill/clobber/merge/loop
regressions. Fresh compiler-driver runs pass on Linux Arm and Apple Arm under
both panic profiles. Fresh source campaigns on both targets pass all 28 compiled
mutations and restored-source checks. Of the six coordinator clear/truncate/remove
mutations per target, all six Apple cases and three Linux cases independently
fail the machine argument obligation; the other three Linux cases instead change
the reviewed initialization shape and fail closed there. Those shape rejections
are not counted as data-flow proof. New mutant panic exits use their actual
compiler noreturn attributes, not an incomplete baseline list.
This complements the eight local stack-backed handoffs;
it is not an equivalent whole-machine proof for all twelve rows. Unknown-address
writes and callee memory effects are assumed not to mutate the tracked private
spill cells, under the reviewed stack ownership and ABI/callee contracts. Known
overlapping writes are checked; arbitrary hidden aliases are not. Input-plan
arithmetic, allocation internals, complete memory initialization, worker joining,
exception tables and recovery remain separate obligations.

The six unwind-profile rows now additionally check the emitted LSDA connection
from native worker creation to cleanup. The closed parser binds the function's
personality/LSDA reference to its table, checks the reviewed encodings and
action/type bytes, and resolves ordered, nonoverlapping label-relative call
ranges to executable landing pads. This follows the table layout described in
[LLVM's personality implementation](https://github.com/llvm/llvm-project/blob/main/libcxxabi/src/cxa_personality.cpp);
it does not emulate personality matching or inspect linked binary offsets.

Native worker creation must have a nonzero landing pad. From that pad, a CFG
walk follows ordinary branches and further recorded exceptional may-edges.
Every reachable return or `_Unwind_Resume` must first pass the exact Storage
clear/drop call; repeated spawning makes storage dirty again. Traps and terminal
abort calls establish no erasure. The analysis assumes valid cleanup arguments
and the reviewed non-unwinding clear/deallocator contracts. Only those exact
cleanup symbols omit conservative exception edges under that assumption; this
is not inferred from mere absence of an LLVM `nounwind` attribute.

All six rows pass and reject 24 assembly-only mutations: omission/early return
at the unwind-only cleanup, or removal/redirection of the spawn landing pad.
Each mutant still passes ordinary-return inspection, so the additional rejection
comes from the exceptional scope. The focused suite rejects 78
binding/range/action/escape regressions. This is deliberately spawn-origin
reachability, not proof that every potentially throwing call has an appropriate
LSDA record. CFI/register/stack recovery, exception-path argument provenance,
action selection, linked table offsets and the runtime unwinder remain unproved.
Earlier ordinary-only checks retain their original scope. Release gates and
production Rust are unchanged.

The complementary throwing-call check now starts at function entry and follows
both ordinary and recorded exceptional edges. After any native spawn attempt,
every reachable return/resume must pass exact Storage cleanup, including failures
from subsequent join, merge and destruction calls. The same non-unwinding
cleanup/deallocator assumptions apply. Calls marked `noreturn` still contribute
their exceptional edges before ordinary traversal stops.

To prevent disappearing LSDA entries from silently shrinking that scope, this
check compares the multiset of LLVM `invoke` callees with machine calls covered
by nonzero landing pads. Direct symbols retain their multiplicities; indirect
calls have a separate counted bucket, without invented target identities. The
six rows match 56 invokes each, except the two 1.98.1 Arm rows with 53 each.
All six pass and reject 286 artifact mutations: removing each call-bearing
nonzero table entry, plus redirecting the later thread-join exception to resume
without cleanup. The latter mutants preserve inventory counts and pass ordinary
return inspection, but fail the broader exceptional walk. Thirty-three focused
regressions cover missing/extra/replaced calls, indirect calls, later exceptional
bypasses and throwing `noreturn` calls. Fresh full standalone compiler-driver
runs pass for 1.98.1 x86 Linux/Apple Arm and 1.90.0 Arm Linux.

This inventory is not one-to-one source-site correspondence: equal-symbol calls
could exchange coverage without changing counts. It also cannot prove that
LLVM itself retained every needed invoke, identify indirect targets, or certify
callee behavior. Exception-path argument provenance, CFI restoration, personality
decisions and linked/runtime unwinding remain outside the claim. These are
development checks only; no release-gate policy was changed.

The exception-only destructor now has a separate local argument check on all six
unwind rows. It identifies the unique empty Storage stack header independently
of cleanup sites, checks that initialization dominates worker creation under the
combined ordinary/exceptional graph, and rejects explicit frame adjustments
between initialization and cleanup. The call must receive that header's exact
full-width address through a bounded, call-free setup sequence. All recorded
incoming edges are considered: a landing pad cannot skip the setup and enter
directly at the destructor call. This covers the additional exception-only drop
site, not a replacement for ordinary-path argument checks.

Fresh full standalone compiler-driver runs passed at both compiler endpoints on
all three targets. Thirty-six assembly-only mutants (six per unwind row) corrupt
the argument, truncate it, shift the address, interpose an indirect call, change
the actual frame offset or redirect a landing pad past setup. Each still passes
cleanup-call reachability but fails the argument check. Forty-five focused
regressions exercise initialization identity/dominance, full-width copies,
clobbers, stack changes and bypassing ordinary/exceptional edges.

This is conditional on the runtime unwinder restoring this function's stack
frame and on reviewed callee/ABI behavior. The checker does not interpret CFI,
prove restored registers or memory, track every preceding header write/alias,
or prove its backing allocation/length remains valid. The existing LLVM header
checks and destructor checks provide separately scoped evidence, not a complete
machine-level provenance proof. Production code and release gates are unchanged.

These checks assume valid Rust owner/Vec invariants and non-unwinding external
clearing contracts. They do not prove worker joining, allocation reuse, all
caller-to-Drop unwind edges or complete machine argument provenance inside
coordinators. Retained glue has the LLVM ordering/argument checks and complete
normal machine-path deallocation checks above, not machine exception-tail or
CFI qualification. Compilation
for Apple/Arm is not fresh native evidence, and abort-profile checks never imply
that abort executes Drop.

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

Three further compositional Kani harnesses follow actual transport consumption
and completion-token methods. Two cover narrow/wide scheduled transfer with
arbitrary u128 positions/limits/accounting, usize counts, valid active-slot masks,
all worker policies, foreign plans, invalid phases and streaming-root rejection.
They check exact successful accounting, terminal cancellation on failure and
clearing of every transport byte, including inactive capacity. A third follows
batch `finish_input` through exact root-bound token consumption by
`Collector::finish_stream`, then rejects a second finalization attempt. It covers
all u16 input-bit counts with no pending bytes or final tail, arbitrary u128 merged
counts, and cancellation at either poll. It is not a full input-buffer proof.

These are explicitly compositional proofs: completed tokens/counters are injected,
sponge absorption is modeled as success or failure for transfer, and sponge
absorption/finalization as success for completion. The volatile primitive is
modeled by its byte-clearing effect; actual owner Drop, guard cancellation,
accounting and token methods are not replaced. Thus these harnesses do not prove
hash values, payload absorption/order, token creation by real worker hashing,
machine-store preservation, registers or every callback/unwind behavior. They
complement the separately scoped runtime, ownership and emitted-code checks.
The standalone driver selects exact harness names and bounds each verifier run;
timeout/interruption is never accepted as a source-mutation counterexample.
All three added harnesses and twelve real-source counterexamples passed with
the pinned Kani 0.67.0. The original four predicate proofs and their nine mutants
also pass. Invalid source anchors and interrupted verifier results are tested
separately; disabling either check is detected by checker mutation tests.

A further `buffer` harness exercises actual `Stream::update`, `update_inner`,
`flush`, cancellation and Drop on two chunked updates. It covers B=1, every
length from zero to twelve bytes, every split point, arbitrary byte values,
cancellation at any of the four outer polls and rejection of any of three
complete groups. A modeled consumer asserts that every full group receives the
next four original bytes in order; it either advances modeled leaf accounting
or returns an error. Successful updates must preserve the exact remaining
prefix, zero unused buffer bytes and report the exact input and merged counts.
Errors must cancel the root, clear pending bytes/counters and reject reuse;
Drop must clear the buffer on both success and failure.

The harness injects an empty root, repurposing otherwise-unused pre-output fields
only as oracle data and a failure selector. These are not claimed to be a valid
hashed transcript. `Collector::merge_stream_batch` is stubbed, so this proof does
not qualify its hashing, CV construction, root absorption or work charging.
Clearing is modeled by byte fill, not machine-store preservation. The real
buffer-copy, flush clearing and cancellation code is not replaced. Partial-bit
tails, larger block/message sizes, more updates and arbitrary unwind remain
outside this bounded proof. Run it separately with
`python3 scripts/assurance/check-parallel-batch-kani.py --proof buffer`.
The positive proof passes with pinned Kani 0.67.0. Five real-source mutants
produce assertion counterexamples: zero-filled copying, discarded input tails,
omitted post-flush buffer clearing, discarded input accounting and disabled
cancellation guards. An initial 33-unroll attempt with generic slice comparisons
timed out and is excluded. Explicit four-byte oracle comparisons and a five-step
unwind bound retain the same input domain; unwinding assertions remain enabled.
The restored-source proof passes again after all five mutations.

A separate `tail` harness follows the real `finish_input` partial-byte branch
with B=1, one to eight total bytes and zero to three valid pending bytes. Payload
bytes are symbolic, with the last byte canonicalized to each possible final
valid-bit count from one to seven. A modeled consumer checks each group against
the original ordered bytes, including exact final bit count, and either counts
its leaves or rejects the first/second group. Cancellation can occur at either
outer poll. On success the completion token must borrow the exact checked root,
and input-bit/leaf counts must match the independent length formula. On error
the root must be cancelled, buffers/counters cleared and further input rejected.
The buffer is also checked after Drop.

This injects pending bytes and matching metadata rather than proving their
creation. The prior byte-update proof supplies separately bounded evidence for
that operation. The consumer and volatile-store effects remain modeled; root
output/finalization, hashing, arbitrary B/message sizes, more updates and unwind
are outside this proof. Both full-prefix flushes and the final partial group
are exercised without replacing actual input-copy, flush or guard methods.
Run `python3 scripts/assurance/check-parallel-batch-kani.py --proof tail`.
Pinned Kani 0.67.0 passes the positive proof and rejects five real-source
mutations: zeroed final byte, byte-aligned replacement of its bit count,
discarded full-byte prefix, lost total-bit accounting and skipped partial flush.
Each rejection is an assertion counterexample, not a compiler error or timeout.
The restored source passes again after the complete mutation campaign.

Remaining compiler obligations include full caller-to-cleanup lifecycle coverage
and machine-level coordinator argument/unwind qualification (standalone Storage
and both forms of inlined LLVM handoff are now checked at the levels above). The new compositional proofs
do not close arbitrary streaming flush/payload paths or thread joining. These
limited checks are not full multibuffer qualification, proof of crypto kernels, register erasure,
native platform collection or independent review.

## Independent scheduled and streaming ParallelHash batch oracle

The `local` binary in `assurance/parallelhash-batch-oracle` reuses the threaded
fixture's bounded public-vector protocol and independent Python SP 800-185
corpus. It exercises a scheduled collector and three streaming layouts: single
byte chunks, block-crossing chunks and all input supplied at finalization.
Each case uses public and secret output APIs with a portable root, compares
outputs, and checks full scratch, output Drop, stream pending storage and
destination canaries. XOF streams reject updates after reader finalization.
Scheduled reports and stream leaf counters are checked against expected counts.
A second borrowed session observes actual authority vector calls, including
calls in consuming finalizers; this does not infer execution from CPU support.

Run `python3 scripts/cryptography/check-parallelhash-local-batch-oracle.py`;
add a matching `--lane` to enable preferred and required SIMD execution. Local
AVX2 passed 2,240 cases: 256 portable, 256 preferred and 48 eligible required
cases for each layout. Vector calls across both output profiles were 0, 600
and 448 respectively per layout campaign. A generic build passed another 1,024
portable cases without SIMD flags. Each build cleanly rejected forty malformed
requests and two invalid mode/layout arguments. Rust 1.90 compilation/tests and
strict Rust 1.98.1 Clippy passed.

`test-parallelhash-local-batch-oracle.py` rejects 132 output/count/layout/status/
route regressions. With a matching `--lane`, six compiled fixture mutations
test forgotten output Drop, corrupted digest encoding, false SIMD routing,
fixture counter overflow, dirty pending storage and skipped stream updates.
All four identities execute separately for each applicable layout: 84 mutant
executions rejected, with restored source passing after every mutation.
Compilation failures do not count as runtime rejection. These are development
oracle checks, not native NEON evidence, whole-lifecycle erasure proof or
independent review. Production code and release/tag gates remain unchanged.

## Independent threaded ParallelHash batch oracle

`assurance/parallelhash-batch-oracle` directly exercises the new bounded threaded
multibuffer API for all four ParallelHash identities. Its CLI processes public
generated vectors, not application secrets. Each case compares transactional
public and borrowed-secret outputs and reports, checks exact leaf/group/vector
participation and reported thread width, and observes full scratch and output
Drop clearing with destination canaries. The root remains portable to isolate
the hardened multibuffer leaf path.

Run `python3 scripts/cryptography/check-parallelhash-batch-oracle.py`; add a
matching `--lane` for preferred/required SIMD. The existing independently composed
Python SP 800-185 oracle supplies 256 arbitrary-bit cases across all identities,
partial-bit customization/output, zero output and varied block sizes. Every case
runs with one, two and three workers. Required mode selects 48 nonempty cases
with four-aligned leaf counts, avoiding incomplete final groups on both vector
widths; portable/prefer still cover the complete corpus.

Local AVX2 passed 1,680 cases: 256 portable, 256 preferred and 48 required for
each of the three worker counts. Vector calls across both output profiles were
respectively 0, 600 and 448 per worker-count campaign. The generic build passed
another 768 portable cases with no SIMD flags. Ten malformed requests and two
worker bounds rejected. Rust 1.90 tests and strict Rust 1.98.1 Clippy passed.

`test-parallelhash-batch-oracle.py` rejects 117 result/count/thread/route
regressions and checks required-group selection at partial-bit boundaries.
With `--lane`, six compiled fixture mutations must reject skipped output Drop,
dirty scratch, corrupted output encoding, forced portable routing, counter
overflow and reduced worker count. Restored source passes after every mutation;
compilation failure is not accepted as evidence. Thread width describes
submitted workers, not a measurement of simultaneous core utilization or
scheduler fairness. This is not independent review, native NEON execution,
fresh platform qualification or separate scheduled/streaming oracle coverage.
Production code and release/tag gates remain unchanged.

## Independent hardened Keccak-family batch oracle

`assurance/hardened-keccak-batch` enables only the distinct hardened Keccak batch
profile. It accepts four optional public test-vector slots across all eight
SHA-3/SHAKE/cSHAKE identities, including arbitrary-bit message/N/S and finite
output bits. Three calls per batch exercise borrowed secret output, consumed
declassification and direct public output. Exact identity/bit/byte widths, output
Drop/declassification clearing, full staging (including excess capacity) and
destination canaries are checked. Its ordinary CLI buffers must never be used
as an application secret-input interface.

Run `python3 scripts/cryptography/check-hardened-keccak-batch-oracle.py`; add a
matching `--lane` for native preferred/required SIMD. Existing independent
Python FIPS 202/SP 800-185 oracles, cross-checked against pinned NIST vectors,
provide 256 full mixed-domain/rate batches. Sixteen derived batches cover every
activity mask, preserving active empty output separately from inactive slots.
Required mode uses the full batches; portable/prefer also run the sparse cases.

Local AVX2 passed 272 portable, 272 preferred and 256 required batches, reporting
respectively 0, 1,062 and 1,056 vector calls across the three API calls per batch.
The generic build also passed all 272 portable batches with no SIMD flags.
Thirteen malformed requests rejected without output or panic on both builds.
Rust 1.90 tests and strict Rust 1.98.1 Clippy passed.

`test-hardened-keccak-batch-oracle.py` checks all activity-mask derivations and
rejects 33 result/status/route regressions. With `--lane`, five compiled mutations
must fail: forgotten output owner, corrupted encoding, forced portable routing,
counter overflow and deliberately dirty post-execution staging. Restored source
passes after each mutant; compilation failure is not accepted as evidence.
This is author development evidence, not an independent review, NEON execution
result, complete erasure proof or fresh platform qualification. Release gates
remain unchanged.

## Independent hardened SHA-224/256 batch oracle

The separate `assurance/hardened-sha256-batch` adapter enables only the distinct
hardened narrow batch profile, not ordinary batch execution. Eight optional
inputs mix SHA-224 and SHA-256 identities. Each request performs borrowed-secret,
consumed declassification and direct-public output calls; it checks exact
identity/width, Drop/declassification clearing and untouched inactive capacity.
All CLI input/output is public generated test data, not an application secret
processing interface.

Run `python3 scripts/cryptography/check-hardened-sha256-batch-oracle.py` for the
generic portable campaign, or add `--lane` naming the matching native platform
for preferred/required SIMD as well. The existing independent Python bit-level
SHA-2 oracle supplies expected results for 384 batches covering all 256 slot
activity masks, both IVs, partial bits, padding boundaries and unequal lengths.
Required mode selects the 128 full batches with eligible message blocks.

Local AVX2 passed 384 portable, 384 preferred and 128 required batches, with
respectively zero, 1,257 and 1,257 actual vector calls across the three API calls
per request. The generic build independently passed all 384 portable batches
without SIMD flags. Ten malformed requests rejected without digest output or
panic. Rust 1.90 fixture tests and strict Rust 1.98.1 Clippy passed.

`test-hardened-sha256-batch-oracle.py` rejects 33 result-validation regressions;
with a matching `--lane` it also compiles four mutants that skip secret-output
Drop, corrupt digest encoding, force portable routing or overflow the fixture
counter. Runtime rejection/oracle mismatch is required, not failed compilation;
restored source must pass after every mutation. These checks do not qualify
NEON without a native run, prove all cleanup, replace independent review or
change any release/tag gate.

## Independent hardened SHA-512-family batch oracle

The separate `assurance/hardened-sha512-batch` public-vector adapter uses only the
distinct hardened feature graph. It runs borrowed-secret, consumed explicit
declassification and direct-public output paths, checks exact algorithm/width
identity, and observes secret destination clearing after both Drop and
declassification without changing inactive buffer capacity. Input/output is
public test data; its ordinary CLI buffers are not an application secret owner.

`python3 scripts/cryptography/check-hardened-sha512-batch-oracle.py` runs the
existing independent Python bit-level SHA-2/SHA-512/t corpus directly through
these APIs. It covers 4,846 mixed batches, all 510 valid t values, sparse slots,
canonical partial bits and padding boundaries. With `--lane` naming a matching
native platform, it also runs prefer mode and the 4,590 full batches eligible for
required SIMD. The actual vector-call counter must be nonzero for accelerated
campaigns and zero for portable execution. A failing or empty execution cannot
be counted as success. No ordinary digest importer handles the secret output.

Local AVX2 execution passed 14,282 batches across portable/prefer/require, with
three output/lifecycle calls per batch. Ten malformed requests rejected without
digest output or panic. The generic build separately passed all 4,846 portable
batches and malformed cases without SIMD build flags. Rust 1.90 fixture tests and strict Rust 1.98.1 Clippy
passed. The result checker rejects 33 coverage/status/output/route regressions.
`test-hardened-sha512-batch-oracle.py --lane amd-x86_64` additionally rejects four
compiled mutations: skipped secret-output Drop, corrupted hex output, forced
portable dispatch and overflowing fixture work counters. Restored source passes
after every mutant. This reuses an existing independent oracle implementation;
it is not a new independent security review, proof of all erasure, qualification
of the other batch families or a fresh native-platform receipt.

## Standalone sanitizer development check

On a matching Linux x86_64 AVX2 or AArch64 NEON host, run:

```sh
python3 scripts/cryptography/test-hardened-batch-asan.py
python3 scripts/cryptography/check-hardened-batch-asan.py
```

The runner uses pinned `nightly-2026-09-11`, offline locked dependencies and a
fresh temporary build directory. It checks SIMD support on every CPU listed in
`/proc/cpuinfo`, selects the matching native target and forces AddressSanitizer
and LeakSanitizer with fatal error exits. Ambient sanitizer options cannot disable
leak checking. Cargo environment target/runner/wrapper overrides are removed;
the checkout and on-disk Cargo/toolchain configuration remain trusted inputs.
CPU scheduling/migration guarantees remain the deployment's responsibility.

Six library-test selections cover the CPU kernels, SHA-2 leaves, Keccak leaves,
hosted adapters, scheduled/streaming ParallelHash and threaded ParallelHash.
Required-backend switches and exact named passing tests prevent portable-only
or empty selections from passing. The CPU suite additionally requires the real
1,024-pair Keccak SIMD marker. All four threaded coordinator-unwind identities
must pass. Nonzero exits, missing results and timeouts reject the run; a runner
that cannot support leak checking must be changed, not run with leaks disabled.

Local x86_64 AVX2 execution passed 117 tests across these six selections with
forced leak checking. Host/environment/result checks and seven enforcement
mutations passed. This is repeatable implementation-author development evidence,
not an AArch64 sanitizer result, native evidence receipt, complete memory-erasure
proof or independent review. This runner is not added to the release/tag gates.

## Standalone comparative hardened-batch timings

`assurance/hardened-batch-bench` compares the actual hardened secret-output batch
paths to their portable counterparts, using public synthetic messages. It covers
640 workloads: both narrow SHA-2 identities, four named wide identities and four
representative general-t identities, plus all eight SHA-3/SHAKE/cSHAKE identities.
Every active-lane count is represented with balanced and unequal lengths at
empty, one block/rate, 4096 and 16384 bytes. XOF output is 4099 bits and cSHAKE
uses nonempty public N/S. General-t timing is representative, not all-parameter
coverage; the separate independent oracle covers all 510 parameters.

Run `python3 scripts/cryptography/check-hardened-batch-bench.py` for generic
portable execution, or add a matching native `--lane` for selected SIMD. Both
routes warm up and alternate order over seven samples. Medians include hashing,
public-reference comparison and secret-output Drop, but exclude allocations,
authority construction, poisoning, cleanup inspection and result formatting.
Destination poisoning is guaranteed incorrect relative to the reference. Every
call checks outputs, complete secret-output clearing, inactive slots, canaries,
and Keccak caller staging. Work reports must match the finite budget's charge.

The driver requires all 640 unique workload rows, stable actual route counters,
exact SHA-2 common-block vector counts and correct Keccak SIMD eligibility.
Slower results remain visible; threshold 1 is not a recommended crossover.
Local AVX2 and a separate generic portable run passed. Rust 1.90 tests and strict
Rust 1.98.1 Clippy passed. `test-hardened-batch-bench.py` rejects 68 malformed
result/coverage/route regressions and explicitly accepts slower results. Six
compiled fixture mutations reject omitted SHA-2/Keccak output Drop, overflowed
vector totals, false portable routing, dirty staging and broken output validation;
restored source passes after each. No production source is mutated.

These exploratory timings are not statistical confidence, dedicated single-stream
instruction comparisons, threaded ParallelHash timings, independent cryptographic
review, constant-time validation or fresh multi-platform qualification. Those
distinct evidence obligations are not closed by this fixture. Native collection
and owner pentest remain pending; release/tag rules are unchanged.

## Standalone threaded ParallelHash timings

The `benchmark` binary in `assurance/parallelhash-batch-oracle` compares local
scheduled portable hashing with the threaded multibuffer API. All four identities
use public synthetic input, a portable root and typed secret outputs. Ninety-six
workloads combine lengths 0/65/4096/16387, block sizes 64/1024 and worker counts
1/2/4. Fixed output is 256 bits and XOF output is 4099 bits. This includes empty
work, one partial group, full groups and nonempty scalar tails.

Run `python3 scripts/cryptography/check-parallelhash-batch-bench.py`; add a
matching native `--lane` to compare preferred SIMD leaves instead of portable
threaded leaves. The selected kernel label describes authority selection; actual
vector counts are checked separately. Each timed call must match the generated
portable reference, clear its owned output, retain its canary and report exact
leaves, groups, accelerated leaves and submitted worker width. The driver also
independently computes the exact full-width leaf permutation count for each
workload. Counters and complete reports must remain stable across samples.

Seven samples alternate route order after warmup. Timings include hash work,
worker allocation/spawn/join, worker-local authority construction, output
comparison and Drop; caller allocation/poisoning, outer executor setup and
post-Drop inspection are excluded. These are end-to-end comparisons, not isolated
kernel timings. One worker still pays thread creation overhead. Submitted
workers do not measure simultaneous physical cores or scheduler fairness.

Separate local AVX2 and generic builds passed all 96 workloads. In the recorded
local runs, threading was not faster in 62/96 AVX2 rows and 68/96 generic rows;
those outcomes were retained, not filtered. This observation is machine/load
specific, not statistical confidence or a recommended crossover. The generic
run compares portable threading against portable scheduling, not SIMD.
Rust 1.90 tests and strict Rust 1.98.1 Clippy passed. The result checker rejects
80 malformed/coverage/accounting regressions, checks group-boundary calculations
for AVX2/NEON and explicitly accepts slower results. Six compiled fixture
mutations reject skipped Drop, counter overflow, false routing, reduced worker
count, damaged canaries and broken output validation; restored source passes.

This supplements, but does not replace, the independent correctness oracles.
It is not native Arm execution, a dedicated single-stream comparison, constant-
time qualification or independent review. No production source or release gate
changed; complete qualification and owner pentest/native collection remain pending.

## Native runtime collection wrapper

[Native collection instructions](hardened-batch-native-collection.md) describe
the standalone fourteen-step wrapper for AMD/Intel Linux, AWS Arm and Apple M2.
It reuses the six native suites, five oracle drivers, two comparative benchmarks
and package acceptance. Every record binds a clean Git commit/tree, compiler,
CPU/feature context and command outputs, while retaining pending owner review
and explicit exclusions for the separately required verifier/compiler evidence.
It does not add release-gate policy. Synthetic tests reject 484 record changes
across four lanes and exercise orchestration failures, environment cleanup,
attestation, source drift and no-overwrite behavior. Synthetic records are not
native qualification results.

The real local AMD wrapper execution at commit
`6b1655f85de9bfdc74df9f098708e8dc45d20979` also passed all fourteen steps,
including their existing oracle/benchmark and package result validators.
It remains a development capture with owner review pending, not a substitute
for the other native lanes or excluded compiler/verifier/pentest evidence.

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
