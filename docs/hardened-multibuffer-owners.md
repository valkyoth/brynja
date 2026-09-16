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
Machine inspection here covers only the exact straight-line entry-to-clear
argument prefix, not deallocation instructions or platform unwind tables.

Nine retained rows pass (all unwind rows plus 1.90.0 abort), rejecting 150 artifact
mutants across those rows. Three 1.98.1 abort rows fully inline the glue and are
explicitly reported as not emitted, not successful retained-glue checks.
The synthetic suite rejects 61 LLVM and 178 machine-prefix regressions. The three
compiled storage-discard/truncation/removal mutants now independently fail both
LLVM and machine-prefix checks for retained glue as well as the standalone
destructor; both twenty-two-mutant source campaigns pass with restored sources.

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
registers and are explicitly PENDING in the driver, not silently counted as
qualified by this stack-backed check.

All eight supported rows pass and reject 48 assembly-only argument/offset
mutations with unchanged LLVM inputs. The focused suite rejects 62
field/width/branch/frame/ABI regressions. This is a local stack-field-to-call
handoff under the reviewed Vec layout, valid stack ownership, linking and
ordinary-return ABI assumptions. It does not establish preceding memory writes,
header/backing-buffer alias provenance, allocation correctness or exception
recovery. In particular, loading the correct field does not by itself prove that
the field still contains the correct allocation value. The separate LLVM checks
do not turn this limited machine check into a whole-machine provenance proof.

These checks assume valid Rust owner/Vec invariants and non-unwinding external
clearing contracts. They do not prove worker joining, allocation reuse, all
caller-to-Drop unwind edges or machine
argument lowering inside coordinators. Retained glue is qualified only to the
LLVM and machine-entry scope above. Compilation
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

Remaining compiler obligations include full caller-to-cleanup lifecycle coverage
and machine-level coordinator argument/unwind qualification (standalone Storage
and both forms of inlined LLVM handoff are now checked at the levels above). The new compositional proofs
do not close arbitrary streaming flush/payload paths or thread joining. These
limited checks are not full multibuffer qualification, proof of crypto kernels, register erasure,
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
