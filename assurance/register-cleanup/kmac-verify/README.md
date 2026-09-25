# Scoped KMAC verification-return diagnostics

Development only. Passing these tests does **not** qualify register cleanup or
close F1. No release-gate command, API default or backend admission changes.

## Current local evidence location

On 2026-09-24 the root `target/` directory was absent; the owner reported that
it was likely removed by the regular Cargo clean. The historical record and
logs cited below were no longer available. The unchanged focused collector was
rerun, not the full release gate or long Miri campaign. All sixteen configurations
passed again, retaining 240 compiler artifacts and 416 return observations with
zero repeated input-marker matches (not proof of erasure).

Use `dist/kmac-verify-nft_nl5x/observations.json` for further local inspection;
its SHA-256 is
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
The full build/record directory was moved outside Cargo's `target/`, with an
additional archive at `dist/kmac-verify-nft_nl5x.tar.gz`, SHA-256
`6a85f5de89c4e0e0f7c3dc725bfb7ab09c93b35525bcdb09645c361d75d26e52`.
Archive integrity was checked with `gzip -t`. Both paths are ignored local
evidence, not GitHub artifacts; ordinary `cargo clean` will not remove them.
The collection log is `dist/kmac-verify-recovery.log`, SHA-256
`fc2fd07c1b7caafdacaa6b9612204891de1af45d55441fe11b24730c829b14af`.

Historical commands below retain the original record path and run hashes;
substitute the new record path when rerunning them. This is a fresh capture,
not restoration of the original bytes or missing historical test logs. It does
not recover other deleted evidence or replace native qualification/retest.

This standalone fixture exercises the actual scoped KMAC128/256 verification
APIs, including required static AVX2/Arm Keccak execution. Four public synthetic
tags are independently generated with the existing Python SP 800-185 oracle,
which first checks its NIST sample. Keys contain 32 repeated marker bytes;
messages contain 135; tags contain 1,027 bits, crossing two 64-byte comparison
chunks before a three-bit final byte. The fixture accepts no real secrets.

| Case | Expected result |
| --- | --- |
| Exact tag | Match |
| First-byte mismatch | Mismatch |
| Final partial-byte mismatch | Mismatch |
| Equal first/final XOR differences | Mismatch; differences must not cancel/reset |
| Wrong application-specified bit length | `InvalidBitString` |
| One-byte tag | `TagTooShort` |
| Authority revoked after absorbing input | Backend error, without portable fallback (accelerated profile) |

Both marker values and strengths are exercised. Input and output-sentinel
arrays remain unchanged. The sentinel is not a secret-output destination and
is not claimed to be erased. Additional controls reject invalid fixture cases,
unknown markers and a changed message with the original tag.

The Linux observer is reused unchanged from the original caller fixture,
including deliberate retaining/clearing controls. It snapshots selected volatile
registers immediately after the C-ABI wrapper returns, and logs only counts.
There are no dead-stack reads or raw secret/register dumps. Preserved registers,
upper vector lanes, spills, interruption snapshots and platform storage are not
measured. Zero repeated-marker matches do not establish absence of other residue.

Run from the repository root on a Linux x86-64 host with native AVX2:

```sh
python3 assurance/register-cleanup/test_kmac_verify_callers.py --mutations
python3 assurance/register-cleanup/check_kmac_verify_callers.py --arm
```

The collector covers Rust 1.90.0/1.98.1, debug/release, portable/static-accelerated
profiles and native x86/QEMU Arm. QEMU is explicitly **not native Arm evidence**.
It records compiler identities, source hashes, runtime logs and hashes of actual
fixture/KMAC/SHA-3/CPU/core MIR, LLVM and assembly artifacts. No artifact is
automatically declared erasure-qualified. This separate fixture leaves the
existing threaded caller record and its source closure unchanged.

The original record was `target/kmac-verify-1iopq9b5/observations.json`, SHA-256
`fd6af99e11917911e3b8c2a0c3784c5b40c40feb99d1d3683d04940024a0dc02`.
All sixteen configurations passed four tests each, with 416 return observations
and zero repeated input-marker matches. All 240 retained artifact hashes and
the source closure were rechecked. Optimized LLVM includes two pointer-based
difference-accumulation call sites in each selected verifier; this call inventory
is not a data-flow or whole-function machine-code erasure proof.

Tests reject 32 malformed/missing/duplicate/overclaim log variations and twelve
genuinely compiled fixture mutations in debug/release: omitted message input,
missing first/final mismatch, wrong exact-length case, inverted verification
verdict and ignored revocation. These mutate the diagnostic fixture, not the
production implementation. Strict all-target/all-feature Clippy passes with the
repository's existing `chunks_exact_to_as_chunks` compatibility allowance.

Production verification logic is unchanged. Complete emitted-code analysis,
native platform qualification and fresh independent retest remain separate;
the earlier long Miri result was retained rather than repeated.

## Retained comparison-path inspection

These commands reuse the record above without compiling or executing Rust:

```sh
python3 assurance/register-cleanup/check_kmac_verify_comparisons.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_verify_comparisons.py target/kmac-verify-1iopq9b5/observations.json
```

The checker validates the exact sixteen-configuration matrix, current source
closure, execution labels, runtime-log observations and all 240 artifact hashes.
Across 48 instantiated verifier bodies, each has two pointer-only accumulation
calls and one pointer-input, byte-sized `Choice` verdict call. The 24 core
accumulation forwarding wrappers have a closed LLVM instruction grammar: input
pointers may be stored in local debug slots, but no secret-byte loads, arithmetic,
branches or extra calls are allowed. Each forwards the same three pointers to
the private accumulation boundary. The existing difference and predicate
assembly validators also pass on all 32 private boundaries in this record.

Negative controls reject 480 call-ABI, 264 pointer-forwarding and 160 assembly
mutations, sixteen missing-verifier inventories and twelve record/source/hash/
log changes. These are LLVM/assembly-text mutations, **not** newly compiled or
executed mutants. The test forbids subprocess execution. Inspection log:
`target/development-v02449/kmac-verify-comparisons.log`, SHA-256
`3424d808ae64da75ade5737f187820177d87f8d92dddbc70ec8aab1ade7c935d`.

This proves neither pointer provenance at the verifier call sites nor cleanup
of its full body, predicate wrapper, callee tree or compiler spills. Normalized
verification results intentionally leave the comparison boundary. It does not
extend the original observation scope to native Arm, Apple or Windows, and
does not close F1 or replace the pending independent retest.

## Verdict conversion path

The remaining predicate forwarding path can be checked without rebuilding:

```sh
python3 assurance/register-cleanup/check_kmac_verdict.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_verdict.py target/kmac-verify-1iopq9b5/observations.json
```

All sixteen configurations pass. Debug artifacts retain the public wrapper,
private `apply` wrapper and `Choice::from_lsb`; optimized artifacts fold these
into the public wrapper. The checker follows all 32 retained wrappers with a
closed LLVM grammar. It requires the original borrowed difference pointer and
full-byte mask at the private boundary, exact predicate normalization and a
returned value derived from that predicate. No raw difference load is permitted
in these wrappers. Optional local debug stores contain only pointers, a public
mask or the normalized verdict intentionally exposed by verification. The
existing assembly validator checks the private predicate in all sixteen builds.

Tests reject 400 load/store/call/return/normalization LLVM-text mutations and 48
missing definitions, with subprocess execution forbidden. Log:
`target/development-v02449/kmac-verdict.log`, SHA-256
`fd0e3edccd67a3cd079fa56baf4228c668c7a74b296a3b91d7671510cae1c0c3`.
This closes the narrow predicate-wrapper inspection item noted above, not the
whole-verifier pointer-provenance, machine-code spill or native-platform review.
No production code, original evidence, or release gate changed.

## Direct verifier memory accesses

```sh
python3 assurance/register-cleanup/check_kmac_verify_memory.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_verify_memory.py target/kmac-verify-1iopq9b5/observations.json
```

All 48 retained verifier bodies pass: 2,152 direct loads, 2,288 stores and 508
memory copies. Their addresses resolve to local allocations or the three input/
owner descriptors, using only constant-offset alias propagation. A pointer
loaded from a descriptor does **not** grant trusted provenance to its pointee;
direct accesses through that pointer reject. Access widths and offsets must
fit the allocation bounds or the conservative 32-byte descriptor envelope.
Portable `Core` can be smaller (24 bytes), so this envelope is not an exact Rust
object-layout or memory-safety proof. Unreviewed vector/volatile/atomic accesses,
inline assembly and memory intrinsics also reject.

The tests reject 672 access/copy/bounds LLVM-text mutations and accept 48 bounded
local-alias controls. They forbid subprocess execution and do not rerun Rust.
Log: `target/development-v02449/kmac-verify-memory.log`, SHA-256
`0ea30bfd496724b2f38aa72278bf10f38aa4eb5c46f3d5b274d2a9a777707b7d`.

This is a direct-memory inspection, not complete secret-data provenance: it
does not establish what callees write into result slots, recursively inspect
their behavior, or prove machine-code spill cleanup. Those obligations and
native-platform qualification remain separate. F1 remains open.

## Debug secret-output accessors

```sh
python3 assurance/register-cleanup/check_kmac_output_accessors.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_output_accessors.py target/kmac-verify-1iopq9b5/observations.json
```

The retained debug `HardenedSha3SecretOutput::expose` path has seven reachable
functions, including `OwnedSecretRegion::expose`, slice/option forwarding and the
empty-slice constructor. All eight debug configurations pass: 56 functions and
152 direct descriptor loads. Exact call-graph coverage and bounded descriptor/
local-slot accesses are checked. Pointer reload aliases must agree with their
final store inventory; payload pointers do not authorize further dereferences.
The `as_ref` summary is bound to the retained borrowed-region field at offset 8.

Tests reject 336 memory/call/missing-definition mutations plus 32 actual payload
dereference, field-offset and alias-overwrite mutations. These are LLVM-text
tests with subprocess execution forbidden, not compiled/runtime campaigns.
Log: `target/development-v02449/kmac-output-accessors.log`, SHA-256
`e95107ef8a26e79d75d77ce89488c8c976529817b0390a50735171d9e4c85fbb`.

Optimized accessors are inlined; this check does not invent separate optimized
functions or replace the direct-verifier inspection above. Null alternatives
are ignored for descriptor-access classification, not proven unreachable by a
CFG analysis. This is not a proof of alias safety, output-producer effects,
result-slot contents, machine-code spill cleanup or erasure. Those obligations,
native qualification and fresh retest remain open; no release gate changed.

## Optimized initialization-to-output handoff

```sh
python3 assurance/register-cleanup/check_secret_output_finish.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_secret_output_finish.py target/kmac-verify-1iopq9b5/observations.json
```

The retained `SecretRegionInitialization::finish` code passes in all eight
optimized configurations. A closed instruction interpreter follows its absent,
complete and incomplete metadata cases and visits all 48 retained basic blocks.
Success returns the original destination pointer/length. Incomplete
initialization returns the value-free error and requests exactly one clearing
of that original full region. No payload load or copy is accepted in this
handoff; only descriptor fields are read/written. Rust 1.90's explicit nulling
of the consumed input descriptor is allowed, as is its removal in Rust 1.98.

All 160 retained-LLVM mutations reject, covering vacuous/inverted completion,
wrong fields, returned ownership, missing/partial/duplicate cleanup, payload
loads/copies and broken control flow. Tests prohibit subprocess execution.
Log: `target/development-v02449/secret-output-finish.log`, SHA-256
`572e2ac5f87d60035304e26ae74c55201a26c4cc6abda5173e74694193770f05`.

This checks the optimized ownership-handoff control flow, not whether prior
writes produced the correct bytes, whether the volatile cleanup callee completes,
or whether machine-code spills are erased. Debug completion bodies, surrounding
SHA-3 result wrapping, squeeze/finalization producers and platform qualification
remain separate review obligations. No production or release-gate changes.

## Optimized SHA-3 output wrapping

```sh
python3 assurance/register-cleanup/check_sha3_output_wrap.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_sha3_output_wrap.py target/kmac-verify-1iopq9b5/observations.json
```

All eight optimized `finish_secret` wrappers pass, covering all 52 blocks in
the retained Rust 1.90/1.98 artifacts. Empty, complete, incomplete and missing-
region cases are followed separately. The only copy transfers the 24-byte
initialization descriptor, not payload bytes; the exact core completion callee
is independently checked by the preceding handoff inspector. Success preserves
the original pointer/length, failures become the value-free SHA-3 secret-memory
error, and empty output bypasses completion without fabricating ownership.

All 160 descriptor/call/result/branch mutations and eight broken core-handoff
bindings reject. Tests prohibit subprocess execution. Log:
`target/development-v02449/sha3-output-wrap.log`, SHA-256
`17c7988941b6d451f835b2aa886b6f1f8ddebf4da984a9f5a54c666a6651dfb8`.

Source tracing also confirms that portable `sponge.rs::squeeze_secret` and
accelerated `in_place/xof/core.rs::Borrowed::secret` write through initialization
owners and guarded staging. That source review is not new emitted-code
qualification of those producers. Debug completion/wrapping, byte-production
paths, machine-code spills and platform qualification remain separate; F1 is
not closed by this checkpoint. No production or release-gate change.

## Optimized secret-output writes

```sh
python3 assurance/register-cleanup/check_secret_output_write.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_secret_output_write.py target/kmac-verify-1iopq9b5/observations.json
```

All eight optimized `SecretRegionInitialization::write` bodies pass. Their
five-block control flow checks region presence, addition overflow and capacity
before dispatch. The exact original source and length are copied to the original
destination plus its initialized offset; only after that call does the updated
count commit. The direct function body reads descriptor fields, not payload
bytes. Existing copy-boundary assembly inspection passes in all eight builds.
The checker explicitly handles Rust 1.90's overflow intrinsic and Rust 1.98's
add/unsigned-comparison lowering, including their different success discriminants.

Tests reject 144 guard/forwarding/progress LLVM-text mutations and 40 copy-boundary
assembly mutations. They forbid subprocess execution. Log:
`target/development-v02449/secret-output-write.log`, SHA-256
`bd47c7c0fad2a1553656a1de9a5662e2d0cf458e7ab40d62be7c373ec99f3c42`.

This qualifies neither the bytes supplied by the upstream sponge producer nor
all surrounding compiler spills. Debug write paths, producer staging/cleanup,
native platforms and independent retest remain separate obligations. No new
production defect was found and no production or release-gate code changed.

## Portable producer staging loop

```sh
python3 assurance/register-cleanup/check_sha3_staging.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_sha3_staging.py target/kmac-verify-1iopq9b5/observations.json
```

Both 136-byte and 168-byte rate instantiations pass in all eight optimized
configurations: 16 portable `squeeze_secret` loops. The inspected loop passes
the bounded chunk to the actual fill definition, rejects its failure before
writing, and forwards the original initialization owner and its staging slice
to the exact core write symbol. A full 168-byte staging clear is requested
before either branch on the write result. Only the successful branch advances
the remaining count; fill and write errors retain their error results.

All 416 retained-LLVM mutations reject, including moving the clear before the
write, shortening its range, substituting source/owner pointers, removing calls,
and reversing loop/error edges. Tests prohibit subprocess execution. Log:
`target/development-v02449/sha3-staging.log`, SHA-256
`4c62bb0d5b1f90e15387d374cb2a0a5078c2effd6e89e89bc8d9cbf4c11920ab`.

This checks the selected loop blocks, not correctness of `fill_staging` or the
clear callee, the entire producer control flow, debug bodies, accelerated
cleanup guards, compiler spills or native-platform qualification. In particular,
the local clear-after-write check is not proof of cleanup after a fill failure
or unwinding; those paths rely on outer owners/guards. The Arm artifacts are
from QEMU, not native evidence. F1 remains open. Production code, release gates
and the retained runtime record are unchanged; no full sweep was restarted.

## Accelerated producer staging and selected cleanup paths

```sh
python3 assurance/register-cleanup/check_accelerated_staging.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_accelerated_staging.py target/kmac-verify-1iopq9b5/observations.json
```

The four optimized accelerated builds pass (Rust 1.90/1.98, native x86 and
Arm/QEMU). The inspector binds the engine read and initialization write to the
same original staging address and bounded chunk count. Successful writes
immediately request a full 168-byte staging clear. It follows the selected read
and write error/unwind continuations to 24 exits, checking initialization-drop
requests and engine-memory, staging and domain cleanup requests. Normal error
returns retain their error discriminant; recoverable unwinding resumes rather
than becoming success. The actual operation-drop body is checked with both
completion values, and unwind calls must pass the original owner with the
completion flag unset.

All 164 retained-LLVM producer/guard mutations reject, including wrong owners,
wrong widths, skipped initialization destruction, omitted cleanup calls,
inverted result checks, completed-on-unwind guards and cleanup bypasses. Tests
forbid subprocess execution. Log:
`target/development-v02449/accelerated-staging.log`, SHA-256
`99b197011dd39ad7a52b1fc05e6b30036bd96ca00d556d59108b0801f44b366b`.

The path checks start at the instantiated read/write calls, assuming the live
initialization owner required to reach them. They do not establish every
upstream state transition or the producer's entire CFG. A cleanup *request*
does not prove that the callee erases memory. Double-panic aborts, debug bodies,
all compiler spills, native Arm/Windows and broader platform qualification
remain outside this checkpoint. No new runtime vulnerability was established;
no production code, release gate or runtime record changed. F1 remains open.

## Portable fill-loop geometry

```sh
python3 assurance/register-cleanup/check_sha3_fill.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_sha3_fill.py target/kmac-verify-1iopq9b5/observations.json
```

All 16 optimized `fill_staging` bodies pass 42,704 modeled cases across the
two rate instantiations and eight retained builds. A closed LLVM instruction
interpreter compares the emitted loop with an independently written geometry
model: checked request/cursor bounds, exact permutation and scratch-clear
arguments/order, state-to-staging slice ranges, copy failures, cursor commits
and error returns. Its only permitted direct load/store address is the owner's
cursor byte; payload copying remains a borrowed call. A permutation requests
clearing of all three scratch regions before copying output.

The campaign includes every count from 0 through 169 at selected cursor
boundaries, all 256 cursor-byte values at selected lengths (including `u64::MAX`),
and selected first/second-copy failures. It is not the full Cartesian product
or a formal all-input proof. Twelve hand-written model examples and 528 LLVM
address/copy/permutation/clear/control mutations pass/reject as expected. Tests
forbid subprocess execution. Log: `target/development-v02449/sha3-fill.log`,
SHA-256 `8bfac5d98dc7c554966e3d2435f1197053930d926d13f1c7980eba5aed91939c`.

This does not establish the permutation, copy or clear callee's implementation,
debug/accelerated producers, entire caller spill behavior, or native-platform
qualification. Arm evidence remains QEMU execution. No production defect was
found; production, release gates and the retained runtime record are unchanged.
F1 and the independent-retest requirement remain open.

## Accelerated read-loop boundaries

```sh
python3 assurance/register-cleanup/check_accelerated_read.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_accelerated_read.py target/kmac-verify-1iopq9b5/observations.json
```

All four optimized accelerated `Engine::read` bodies pass the loop-boundary
inspection. The destination/length phis start with the original caller slice;
the cursor and rate are read from their actual owner fields. Permutation uses
the same session and lane buffer, and cursor reset follows only its success.
The available rate must be nonzero and not underflow. The copy width is the
minimum of remaining output and available state; checked end arithmetic and
the 200-byte lane bound precede the borrowed equal-length copy. Cursor progress
commits only after successful copying. Copy/permutation errors retain their
failure result and request terminal owner cleanup; the unwind path requests
the same memory cleanup and resumes the original exception.

All 120 retained-LLVM mutations reject, including moved-before-copy cursor
commits, copy-pointer/length substitutions, off-by-one lane bounds, missing
wipes, reversed loop checks and substituted unwind results. Subprocess
execution is forbidden. Log: `target/development-v02449/accelerated-read.log`,
SHA-256 `7cb43861c0349d3717183ac76bc227ca7770e2cb6b709c3047f05703c967e7e7`.

This inspection does not prove the preflight/output-counter calculation,
callee erasure or permutation correctness, debug lowering, the complete
caller spill footprint, or native-platform behavior. These checks reuse
native x86 and Arm/QEMU artifacts, not fresh native Arm/Windows evidence.
Production and release gates are unchanged. F1 remains open pending the
remaining qualification and fresh independent retest.

## Accelerated reader admission and output counter

```sh
python3 assurance/register-cleanup/check_read_counter.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_read_counter.py target/kmac-verify-1iopq9b5/observations.json
```

Four optimized builds pass 1,328 modeled preflight/commit cases. The checker
first reuses the read-loop boundary inspection, then interprets the entry and
counter code. Failed/non-squeezing owners reject before session checks;
otherwise the original session is checked before output-counter admission.
Overflow rejects without committing the counter. Accepted empty output returns
directly, while accepted nonempty output reaches the data loop. On the modeled
successful-loop continuation, the new 128-bit count is encoded into exactly
the original 16-byte little-endian counter field.

Cases include all 128 single-bit counter values, public-length bit/boundary
cases through bit 62, exact-maximum addition, overflow, a mixed-byte value,
terminal flags and revoked-session results. Vector insertion/shuffle/shift
lowering is evaluated rather than checked only for a store's presence. The
model rejects sampled violations of `nuw`, `nsw` and disjoint arithmetic
assumptions. All 116 LLVM mutations reject; two valid post-admission `nuw`
strengthening controls pass. Subprocess execution is forbidden. Log:
`target/development-v02449/read-counter.log`, SHA-256
`53345ca49f76510397855c6b570261ed098e7c958475b44dcf970cc4a8955cfa`.

The byte-processing loop is checked separately, not simulated here: counter
commit evaluation explicitly assumes successful loop completion. Session
internals and a throwing session check are not modeled. This is bounded
artifact analysis, not an all-input formal proof, full LLVM semantics, debug
qualification, whole-call spill erasure or native-platform evidence. Arm
artifacts remain QEMU-based. No production code, release gate or retained
runtime record changed. F1 remains open pending remaining qualification and
fresh independent retest.

## Debug secret-output write helpers

```sh
python3 assurance/register-cleanup/check_debug_output_write.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_debug_output_write.py target/kmac-verify-1iopq9b5/observations.json
```

Eight retained debug builds pass 2,072 modeled cases. Each write entry is bound
to its actual sixteen-function LLVM call closure. The small interpreter follows
the emitted Option, Result, checked-add and mutable-slice helpers rather than
assuming their result from the root function's name. Missing owners, arithmetic
overflow and insufficient capacity reject without changing owner progress.
Successful writes forward the original input and the exact output subrange to
the opaque borrowed-copy boundary, then commit progress once. The original
output pointer and capacity remain unchanged.

The model permits descriptor-local memory accesses but rejects direct accesses
to the symbolic input/output payload allocations. Undefined inactive Option
payload fields may be forwarded without being used for arithmetic, addresses
or decisions. Cases include empty/exact/over-capacity writes, selected size and
overflow boundaries, and deliberately invalid progress metadata. Huge lengths
are symbolic metadata, not allocated or fabricated Rust slices. Five additional
synthetic helper-return failures per build exercise slice rejection and all four
copy-error values; these are model injections, not runtime fault tests.

All 260 retained-LLVM mutations and 40 borrowed-copy assembly mutations reject.
Twenty-four positive controls accept removal of debug declarations or changes
to unused descriptor loads. Subprocess execution is forbidden in the tests.
Log: `target/development-v02449/debug-output-write.log`, SHA-256
`fc8fcddc0ec8152c804f4b75b0359d2502eef9597a00205f8b435e57b234db36`.

The copy operation is an opaque event in the model; its saved assembly is
checked separately by the existing copy-boundary inspector. This is bounded
metadata analysis, not full LLVM/alias/ABI semantics, exhaustive path or input
coverage, source-byte correctness, a whole-call register/spill erasure proof,
or fresh native-platform evidence. Non-null pointer-to-integer conversion is
modeled only for null discrimination, not as a numerical machine address.
Arm artifacts still use QEMU; Windows is not qualified here. No production
code, release gate or retained runtime record changed. F1 remains open pending
remaining qualification and fresh independent retest.

## Debug output completion and recoverable-unwind handoff

```sh
python3 assurance/register-cleanup/check_debug_output_finish.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_debug_output_finish.py target/kmac-verify-1iopq9b5/observations.json
```

Eight retained debug builds pass 560 modeled cases through their nine-function
completion/helper closures, stopping at the volatile-clear boundary. Completed
initialization transfers the original pointer and length into the returned
owner, consumes the initializer's optional borrow, and does not request wiping
the transferred output. Incomplete initialization returns the error and requests
clearing the full original region exactly once. Missing owners reject without a
wipe request. Progress metadata is not modified by completion.

The model also injects failures before the initial descriptor accessor or the
ownership-taking helper executes, and a missing-borrow result from that latter
helper. On the selected recoverable-unwind paths, the actual emitted Drop glue
and destructor forward the original buffer/length to cleanup and resume the
original exception pointer and selector without returning an output descriptor.
Every entry-function block except its unreachable and double-panic-abort blocks
is visited across these cases. This is not every path through every helper.

All 256 retained-LLVM mutations reject, covering omitted destructors, incorrect
wipe ranges, broken ownership transfer, suppressed unwinds, and altered exception
identities. Eight debug-metadata controls pass. The earlier debug-write campaign
still rejects all 260 LLVM and 40 copy-assembly mutations, with 24 positive
controls. Both mutation suites prohibit subprocess execution. Log:
`target/development-v02449/debug-output-finish.log`, SHA-256
`17f994b12f63d72dbc53faf4ffa4c3d3f39d15e67d5f40242eeb5f51d1059256`.

Wiping is an opaque request in this model, not proof of volatile-callee erasure.
Injected exceptions occur before the modeled helpers mutate the live owner;
this does not claim arbitrary mid-helper interruption coverage. Double-panic
abort, full LLVM/ABI semantics, whole-call register/spill cleanup and native
platform qualification remain outside this checkpoint. Arm artifacts use QEMU;
Windows evidence is not supplied here. No production code, release gate or
retained runtime record changed. F1 remains open for the remaining qualification
and fresh independent retest.

## Optimized volatile-clear geometry

```sh
python3 assurance/register-cleanup/check_volatile_clear.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_volatile_clear.py target/kmac-verify-1iopq9b5/observations.json
```

All eight retained optimized `zeroize_region_volatile` bodies pass 2,112 modeled
length cases. The inspector evaluates the actual LLVM loops, including x86's
remainder loop and eight-byte unrolling and Arm's byte loop. Every byte in the
original slice is addressed once, in order, by a volatile zero-byte store before
exactly one sequentially consistent single-thread compiler fence. Empty input
performs no store and still reaches the fence. The closed instruction grammar
does not permit payload loads, extra calls or ordinary nonvolatile stores.

The cases cover every length from 0 through 257, plus 511/512/513 and
1023/1024/1025, using a nonzero, unaligned symbolic base. All emitted blocks are
visited across those cases. Pointer geometry is checked against the original
slice, arithmetic flags are checked for the modeled values, and loop phis use
simultaneous predecessor values. This is bounded interpretation, not a formal
proof for every valid slice length or a complete LLVM semantics implementation.

All 312 retained-LLVM mutations reject, including omitted/nonvolatile/nonzero
stores, repeated or shifted addresses, broken strides/remainders, inverted
branches, and missing, weakened or premature fences. Sixteen harmless SSA-name
and phi-predecessor-order controls pass. Tests forbid subprocess execution. Log:
`target/development-v02449/volatile-clear.log`, SHA-256
`eeff5899bc7c7d67fcccfc27e3c87945b789a1f572755e0dc538ad2f46330715`.

This examines the optimized clearing callee separately from the previous caller
checks. It does not qualify the debug callee, final assembly, interruption/abort
behavior, whole-call register/spill erasure, or native Arm/Windows platforms.
The retained Arm artifacts remain QEMU-based. No production code, release gate
or retained runtime record changed; no production defect was established.
F1 remains open pending remaining qualification and fresh independent retest.

## Debug volatile-clear iterator and store paths

```sh
python3 assurance/register-cleanup/check_debug_volatile_clear.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_debug_volatile_clear.py target/kmac-verify-1iopq9b5/observations.json
```

Eight retained debug builds pass 416 modeled lengths through six-function
clearing/helper closures. The actual emitted iterator construction, iterator
advance, `write_volatile` body and compiler-fence ordering selection are followed.
Every requested byte receives exactly one volatile zero store, after its byte
pointer check, followed by one sequentially consistent single-thread compiler
fence after the entire slice. Empty input skips stores but still reaches the
fence. Ordinary payload loads/stores are prohibited by the model.

The byte-pointer precondition helper is a deliberate model boundary: it receives
the original in-range, non-null byte address and alignment one, and successful
return is assumed. Its assertion/panic implementation is not evaluated. All live
blocks in the clearing, iterator and volatile-write functions are visited across
the cases; only the requested SeqCst path of the ordering helper is required.
Lengths cover 0..33 and selected boundaries around 64, 128, 136, 168, 256 and 512,
with a nonzero, unaligned symbolic base and surrounding allocation space.

All 192 retained-LLVM mutations reject; eight debug-metadata controls pass.
The indexed descriptor-memory implementation matches the existing model for
100 overlapping-store cases. After extending the shared model, the prior write
and finish suites still reject 260 write LLVM mutations, 40 copy-assembly
mutations and 256 finish mutations; their 32 positive controls pass. Tests forbid
subprocess execution. Log: `target/development-v02449/debug-volatile-clear.log`,
SHA-256 `9fe2478036d2e133c1d9ed2a2ac7110e6c22a186375ee12de101f512921b1f78`.

These are bounded artifact/model checks, not newly compiled fault tests, a
complete LLVM/ABI interpretation, an all-length or pointer-precondition proof,
or final machine-code/whole-call register and spill qualification. Arm artifacts
remain QEMU-based; no fresh native Arm/Windows evidence is supplied. No production
code, release gate or retained runtime record changed, and no production defect
was established. F1 remains open for remaining qualification and fresh retest.

## Optimized volatile-clear assembly

```sh
python3 assurance/register-cleanup/check_volatile_clear_assembly.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_volatile_clear_assembly.py target/kmac-verify-1iopq9b5/observations.json
```

Eight retained optimized builds match closed, manually reviewed x86/Arm assembly
contracts, alongside 2,112 modeled length cases through their linked LLVM bodies.
The 156 normalized instructions, labels and annotations describe literal-zero
byte stores and public pointer/length loops, with no payload loads, calls, stack
work or vector operations. Only labels and spacing are normalized; unexpected
instructions reject. The compiler barrier annotation is not a hardware fence;
the linked LLVM inspector separately checks the single-thread SeqCst fence.

All 344 assembly mutations reject; 16 harmless label/spacing controls pass.
Tests prohibit subprocess execution. Log:
`target/development-v02449/volatile-clear-assembly.log`, SHA-256
`4ec423a46bb013ddaf388fd78ac44f35b20bced1f690b08b5aef38e568d7f342`.

This is inspection of retained optimized LLVM and emitted assembly, not newly
executed machine code, a formal compiler-equivalence/all-length proof, or support
for arbitrary compiler output. Debug assembly, whole-call register/spill erasure,
interruption/abort behavior and native Arm/Windows qualification remain outside
this checkpoint. Arm artifacts remain QEMU-based. No production code, release
gate or retained runtime record changed. F1 and root `PENTEST.md` remain open
pending remaining qualification and fresh independent retest.

## Debug clearing entry and byte-write assembly

```sh
python3 assurance/register-cleanup/check_debug_clear_assembly.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_debug_clear_assembly.py target/kmac-verify-1iopq9b5/observations.json
```

All eight retained debug builds pass paired entry/write-helper assembly contracts
and the previously described 416 LLVM length cases. The 416 normalized machine
instructions/labels preserve the iterator's returned destination, pass literal
zero to the write helper, and preserve that byte and address across its pointer
check before the byte store. The entry requests the SeqCst compiler fence after
iteration ends. No payload loads or extra calls are admitted in these two bodies;
their debug stack traffic contains descriptors, the zero write value, public
source-location metadata and ABI frame state, not imported old payload bytes.
This does not erase or qualify pre-existing caller values in saved ABI registers.

Calls bind to exact helper identities from the associated LLVM closure. Only
known debug/unwind directives, block labels, symbol names and whitespace are
normalized. The actual iterator, fence and pointer-precondition machine bodies
are not checked here; the existing LLVM model evaluates iterator/fence behavior
and assumes successful valid-pointer precondition return. This is not a full
assembly interpreter or a formal LLVM-to-machine equivalence proof.

All 1,016 instruction/call/identity mutations and 48 function-extraction mutations
reject, including instructions hidden after debug directives. Forty-four harmless
spacing, label and debug-location controls pass. Tests prohibit subprocess
execution. Log: `target/development-v02449/debug-clear-assembly.log`, SHA-256
`f56a0d4cef39a8f6cffc95648115d769c1bc5237d331d1ad475bc445a0100554`.

No production code, retained runtime evidence or release gate changed. These
retained-artifact checks are not new machine-code execution, arbitrary-compiler
qualification, whole-call register/spill erasure or interruption/abort coverage.
Arm remains QEMU-based; fresh native Arm/Windows qualification and independent
retest remain outstanding. F1 and root `PENTEST.md` remain open.

## Debug clearing iterator and fence assembly

```sh
python3 assurance/register-cleanup/check_debug_clear_helpers.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_debug_clear_helpers.py target/kmac-verify-1iopq9b5/observations.json
```

Eight retained debug builds pass manually reviewed iterator-construction,
iterator-advance and compiler-fence route contracts. Their 740 normalized
instructions/labels/annotations keep iteration descriptor-only: construct the
original start/end pair, compare the current pointer with the end, advance by
one byte and return the original current pointer, or return None at the end.
They do not read the payload. The entry/write assembly checks and existing 416
LLVM length cases are also rerun; those are not additional independent vectors.

The fence check binds the exact dispatch from the caller's checked SeqCst
discriminant (four) through the compiler-barrier annotation and return. On x86
it also binds the unique five-entry relative jump table, including the selected
entry and target labels. Arm's compare/branch dispatch is checked explicitly.
The annotation is not a hardware fence or proof of hardware ordering. The
Relaxed-order panic block is unreachable from this checked input and deliberately
excluded; a positive control confirms that its body is not being claimed as
qualified. Unwind metadata is normalized, not validated as an unwind guarantee.

All 1,480 instruction/branch/annotation mutations, 36 jump-table mutations and
20 table-binding mutations reject. Sixty-four scoped positive controls pass.
The preceding debug entry/write and optimized clearing mutation suites also
still pass (1,064 and 344 rejections, respectively). No subprocess execution is
allowed by these mutation tests. Log:
`target/development-v02449/debug-clear-helpers.log`, SHA-256
`eceaccbb796784acd9f080ce2547ac14bb9c9051d1e7866e79c0b67065d3f37f`.

These checks extend retained debug assembly coverage, not the production erasure
guarantee. The pointer-precondition machine body, panic behavior, formal compiler
equivalence, whole-call register/spill residue and interruption/abort behavior
are not established. Arm artifacts remain QEMU-based; native Arm/Windows and
independent qualification remain outstanding. No production code, release gates
or runtime records changed. F1 and root `PENTEST.md` remain open.

## Debug byte-precondition normal-return LLVM paths

```sh
python3 assurance/register-cleanup/check_debug_byte_precondition.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_debug_byte_precondition.py target/kmac-verify-1iopq9b5/observations.json
```

Eight retained debug builds pass twelve normal-path contracts (216 LLVM
instructions). Rust 1.90 checks alignment inline; Rust 1.98 delegates to a bound
`is_aligned_to` definition, whose normal-return path is included. The actual
caller/write assembly is rechecked to supply alignment one. The prior 416 LLVM
length cases are repeated, not counted as new independent vectors.

These closed contracts corroborate the clearing model's earlier successful
precondition-return assumption: the bit count of alignment one is one, and
`address & (alignment - 1)` is zero independently of the address representation.
The normal path stores descriptors/public diagnostic metadata in local slots,
not payload bytes, and performs no payload loads. No general LLVM interpreter
or new runtime execution is claimed. The existing model remains unchanged.

All 544 normal-path/ABI mutations reject; 24 debug-metadata and excluded-panic
controls pass. Tests prohibit subprocess execution. The previous entry/write and
iterator/fence mutation suites still pass. Log:
`target/development-v02449/debug-byte-precondition.log`, SHA-256
`27dec94d6ded7fad02466fd370aa88beaeb31148ffa1f5d3f15c5f8974a21a76`.

Alignment acceptance is not a null check or allocation-validity check. Live,
exclusive storage remains the caller's Rust-borrow obligation, not something
this predicate proves. Invalid-alignment, panic and unwind paths are deliberately
excluded; mutations of diagnostic panic bodies are accepted as scope controls.
The precondition's own machine-code lowering, whole-call residue and fresh native
Arm/Windows qualification remain outside this checkpoint. Arm artifacts are
QEMU-based. Production, runtime records and release gates are unchanged; F1 and
root `PENTEST.md` remain open pending remaining qualification and independent
retest.

## Byte-precondition normal-return assembly

```sh
python3 assurance/register-cleanup/check_byte_precondition_assembly.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_byte_precondition_assembly.py target/kmac-verify-1iopq9b5/observations.json
```

Eight retained debug builds pass twelve normal-return function contracts,
covering 338 machine instructions and the preceding 216 LLVM instructions.
The caller/write handoff is rechecked to pass alignment one, and the existing
416 modeled length cases are repeated. These are reused checks, not new
independent runtime vectors.

The inspected paths retain the address/alignment arguments, calculate the
alignment predicate and return successfully for alignment one. Rust 1.98's
additional helper is bound by exact identity at both caller and callee. x86's
integer bit-count sequence and Arm's vector bit-count sequence operate on the
public alignment value, not the pointed-to bytes. No checked normal block
loads payload data. Arm's use of vector registers here is therefore not secret
state processing. Stack traffic covers public values, descriptors and ABI frame
state; pre-existing caller register values are not claimed erased.

All 796 instruction/branch/identity mutations and 36 extraction mutations
reject; 48 label/spacing/debug-location/excluded-failure controls pass. The prior
LLVM precondition, entry/write and iterator/fence mutation suites still pass.
Tests prohibit subprocess execution. Log:
`target/development-v02449/byte-precondition-assembly.log`, SHA-256
`a2f6f1524598c1b035c25a084d98e5f55a01b97a08999551a48f6dd900d728ce`.

This completes the bounded saved-debug-clearing normal-path inspection sequence:
entry/write, iterator/fence, and byte-precondition helpers each have linked
LLVM/assembly checks for the retained matrix. It is not a whole-call erasure
proof or a formal proof of compiler equivalence. Invalid-alignment diagnostics,
panic/unwind and interruption paths remain deliberately excluded. Alignment
acceptance does not establish nullness, liveness or exclusivity; those remain
the caller's Rust-borrow obligations. Arm artifacts remain QEMU-based, not fresh
native qualification. Production code, runtime records and release gates are
unchanged. Broader F1 qualification and independent retest remain outstanding;
root `PENTEST.md` stays open.

## Scoped KMAC metadata clearing requests

```sh
python3 assurance/register-cleanup/check_kmac_metadata_clear.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_metadata_clear.py target/kmac-verify-1iopq9b5/observations.json
```

The sixteen retained compiler/target/profile/mode configurations pass checks of
48 metadata wipe/Drop/guard definitions, 96 modeled invocations and sixteen core
clearing-wrapper contracts. The scoped guard dereferences its original borrowed
metadata descriptor; all three cleanup entry points request the complete regions
in order: key classification (1 byte), verification staging (64 bytes), and
comparison difference (1 byte). The retained layout places those at offsets
64, 0 and 65; this is an artifact observation, not a stable Rust layout promise.
Both zero and nonzero modeled owner offsets are checked. Payload loads/stores
outside the opaque clearing call are rejected.

The core LLVM wrapper is separately checked to skip empty slices and forward the
original nonempty pointer and width to the bound volatile-clearing symbol. Its
debug emptiness helper reads only the descriptor length. The compiler-specific
result representation is checked without assuming stable enum layout. Cleanup
callers discard the clearing result; this model does not infer erasure from that
return value. The zeroizer body has the separate bounded checks described above.

All 1,728 region/call/identity/forwarding mutations reject; 112 comment and debug
metadata controls pass. These are LLVM-text mutations, not compiled fault tests.
Tests forbid subprocess execution. Log:
`target/development-v02449/kmac-metadata-clear.log`, SHA-256
`a35d58b07ca5878ffa31f520bc5527dd2a9ea4ddbd4fa5686366fd28046d92fd`.

This closes the scoped LLVM clearing-request/forwarding inspection, not destructor
reachability, machine-level caller residue or whole-call erasure qualification.
No runtime campaign was repeated; production, runtime records and release gates
are unchanged. Arm artifacts remain QEMU-based; fresh native Arm/Windows evidence
and broader F1 qualification/retest remain outstanding. Root `PENTEST.md` remains
open.

## Scoped KMAC metadata cleanup assembly

```sh
python3 assurance/register-cleanup/check_kmac_metadata_assembly.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_metadata_assembly.py target/kmac-verify-1iopq9b5/observations.json
```

All sixteen retained configurations pass 72 function checks covering 956 machine
instructions. These comprise the metadata wipe, metadata Drop, borrowed-guard
Drop and core clearing wrapper, plus the separate debug emptiness helper.
The preceding 96 LLVM cases are repeated, not reported as new runtime vectors.
Exact function identities come from the hash-validated corresponding LLVM and
assembly artifacts; the instruction contracts are explicit reviewed templates.

The normal-return paths preserve the original metadata pointer, request the
complete 1/64/1-byte regions, and retain the guard's descriptor dereference.
Optimized wrappers tail-call the bound core clearer for the final byte; x86's
indirect target is loaded from that exact symbol, not accepted as an arbitrary
function pointer. Core wrappers forward the original pointer/length only when
nonempty. Branches and compiler-private result-byte representations are checked.
Payload bytes are not loaded by these wrappers. Their stack traffic comprises
descriptors, public lengths/results and saved ABI state; saved pre-existing
caller values are not claimed erased.

All 3,088 instruction/callee/identity mutations and 216 function-extraction
mutations reject; 200 spacing/label/debug-location/CFI controls pass. The previous
1,728 LLVM cleanup mutations and 112 controls still pass. These are retained
artifact-text tests, not compiled fault injection; subprocess execution is
forbidden. Log: `target/development-v02449/kmac-metadata-assembly.log`, SHA-256
`0328966fefb35a3bf86783cbdf1a44f42ad198704af1ff3deb43149991b28959`.

This corroborates the cleanup argument handoff in LLVM and machine code. It does
not prove destructor reachability, unwind correctness, arbitrary compiler
equivalence or whole-call residue removal. CFI metadata is explicitly outside
this normal-return inspection. Arm artifacts remain QEMU-based; no new runtime
execution or native Arm/Windows qualification is claimed. Production, retained
runtime records and release gates are unchanged. F1 and root `PENTEST.md` remain
open pending remaining qualification and independent retest.

## Instantiated guard glue and debug verifier cleanup paths

```sh
python3 assurance/register-cleanup/check_kmac_guard_paths.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_guard_paths.py target/kmac-verify-1iopq9b5/observations.json
```

The compiler-generated guard drop glue is distinct from the `Drop` method above.
All sixteen retained LLVM/assembly glue definitions pass, covering 192 machine
instructions and 32 modeled invocations. Debug glue receives the guard descriptor
and forwards to its bound `Drop`; optimized glue receives the promoted metadata
pointer directly and requests the complete ordered 1/64/1-byte regions. Its
nonnull assumption is checked, not treated as a runtime pointer validator. The
corresponding assembly uses the exact previously reviewed forwarding sequences.

All 24 retained debug verifier bodies also pass an explicit control-flow check:
2,718 reachable blocks and 120 selected operation sites. Starting at the unique
guard initialization and at both normal/unwind successors of each selected
operation, every modeled return or resumed unwind has invoked the bound guard
glue with the local cleanup descriptor. The five sites per body are two
comparison accumulations, verdict conversion, full-byte secret reading and
final-partial-byte secret reading. Their callees must have retained definitions.
All branch outcomes are considered; loops converge over block/invocation states.
Initialization must dominate every selected operation and guard invocation;
those sites must also be reachable from the initialized region itself.
Each selected start must retain a reachable return or resume, preventing vacuous
success from an all-abort/all-loop replacement.

Tests reject 376 glue LLVM, 628 glue assembly, 48 extraction and 744 caller-CFG
mutations. Sixty-four comment/label/debug controls pass. Tests prohibit subprocess
execution; these are artifact-text tests, not compiled or executed fault campaigns.
Log: `target/development-v02449/kmac-guard-paths.log`, SHA-256
`452df6fcb5338c79a9bb502402f107d9d90917915d2cf5b785d2fbc79e65e187`.

Invocation does not establish successful cleanup: the CFG follows the glue's
explicit unwind edge too. The known double-panic abort path is excluded, not
treated as a cleanup success. This is not a termination, alias/provenance,
implicit-unwind or whole-verifier machine-code proof. The initialized descriptor's
provenance and optimized verifier caller CFG remain separate qualification work.
No new runtime collection occurred; Arm remains QEMU-based and fresh native
Arm/Windows evidence remains outstanding. Production, runtime records and release
gates are unchanged. F1 and root `PENTEST.md` remain open pending the remaining
qualification and independent retest.

## Optimized verifier cleanup control flow

```sh
python3 assurance/register-cleanup/check_kmac_optimized_cleanup.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_optimized_cleanup.py target/kmac-verify-1iopq9b5/observations.json
```

All 24 optimized verifier bodies in eight retained configurations pass a scoped
LLVM control-flow check: 1,386 reachable blocks, 216 cleanup call sites and 72
comparison sites. The inspected region begins when the metadata pointer is
extracted after `finish`, not at verifier entry. Its descriptor is a bounded
24/32-byte result slot written by the bound finish callee, with metadata at the
observed 16/24-byte field offset. The verdict uses the difference byte at metadata
offset 65. These are retained layouts, not a stable Rust layout promise or proof
of the contents produced by `finish`.

Starting at extraction and at both successors of each comparison, all modeled
normal returns follow the complete ordered 1/64/1-byte clearing requests or a
normally completed bound guard-glue call. Constant-offset aliases must resolve to
the extracted metadata owner. Cleanup progress advances only on normal invoke
edges; an unwind retains an attempt, not an assumed completion. Resumed unwinds
must have attempted cleanup. Inlined sequences and glue are both checked, as are
explicit normal-versus-landingpad edge kinds, callee identities and call ABIs.
No comparison may follow the start of cleanup. Each selected start must have a
reachable return/resume, and comparisons must be dominated by extraction.

All 2,562 region/sequence/control-flow/identity mutations reject; 72 owner-name,
label and comment controls pass. Mutations include skipping actual clearing
calls while preserving their continuations, wrong widths/owners, swapped invoke
edges, partial-cleanup return bypasses, wrong result fields and vacuous loops.
The prior 1,796 guard-glue/debug-CFG mutations and 64 controls still pass.
Subprocess execution is prohibited; these are LLVM-text tests, not new compiled
fault campaigns. Log: `target/development-v02449/kmac-optimized-cleanup.log`, SHA-256
`00c5d2a36ad3bf39bff785cf1620d5000f2e6ef7b05a989ce2201bdea9a95c0b`.

This does not establish successful cleanup after a clearer unwinds. Early exits
before metadata extraction, finish-callee contents, comparison-byte provenance,
implicit unwinds, termination and whole-verifier machine-code spills remain
outside this checkpoint. Known double-panic aborts are excluded, not treated as
successful cleanup. Arm artifacts remain QEMU-based; no new runtime or native
Arm/Windows qualification is claimed. Production, retained runtime records and
release gates are unchanged. F1 and root `PENTEST.md` remain open pending remaining
qualification and independent retest.

## Early verifier rejection and ownership handoff

```sh
python3 assurance/register-cleanup/check_kmac_early_cleanup.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_early_cleanup.py target/kmac-verify-1iopq9b5/observations.json
```

The 24 optimized verifier bodies now also pass a separate check from entry up to
the `finish` handoff: 216 blocks and 96 metadata-cleanup call sites across eight
retained builds. Every modeled early normal return follows the ordered
1/64/1-byte clearing requests against metadata loaded from the original Core
descriptor. The explicit state-destructor unwind path invokes the original
metadata guard before resuming. Cleanup attempts and normal completion remain
distinct; a double-panic abort is excluded rather than called successful cleanup.

The accepted handoff copies the full observed 24/32-byte Core descriptor from
`self` into the bounded local descriptor passed to the bound `finish` callee.
This path must precede metadata cleanup. The small pre-handoff slice rejects
stores, indirect calls and unreviewed side effects. State-destructor calls are
bound to retained SHA-3 definitions, including exact compiler-generated
`void(ptr)` aliases where LLVM merged monomorphizations. Their argument must
refer to the original state field; their internal cleanup behavior is not proved
by this check. Both explicit branch outcomes are explored, and loops, missing
return/resume/handoff paths and wrong metadata provenance reject.

All 2,040 ownership/region/handoff/control-flow mutations and six alias-binding
regressions reject; 72 owner-name, label and comment controls pass. The preceding
2,562 optimized cleanup mutations and 72 controls still pass. Tests forbid
subprocess execution and only mutate retained LLVM text. Log:
`target/development-v02449/kmac-early-cleanup.log`, SHA-256
`419818b217e434772100cde9fa4677a171ce2db059a9997066bd1c22d3f43e76`.

This advances early-rejection coverage, not whole-verifier erasure. The check
stops at the handoff; `finish` error paths and output contents, comparison-byte
provenance, successful cleanup after unwinding, implicit unwinds, termination
and machine-code spills remain separate obligations. It relies on the existing
borrowed-state/metadata separation contract, not a new aliasing proof. Arm
artifacts remain QEMU-based, not native Arm/Windows qualification. No production,
runtime-record or release-gate changes; F1 and root `PENTEST.md` remain open for
remaining qualification and independent retest.

## Finish error and unwind metadata cleanup

```sh
python3 assurance/register-cleanup/check_kmac_finish_cleanup.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_finish_cleanup.py target/kmac-verify-1iopq9b5/observations.json
```

This extends the preceding checkpoint into the actual `finish` callees selected
by the 24 optimized verifiers. The retained matrix covers 72 explicit error-result
roots and 576 invoke unwind edges, including repeated landing-pad destinations
and identified double-panic abort destinations. The selected cleanup regions
contain 480 finish blocks and 144 blocks in the 24 matching Core destructors.

The error-result roots use the observed compiler layouts: an error discriminator
at byte 8 of the 24-byte portable result, or a null reader pointer at byte 0 of
the 32-byte accelerated result. These are artifact-specific layouts, not stable
Rust ABI promises. Every root must be reachable from finish entry. Following
every explicit successor from these roots, normal returns require completion
of the ordered metadata clearing requests; resumed unwinds require an attempt.
The actual Core destructor is inspected too: it reaches metadata clearing after
normal state destruction, and the original guard on the state's unwind edge.
Its name alone is not treated as proof that cleanup occurs.

The checker binds state, framing/packer and metadata destructor identities to the
retained artifacts, verifies original owner pointers and call ABIs, and rejects
wrong normal/unwind edge kinds, unreviewed writes/calls, partial clearing and
loops in the selected cleanup slice. Only identified double-panic aborts are
excluded. A direct abort destination is reported as an exclusion, not as a
successful cleanup or resumed unwind.

All 3,816 finish-path and 1,320 Core-destructor mutations reject, with 96 label
and comment controls passing. The preceding 2,040 early-path mutations, six alias
regressions and 72 controls remain green. These are retained LLVM-text tests;
subprocess execution is forbidden. Log:
`target/development-v02449/kmac-finish-cleanup.log`, SHA-256
`7175ab817eed4bdeff1c393a8f7eb527867599b860f07468971106baa542a0c4`.

This checks cleanup after the explicit error-result stores and on explicit
invoke unwinds. It does not prove error classification before those stores,
success-result metadata transfer, comparison-byte provenance, state/framing
callee internals, successful cleanup after a clearer unwinds, implicit unwinds,
termination, or machine-code register/spill clearing. Existing borrowed-owner
separation remains an assumption, not a new alias proof. Arm remains QEMU-based;
fresh native Arm/Windows qualification and independent retest remain outstanding.
Production, retained runtime records and release gates are unchanged. F1 and
root `PENTEST.md` remain open.

## Successful metadata transfer into verification

```sh
python3 assurance/register-cleanup/check_kmac_metadata_transfer.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_metadata_transfer.py target/kmac-verify-1iopq9b5/observations.json
```

All 24 retained optimized finish/verifier pairs pass a linked metadata-transfer
check: 84 success-result field stores and 48 matching discriminator decisions.
The callee stores the metadata pointer loaded from its original Core into the
last pointer field of the observed 24/32-byte result. The caller passes a bounded
matching result slot, tests that slot's returned discriminator and extracts its
matching metadata field. The prior verifier inventory links that extracted owner
to the difference byte at metadata offset 65.

The success branch must be the non-error edge of the actual tested discriminator;
the opposite callee edge writes a recognized error result. The value written into
the success result must be the value tested. Result fields have the reviewed
nonoverlapping layouts, with one metadata store and no overlapping later stores.
The callee's small transfer/state-drop/return diamond permits no further output
writes or unreviewed calls. On the caller side, the interval from finish return
through metadata extraction rejects writes, unreviewed calls and premature result
lifetime end. The accelerated reader's 15-byte descriptor copy is allowed only
from result offset 9 into a distinct bounded local allocation, not back into the
result or across its metadata field.

All 996 callee and 504 caller mutations reject; 144 owner-name, label and comment
controls pass. Mutations cover wrong owners/fields, overlapping stores, mismatched
discriminators, inverted branches, altered extraction, result clobbering and wrong
callee bindings. The previous 3,816 finish-path and 1,320 Core-destructor mutations
and 96 controls remain green. Subprocess execution is forbidden; no new runtime
or compilation campaign occurred. Log:
`target/development-v02449/kmac-metadata-transfer.log`, SHA-256
`c2bcfda48ee9e22d278a8b414094e1b717c7705a822b815fed1acfd7507cd30a`.

This is a bounded metadata descriptor handoff, not a proof of the reader fields'
contents, earlier opaque-callee/alias effects, comparison-byte provenance,
implicit unwinds or machine register/spill clearing. Compiler-private layouts
are not stable Rust ABI promises. Arm artifacts remain QEMU-based; native
Arm/Windows qualification and independent retest remain outstanding. Production,
runtime records and release gates are unchanged. F1 and root `PENTEST.md` remain
open pending remaining qualification and retest.

## Optimized comparison operand routing

```sh
python3 assurance/register-cleanup/check_kmac_operand_routes.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_operand_routes.py target/kmac-verify-1iopq9b5/observations.json
```

All 24 retained optimized verifiers pass: 48 accumulation sites, 48 bound reader
producers and 744 selected SSA definitions. Bulk actual/candidate pointers use
the same byte index, starting at zero with unit feedback. Candidate chunk pointers
start at the input descriptor and advance by the requested squeeze width, bounded
by the observed `umin(remaining, 64)` expression. The final candidate pointer is
the input pointer plus its byte length minus one. Actual pointers come from the
separate bulk/final secret-output descriptors, while the difference pointer uses
metadata offset 65 (directly, or through Rust 1.90's one-byte loop).

The checker follows both pieces of each returned pointer field: the separately
loaded/stored first byte and the remaining bytes within a 15-byte descriptor copy.
Arm's additional 15-byte staging allocation is matched to its source copy. Each
result is tied to a reader invocation that receives the extracted metadata buffer
and the matching bulk width or single final byte. Selected SHAKE/cSHAKE LLVM
aliases must name a defined target with the reviewed family mapping and argument
layout; accelerated readers share the rate-carrying implementation.

All 1,752 LLVM mutations and 18 alias regressions reject; 72 owner-name, label and
comment controls pass. These include swapped/self-comparison operands, wrong
offsets, loop steps and widths, partial/duplicate descriptor copies, missing
pointer bytes and wrong reader buffers. The preceding 996 callee and 504 caller
metadata-transfer mutations and 144 controls also pass. Log:
`target/development-v02449/kmac-operand-routes.log`, SHA-256
`27d98d1a185e21d3feb0635c5311128edda3d4bcc75d8b2c80078fdf1688a615`.

This is selected routing under the reader-result contracts, not a complete
control-flow/dominance, bounds, initial remaining-length, final-bit mask or
intervening alias-effects proof. It does not establish callee output contents,
all memory writes, machine spills or whole-call erasure. Text mutations do not
execute modified cryptographic binaries. No compiler/runtime campaign was rerun;
the tests forbid subprocess execution. Production and release gates are unchanged.
Arm remains QEMU-based; fresh native Arm/Windows qualification and independent
retest remain outstanding. F1 and root `PENTEST.md` remain open.

## Candidate length and partial-byte routing

```sh
python3 assurance/register-cleanup/check_kmac_candidate_shape.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_candidate_shape.py target/kmac-verify-1iopq9b5/observations.json
```

All 24 optimized verifiers pass a follow-up check of 168 additional SSA
definitions and 144 selected blocks. The initial remaining length is now bound
to the candidate descriptor: byte-aligned inputs use the full byte length;
partial-byte inputs use length minus one, with the zero-length branch unable to
reach a reader or comparison. The split phi accounts for every incoming edge,
including both aligned switch cases. An empty split skips the bulk loop; the
bulk loop's remaining-count check feeds the same final-byte decision.

Both alignment switches use the candidate's valid-bit field, and that same value
is passed to the final secret reader. The aligned cases go directly to the
difference predicate. The final reader is reachable from the partial-byte edge
and cannot be reached from function entry with that edge removed.

All 1,056 candidate-shape LLVM mutations reject, with 72 valid-bit-name, label
and comment controls passing. The preceding 1,752 operand-routing mutations,
18 alias regressions and 72 controls also pass. Log:
`target/development-v02449/kmac-candidate-shape.log`, SHA-256
`ab1000035b27800feb16ef74cf39377af129ef6ce1eae3cb52cd8b89e019949a`.

This checks selected descriptor-field and control-flow relationships; it does not
prove descriptor construction, the reader's masking/output semantics, every
loop iteration, intervening memory writes or register/spill erasure. The retained
artifacts and their compiler/source bindings are reused; tests forbid subprocess
execution. No production or release-gate changes. Native Arm/Windows qualification
and independent retest remain outstanding; F1 and root `PENTEST.md` remain open.

## Bulk comparison loop geometry

```sh
python3 assurance/register-cleanup/check_kmac_compare_loop.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_compare_loop.py target/kmac-verify-1iopq9b5/observations.json
```

All 24 optimized verifiers pass checks of 156 additional SSA definitions and 96
selected blocks. The comparison bound is the unsigned minimum of the requested
chunk width and the length loaded from the actual secret-output descriptor.
The index starts at zero, advances by one and repeats until that bound is reached.
The checker follows LLVM 20's nested one-byte difference loop and LLVM 22's direct
accumulation-to-latch edge. Null/empty output guards must use the same pointer and
length as the comparison and guard entry into the loop. Their rejection paths
cannot reach the current chunk's comparison before another reader invocation.

All 756 LLVM mutations reject; 72 internal-SSA-name, label and comment controls
pass. They cover wrong descriptor fields, minimum-to-maximum changes, unrelated
lengths, inverted guards and bypassed index advancement. The preceding 1,056
candidate-shape mutations and 72 controls also pass. Log:
`target/development-v02449/kmac-compare-loop.log`, SHA-256
`6862b1e9eb6bdfc64aeb1fc380b2b1e0e4fe2684526d2c449a4fd746fdc77c12`.

This is selected loop geometry, not proof that a reader returns the complete
requested length or correct bytes, or proof of all result-discriminator/alias
effects. Those remain separate callee contracts. No whole-call register/spill
erasure or native Arm/Windows qualification follows. These retained-text tests
forbid subprocess execution; no production, runtime-record or release-gate
changes were made. F1 remains open for remaining qualification and retest.

## Reader-result and output-ownership decisions

```sh
python3 assurance/register-cleanup/check_kmac_reader_results.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_reader_results.py target/kmac-verify-1iopq9b5/observations.json
```

All 24 optimized verifiers pass checks of 48 result/ownership decisions and 144
additional SSA definitions. Each decision loads the discriminator from the
24-byte result slot passed to its actual reader invocation. The normal-return
decision block permits only the reviewed loads, field addressing and comparisons;
it cannot call another function or overwrite the result before the decision.
The observed error discriminator takes a path that cannot reach a reader,
accumulation or verdict predicate. The non-error edge uniquely enters output
construction and dominates the corresponding comparison.

The output descriptor receives that same discriminator. Its owned-payload bit
controls the actual pointer-load block; a rejected payload cannot reach the
current comparison before another reader invocation. These are observations of
the retained compiler-private enum layouts, not stable Rust ABI promises.

All 1,152 LLVM mutations reject; 72 internal-SSA-name, label and comment controls
pass. The preceding 756 comparison-loop mutations and 72 controls also pass. Log:
`target/development-v02449/kmac-reader-results.log`, SHA-256
`664a936baa6187ffea5feb4b2b11d5d4d37da869b5c5d18b48210ca52199c4e5`.

This closes the selected caller result/ownership routing check, not proof of
callee result semantics, the exact returned bytes/length, every alias/write
effect, the final returned error encoding or machine register/spill erasure.
No compiler/runtime campaign was rerun; tests forbid subprocess execution.
Production, retained runtime records and release gates are unchanged. Native
Arm/Windows qualification and independent retest remain outstanding; F1 and
root `PENTEST.md` remain open.

## Portable final-reader result handoff

```sh
python3 assurance/register-cleanup/check_kmac_final_adapter.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_final_adapter.py target/kmac-verify-1iopq9b5/observations.json
```

All 16 portable final-reader adapters actually called by the retained optimized
verifiers pass checks of 48 selected blocks. The reader receives the original
state and lifecycle flag; its distinct 24-byte result slot supplies the error
discriminator. Only the non-error edge may copy the complete result into the
adapter's caller-owned return slot. The error path cannot reach that copy or
reenter the reader. After the copy, only the reviewed local lifetime ends and
return are permitted. Selected cSHAKE final-reader aliases must bind to a defined
SHAKE reader of the matching strength and reviewed result ABI.

All 432 LLVM mutations and six alias regressions reject; 48 SSA-name, label and
comment controls pass. The preceding 1,152 reader-result mutations and 72 controls
also pass, as do the SHA-3 wrapper's 160 mutations and eight core-binding
regressions. Log: `target/development-v02449/kmac-final-adapter.log`, SHA-256
`77e5eb23319661fcf6633b7a6d4be6e00eaf21686a282f132d38ea84cf841092`.

The accelerated verifier invokes its final reader directly; unused portable
adapter code is not counted as accelerated coverage. This checks successful
descriptor handoff, not output-constructor or reader semantics, exact returned
bytes/length, all error cleanup/encoding, alias effects or register/spill erasure.
These are retained compiler-private layouts, not stable ABI guarantees. Tests
forbid subprocess execution; production, runtime records and release gates are
unchanged. F1 and root `PENTEST.md` remain open for remaining qualification and
independent retest, including fresh native Arm/Windows evidence.

## Portable final-reader input forwarding

```sh
python3 assurance/register-cleanup/check_kmac_final_input.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_final_input.py target/kmac-verify-1iopq9b5/observations.json
```

All 16 retained optimized portable adapters pass checks binding their constructor
call to the defined SHA-3 `Fips202Output::new` symbol and result ABI. The original
destination pointer, length and valid-bit count are forwarded unchanged. The
constructor result is tested before reader entry; the rejected-result edge
cannot reach the reader or reenter the constructor. Only local allocations and
lifetime markers may precede construction.

A bounded opaque-byte provenance model follows all 32 descriptor bytes through
the selected success path. Both scalar stores and the 24 total tail copies
(including Arm's intermediate staging) must preserve their original positions.
The model rejects unknown calls, overlapping or missing writes, out-of-bounds
accesses and reads after a local lifetime ends. The actual reader argument must
be the complete forwarded descriptor, not the constructor's expired result slot.

All 640 LLVM mutations and six constructor-binding regressions reject; 48
SSA-name, label and comment controls pass. The previous result-handoff tests
also pass: 432 mutations, six alias regressions and 48 controls. Log:
`target/development-v02449/kmac-final-input.log`, SHA-256
`b69c98db4949e2c4219f4dc53d8cf7550e86f97fb8cd2040f2f90d00743a5ce9`.

Opaque byte provenance is not a claim that padding is initialized, nor a proof
of constructor validity arithmetic, reader semantics, all error/unwind cleanup
or register/spill erasure. Compiler-private layouts are not stable ABI promises.
Accelerated readers are not counted as portable adapter coverage. Tests forbid
subprocess execution; production, retained runtime records and release gates
are unchanged. F1 and root `PENTEST.md` remain open for remaining qualification
and independent retest; Arm execution remains QEMU, not fresh native evidence.

## Output constructor shape and length boundaries

```sh
python3 assurance/register-cleanup/check_fips202_output_constructor.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_fips202_output_constructor.py target/kmac-verify-1iopq9b5/observations.json
```

The constructor is selected from the same validated SHA-3 artifacts and bound
to the actual portable KMAC adapter calls. All eight optimized bodies pass a
bounded LLVM metadata model: 20,480 cases cover all 256 final-bit-count values at
ten lengths (0, 1, 2, 63, 64, 65, 2^61-1, 2^61, 2^61+1 and 2^63-1).
These are abstract lengths, not allocated slices or executed Rust calls.
Every retained constructor block is exercised (64 across the eight bodies).

The mathematical comparison checks empty/nonempty shape validation, exact
`(length - 1) * 8 + valid` length, overflow rejection, error identity and the
original output pointer/length/valid fields. The closed instruction model
rejects payload reads/writes and unexpected calls; only bounded nonoverlapping
result fields may be written. LLVM 20's speculative `nuw` sum may become poison
on an error path, but selected phi/store operands cannot consume that poison.
LLVM 22's different overflow sequence is checked against the same result model.

All 400 arithmetic, result, poison-use and payload-access mutations reject;
24 SSA-name, label and comment controls pass. The preceding input-forwarding
tests also pass (640 mutations, six binding regressions and 48 controls). Log:
`target/development-v02449/fips202-output-constructor.log`, SHA-256
`363c1c6989cba2b684ddc23856983f521c00f33b523631392bd5b61e25e20d1b`.

This is bounded metadata-model coverage, not exhaustive verification of every
length, a general LLVM interpreter, padding initialization, reader semantics,
machine-code qualification or register/spill erasure. Compiler-private result
layouts remain nonportable evidence details. Tests forbid subprocess execution;
production, runtime records and release gates are unchanged. F1 and root
`PENTEST.md` remain open for remaining qualification and independent retest;
fresh native Arm/Windows evidence is still outstanding.

## Consuming portable final-reader cleanup requests

```sh
python3 assurance/register-cleanup/check_sha3_final_reader.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_sha3_final_reader.py target/kmac-verify-1iopq9b5/observations.json
```

All 16 portable reader bodies reached by the inspected KMAC adapters (including
validated cSHAKE-to-SHAKE aliases) pass checks of all 80 blocks. The original
owner and lifecycle flag initialize a bounded local borrowed handle. The
original destination pointer, length and valid-bit field reach a defined
`Borrowed::secret` with final-bit mode enabled and the original return slot.
The callee's calling convention, argument count and types are bound to its
retained definition.

Both normal and unwind paths reload the owner pointer from the borrowed handle
and request the same bound owner wipe: 32 request sites across the matrix.
Normal return follows the wipe call. Recoverable unwind resumes the original
exception after cleanup returns; cleanup failure enters only the identified
double-panic abort path. No additional work or result writes are allowed in
these closed exit blocks.

All 560 LLVM mutations and 48 callee-binding regressions reject; 48 SSA-name,
label and comment controls pass. The preceding final-input and constructor
tests remain green (640 and 400 mutations respectively). Log:
`target/development-v02449/sha3-final-reader.log`, SHA-256
`1e91ba9d95669507cbd2d8c1d64c8e90e21848212fffa5df43cca9109437be30`.

This establishes forwarding and cleanup requests, not that the borrowed callee
preserves the handle's owner field or that the wipe callee clears its regions.
Those callee effects remain separate obligations, as do output semantics,
machine-code spills and register erasure. Abort and double-panic cleanup are
not claimed. Tests forbid subprocess execution; production, retained runtime
records and release gates are unchanged. F1 and root `PENTEST.md` remain open
for remaining qualification and independent retest, including fresh native
Arm/Windows evidence.

## Borrowed-reader destination initialization ordering

```sh
python3 assurance/register-cleanup/check_sha3_reader_initialization.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_sha3_reader_initialization.py target/kmac-verify-1iopq9b5/observations.json
```

All 16 portable borrowed readers selected through the actual final-reader calls
bind to a verified core initializer. Its retained definition, volatile loop and
assembly are checked by the secret-output initialization boundary checker. Reused
initializer symbols must have identical definitions across the retained records.

Reader entry permits only bounded local metadata preparation before testing the
original destination length. Nonempty destinations must immediately pass their
original pointer/full length to the initializer, before lifecycle reads or
squeeze work. The initializer's actual result controls the next branch. Failure
sets the reader inactive, requests a bound wipe of the original owner and returns
a value-free `SecretMemory` error without entering the normal operation. The
empty-destination path requires no output-region clearing.

All 592 LLVM mutations and 32 missing initializer/wipe bindings reject; 48
naming/comment controls pass. Existing initializer tests reject 280 mutations
and eight wrong-callee bindings; handle-preservation tests reject 576 mutations
(64 controls). Log: `target/development-v02449/sha3-reader-initialization.log`,
SHA-256 `b98816bc22c279bf0f33adef4b8c8187ba9c13ddad74ba6ff1ffece73f083edc`.

This connects the entry ordering to the verified initializer. Subsequent
initialization-handle transfer/drop, squeeze semantics, unwind destination
cleanup and whole-call register/spill erasure remain separate obligations.
Arm remains QEMU evidence. Tests forbid subprocess execution; no production,
retained runtime-record or release-gate changes. F1 and root `PENTEST.md` remain
open for remaining qualification and independent retest, including fresh native
Arm/Windows evidence.

## Borrowed reader owner-pointer preservation

```sh
python3 assurance/register-cleanup/check_sha3_borrowed_handle.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_sha3_borrowed_handle.py target/kmac-verify-1iopq9b5/observations.json
```

All 16 borrowed secret bodies selected through the inspected portable final
readers pass a handle-use scan over all 504 blocks and 128 field/address uses.
The exclusive 16-byte handle parameter and every constant-offset derivative
are tracked. Allowed uses are owner-pointer loads at offset zero, lifecycle
byte loads/stores at offset eight, and constant addressing of those fields.
The owner-pointer bytes cannot be overwritten. Handle addresses cannot be
stored elsewhere, passed to callees, converted to integers or hidden behind
unreviewed pointer transformations. Unknown handle uses reject.

This closes the preceding final-reader checkpoint's local handle-preservation
obligation under the valid exclusive-reference contracts: the outer destructor
reloads the owner pointer that it originally stored. It does not inspect what
the owner wipe or squeeze callees do to their own storage.

All 576 overwrite/escape/field mutations reject; 64 SSA-name, label, comment and
benign zero-offset alias controls pass. The preceding final-reader tests also
pass (560 mutations, 48 binding regressions and 48 controls). Log:
`target/development-v02449/sha3-borrowed-handle.log`, SHA-256
`8f149ae5027934d5368c0060f49cf93a7dd5f177b7d08e246dd3713e06409a15`.

This is local pointer preservation, not proof against invalid external aliases,
arbitrary memory corruption, wipe/squeeze semantics, compiler spills or register
erasure. Tests forbid subprocess execution; production, retained runtime records
and release gates are unchanged. F1 and root `PENTEST.md` remain open for the
remaining qualification and independent retest, including native Arm/Windows
evidence.

## Final-reader owner wipe and core clearing

```sh
python3 assurance/register-cleanup/check_sha3_owner_wipe.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_sha3_owner_wipe.py target/kmac-verify-1iopq9b5/observations.json
```

The actual owner wipe selected by each of the 16 portable final-reader bindings
passes a straight-line region check. Its thirteen clearing calls cover exactly
1,040 bytes, without overlaps or gaps, in the retained compiler layout. The
regions correspond to lanes, partial input, message/output/cSHAKE lengths,
domain/phase/suffix metadata, padding/squeeze staging and permutation scratch.
The reader bindings may share a compiler-merged wipe; sixteen bindings do not
mean sixteen distinct implementations.

Each call is bound to the recorded core `clear_owned_region` definition. The
existing wrapper checker verifies unchanged pointer/length forwarding to the
actual volatile callee. The existing volatile-loop model is then executed for
all seven field widths (1, 3, 4, 16, 40, 168 and 200), covering every retained
loop block, and the matching core assembly must satisfy its existing closed
zero-store contract. No new LLVM interpreter or assembly validator was added.

All 1,552 region regressions and 144 composed core/assembly regressions reject;
32 naming/comment controls pass. The preceding handle-preservation and
final-reader tests also pass (576 and 560 mutations respectively). Log:
`target/development-v02449/sha3-owner-wipe.log`, SHA-256
`c44c7675f6eea48be8df17b3ad6075cb662c58525a0dd77fae60cf0cc429185e`.

This closes the selected portable final reader's owned-storage wipe-coverage
obligation on normal cleanup completion, using retained source-bound compiler
evidence. It is not a stable Rust layout guarantee, new native execution,
asynchronous/abort cleanup, squeeze correctness or whole-call register/spill
erasure. Tests forbid subprocess execution; production, runtime records and
release gates are unchanged. F1 and root `PENTEST.md` remain open for remaining
qualification and independent retest, including fresh native Arm/Windows evidence.

## Final-adapter constructor rejection and unwind

```sh
python3 assurance/register-cleanup/check_kmac_final_rejection.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_final_rejection.py target/kmac-verify-1iopq9b5/observations.json
```

All 16 portable final adapters pass checks of 64 selected rejection/cleanup
blocks. Constructor rejection writes an error-shaped result and wipes the
original owner before returning. Recoverable constructor unwind requests the
same wipe, then resumes the original exception. The double-panic termination
path is identified, not treated as successful cleanup.

The 32 wipe call sites are bound to actual source-bound definitions, including
compiler aliases. Each selected wipe is checked with the preceding thirteen-
region, 1,040-byte coverage model, core forwarding, volatile-loop and matching
assembly checks. Internal error codes 6/18 and discriminator 2 describe these
retained compiler layouts only; they are not stable Rust ABI guarantees.

All 384 LLVM mutations and 16 missing-wipe binding regressions reject; 48
naming/comment controls pass. The owner-wipe suite (1,552 region and 144 composed
core/assembly regressions) and final-input suite (640 mutations and six binding
regressions) also pass. Log:
`target/development-v02449/kmac-final-rejection.log`, SHA-256
`97aa986142a1a2b76f5dfb93a18176ade00be5ec8916cb3b6c245a83cf895866`.

This covers constructor rejection and recoverable unwind, not downstream reader
error conversion, caller destination clearing, abort/double-panic cleanup or
whole-call register/spill erasure. Tests forbid subprocess execution; no
production, retained runtime-record or release-gate changes. F1 and root
`PENTEST.md` remain open for remaining qualification and independent retest,
including fresh native Arm/Windows evidence.

## Final-adapter downstream reader-error conversion

```sh
python3 assurance/register-cleanup/check_kmac_final_error.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_kmac_final_error.py target/kmac-verify-1iopq9b5/observations.json
```

All 16 portable final adapters preserve the failed reader's error descriptor
through the downstream conversion block. The check binds the loaded error byte
to that reader's result slot, checks all five entries of the retained packed
mapping, and requires the mapped byte and error discriminator to be stored only
in the caller's result descriptor before reaching the checked return block.
No payload access, additional callee or success-descriptor copy is permitted in
this branch. This composes with the preceding reader-result decision check.

The five retained SHA-3 error values map to KMAC bytes `(0, 3, 4, 4, 5)` in the
portable-only build and `(12, 15, 16, 16, 17)` with acceleration features. These
are reviewed compiler-private layouts, not stable enum discriminants or an ABI
promise. The 80 valid-value checks cover the shift-width/flag premises; invalid
Rust enum representations are outside this contract.

All 512 LLVM mutations and 32 unknown/mismatched feature-layout tests reject;
48 naming/comment controls pass. Prior adapter tests (432 mutations and six
alias regressions) and constructor-rejection tests (384 mutations and sixteen
wipe-binding regressions) remain green. Log:
`target/development-v02449/kmac-final-error.log`, SHA-256
`f033cdb024345f10b9721d649b462a73da54af3b08157666a519aef155ca00c2`.

This closes the local downstream error-conversion check, not reader correctness,
caller destination clearing or whole-call register/spill erasure. Tests forbid
subprocess execution; production, retained runtime records and release gates
are unchanged. F1 and root `PENTEST.md` remain open for remaining qualification
and independent retest, including fresh native Arm/Windows evidence.

## Secret-output initialization boundary

```sh
python3 assurance/register-cleanup/check_secret_output_begin.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_secret_output_begin.py target/kmac-verify-1iopq9b5/observations.json
```

All eight optimized core initialization bodies pass inspection of all 32 blocks.
Only an empty original destination skips the volatile clearing call, returning
the retained empty-region error. For nonempty regions, the actual defined
volatile callee receives the original pointer and full length before the result
descriptor stores that pointer/length and a zero initialized-byte count. The
shared return selects success only from the nonempty branch. No additional
payload access, copy or callee is allowed in this boundary.

The same record's volatile LLVM body is checked with the existing 264-length
bounded model, and its exact emitted symbol is checked against the existing
x86/Arm assembly contract. This reuses the established clearing checks; it does
not introduce an all-length proof or new native execution.

All 280 initialization LLVM mutations and eight wrong-callee bindings reject;
24 naming/comment controls pass. Existing output-completion tests reject 160
regressions and volatile-clearing tests reject 312 regressions (16 controls).
Log: `target/development-v02449/secret-output-begin.log`, SHA-256
`b177409b7d453362b6de94c4656fd522537f60c703a8966a074509d058de81bd`.

This checks the initialization callee, not the caller's ordering or subsequent
write/drop behavior, abort cleanup or whole-call register/spill erasure. Arm
remains QEMU evidence. Tests forbid subprocess execution; production, retained
runtime records and release gates are unchanged. F1 and root `PENTEST.md` remain
open for remaining qualification and independent retest, including fresh native
Arm/Windows evidence.

## Secret initialization destructor boundary

```sh
python3 assurance/register-cleanup/check_secret_output_drop.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_secret_output_drop.py target/kmac-verify-1iopq9b5/observations.json
```

All eight optimized initialization destructor bodies pass inspection of all 24
blocks. Only absent ownership skips cleanup. A present region forwards its
original stored pointer and complete region length to the defined volatile
callee, then returns. The initialized-prefix field is never substituted for the
full region length. No payload reads, extra calls or descriptor writes are
allowed in this destructor boundary.

The actual destructor symbol is referenced by both portable borrowed-reader
strengths in each matching SHA-3 artifact. Its volatile callee is checked with
the existing bounded LLVM model and the matching assembly contract. Symbol
references alone do not prove that every caller path invokes Drop correctly or
that the transferred descriptor is unchanged; those remain caller obligations.

All 184 LLVM mutations and eight wrong-callee bindings reject; 24 naming/comment
controls pass. The initializer suite (280 mutations and eight binding failures)
and completion suite (160 regressions) remain green. Log:
`target/development-v02449/secret-output-drop.log`, SHA-256
`9454a51bd9b6a1e27f34232afd5114e6589678eba29e55d01d0b9b7618d93669`.

This checks normal destructor completion, not caller transfer/drop coverage,
abort-time cleanup or whole-call register/spill erasure. Arm remains QEMU
evidence. Tests forbid subprocess execution; no production, retained runtime-
record or release-gate changes. F1 and root `PENTEST.md` remain open for remaining
qualification and independent retest, including fresh native Arm/Windows evidence.

## Terminal-reader output ownership and cleanup

```sh
python3 assurance/register-cleanup/check_sha3_terminal_output.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_sha3_terminal_output.py target/kmac-verify-1iopq9b5/observations.json
```

All 16 selected portable borrowed readers preserve the complete 24-byte
initialization descriptor through its one-byte load and two 23-byte tail copies.
Source lifetimes, local bounds, ownership discriminators and predecessor edges
are checked. Empty destinations carry absent ownership; descriptor padding is
treated as opaque and is not claimed initialized.

On the terminal-reader branch, the checked lifecycle decision produces only
`StateConsumed`. Nonempty output must call the verified initialization destructor
with the reconstructed original descriptor, then end local lifetimes and return.
Only the original empty-destination condition permits skipping Drop. Together
with the initializer and destructor checks, this binds terminal-state output
cleanup to the original full destination rather than merely a named call.

All 912 LLVM mutations and 16 missing-destructor bindings reject; 48 naming/
comment controls pass. The reader-initialization suite (592 mutations, 32 binding
regressions) and destructor suite (184 mutations, eight bindings) remain green.
Log: `target/development-v02449/sha3-terminal-output.log`, SHA-256
`e2ed0886a45ccc03ad5e9e4d568eb25b16794d78a6b90f7ff9b030ccbf6f54c6`.

This closes the local terminal-state transfer/drop path, not active squeezing,
recoverable-unwind destination cleanup, abort cleanup or whole-call register/
spill erasure. Arm remains QEMU evidence. Tests forbid subprocess execution;
production, retained runtime records and release gates are unchanged. F1 and
root `PENTEST.md` remain open for remaining qualification and independent retest,
including fresh native Arm/Windows evidence.

## Squeeze error identity and normal cleanup

```sh
python3 assurance/register-cleanup/check_sha3_squeeze_error.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_sha3_squeeze_error.py target/kmac-verify-1iopq9b5/observations.json
```

All 16 selected portable readers pass 32 bulk/final result decisions and their
normal error continuations. The actual source-bound squeeze signatures select
the two reviewed compiler-private result layouts; these are not stable Rust ABI
promises. Only the successful result enters output completion. Both error phi
inputs retain the actual callee result, and all five valid errors retain their
identity through either the direct-byte or pointer-encoded return layout.

Present output ownership invokes the verified destructor on the original
initialization handle before wiping the original borrowed owner. Absent
ownership alone skips destination Drop. A destructor unwind enters the already
checked exceptional owner-cleanup path. Normal cleanup ends the local descriptor
lifetimes and returns an error without reactivating the reader or retrying
successful work. Closed blocks reject extra payload writes or unreviewed calls.

All 1,032 LLVM mutations and 96 missing/incompatible signature bindings reject;
48 naming/comment controls pass. The adjacent unwind suite remains green
(656 mutations, 32 cleanup bindings, 48 controls). Log:
`target/development-v02449/sha3-squeeze-error.log`, SHA-256
`c857a817030461f5ec39dbfaa528e8960bc7efa8dbc43053d341c61b180a3a52`.

This qualifies caller error routing under the retained result and ownership
contracts. Squeeze-callee semantics/descriptor preservation, successful output
completion and whole-call register/spill erasure remain separate obligations.
Arm remains QEMU evidence. Tests forbid subprocess execution; no production,
runtime-capture or release-gate changes. F1 and root `PENTEST.md` remain open
until remaining qualification and independent retest, including fresh native
Arm/Windows evidence, are complete.

## Active-reader descriptor transfer and squeeze arguments

```sh
python3 assurance/register-cleanup/check_sha3_active_output.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_sha3_active_output.py target/kmac-verify-1iopq9b5/observations.json
```

All 16 selected portable borrowed readers preserve the complete 48-byte
operation descriptor at the active-reader handoff. The reader is made inactive
before this transfer. The original initialized-output descriptor and references
to original public length/final-bit metadata reach the bulk/final decision;
only present output ownership takes the squeeze path.

The 32 actual bulk/final squeeze invocations bind to defined portable sponge
functions and pass the original borrowed owner, initialization handle, length
and (where applicable) final-bit count. Their setup blocks reject intervening
payload writes and extra work. Predecessor checks prevent alternate entries
from bypassing the inspected handoff. Both invocations retain a shared unwind
edge, whose cleanup behavior is a separate obligation.

All 864 LLVM mutations and 32 missing-squeeze-definition bindings reject;
48 naming/comment controls pass. The terminal-output regression suite remains
green (912 mutations and 16 destructor bindings). Log:
`target/development-v02449/sha3-active-output.log`, SHA-256
`6ea470928fa6c9223a24d8eee8360fff2a021bbce6152fb816b276f24534839c`.

This checks argument routing, not squeeze-callee algorithm/length semantics,
returned-result handling, recoverable-unwind destination cleanup or whole-call
register/spill erasure. Arm remains QEMU evidence. Tests forbid subprocess
execution; production, retained runtime records and release gates are unchanged.
F1 and root `PENTEST.md` remain open for remaining qualification and independent
retest, including fresh native Arm/Windows evidence.

## Squeeze unwind destination and owner cleanup

```sh
python3 assurance/register-cleanup/check_sha3_squeeze_unwind.py target/kmac-verify-1iopq9b5/observations.json
python3 assurance/register-cleanup/test_sha3_squeeze_unwind.py target/kmac-verify-1iopq9b5/observations.json
```

All 16 selected portable readers pass checks of the shared cleanup reached by
their 32 bulk/final squeeze invoke edges. Across 112 selected blocks, present
output ownership invokes the verified destructor on the original initialization
handle before requesting the bound wipe of the original borrowed owner. Only
absent output ownership skips destination Drop. Normal cleanup completion
resumes the original squeeze exception; the exception phi and separate cleanup
landing pad are checked explicitly.

The two double-panic paths must end in the identified core cleanup-panic routine
and are excluded from completed-cleanup claims. No payload writes, extra
callees, normal return or replacement exception are allowed on these slices.

All 656 LLVM mutations and 32 missing-cleanup bindings reject; 48 naming/comment
controls pass. The active-reader suite remains green (864 mutations and 32
callee bindings). Log: `target/development-v02449/sha3-squeeze-unwind.log`,
SHA-256 `e26273c3ef94fbdcbdc8f4db94ab7ae896bfd3249ab3783f030e123c8920a5b5`.

This checks exceptional caller routing under the retained descriptor-ownership
contract. Preservation of that descriptor by the squeeze callees, normal result
handling, abort cleanup and whole-call register/spill erasure remain separate
obligations. Arm remains QEMU evidence. Tests forbid subprocess execution;
production, retained runtime records and release gates are unchanged. F1 and
root `PENTEST.md` remain open for remaining qualification and independent retest,
including fresh native Arm/Windows evidence.

## Borrowed-reader output completion

```sh
python3 assurance/register-cleanup/check_sha3_output_completion.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_sha3_output_completion.py dist/kmac-verify-nft_nl5x/observations.json
```

All 16 selected portable readers pass checks of the successful squeeze-to-output
handoff, including the empty-output branch. Only present ownership transfers
the complete 24-byte initialization descriptor into the verified core `finish`
callee. The actual finish result controls success or failure; successful owned
results preserve the returned pointer and full length, while empty success
exposes no owned payload. Only successful completion reactivates the original
reader. Predecessor checks reject alternate entries bypassing these decisions.

Finish failures remain `SecretMemory` errors and enter the already checked
original-owner wipe. Finish unwinding enters its verified exceptional cleanup.
The eight optimized core finish definitions are checked for absent, complete
and incomplete initialization; their actual incomplete-output cleanup callee
is bound to the existing volatile LLVM model and matching x86/Arm assembly.
This composes the previously separate completion-callee and caller inspections.

All 1,120 LLVM mutations and 16 missing-finish bindings reject; 48 naming/comment
controls pass. The adjacent squeeze-error suite (1,032 mutations, 96 bindings),
core finish suite (160 mutations) and 16 original-owner wipe checks also pass
against the recovered record. Log: `dist/sha3-output-completion.log`, SHA-256
`e75627922c2d9b5b9e8678b1805510bd95d412b6ae1d1319925fc15009a6f144`.

The caller proof assumes the squeeze callees preserve initialization ownership
and report their results correctly; their complete semantics remain a separate
obligation. No whole-call register/spill erasure, abort cleanup or native Arm
qualification is established here. The regression tests prohibit subprocess
execution; only the separately reported focused recovery capture rebuilt Rust.
Production code and release gates are unchanged. F1 remains open for remaining
qualification, fresh native platform evidence and independent retest.

## Squeeze initialization ownership and post-write cleanup

```sh
python3 assurance/register-cleanup/check_sha3_squeeze_ownership.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_sha3_squeeze_ownership.py dist/kmac-verify-nft_nl5x/observations.json
```

Across 32 selected bulk/final squeeze bodies, all 48 direct initialization-handle
uses are confined to the actual core write routine and the final-to-bulk
forwarding call. The original exclusive initialization borrow is not directly
read, copied, stored, cast, returned or aliased by either squeeze body. Core
write definitions are separately checked: they preserve region pointer/length,
check bounds before copying, and commit only the initialized-byte count.

Writes use the original owner's staging region at its retained byte offset 584.
Bulk source lengths are bounded by a supported 136/168-byte rate; the final tail
write is exactly one byte. Every normal write result is followed by clearing all
168 staging bytes before either continuing or returning a `SecretMemory` error.
The write-result discriminator and error return edge are checked for both
compiler-private layouts. Core write/copy and clearing dependencies bind to
their checked source-specific LLVM and assembly artifacts.

All 1,040 LLVM mutations and 96 missing dependency bindings reject; 96 naming/
comment controls pass. Adjacent core write/copy regressions pass (144 LLVM and
40 assembly mutations), as do the completion regressions (1,120 mutations,
16 bindings, 48 controls). Log: `dist/sha3-squeeze-ownership.log`, SHA-256
`e9fde5e59de76632e1799838e32e36ddcf2f8efc48ab665be819595390770689`.

This checks direct descriptor uses and normal post-write routing under valid,
disjoint Rust borrows. It is not a full proof of squeeze length/counter
progression, staging-byte generation, other callee effects, unwinding or
whole-call register/spill erasure. Those wider obligations remain separate;
Arm remains QEMU evidence. No Rust compilation/runtime test was repeated for
this checkpoint, and production code and release gates are unchanged. F1 and
root `PENTEST.md` remain open for remaining qualification and independent retest.

## Bulk squeeze progress and commit routing

```sh
python3 assurance/register-cleanup/check_sha3_squeeze_progress.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_sha3_squeeze_progress.py dist/kmac-verify-nft_nl5x/observations.json
```

All 16 selected bulk squeeze bodies pass the loop-control checks. The remainder
starts at the original requested length. Each nonempty iteration takes the
minimum of that remainder and a supported chunk bound, passes that exact count
to the actual defined staging-fill callee, and writes exactly the filled chunk.
Only a successful fill permits writing; only a successful write permits
subtracting the chunk. The loop repeats exactly when the remainder is nonzero.

The commit block has only two predecessors: the zero-length branch and the
last successful iteration. Admission, fill and write failures return their
specified status without entering it. Exact predecessor sets reject alternate
entries and premature commits. The sole direct store in these bulk functions
is in that commit block. This checks reachability, not the counter value being
serialized or indirect memory effects inside callees.

All 656 LLVM mutations and 16 missing-fill bindings reject; 48 naming/comment
controls pass. Mathematical boundary checks cover chunk transitions and one
step at the maximum `u64` remainder; they are not execution of LLVM or an
exhaustive runtime campaign. The adjacent ownership suite remains green
(1,040 mutations, 96 bindings, 96 controls). Log:
`dist/sha3-squeeze-progress.log`, SHA-256
`078958ba99f163f0c65b3ddbe86adea2d866ba8a7e44a6ae2177c2f26d4a1fbf`.

Counter decoding, overflow arithmetic and serialization, staging-byte
generation, final-bit semantics and whole-call register/spill qualification
remain separate obligations. Arm remains QEMU evidence. Tests forbid subprocess
execution; no compiler/runtime rerun, production change or release-gate change.
F1 and root `PENTEST.md` remain open for remaining qualification and independent
retest, including native platform evidence.

## Bulk squeeze counter admission and serialization

```sh
python3 assurance/register-cleanup/check_sha3_squeeze_counter.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_sha3_squeeze_counter.py dist/kmac-verify-nft_nl5x/observations.json
```

The selected 16 bulk bodies pass 9,568 bounded interpreter cases for decoding
the original owner's byte-aligned 128-bit counter, checking addition of the
requested byte count, and committing the exact little-endian result. Cases
cover every counter bit, carries, zero requests, rate boundaries, maximum
`u64` requests, and both sides of the `u128` overflow boundary. Overflow must
return its error before any loop work or counter write. The separate progress
checker binds successful loop completion to the modeled commit block; this
counter model does not execute the staging-fill or output-copy routines.

The existing accelerated-reader interpreter has an explicit portable-layout
mode; its default owner layout and session checks remain unchanged. Rust 1.90's
unused `add nuw` result can become poison on a rejected overflow path. That
unused value is allowed, but an invalid value reaching a decision or committed
counter rejects. Dedicated selected/unselected-poison controls exercise this
distinction. This is a restricted model of the observed instructions, not a
general LLVM interpreter or an all-input formal proof.

All 2,032 counter LLVM mutations reject; 56 naming/comment and valid arithmetic
controls pass. The accelerated-reader checks still pass 1,328 cases and reject
116 mutations, with two valid controls. Bulk progress still rejects 656 mutations
and 16 missing-fill bindings, with 48 controls. Log:
`dist/sha3-squeeze-counter.log`, SHA-256
`0a2bc2b33089c788cfe0e0c70e9ef77a83621a7d75b2ddadd9979614b4674f26`.

Staging-byte generation, final-bit semantics and whole-call register/spill
qualification remain separate obligations. Arm remains QEMU evidence. Tests
forbid subprocess execution; production code and release gates are unchanged.
F1 and root `PENTEST.md` remain open for remaining qualification, fresh native
platform evidence and independent retest.

## Reader-bound staging dependencies

```sh
python3 assurance/register-cleanup/check_sha3_fill_dependencies.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_sha3_fill_dependencies.py dist/kmac-verify-nft_nl5x/observations.json
```

The existing fill-geometry model is now composed with the actual dependencies
selected by the checked bulk reader. Both rate instantiations in every retained
release configuration pass: 16 bodies and 42,704 modeled cursor/count/error
cases. No replacement geometry model or fresh compiler/runtime campaign was
introduced. LLVM and assembly remain paired by their record row even when
function bodies are identical across builds.

The three-block core copy wrapper checks equal slice lengths before forwarding
the original pointers and complete length to its defined `copy_bytes` primitive.
Length mismatch remains an error; the wrapper has no payload loads or stores.
The matching copy assembly passes the existing opaque-boundary/register-cleanup
checker. The actual scalar permutation definition is likewise bound to its
matching assembly and existing boundary checker. All three requested scratch
clears bind through the core wrapper to the checked volatile implementation.
This connects caller geometry to the real callees instead of assuming that a
matching function name alone establishes their cleanup behavior.

All 272 copy-wrapper mutations and 208 composed dependency mutations reject;
48 naming/comment controls pass. Missing callees, wrong target/rate identities,
removed erasure boundaries and altered volatile clearing reject. Existing fill
regressions (528 mutations, twelve model examples) and bulk progress regressions
(656 mutations, 16 missing-fill bindings, 48 controls) also pass. Log:
`dist/sha3-fill-dependencies.log`, SHA-256
`9e4f8d51b656c90b79f4255fc6a74a8e485d5b7a6b398a01a6eb78d8c5196a86`.

This is composition of bounded geometry/error models and existing dependency
assembly checks, not a new cryptographic proof or exhaustive byte-value test.
Final-bit handling, debug paths and whole-call register/spill qualification
remain separate. Arm remains QEMU evidence. Production and release gates are
unchanged; subprocess execution is forbidden in the regression suite. F1 and
root `PENTEST.md` remain open for remaining qualification and independent retest.

## Final-bit admission, masking and error routing

```sh
python3 assurance/register-cleanup/check_sha3_final_tail.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_sha3_final_tail.py dist/kmac-verify-nft_nl5x/observations.json
```

All 16 reader-selected final-bit bodies pass 2,896 admission cases within the
valid output-metadata domain: empty output, full-byte output, and one through
seven valid bits in a nonempty final byte. The complete-byte switch and
saturating tail adjustment are checked structurally. The retained counter
instructions reject overflowing byte counts before forwarding to bulk output;
admitted calls forward the original owner, initializer and exact complete count.
This extends the existing counter interpreter only for the observed unsigned
comparison, byte selection and complete-count phi instructions.

The full eight-block final-tail graph is checked. Successful bulk output alone
reaches the tail decision; fractional output alone reaches the one-byte fill.
The freshly staged byte is masked to its low valid bits before the original
initializer writes it. The set mask is zero. Every normal write result clears
the entire staging region through the existing ownership checker. Admission,
bulk, fill and write error paths preserve their specified results, with exact
predecessor sets rejecting bypasses.

The actual mask wrapper forwards the original byte and both public mask values
to its defined primitive, respecting the retained x86/Arm argument attributes.
The matching assembly passes the existing one-byte operation and register-wipe
checker. All 1,792 byte/partial-width mathematical combinations agree with
low-bit truncation; this is not execution of the emitted machine code.

All 2,184 LLVM mutations and 160 mask-dependency mutations reject; 48 naming/
comment controls pass. Adjacent accelerated counter checks (1,328 cases,
116 mutations), bulk counter regressions (2,032 mutations, 56 controls) and fill
dependency regressions (272 wrapper mutations, 208 dependency mutations,
48 controls) also pass. Log: `dist/sha3-final-tail.log`, SHA-256
`0d214ba89099ad05e9b719f48499675850ba56599ee05698e24aab819e3d620e`.

These are bounded admission and structural routing checks for valid metadata,
not proof of upstream metadata validation, all-input correctness, debug paths,
whole-call register/spill erasure or native platform qualification. Arm remains
QEMU evidence. No production code, runtime artifact or release gate changed;
tests forbid subprocess execution. F1 and root `PENTEST.md` remain open pending
the remaining qualification and independent retest.

## Composed final metadata and reader chain

```sh
python3 assurance/register-cleanup/check_kmac_final_chain.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_kmac_final_chain.py dist/kmac-verify-nft_nl5x/observations.json
```

This standalone diagnostic connects the previously separate constructor,
adapter, reader, output-owner and final-tail checks. Each of the 16
verifier-selected KMAC paths resolves its actual callees and LLVM/assembly
dependencies from the same retained build row. It does not pool symbol names
across compilers, targets or feature configurations.

The existing constructor model checks all 256 valid-bit values at ten length
boundaries. The composed matrix checks 40,960 constructor cases (the same eight
definitions checked for both KMAC strengths, not twice as many unique bodies),
9,568 counter cases, 2,896 tail-admission cases and 42,704 fill cases. Original
descriptor forwarding, invalid-metadata owner cleanup, reader error conversion,
initialization, terminal-state rejection, unwind cleanup and output completion
are checked together with the actual write, mask, copy, scalar permutation and
volatile-clear dependencies. The output writer must call the exact defined copy
primitive, not merely a symbol containing the expected name fragment.

All 320 composition mutations reject and 48 comment controls pass. These alter
actual dependency bodies without changing their symbols/ABIs, substitute
unbound callees, change compiler/feature/architecture identities, or remove
mask cleanup. The regression suite forbids subprocess execution. Final log:
`dist/kmac-final-chain-composition.log`, SHA-256
`4b898a4ded55faf16a30cb1f13cc02ade494f617d5715880c3e08a9e2dc37736`.
Adjacent constructor regressions (400 mutations, 24 controls), adapter rejection
regressions (384 mutations, 16 missing bindings, 48 controls) and completion
regressions (1,120 mutations, 16 missing bindings, 48 controls) also pass, logged
in `dist/kmac-final-chain.log`, SHA-256
`1c07513916c6319bab856b7da301ad19746fa6740c95c129e130900b9ad75118`.
That adjacent log predates the final additional exact-copy-callee check; the
composition log above includes the final checker and its regression.

Constructor rejection requests owner cleanup; this does not claim that the
constructor itself clears the caller's destination. Whole-verifier error
cleanup remains a separate contract. Likewise, these bounded models and
structural checks are not exhaustive cryptographic or whole-call register/spill
erasure proofs. Debug paths, wider caller qualification, native platform
evidence and independent retest remain outstanding. Arm artifacts remain QEMU
evidence. No production code or release gate changed, and no compiler/runtime
rerun was needed. F1 and root `PENTEST.md` remain open.

### Bulk/final reader pairing follow-up

The same composed command now selects both calls from each actual optimized
portable verifier. The bulk entry must forward the original result, borrowed
handle, destination and complete length directly to the exact borrowed-reader
specialization used by final output. Its two-instruction body contains no
payload loads, copies or extra calls. The final-mode flag is false; the unused
Option payload is `undef`, not an asserted valid-bit count. Existing active-reader
checks bind selection and output ownership in the shared callee.

All sixteen paths pass with unchanged constructor/counter/tail/fill case counts.
The expanded suite rejects 352 composition mutations and 192 focused bulk-call
mutations; 48 comment controls pass. Log: `dist/kmac-bulk-final-chain.log`, SHA-256
`7cf0d8d4548a23ef050de26081973f1cb831ed35ec7dc8131accde94dc456507`.
Adjacent reader-result tests reject 1,152 mutations with 72 controls, and final
reader tests reject 560 mutations plus 48 missing bindings with 48 controls.
Log: `dist/kmac-bulk-final-adjacent.log`, SHA-256
`2e375af2c458d98d9865185e5e86f93ab89076b34d80b1f3b09b8261fd7c6d2f`.
This completes this optimized portable bulk-entry connection, not accelerated
or debug verifier qualification or whole-call machine-code erasure. The current
[pre-pentest checklist](../qualification-status.md) records those outstanding
work packages separately from post-pentest native evidence and release checks.

## Accelerated reader entry and consuming cleanup

```sh
python3 assurance/register-cleanup/check_kmac_accelerated_readers.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_kmac_accelerated_readers.py dist/kmac-verify-nft_nl5x/observations.json
```

All eight optimized accelerated KMAC bulk/final reader pairs are selected from
their actual verifier calls. Same-row alias and callee checks bind both entries
to the defined accelerated borrowed producer and its calling convention. Bulk
reads load only the storage pointer from their borrowed handle, forwarding
original output and length in bulk mode. Final reads forward original storage,
output, length and valid bits in final mode; this check does not establish the
producer's full metadata validation or successful result semantics.

The consuming final reader's complete five-block boundary is checked. Normal
return marks the original engine terminal, resets its cursor and clears its
owned memory, all 168 staging bytes and both domain bytes. Recoverable unwind
calls the actual same-storage destructor, whose corresponding cleanup body is
also inspected, then resumes the original exception. Only the identified
double-panic termination is excluded. The engine wipe covers its 234 owned bytes
exactly: 200 lane bytes, two 16-byte counters and two suffix bytes. Clear calls
bind to the existing core volatile LLVM/assembly checks, not just a matching name.

All 824 LLVM and 64 dependency/ABI mutations reject; 64 naming/comment controls
pass. Adjacent staging tests reject 164 mutations and accelerated read tests
reject 120. Tests forbid subprocess execution. Log:
`dist/kmac-accelerated-readers.log`, SHA-256
`f853adea9367abc090e54a07ed9cabe946598bd0dd2229d3de9e92799b085aa4`.

The existing accelerated producer staging/error-path checker is composed with
these entry checks. This does not qualify the entire producer, backend session,
debug execution, machine spills or native platform. The shared CPU/session
scratch has its separate kernel/operation contract; this is not a claim to wipe
every byte of the containing 1,088-byte storage, including public metadata and
padding. Arm remains QEMU evidence. No production or release-gate change, no
compiler/runtime rerun, and no F1 closure is implied.

### Accelerated producer initialization and descriptor transfer

```sh
python3 assurance/register-cleanup/check_accelerated_initialization.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_accelerated_initialization.py dist/kmac-verify-nft_nl5x/observations.json
```

Eight instantiated optimized paths (four unique compiler/target configurations,
each reached by both strengths) pass. Before destination initialization the
closed entry permits only local metadata preparation. Nonempty output calls the
actual same-row core initializer with the original pointer and full length;
its existing checker establishes volatile clearing before ownership is returned.
Only zero-length output skips that call. Initialization rejection terminates
the engine, resets its cursor, clears its 234 owned memory bytes, 168 staging
bytes and two domain bytes, and returns `SecretMemory` without entering output
production. The cleanup callees retain their existing LLVM/assembly bindings.

Successful initialization transfers all 24 descriptor bytes into the operation:
the compiler's one-byte plus 23-byte split, including the additional Arm local
copy, is checked completely. The presence discriminator is set only on that
successful path. Original length and final-bit metadata are preserved; empty
output remains absent, not a fabricated initialized region. These copies are
pointer/length/ownership metadata, not a claim that payload bytes are copied or
that metadata itself is erased.

The regression suite rejects 984 entry/transfer mutations and 56 dependency
mutations; 16 comment/SSA controls pass. Tests forbid compiler/runtime subprocess
execution. Adjacent accelerated-reader tests (824 LLVM and 64 dependency
mutations, 64 controls) and staging tests (164 mutations) also pass. Log:
`dist/accelerated-initialization.log`, SHA-256
`c509ee6c6b8a79a93d02a00042894abb3b63fec85def8e58d10a11d92ed38b07`.
Later shape/state/authority admission, progress, output completion,
debug execution and register/spill qualification remain separate unfinished
work. Arm remains QEMU evidence. Production code and release gates are unchanged;
F1 and root `PENTEST.md` remain open.

### Accelerated producer completion and operation cleanup

```sh
python3 assurance/register-cleanup/check_accelerated_completion.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_accelerated_completion.py dist/kmac-verify-nft_nl5x/observations.json
```

The eight actual optimized accelerated paths now compose the checked entry with
the completion boundary. Only a present initializer moves its complete 24-byte
descriptor into the same-row core `finish` function. That function's existing
model checks absent, incomplete and complete ownership; its cleanup is bound to
the actual volatile implementation. Only successful completion returns the
finished original pointer and full extent. Empty output returns the absent
discriminator, not an owned output. Predecessor checks reject alternate entries
that bypass the presence or finish-result decisions.

The producer's successful operation clears all 168 staging bytes and preserves
the live engine. Failed finish maps to `SecretMemory`, marks the engine terminal,
resets its cursor and clears engine memory, staging and domain bytes. The shared
cleanup block's predecessor-selected address and extent are checked explicitly.
This producer-level success behavior differs intentionally from the consuming
final reader, which subsequently clears its whole owned engine state.

Completion unwind invokes the actual incomplete operation guard on the original
storage and resumes the original exception; the guard's clear requests are
checked through the existing cleanup model. A second panic during cleanup is a
nonreturning excluded path. This does not claim destination clearing after an
arbitrary panic inside an unreviewed callee: the actual retained core finish
contains only the inspected ownership/length logic and volatile clear call.

All 916 LLVM and 64 dependency mutations reject; 16 comment/SSA controls pass.
Adjacent initialization tests reject 984 entry/transfer and 56 dependency
mutations with 16 controls; core output-handoff tests reject 160 mutations and
staging tests reject 164. Log: `dist/accelerated-completion.log`, SHA-256
`b34fef4402aa27f26efbcd38ae210dd58f4a564c494e584ef21eba2b112f3a65`.
These are retained-artifact checks, not new compiled or runtime campaigns.
Producer shape/state/authority admission, complete read/mask/write loop progress,
debug callers, register/spill qualification and fresh native evidence remain
outstanding. Arm remains QEMU; F1 and root `PENTEST.md` remain open. No production
code or release gate changed.

### Accelerated producer admission and read/mask/write loop

```sh
python3 assurance/register-cleanup/check_accelerated_output_loop.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_accelerated_output_loop.py dist/kmac-verify-nft_nl5x/observations.json
```

Eight instantiated paths compose the existing initialization/completion checks
with the producer's full-request preflight and loop. Final output accepts zero
valid bits only for an empty destination and one through eight bits for a
nonempty destination; bulk mode uses the original full byte count. Terminal or
non-squeezing state rejects before authority revalidation, which precedes the
checked 128-bit output-count admission. The unchanged bounded counter model is
reused with the verified original length phi supplied explicitly and the owner
parameter alpha-renamed; its parser now also accepts the ordinary `call` spelling
of the same pure checked-add intrinsic. No arithmetic behavior is weakened.

Both producer preflight and the actual engine read are tested across 2,656
modeled cases each (four compiler/target configurations, instantiated twice for
the two strengths). The producer checks the reconstructed counter itself, not
just its overflow decision: incorrect byte offsets can otherwise escape sparse
accept/reject tests. This is bounded modeling, not an all-input formal proof.

Only nonempty admitted output enters the loop. Each iteration reads exactly
`min(remaining, 168)` bytes into the original staging region, optionally masks
only the last byte of the final chunk, writes the same count into the original
owned initializer, clears all 168 staging bytes, and then subtracts that count.
Completion is reached only on zero original length or exact loop exhaustion.
Predecessor checks reject bypasses of read, mask, write, clearing and progress.
Mask, read, write, copy and destination-drop helpers are bound to the actual
same-configuration LLVM/assembly checks, not just matching symbol fragments.
Existing error/unwind cleanup checks are reused for the new paths. Session
internals retain their separate authority/kernel qualification scope.

All 1,924 LLVM and 72 dependency regressions reject; 20 comment/SSA/equivalent-call
controls pass. Adjacent completion (916 LLVM/64 dependency mutations, 16 controls),
engine counters (116 mutations, two controls), portable bulk counters (2,032
mutations, 56 controls) and final-bit tails (2,184 LLVM/160 dependency mutations,
48 controls and 1,792 mathematical mask cases) pass. Log:
`dist/accelerated-output-loop.log`, SHA-256
`50be5e058ebf57e3138e483ad92b779992d687c92647905d70901f02aa23c4a8`.
No cryptographic implementation, runtime artifact or release gate
changed. This supersedes the preceding checkpoint's outstanding optimized
producer admission/progress item, not the debug, wider caller/worker,
register/spill or native-platform work. Arm remains QEMU evidence; F1 and root
`PENTEST.md` remain open.

### Debug bulk-reader forwarding and result ownership

```sh
python3 assurance/register-cleanup/check_debug_kmac_bulk_bridge.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_kmac_bulk_bridge.py dist/kmac-verify-nft_nl5x/observations.json
```

The 24 instantiated debug bulk bridges are selected from actual verifier calls
in the retained eight debug configurations. Each binds five real functions from
the same configuration: the KMAC trait bridge, SHA-3 reader wrapper, result
mapper, error-call adapter and error conversion. Sixteen paths use portable
readers (including their instantiations in acceleration-enabled builds); eight
use accelerated readers. The selected borrowed producer's definition and ABI
are bound, but its body is deliberately opaque in this checker.

The existing bounded descriptor interpreter executes these five-function
closures. The original borrowed reader, output pointer and complete length must
reach the producer exactly once, with bulk mode and no final-bit shape. Only
24-byte ownership-descriptor copies are permitted in the result handoff; direct
reader-state or output-payload accesses are rejected by the model. Success
preserves the original empty/nonempty output descriptor. All five portable and
twelve accelerated error encodings are checked, including the feature-dependent
KMAC enum encoding. A synthetic producer exception must propagate unchanged,
without publishing an output result. No producer clearing behavior is assumed.

All 1,568 modeled cases pass, covering seven lengths and every reachable block
in the selected bridge/wrapper/error-helper closures. Huge lengths are scalar
metadata scenarios, not manufactured Rust slices or allocation/runtime tests.
This does not check the verifier's arguments before bridge entry, consuming-final
bridges, debug producer internals, arbitrary helper panics, machine registers or
compiler spills. It is not an all-input formal proof or native-platform evidence.

All 1,032 forwarding, ownership, error, payload-access and ABI mutations reject;
48 metadata/SSA controls pass. Adjacent debug output-finish tests reject 256
mutations with eight controls; debug writes reject 260 LLVM and 40 copy-assembly
mutations with 24 controls. These tests prohibit subprocess execution and reuse
the protected artifacts without a compiler/runtime rerun. Log:
`dist/debug-kmac-bulk-bridge.log`, SHA-256
`e60999eeb55d5b4ac095e04253917b3f79535c4a64ff8fbdadd3deb9746299e2`.
No production code or release gate changed. Arm remains QEMU; F1 and root
`PENTEST.md` remain open pending the remaining qualification and independent retest.

### Accelerated debug consuming-final handoff

```sh
python3 assurance/register-cleanup/check_debug_kmac_final_bridge.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_kmac_final_bridge.py dist/kmac-verify-nft_nl5x/observations.json
```

Eight actual accelerated final bridges bind fourteen-function closures from
their own KMAC, SHA-3 and core artifacts. Generic helpers resolve in their
caller's artifact; definitions from unrelated configurations are not pooled.
The closure includes the trait handoff, consuming reader, real destructor
chain, engine cancellation, engine-memory wipe, staging/domain cleanup,
core clearing wrapper and result/error conversion. The borrowed producer and
volatile byte-clearing primitive remain explicit opaque boundaries with their
actual definitions and ABIs checked, not bodies interpreted by this diagnostic.

The original storage, destination, length and valid-bit value reach the producer
in final mode. On success, every returned backend error and a synthetic producer
exception, the real destructor chain marks the same engine terminal, resets its
cursor and requests all six original owned-region clears: engine state (200
bytes), two 16-byte counters, two engine-domain bytes, all 168 staging bytes and
two XOF-domain bytes. The wrapper publishes the original secret-output descriptor
or exact backend error only after cleanup. Producer unwind performs the same
cleanup and resumes the original exception identity and selector. Double-panic
abort and arbitrary exceptions from cleanup helpers are excluded.

The 4,704 modeled cases cover seven lengths, six byte-sized valid-bit values,
empty/nonempty successful result descriptors, all twelve accelerated-error encodings
and producer unwind. These are synthetic boundary results, not claims that the
opaque producer accepts invalid output shapes or can allocate enormous slices.
Every selected reachable block is exercised; the core wrapper's unused
empty-region branch and cleanup-abort block are explicitly outside these paths.
Direct payload/state reads, wrong clear offsets/extents, skipped/duplicated
cleanup and publication before cleanup reject. This is not a proof of producer
behavior, debug portable-final handoff, whole-verifier control flow, compiler
spills or native-platform behavior. The existing volatile LLVM/assembly checks
retain their own narrower guarantees.

All 684 retained-LLVM handoff/drop/clear/unwind mutations reject; 16 harmless
metadata/SSA controls pass. Adjacent bulk-bridge tests reject 1,032 mutations with
48 controls; volatile clearing rejects 192 mutations with eight controls and
checks 100 overlapping-store model cases. Clearing assembly rejects 1,016
instruction/call/identity and 48 extraction mutations with 44 controls. All use
the retained artifacts and prohibit subprocess execution. Log:
`dist/debug-kmac-final-bridge.log`, SHA-256
`3c99361ce9db9fa202ec0e1847a90436aa11581dcde959de38b27f09a6a6935f`.
No production code or release gate changed. Arm remains QEMU, and F1 and root
`PENTEST.md` remain open.

### Debug final-output constructor and actual range helpers

```sh
python3 assurance/register-cleanup/check_debug_fips202_output.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_fips202_output.py dist/kmac-verify-nft_nl5x/observations.json
```

The constructor used by portable consuming-final readers now binds its actual
nineteen-function shape, checked-length, result and range-helper closure in all
eight retained debug configurations. The inclusive range helpers are resolved
from the same configuration's `brynja-hash-core` LLVM file, not substituted by
an assumed range predicate. The model reads the actual constant bounds and
checks the original destination, byte length, computed bit length and final-bit
value, or the exact shape/overflow error. Payload access is rejected.

All 256 final-bit values over ten selected length boundaries pass: 20,480 cases.
These are scalar descriptor models, not fabricated Rust slices or huge runtime
allocations. Coverage includes constructor and fixed-inclusive helper paths;
generic Excluded/Unbounded arms and disconnected compiler unwind scaffolding
are explicitly outside those paths. This does not qualify the consuming-reader
handoff, producer behavior, whole-verifier cleanup, registers or spills.

The eight supplemental hash-core files were present in the protected full
archive but absent from the original 240-artifact observation index. Each was
compared byte-for-byte with its regular archive member and is separately
SHA-256-pinned in the diagnostic. The original observation record is unchanged.
The full archive `dist/kmac-verify-nft_nl5x.tar.gz` was independently rehashed as
`6a85f5de89c4e0e0f7c3dc725bfb7ab09c93b35525bcdb09645c361d75d26e52`.
These supplemental author-review pins are not new release-gate requirements.

All 352 LLVM/constant/dependency mutations and eight changed-artifact pin cases
reject; sixteen metadata/SSA controls pass. The shared metadata interpreter now
accepts the compiler's two-field literal aggregate syntax, with fifteen value
controls and three malformed-constant rejections. Adjacent bulk/final bridge,
output write/finish and volatile-clearing mutation suites pass. Mutation tests
forbid subprocess execution; no compiler/runtime campaign was repeated. Log:
`dist/debug-final-output-constructor.log`, SHA-256
`568d6eef066262c2db95c2fd6db01f4b808453bd70dfbca4eef740e1bff44cfd`.
No production code or release gate changed. Arm remains QEMU; F1 and root
`PENTEST.md` remain open pending the remaining qualification and independent retest.

### Portable debug consuming-final handoff

```sh
python3 assurance/register-cleanup/check_debug_portable_final_bridge.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_portable_final_bridge.py dist/kmac-verify-nft_nl5x/observations.json
```

Sixteen portable final-reader paths (both cSHAKE strengths, including builds
with accelerated features enabled) now bind thirty-five-function closures from
their own retained KMAC, SHA-3, core and supplemental hash-core artifacts. The
actual output constructor, descriptor extraction, reader transfer, destructor
chain, owned-clear wrapper and error conversion execute in the metadata model.
Duplicate instantiated helpers in different caller artifacts must have identical
normalized bodies and parameter lists; unrelated configurations are never pooled.

All 6,528 modeled cases pass: eight selected lengths, six final-bit values,
both incoming reader-active flags, successful production, every portable backend
error, and selected constructor/producer boundary unwind. Invalid shapes and
bit-length overflow return the feature-correct KMAC error without calling the
producer. Valid inputs preserve the original owner, active flag, output pointer,
length and final-bit value into the borrowed producer in final mode. Synthetic
exceptions retain their original identity and selector.

Every selected return/resume path requests all thirteen original owner-region
clears exactly once. Both strengths own 168-byte maximum-rate input/padding/output
buffers; their different algorithmic rates do not shrink those clearing extents.
Shape errors write their result before dropping the reader but complete cleanup
before returning. After successful ownership transfer, producer success/errors
complete cleanup before the outer result is written. The model rejects direct
payload/state access and does not model secret bytes as ordinary metadata.

Coverage includes every selected constructor, handoff, result and destructor
block, except the fixed-inclusive range helper's unused generic arms,
disconnected compiler unwind scaffolding, the clearing wrapper's empty-region
branch and double-panic abort blocks. Huge lengths are scalar descriptors, not
runtime allocations. Producer and volatile primitive bodies remain explicit
opaque boundaries. This does not establish producer behavior, output-buffer
clearing inside the producer, arbitrary helper panics, whole-verifier register
or spill cleanup, native-platform behavior or an all-input formal proof.

Main check log: `dist/debug-portable-final-bridge-check.log`, SHA-256
`c4dd5397797431fef9f237f57ec7e33abf7366a848cc912b04b38e336fe31f84`.
All 1,240 ownership, cleanup, result, dependency and unwind mutations reject;
32 harmless metadata/SSA controls pass. Pure repeated metadata copies are not
counted as security failures; duplicated owned-region cleanup is rejected.
Mutation log: `dist/debug-portable-final-bridge-mutations.log`, SHA-256
`fb8ddbfb13f74a833aa8a070750f5c3a65a533ee99de0b39e501899322474e0d`.
Mutation tests prohibit subprocess execution; no compiler/runtime campaign was
repeated. The existing constructor and volatile-body diagnostics keep their own
recorded scope and are not replaced by this handoff model.
No production code, shared model, release gate or original observation record
changed. Arm remains QEMU; F1 and root `PENTEST.md` remain open.

### Portable debug producer handoff and operation guard

```sh
python3 assurance/register-cleanup/check_debug_portable_producer_guard.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_portable_producer_guard.py dist/kmac-verify-nft_nl5x/observations.json
```

Sixteen actual portable producer paths now bind nineteen-function closures from
the retained same-configuration SHA-3/core artifacts. Both cSHAKE strengths and
both feature configurations are covered under Rust 1.90.0/1.98.1 and x86/Arm. The
constructor/consumer diagnostic identifies the actual producer; this diagnostic
then follows its initialization handoff, instantiated operation guard, success
predicate, initializer/output destructors, owner wipe and core clearing wrapper.
It resolves both compiler symbol formats against actual definitions.

All 27,648 modeled cases pass across nine lengths, bulk/final output shapes,
both reader-active states, five synthetic initializer errors, five operation
errors, success and selected operation/result-predicate unwind. Bulk mode also
includes an undefined inactive bit-tail byte; it is preserved as metadata, not
used as a branch or address. Huge lengths remain scalar descriptor scenarios,
not allocated Rust slices or runtime tests.

The original destination reaches the initializer before changing reader state. An
initialization error deactivates the reader and requests all thirteen original
owner-region clears before returning its exact error. Terminal readers never
invoke the operation: the actual closure/initializer destructor requests full
destination clearing for a present initializer. Otherwise the guard deactivates
the reader before invoking the operation with the original owner, complete
initializer descriptor, length and optional final-bit metadata. Only success
restores the active flag. Operation errors and selected unwind clear the owner
before return/resume. A synthetic predicate unwind also destroys any returned
nonempty output before owner clearing, preserving exception identity/selector.

Initializer, operation and volatile primitive bodies remain explicit opaque
boundaries with checked actual ABIs. The operation boundary does not imply that
its destination was cleared on error/unwind; that belongs to its pending body
review. Likewise, this does not establish initializer-body or initializer-unwind
behavior. No secret payload/state read or direct write is allowed by the model.
Result metadata may be written before destructor execution, but cleanup must
finish before returning control to the caller.

All selected blocks are covered except double-panic abort, unreachable blocks,
the root's pre-transfer unwind arm (the only invoke follows ownership transfer),
the valid initializer's unused inner-None branch, and the clear wrapper's
empty-region branch. These exclusions do not authorize skipping any exercised
cleanup. Arbitrary helper panics, corrupted initializer representations,
whole-verifier register/spill behavior and native platforms remain outside this
check. Main log: `dist/debug-portable-producer-guard-check.log`, SHA-256
`0fbb1bae049e9e83e85986bcb4351bf043357cb9ceb8ac92b602df4feee3ccbf`.

All 1,872 retained-LLVM handoff, lifecycle, cleanup, dependency and unwind
mutations reject; 32 metadata/SSA controls pass. Tests exercise changed initializer
and closure arguments, truncated descriptor transfers, missing/duplicate cleanup,
incorrect active/keep decisions, altered clear extents and swallowed/substituted
exceptions. They prohibit subprocess execution and do not rebuild production
code. Mutation log: `dist/debug-portable-producer-guard-mutations.log`, SHA-256
`b0bc4e60604955e433589ce25a36268bcf568502d1d82d47df1ccd5e913fa391`.

No production code, shared interpreter or release gate changed. The original
observation record is unchanged; Arm remains QEMU. F1 and root `PENTEST.md`
remain open pending the remaining qualification and independent retest.

### Debug destination initializer and producer composition

```sh
python3 assurance/register-cleanup/check_debug_output_begin.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_output_begin.py dist/kmac-verify-nft_nl5x/observations.json
```

The actual `begin_secret` body now binds its slice-empty test, core
`SecretRegionInitialization::begin`, clearing wrapper, ownership construction,
result adapters and error conversion. The closure has twelve or thirteen
functions depending on whether the compiler emits distinct slice-empty helper
instances. The separately emitted helper is resolved from the same retained
configuration's already-pinned hash-core artifact, not replaced with an assumed
predicate. No new capture files or observation-index entries were created.

The actual initializer is also composed with both portable producer strengths
and their previously checked operation guards, producing twenty-nine/thirty-
function closures. All 6,976 modeled cases pass over ten selected lengths,
active/terminal readers, bulk/final metadata, operation success/errors and
selected operation/predicate unwind. Direct core-constructor checks distinguish
its empty-region rejection from the SHA-3 adapter's successful empty `None`.
Four injected clearing-wrapper error values preserve their exact identity in
the core result before the SHA-3 adapter maps them to `SecretMemory`.

Nonempty initialization requests clearing of the complete original destination
before returning its original pointer/length and zero initialized-byte count.
The producer consumes that actual descriptor with the original output metadata;
terminal rejection drops it, initialization errors deactivate/clear the owner,
and the operation guard preserves its recorded success/error/unwind behavior.
The model forbids direct payload/state access. Huge lengths are scalar boundary
scenarios, not allocated slices or runtime workload tests.

Coverage includes the initializer's selected blocks and both empty/nonempty
branches of the actual clear wrapper, plus the composed guard paths. Exclusions
remain unreachable blocks, cleanup double panic, the producer's pre-transfer
unwind arm and the valid owner's unused inner-None branch. Clearing-wrapper
errors are synthetic fault propagation, not claims that every error is currently
reachable for a valid nonempty slice. Arbitrary initializer/helper unwind is not
qualified. The squeeze/finish-operation and volatile primitive bodies remain
opaque here; their behavior, whole-verifier register/spill cleanup and native
platforms are not inferred from this model.

Main log: `dist/debug-output-begin-check.log`, SHA-256
`11a6386eb8930bd5ab6ee9e49d70f15a6f2bad6413faaf0eb1d99833d4b2eab7`.
All 988 clearing, descriptor, error-mapping and ABI mutations reject; 32
metadata/SSA controls pass. The mutation harness forbids subprocess execution.
Mutation log: `dist/debug-output-begin-mutations.log`, SHA-256
`379388b62080dc5cec31e376216ddd17abd51be7cc00b589b8df9fbb5a4b4323`.
No production code, shared interpreter, release gate or original observation
record changed. Arm remains QEMU; F1 and root `PENTEST.md` remain open.

### Debug output-completion adapter

```sh
python3 assurance/register-cleanup/check_debug_finish_adapter.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_finish_adapter.py dist/kmac-verify-nft_nl5x/observations.json
```

The portable operation's actual `finish_secret` target now binds sixteen
same-configuration functions: its empty-output constructor, core initializer
completion and destructor helpers, ownership conversion and error adapters.
All 1,136 modeled cases pass across sixteen instantiated paths. These cover
empty outer `None`, complete/incomplete/over-complete initialization, missing
inner ownership, seven selected capacities and synthetic dereference/take faults.
Malformed descriptors and huge lengths are model rejection probes, not Rust
values manufactured or allocated in a runtime test.

Success consumes the original owner and publishes its original destination and
length. Incomplete/missing ownership returns `SecretMemory`; present unsuccessful
owners request a full original-region clear. Selected helper unwind clears before
resuming the original exception. The model also checks core ownership revocation
and initialization-progress preservation, not just the outer result. All actual
adapter/core blocks are visited except unreachable blocks and cleanup double
panic. Payload reads/copies are prohibited; descriptor copies remain metadata.

The core constructor/finish checks enforce core error identity separately. This
adapter intentionally collapses core errors into `SecretMemory`, so changing one
core error into another is an accepted control at this layer, not claimed as a
rejected adapter regression. The upstream squeeze/operation body and its actual
completion handoff still need qualification. Volatile clearing remains an opaque
request here. This does not establish arbitrary-helper unwind, whole-verifier
register/spill cleanup, native Arm/Windows behavior or independent review.
No production, shared interpreter, original capture record or release gate changed.

All 1,120 adapter/core ownership, cleanup, result-mapping and ABI mutations reject.
The 48 accepted controls cover harmless debug/SSA changes and the intentional
core-error collapsing described above. The mutation harness forbids subprocess
execution; no compiler/runtime campaign was repeated. Log:
`dist/debug-finish-adapter.log`, SHA-256
`c1f041bb1257b5e2829acaf018ac1b3b15487ceeebc9f670f76415e35145d2ca`.
Documentation links, script layout and acceptance metadata/checker regressions
pass. Arm remains QEMU; F1 and root `PENTEST.md` remain open.

### Debug portable operation composition

```sh
python3 assurance/register-cleanup/check_debug_producer_operation.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_producer_operation.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_zero_arguments.py
```

The actual portable producer operation now composes its initialization, operation
guard, dispatch/result adapters, finish adapter and core destructors. This binds
forty-five/forty-six same-configuration functions, including the actual
twenty-four-function operation/completion closure. All 21,728 modeled cases pass
across sixteen instantiated paths and ten selected output lengths. The three
opaque operation boundaries have their actual borrowed ABIs checked: byte
squeeze, final-bit squeeze and the empty-output `check_output_bytes(0)` call.
Their bodies are not modeled by this checkpoint.

The operation receives the original initializer and captured output metadata with
the reader guard armed. It dispatches the original owner, destination descriptor,
length and optional final-bit value to the correct boundary. Inactive readers and
initialization failures do not enter the operation. Failure after synthetic
partial progress clears the original output and owner; incomplete successful
boundary progress cannot escape as a completed output. Successful completion
transfers the actual original output descriptor and alone reactivates the reader.
Selected squeeze, core-finish and result-predicate unwind retain cleanup and the
original exception. Every actual operation block is visited except unreachable
and cleanup double panic; this is not full coverage of every block of every
composed helper, whose standalone checks remain separately scoped.

Boundary progress/errors are injected metadata effects, not generated secret
bytes or evidence of squeezing correctness. Final-bit values outside valid API
shapes test forwarding only; huge lengths are not allocated/runtime workloads.
The volatile primitive remains opaque. Actual squeeze/check bodies, accelerated
debug producer paths, whole-verifier register/spill behavior and native platforms
remain outstanding. Arm remains QEMU; F1 and root `PENTEST.md` remain open.

An actual empty-output error mapper has zero arguments. The shared diagnostic
interpreter now normalizes an empty argument list for definitions, calls and
invokes; malformed lists and arity mismatches remain rejected. Eight normal,
whitespace, nonempty-parameter and unwind controls pass, with fourteen negative
cases. Existing retained output-write (2,072 cases), output-finish (560 cases)
and finish-adapter (1,136 cases) checks also pass with that interpreter change.
Regression log: `dist/debug-zero-argument-regressions.log`, SHA-256
`7755c2505d56df41a484c63c01760d45be32d7228cb0ec784987c0f0c604c0d5`.
No production code, release gate or original capture record changed; no Rust
compiler/runtime campaign was repeated.

The existing core-finish mutation suite also rejects all 256 ownership/cleanup/
unwind mutations, with eight metadata controls passing under the updated model.
Log: `dist/debug-zero-argument-finish-mutations.log`, SHA-256
`860fb6a8b0bf755b8fdc4a627bc951b5d30539ce651abc3d97c1ecfdb4dbc2b4`.
Operation check log: `dist/debug-producer-operation-check.log`, SHA-256
`a36972995812ee9a6a1b179d23cba588bc17187d54b8c8fa4c35075b4809449a`.

All 816 dispatch, ownership, cleanup, unwind and ABI mutations reject. The 48
accepted controls cover harmless debug metadata, SSA renaming and a redundant
initial drop-flag store that is immediately overwritten before use. This dead
store is not counted as a security regression. The mutation harness forbids
subprocess execution. Mutation log: `dist/debug-producer-operation-mutations.log`,
SHA-256 `5ce87673f7f2ba73f2f3569fa3ec436eacb3884a6adc713cf8768e2b770be1d7`.
Documentation links, script inventory and acceptance metadata checks pass.

### Debug output-limit composition

```sh
python3 assurance/register-cleanup/check_debug_output_limit.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_output_limit.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_wide_arithmetic.py
```

The actual debug output-limit helper now binds six same-configuration functions:
counter-field selection, checked u128 addition and Option/result mapping. It
composes with the portable empty-output producer in fifty-one/fifty-two-function
closures. All 4,928 modeled cases pass across sixteen instantiated paths. Eleven
counter and increment values cover zero, 64/127/128-bit boundaries and the full
u128 maximum. The checked-add helper's exact successful sum is tested separately
because the limit adapter intentionally discards that sum; checking only the
overflow tag would miss arithmetic-value regressions. Inactive Option payloads
remain undefined rather than being invented as initialized zeroes.

The original owner's exact sixteen-byte output-counter field reaches a borrowed
decoder boundary once, without owner mutation. Empty output admits zero additional
bytes even at the maximum counter. Terminal readers never reach the decoder;
synthetic decoder unwind traverses the actual guard and thirteen owned-region
clear requests, preserving the original exception. All six limit-helper control
flow graphs are covered except unreachable blocks. This supersedes the opaque
limit-check boundary for these paths, not the actual byte/final-bit squeeze bodies.

The shared diagnostic model now handles checked u128 addition and the retained
sixteen-byte Option tag layout in addition to its prior 64-bit forms. Its focused
tests pass 302 arithmetic/constant controls and 76 poison, malformed-operand,
range and read-only-storage rejections. This remains a bounded interpreter of
selected LLVM instructions, not a complete LLVM implementation or formal proof.
The counter decoder and volatile primitive bodies remain opaque. Injected scalar
counters and synthetic decoder unwind do not prove scalar-copy/register/spill
cleanup, whole-verifier behavior or native platform qualification. Arm remains
QEMU; F1 and root `PENTEST.md` remain open. No production implementation, original
capture record or release gate changed, and no Rust campaign was repeated.

Existing retained output-write (2,072 cases), core-finish (560 cases),
finish-adapter (1,136 cases) and producer-operation (21,728 cases) checks pass
with the shared model change. The existing core-finish mutation test rejects all
256 mutations with eight controls; zero-argument tests retain eight controls and
fourteen rejections. Regression log: `dist/debug-wide-arithmetic-regressions.log`,
SHA-256 `82ef7b70ec02263a1cd302f6f2542d22c32dc22e066f1808bd45081159e5ffad`.
Output-limit check log: `dist/debug-output-limit-check.log`, SHA-256
`2655768eb55c0b3c3bad3d8ba4ea485ad0051dda884472eb5a3570102ffed062`.

All 400 arithmetic, counter-field, result-mapping and decoder-ABI mutations
reject; 32 debug-metadata/SSA controls pass. The mutation harness forbids
subprocess execution. Mutation log: `dist/debug-output-limit-mutations.log`,
SHA-256 `5da77bd207d4d69cf395e190cc595f9f3ead392b9999dca6d52473deb6c4c2a0`.
Documentation links, script inventory and acceptance metadata checks pass.

### Debug counter-decoder composition

```sh
python3 assurance/register-cleanup/check_debug_counter_decode.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_counter_decode.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_counter_operations.py
python3 assurance/register-cleanup/test_debug_counter_packing.py
```

The retained debug counter decoder now binds twelve actual same-configuration
functions, including slice construction/iteration, enumeration, checked offset
conversion/multiplication and Option/Result handling. Composition with the actual
limit helper and empty-output producer binds sixty-three/sixty-four functions.
All 3,792 modeled cases pass across sixteen instantiated paths. The decoder reads
exactly the sixteen original counter bytes, once each and in order. Zero, all
ones, all 128 single-bit values and two mixed byte patterns check little-endian
reconstruction; enclosing limit decisions cover both sides of overflow boundaries.
Empty producer paths retain the reader's original ownership and active state,
and terminal readers never decode the counter.

The byte-shift helper's integer-conversion/multiplication fallback paths are
checked with separate synthetic offsets, not presented as reachable iterator
inputs. All decoder/helper normal control-flow blocks are covered. The two
overflow-panic boundaries are prohibited; paths reachable only through them and
blocks without an entry path are excluded rather than claimed tested. Arbitrary
unwind and machine-level residue behavior are not established by this model.

Rust 1.98 moves one conversion result through an eight-byte integer ABI carrier
containing smaller fields and undefined padding. A local-only packed-field model
preserves those fields through stores and memcpy without inventing initialized
padding or allowing that carrier to participate in arithmetic. Nine round-trip
controls and 24 width/escape/copy/arithmetic rejections pass. Bit operations,
checked u32 multiplication and four-byte constants have 218 positive controls
and 22 rejected malformed/poison/constant operations. Earlier shared-model
regressions remain green: 302 wide-arithmetic controls/76 rejections, eight
zero-argument controls/14 rejections, retained output-write (2,072), core-finish
(560), finish-adapter (1,136) and limit (4,928) cases, and 256 core-finish mutations
with eight controls.

Actual scalar counter bytes are modeled here for functional decoding, not secret
erasure. The debug IR contains scalar accumulator/byte temporaries; this check
does not prove those copies or their registers/spills are erased. Squeeze bodies,
wider caller/worker qualification and native platforms remain pending. Arm remains
QEMU; F1 and root `PENTEST.md` remain open. No production implementation, original
capture record or release gate changed; no Rust compiler/runtime campaign ran.

Decoder log: `dist/debug-counter-decode-check.log`, SHA-256
`be346eadf552ac64b341ac1e2624a8abd2da8d5748644b378deecf7b9b258e5f`.
Regression log: `dist/debug-counter-model-regressions.log`, SHA-256
`6d0ea347f5981d25f7f5db971c37e3568c100a51b8b856b53db10a6c8a72e0b6`.

All 776 byte-read, iterator, arithmetic and dependency/ABI-layout mutations
reject; 32 debug-metadata/SSA controls pass. Harmless branches that only take an
extra side-effect-free jump to the same successor are not counted as regressions.
The mutation harness forbids subprocess execution. Mutation log:
`dist/debug-counter-decode-mutations.log`, SHA-256
`c47dc25d5a02aa1929ea80fc91e31af2c29cc49da02d19e4c86539824b89f568`.
Documentation links, script inventory, acceptance metadata and its regression
tests pass without crypto execution.

### Debug counter-writer and decoder round-trip

```sh
python3 assurance/register-cleanup/check_debug_counter_write.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_counter_write.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_counter_write_model.py
```

The writer is selected from the actual byte-squeeze body's call, not found by an
unrelated matching name. Its fourteen-function closure includes mutable slice
iteration, enumeration, checked byte shifts, narrowing and Result defaults. Five
helpers are shared with the checked decoder; the combined function set contains
seventy-two/seventy-three functions. All 6,608 modeled cases pass across sixteen
instantiated paths. This binds the writer to its actual caller but does not yet
execute the complete squeeze body or establish its counter-commit/error ordering.

Each destination byte starts as the complement of its expected value. The model
requires sixteen exact, ordered writes with no old-counter reads and no writes
outside the original sixteen-byte field, then reads back through the actual
decoder. Zero, all ones, every single-bit u128 value and two mixed byte patterns
check encoding independently of readback. All 256 byte values and four overflow
values exercise the actual narrowing/default helpers; synthetic shift offsets
exercise the shared checked-conversion/multiplication defaults. All normal writer
helper blocks are covered, excluding panic-only paths and blocks without an entry
path. These synthetic helper cases are not represented as reachable writer inputs.

Logical right shifts and one-byte constant layouts extend the bounded diagnostic
model. Forty-three shift/constant/exact-write controls and 29 poison/constant/
mutation-boundary rejections pass. Existing counter-operation (218 controls/22
rejections), packed-ABI (nine/24), wide-arithmetic (302/76) and zero-argument
(eight/14) tests remain green, along with retained output-write (2,072), core-finish
(560), output-limit (4,928) and counter-decoder (3,792) cases.

This is functional modeling of scalar counters and bounded owner-field effects,
not proof of scalar-copy/register/spill erasure. Squeeze execution/commit ordering,
broader caller/worker qualification and native platforms remain pending. Arm stays
QEMU; F1 and root `PENTEST.md` remain open. No production implementation, original
capture record or release gate changed; no Rust compiler/runtime campaign ran.

Writer log: `dist/debug-counter-write-check.log`, SHA-256
`8aa58cc81c7ef65d3b792c86199ba14a6b039f7a81c9a4c4af883bdbf20df50f`.
Regression log: `dist/debug-counter-write-regressions.log`, SHA-256
`dda386b2a94ff9ad489633e66d4f6724d434db724d6ee1dbdc64dd9bd2145e5a`.

All 648 store/order/arithmetic/iterator/dependency/ABI mutations reject; 32
debug-metadata/SSA controls pass. Eight paths reject 41 mutations each and eight
reject 40; shared decoder helpers retain their earlier mutation coverage rather
than being counted again. The harness forbids subprocess execution. Mutation log:
`dist/debug-counter-write-mutations.log`, SHA-256
`c4b0582385d10893eff9eea9d091335ede0c1ec802763e25a19c4df1e0f70efd`.
Documentation links, script inventory, acceptance metadata and its regression
tests pass without crypto execution.

### Debug byte-squeeze scheduling and counter commit

```sh
python3 assurance/register-cleanup/check_debug_squeeze_operation.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_squeeze_operation.py dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/test_debug_squeeze_model.py
```

This models the actual portable debug byte-squeeze body selected by the producer,
including its actual decoder/writer, checked arithmetic, slice, result-mapping,
output-initialization write and clear-request helpers. The local closure contains
fifty-eight functions; composition with earlier helper sets contains ninety-eight/
ninety-nine functions. The rate is checked independently against the reader
identity, while the staging allocation/clear size stays 168 bytes for both rates.

The full matrix covers 6,208 cases: seven zero/rate/multiple-rate lengths, four
counter values straddling overflow, and failures at every iteration of the
selected one-, two- and three-chunk requests. Overflow precedes work; successful
copies advance the original initializer by the exact chunk length. Returned
write failures still request complete staging clearing before propagation.
Counter bytes are committed exactly once, after complete success, and remain
unchanged on fill, slice or write errors and selected fill/copy unwind. The
counter value, sixteen read/write positions and output descriptor are checked
independently of the event-order assertions.

Fill and copy internals remain explicit boundaries, as does the volatile wipe
primitive. Failure/unwind injection is synthetic, not a claim that those helper
failures are reachable from valid inputs. The zero-length direct-helper case is
a metadata probe, not a constructed Rust zero-length initializer. The modeled
body does not clear the whole owner on its own: outer-guard composition remains
pending. These bounded cases do not establish all-input/helper-block coverage,
arbitrary unwind behavior, secret-copy/register/spill erasure, final-bit squeeze
behavior or native qualification. Existing standalone helper evidence retains
its separately recorded scope. Arm stays QEMU; F1 and root `PENTEST.md` stay open.

Eighteen model saturation/boundary controls pass and seventeen malformed calls
are rejected. No shared model, production implementation, capture record or
release gate changed, and no Rust/native campaign was rerun.

Squeeze log: `dist/debug-squeeze-operation-check.log`, SHA-256
`fdc77068ac33207d1c7db74aeadef58a89a332b2e63ad873da09d708a427b703`.
Model-test log: `dist/debug-squeeze-model-tests.log`, SHA-256
`23b6fbd4d04d30374a6d1ac5437c86ef7082b190119f4e39953c1202b682057c`.

All 736 dependency/ABI/scheduling/cleanup mutations reject (46 per path);
32 metadata/SSA controls pass. Subprocess execution is forbidden by the harness.
Mutation log: `dist/debug-squeeze-operation-mutations.log`, SHA-256
`f6f2d2db7f62cc5454b0501697cf97bb81c6ed16ec06a9e0eaa8884573ac22bb`.

### Preserved source checkout after the CI test correction

The capture's source manifest includes Rust tests. The subsequent ParallelHash
Arm test correction changes that manifest, not production code. Keep the record
unchanged: it does not validate against the corrected main checkout. The ignored
worktree `dist/register-cleanup-review-source` preserves the captured sources from
diagnostic checkpoint `cc5b9add`, where exact source equality and all retained
artifact hashes passed. Subsequent diagnostic-only scripts can be added there
without changing those captured inputs.
Run retained inspections from that checkout, passing an absolute record path:

```sh
record="$PWD/dist/kmac-verify-nft_nl5x/observations.json"
cd dist/register-cleanup-review-source
python3 assurance/register-cleanup/check_debug_squeeze_operation.py "$record"
```

This preserves historical qualification without recollection, source-hash
exceptions or release-gate changes. It does not qualify subsequently changed
implementation code. The checkout and artifacts remain local and ignored;
neither is under Cargo's `target/` directory.

### Composed debug byte-squeeze guard

From the preserved source checkout, using the absolute record path above:

```sh
python3 assurance/register-cleanup/check_debug_squeeze_guard.py "$record"
python3 assurance/register-cleanup/test_debug_squeeze_guard.py "$record"
```

All 7,936 cases pass (496 per instantiated path) through the actual portable
producer/initializer/operation/byte-squeeze/completion/destructor chain. The
ninety-eight/ninety-nine-function sets reuse the existing helper checks. Six
zero/rate/multiple-rate lengths and four counter values cover empty requests,
overflow and success boundaries; terminal readers and all four synthetic
initializer-clear errors are included. Each selected loop iteration is exercised
with all five fill errors, four write errors, missing staging slices and selected
fill/copy unwind. These injections are not claims that each fault is reachable
from valid Rust inputs.

The check requires the original reader to stay inactive during fill and output
transfer. Only successful completion transfers the complete output descriptor
and reactivates it. Errors/unwind request complete output clearing and all thirteen
owner-region clears in the actual guard chain. Counter encoding is committed only
on successful byte squeezing; the model's recorded counter bytes reflect algorithm
writes, not memory contents after the opaque volatile-clear request.

Four synthetic model controls and twelve malformed/unarmed-call rejections pass.
Fill, byte-copy and volatile-wipe internals remain boundaries. This is bounded
functional/event-order qualification, not proof of all-input behavior, arbitrary
unwind, final-bit squeezing or register/spill erasure. Arm remains QEMU. F1 and
root `PENTEST.md` remain open; no production code, captured record or release gate
changed, and no Rust/native campaign was repeated.

Composition log: `dist/debug-squeeze-guard-check.log`, SHA-256
`8fcea16c8242f8aa36e96cb863ad51a2b787834a9e8fb8116af49ab0495ca37f`.
Model-test log: `dist/debug-squeeze-guard-model.log`, SHA-256
`3c2a74d32ce2bfb6207d6a40f511f75ecc8fbf4b8029444736af412f82a32d23`.
The retained dependencies were imported from the matching checkout while the
new inspector ran from the main checkout; its additional SHA-256 is
`b1017b111b7b30a446610a06f0cff801362d0ac2c20c5602eccaee419719571c`.

All 320 handoff/cleanup/commit/unwind mutations reject (twenty per path), and
32 debug-metadata/SSA controls pass. The harness includes both older
`drop_in_place` and newer `drop_glue` destructor symbols; its initial run caught
incomplete mutation coverage of the latter, which was corrected before the full
passing rerun. Compiler/runtime subprocess calls are forbidden in the harness.
Mutation log: `dist/debug-squeeze-guard-mutations-final.log`, SHA-256
`699feb0a56b7150ef9acdba3700c10b3e0c9fde387573a2556156c13114d7251`.
Final mutation harness SHA-256:
`814786a4b5fe9642d2cd68ccb5a2cfad1aa93d8860674aba064268f21e9ebf1e`.

### Direct debug final-bit squeeze

From the source-matching checkout with the absolute record path above:

```sh
python3 assurance/register-cleanup/check_debug_final_squeeze.py "$record"
python3 assurance/register-cleanup/test_debug_final_squeeze.py "$record"
python3 assurance/register-cleanup/test_debug_final_arithmetic.py
```

Both retained-artifact commands optionally accept `--shard 0`, `1`, `2` or `3`.
Each shard covers four disjoint paths; all four are required for the full matrix.
This diagnostic-only partition does not change any release gate.

All 3,888 direct helper cases pass (243 per path). Nineteen newly interpreted
helpers join the earlier byte-squeeze closure in 117/118-function sets. The
matrix covers empty output, every valid tail width, selected rate/multirate
lengths and counter boundaries. All five fill errors, four output-write errors,
missing staging slices/tail references and selected fill/copy unwind are injected
at every iteration for representative one-byte/multichunk shapes. These are
synthetic boundary faults, not claims of reachability from valid Rust inputs.

The complete-byte prefix is counted before the partial-byte tail is processed.
Thus a tail error retains the committed prefix counter inside this direct helper;
the expectation does not incorrectly require all-or-nothing counter mutation.
Successful partial tails request the exact low-bit mask on the original staging
byte, then copy and request all 168 staging bytes cleared. Returned write errors
also request that clear; pre-write errors/unwind rely on the outer guard, which
is not composed by this checkpoint. Public metadata alone is interpreted;
fill/copy/mask/volatile primitive bodies remain explicit boundaries.

The new arithmetic model passes 8,312 controls and rejects 27 malformed/poison
cases. Existing counter/packing/wide-arithmetic/zero-argument/squeeze model tests
also pass. Exact source/artifact validation remains enabled. No production Rust,
captured evidence or release gate changed; no Rust/native campaign was repeated.
F1 and root `PENTEST.md` remain open. Arm remains QEMU; this does not establish
whole-call register/spill erasure or all-input/arbitrary-unwind behavior.

The initial matrix passed Rust 1.90 but stopped at Rust 1.98's renamed
`slice_index_fail` panic boundary. That exact compiler symbol is now recognized
as a forbidden panic call, not treated as successful execution. The complete
four-shard direct check passed after the diagnostic correction.

The new checker ran from the main checkout while unchanged dependencies came
from the preserved checkout. Checker SHA-256:
`ad5b62933b960c37177c1ec49044c4de7c54f18870145df3e19d609e6cdf37a4`;
mutation harness:
`9f1cb185190b3ba3571d77d24fbcc7ae9ce371c3e434927cf81ac3bdbfad0210`;
arithmetic model test:
`41098f2462a751a036b68579e0b2dd07fd7080444ac54e76d9ee0199bf3da063`.
The shared model hash recorded in the logs is
`208ad72a0b12274575d774c6752a25383b03f673cc1d66de717a6d25b109e99d`.
Identical final diagnostic files are preserved in the source-matching checkout.

Retained logs (all paths relative to ignored `dist/`, outside Cargo clean):

| Log | SHA-256 |
| --- | --- |
| `debug-final-squeeze-check-shard-0.log` | `f6606b29452c82aa0fc1ee37a06fd0ece849801d01fea182fdbe80857a6cea20` |
| `debug-final-squeeze-check-shard-1.log` | `787421a656708ea147e183cd6eacb1e388c69da03ccaad8f7d41188e7315c036` |
| `debug-final-squeeze-check-shard-2.log` | `734f1673329bf7d290dbd1eba8618782e2687a1c0f5c4c74f6212eeeb63dbe6b` |
| `debug-final-squeeze-check-shard-3.log` | `61e1dc2f0e3cd1727dc140c674e59e072c4ead6bcb729deacb3cd98d5e1814dc` |
| `debug-final-squeeze-model.log` | `d80f86451c2e8e6eb33aa22ada8dd47f39e70916eba3a7344b7ce24c6f9ca050` |
| `debug-final-squeeze-mutations-shard-0.log` | `8a4a7b5875d08a2ea75ac2aa2efac48600bbaf01738cec19fb6cc5cc7e09e794` |
| `debug-final-squeeze-mutations-shard-1.log` | `03dea3c94015c6083ed420b5ac1ba705225a22eb847dc442227662def030ef96` |
| `debug-final-squeeze-mutations-shard-2-final.log` | `e7ba946722b3149869609bfe5593265b3fb08c9d43d41d717ed20a0c5a4b72bf` |
| `debug-final-squeeze-mutations-shard-3-final.log` | `5a3d2e832dec0284fd370424bb50369d447e0cd16bc2ee3c63295905f96ec8d2` |

All 672 retained-IR mutations reject (42 per path), with sixteen passing SSA
rename controls. The internal complete-byte/mask helpers also pass 20,480
controls over every u8 tail value and four selected lengths; this does not imply
the public API accepts invalid tail shapes. The boundary model passes 26 controls
and rejects twelve malformed/unordered calls. Compiler/runtime subprocess calls
are forbidden throughout the mutation harness.

Rust 1.90 mutation shards 0/1 started with inspector SHA-256
`26dd3422a2726cba50dc673c3f4ed588143968c3cefbcad67246bad43d3a01b5`,
retained as `dist/debug-final-squeeze-initial.py`. Shards 2/3 use the final
inspector above. The differences are only the Rust 1.98 forbidden-panic symbol
and optional direct-check shard dispatch; the Rust 1.90 interpreted behavior and
mutation expectations are unchanged. Their completed results were reused rather
than repeated. The initial unsharded/interrupted and pre-correction failure logs
remain in `dist/` but are not passing evidence for the complete matrix.

### Composed debug final-bit producer guard

From the preserved source-matching checkout, with the absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_final_guard.py "$record"
python3 assurance/register-cleanup/test_debug_final_guard.py "$record"
```

Both commands accept optional `--shard 0`, `1`, `2` or `3`; all four disjoint
shards are required for the complete matrix. All 5,984 composed cases pass
(374 per path) using the same 117/118-function sets as the direct final-bit
checkpoint. This connects the actual initializer, producer operation, final-bit
body, byte-prefix body, completion and guard/destructor chain. It includes
empty output, terminal readers, four initializer errors, all valid tail widths,
selected rate/multirate lengths and counter boundaries. Representative one-byte
and multichunk shapes exercise every loop iteration with synthetic fill/write/
slice/tail failures and selected fill/copy unwind.

The original guard remains armed during fill, mask and output transfer. Exact
initialization progress is retained until successful descriptor transfer or
destruction. Failures after processing starts and selected unwind request complete
destination clearing and all thirteen owner-region clears. Initializer failure
also deactivates and requests owner clearing. Already-terminal rejection requests
output clearing without reading counters or requesting another owner clear.
Tail failures retain any earlier
prefix-counter commit before those opaque wipe requests; the diagnostic does
not mistake an unchanged numeric counter for proof of complete cleanup.
Only successful producer completion restores the borrowed reader's active flag.
The outer consuming-reader wrapper still consumes the public final-output API;
that separately checked wrapper is not composed in this checkpoint.

Six synthetic boundary controls pass and eighteen malformed/unarmed calls
reject. Fill/copy/mask/volatile primitive bodies remain opaque. These bounded
event-order checks do not prove arbitrary unwind, secret-value erasure,
whole-call register/spill cleanup or native Arm execution. F1 and root
`PENTEST.md` remain open. No production Rust, captured sources or release gate
changed, and no Rust/native campaign was repeated.

Both new diagnostics ran from the preserved checkout; the complete inspector
source hashes are included in each direct-check log. Checker SHA-256:
`869c507831768e82dd7ca417e0e7a70cbc7124016c8068e70659b305633b3d5f`;
mutation harness:
`4f2c776afa4518b4144db9992f9dde9fc72a9a046f8d035dca3aa1cf6e18c183`.

All 352 retained-IR mutations reject (22 per path), with sixteen passing SSA
rename controls. They cover omitted final/prefix handoffs, premature completion,
missing masking/counter commits, altered guard activation, missing output/owner
destructors, omitted first/last owner-region clears and swallowed unwind. Both
`drop_in_place` and `drop_glue` compiler spellings are covered. The mutation
harness forbids compiler/runtime subprocess execution; it does not rebuild Rust.

All logs are under ignored `dist/`, outside Cargo's `target/` directory:

| Log | SHA-256 |
| --- | --- |
| `debug-final-guard-check-shard-0.log` | `84aecfd07459ee10dc3e36d4630dc409ffb3227a7396c85c055788222686acb4` |
| `debug-final-guard-check-shard-1.log` | `d0e1086b16fa30158c5804f6b5b48a776e594466d76dc5d506b2139561c014f4` |
| `debug-final-guard-check-shard-2.log` | `7882636d4e17e2dd739f0846a63bfa73b748c37a0fb284bf67e7518d14f0431c` |
| `debug-final-guard-check-shard-3.log` | `45f2e0749fe0587a99910bb2d5825477ed7ff43c8637b0380fe4faa08824d64e` |
| `debug-final-guard-mutations-shard-0.log` | `9b8749a162bc3382cd30c1ff2efe45dfe7ef33106d50af717ce33e3aa15275e3` |
| `debug-final-guard-mutations-shard-1.log` | `660f5678db39dfd1095ff72af4e801f3ae7ed09299c65265bfdb81ebef436109` |
| `debug-final-guard-mutations-shard-2.log` | `cf1627d4ab2c9ce9f48a99d4f25d2d9c1209e934aa11635abd493716365bb84e` |
| `debug-final-guard-mutations-shard-3.log` | `d7912d691f19db9ac62b0f8ee3bd27c26965a1dee158525784a094629ee56183` |

### Composed debug consuming final reader

From the same preserved source-matching checkout and absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_consuming_final.py "$record"
python3 assurance/register-cleanup/test_debug_consuming_final.py "$record"
```

Both accept optional `--shard 0`, `1`, `2` or `3`; all four disjoint shards are
required for the complete sixteen-path matrix. These diagnostics connect the
actual KMAC consuming trait bridge, checked output constructor, SHA-3 consuming
reader and original guarded final producer. Shared helper definitions must
agree before merging the 149/150-function closures. No captured implementation
or release-gate policy changes, and no compiler/native campaign is repeated.

The producer first passes its independent arithmetic/lifecycle/event-order
oracle. Its trace is then compared against execution through the actual wrapper,
including real compiler-local reader and result descriptors. Diagnostic guard
observations refer to that original reader address; no replacement reader or
manufactured descriptor is supplied to the compiled helper bodies. Exact counter
reads/writes, output progress, exception identity and result conversion remain
bound across the handoff. An admitted producer's result is transferred to the
public return descriptor after consuming cleanup. A shape-rejection error is
stored earlier, but owner cleanup still precedes return.

Consuming cleanup requests all thirteen owner-region clears even when the
producer already requested cleanup after failure. The check distinguishes these
two requests rather than claiming a numeric counter rollback or exactly one wipe
for the whole call. Shape rejection occurs before destination initialization:
the consumed owner is cleared, but that path does not promise destination erasure.
Constructor unwind is synthetic; fill/copy unwind is injected at the previously
documented primitive boundaries, not at every machine instruction.

All 6,272 composed cases pass across sixteen paths (392 each), including empty
output, all valid final widths, rate/multirate and counter boundaries, terminal
readers, initializer failures, fill/write/slice/tail errors and selected unwind.
The existing producer oracle is also rerun over its 5,984 modeled cases before
trace comparison. Four synthetic address-binding controls and eleven malformed/
inactive-call rejections pass. All 192 retained-IR mutations reject (twelve per
path), with sixteen passing SSA rename controls. Mutations omit the producer or
normal/unwind destructor calls, corrupt forwarded length/mode/valid-bit metadata,
swallow exceptions or introduce direct secret-payload reads. Both compiler
destructor spellings are covered.
The mutation harness forbids compiler/runtime subprocesses. Secret fill, copy,
mask and volatile primitive bodies remain opaque. This does not qualify arbitrary
unwind, whole-call register/spill erasure or native Arm execution. F1 and root
`PENTEST.md` remain open.

Checker SHA-256:
`5fd9b1000b3c0d48fe1ba3c30027641c962dd4251a3487c2af555aa51a10c1a9`;
mutation harness:
`87137529611eca403ae6290b4be8c0f760ee19585cef184d9f9afb98baff5877`.
Logs use `dist/debug-consuming-final-{check,mutations}-shard-{0,1,2,3}.log`,
outside Cargo's `target/` directory.

| Completed direct-check log | SHA-256 |
| --- | --- |
| `debug-consuming-final-check-shard-0.log` | `0808ad313c06443b6bab12949265c48906956e6013bf20e1ac62946f2c49eb30` |
| `debug-consuming-final-check-shard-1.log` | `4f85fff67a182a375818aa41801e28d76d00f8bd240eb0ef762e8ff673a3a566` |
| `debug-consuming-final-check-shard-2.log` | `1b2c4afbe5d478b4b71160ff3de27c02fb59338d723d68ace2e335c581a70f6b` |
| `debug-consuming-final-check-shard-3.log` | `57eea9d5482601d8e9f79c3a5e49b3b0267fb12498c1ae9782319f34e48b7b6c` |

| Completed mutation log | SHA-256 |
| --- | --- |
| `debug-consuming-final-mutations-shard-0.log` | `dd59a8919e79dae340136d165a70fd1be2da6a9a6b9ff7db5cf0b06605b24951` |
| `debug-consuming-final-mutations-shard-1.log` | `610d128f98479dae8ddb0b6a52f43b3ed9bbb704a6a46b4efd2fb8bebda95127` |
| `debug-consuming-final-mutations-shard-2.log` | `2db729b9319c1dc0d6c10dfbaeb91bc88e03a51257618ac418143d40c653e7df` |
| `debug-consuming-final-mutations-shard-3.log` | `96af782998cccc50468f3e716e86e5cb56d5fc14aea16679ab8432eb3366e0fd` |

### Composed debug bulk reader and byte producer

From the same preserved source-matching checkout and absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_bulk_guard.py "$record"
python3 assurance/register-cleanup/test_debug_bulk_guard.py "$record"
```

Both accept optional `--shard 0`, `1`, `2` or `3`; all four disjoint shards are
required for the complete sixteen-path matrix. This closes the portable
bulk-reader/producer link: the KMAC trait bridge, SHA-3 wrapper, error conversion
and actual guarded byte producer execute together in 103/104-function closures.
The same-configuration helper definitions must agree before composition. The
producer first passes its independent arithmetic/lifecycle/event-order oracle;
the composed execution must preserve its exact trace through the public result.

All 7,936 cases pass (496 per path), including empty and rate/multirate output,
counter limits, inactive readers, initializer failures, fill/write/slice errors
and selected fill/copy unwind. The producer receives the original borrowed
reader, destination and length, with byte mode and no final-bit metadata. Its
compiler-local result is interpreted directly, not synthesized by the wrapper
model. Counter reads/writes, output progress, cleanup requests, error conversion
and original exception identity must match. Successful completion alone restores
reader reuse. Unlike the consuming-final API, this borrowed wrapper does not add
an unconditional owner clear after a successful producer call.

All 256 retained-IR mutations reject (sixteen per path), with sixteen passing
SSA rename controls. They omit/duplicate handoffs, change reader/destination/
length/mode/tail metadata, erase or misclassify errors, or read payload directly.
A synthetic valid handoff and eight malformed/duplicate calls also pass.
The producer oracle is checked once per original quick-test case; mutations may
reuse it only after asserting the complete producer/helper closure is unchanged.
The mutation harness forbids compiler/runtime subprocesses. No compiler/native
campaign was repeated and the original source/artifact validation still passes.

This is metadata/control-flow composition, not qualification of opaque fill,
copy or volatile primitive bodies, whole-verifier register/spill erasure,
arbitrary interruption or native Arm execution. The retained Arm runtime evidence
is QEMU. F1 and root `PENTEST.md` remain open.

Checker SHA-256:
`d0c6f10a8b2125b3ec7b0106f6c4ed628ddd455a56abf1e69eb67ab840bdd7c6`;
mutation harness:
`e389ec01cc61b4670ce0cd9ee351e453f78bcf9d00e2f85d67192ead8047d081`.
The observation record is unchanged:
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
Logs below live under ignored `dist/`, outside Cargo's `target/` directory.
Mutation shard 0 completed through the harness's `main(record, 0)` under the
same subprocess prohibition, with exit 0, 64 rejected mutations and four passing
controls. Its output was observed in the execution console, not redirected to a
retained file; no retained-log hash is claimed for that shard.

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-bulk-guard-check-shard-0.log` | `7c1b59a7dc94c19a40af1b16f529615c4c0de1484a78442f9aa2dd3bc3396b7c` |
| `debug-bulk-guard-check-shard-1.log` | `cb3cfb7ec7ad4c072c25e2cbd61bf983f846c1c9b6a3a1a9f30fb1e003ca3394` |
| `debug-bulk-guard-check-shard-2.log` | `1ad8ef237d67144dc49d7372e8b31796e9540fb1cd9c79f3ea5e1d30eb9afda1` |
| `debug-bulk-guard-check-shard-3.log` | `47349063e4246632073c82b7cc18ce85a78bddfa8833863575aac349fc21c17e` |
| `debug-bulk-guard-mutations-shard-1.log` | `98241ddcabc428cc04e5fa6d920bf8c09135dc187e291bcdce654157b30d4dc9` |
| `debug-bulk-guard-mutations-shard-2.log` | `fec580ec0a9182ebfa0441fbac3e0c2159bbd6c98b12b8c13529516a5ecf72a5` |
| `debug-bulk-guard-mutations-shard-3.log` | `85206e7e0deb0cf851b40ba6f0705c162f436b974c0e01d947537db7c5813adb` |

### Debug staging-fill helper

From the same preserved source-matching checkout and absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_staging_fill.py "$record"
python3 assurance/register-cleanup/test_debug_staging_fill.py "$record"
```

Both accept optional `--shard 0`, `1`, `2` or `3`; all four disjoint shards are
required for the sixteen-path matrix. The reader-selected debug `fill_staging`
body includes its actual 32-function helper closure: range selection, cursor
access/narrowing, checked arithmetic, slices, result conversion, core copy
wrapper and scratch-clearing wrappers. The three primitive boundaries are the
actual same-configuration scalar, byte-copy and volatile-clear definitions;
each must retain its borrowed void ABI. The scalar receives the original
state and three scratch addresses, plus the exact immutable 192-byte round
table checked against the existing independent oracle in the source closure.

All 43,136 cases pass across sixteen paths (2,571 per 168-byte-rate path and
2,821 per 136-byte-rate path). The independent range model covers all cursor
bytes for selected counts, all counts from 0 through 169 for selected cursor
positions, maximum integer count rejection, copy failures and selected scalar/
copy unwind. It checks exact state-to-staging copy ranges, successful byte-copy
handoffs, cursor writes only after successful copies, state-consumed/output-size
errors, permutation at the rate boundary and three scratch-clear requests before
resetting the cursor. Empty fill performs no cursor update or permutation, even
for an invalid stored cursor; oversized fill is rejected before processing.

All 320 retained-IR mutations reject (twenty per path), with sixteen passing
SSA rename controls. Mutations alter fill/cursor admission, staging/source
addresses, cursor/permutation handoffs, scratch clear calls/widths, scalar
operands/constants, primitive return ABIs, or introduce direct secret loads.
The mutation harness forbids compiler/runtime subprocesses. Source/artifact
validation still passes; no compiler or native campaign was repeated.

The scalar, byte-copy and volatile bodies are opaque in this geometry check.
Synthetic primitive unwind preserves the exact event prefix and original
exception; this standalone helper does not promise cleanup after an interrupted
primitive. Its enclosing squeeze/operation guard must still be composed with
the fill body. Existing separate primitive checks are not automatically a
whole-call register/spill guarantee. Arm runtime evidence remains QEMU, not
native qualification. F1 and root `PENTEST.md` remain open.

Checker SHA-256:
`88ab58276da11575d10710959ce61ad41a4b8f8f62fd8f9493eb3443e3dba730`;
mutation harness:
`1a0927e96215ae0b4e04af156e53a1c5a15cd3db1ede2d4b779c7725ed045ca2`.
The observation record remains
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
All logs below live under ignored `dist/`, outside Cargo's `target/` directory.

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-staging-fill-check-shard-0.log` | `c35e69a40ff1b53c4566264933e9dc368d4db32393b5631bd2a77b49dc6db319` |
| `debug-staging-fill-check-shard-1.log` | `2c3fa93f6caaa2932e32134d0ec45485c72558235509bf8b096278b780c44232` |
| `debug-staging-fill-check-shard-2.log` | `d76b39051c69a02f7491f122a78f5178ebf9d9acf0deb67dc33742f70896b1a3` |
| `debug-staging-fill-check-shard-3.log` | `935da83cf9332b36b9cfb316201389fd228c7568756ea9bcd618045e7da51ad0` |
| `debug-staging-fill-mutations-shard-0.log` | `5bc71d3ba9064d776481ec3aab44621dc3317a1e1a562879910978ba10282eb8` |
| `debug-staging-fill-mutations-shard-1.log` | `59a84a399aef0d44180d3c8a96be6c9dca8ea618bef946235c54f03fa8e87ecc` |
| `debug-staging-fill-mutations-shard-2.log` | `2366fa8a456a536d419c8c440db10ec45685f9e296b897407c199b5665c51b70` |
| `debug-staging-fill-mutations-shard-3.log` | `95b9e5540476b5b08389af0b556c9d9e6cbee6e45a00dfee4539e2d518d74717` |

### Staging fill inside the debug byte squeeze and owner guard

From the same preserved source-matching checkout and absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_filled_squeeze.py "$record"
python3 assurance/register-cleanup/test_debug_filled_squeeze.py "$record"
```

Both accept optional `--shard 0`, `1`, `2` or `3`; all four disjoint shards are
required for the sixteen-path matrix. The previously checked fill body now runs
inside the actual byte squeeze, initializer, operation/completion and owner-guard
chain. Shared helper definitions must agree before combining the 118/119-function
closures. The original guard stays armed during fill and output transfer.
The same model executes the actual fill body and carries its cursor across
chunks; it does not replace the fill with a success/error stub. Scalar, byte-copy
and volatile-clear bodies remain explicit primitive boundaries.

All 3,760 cases pass (235 per path). Selected empty, one-byte, rate and multirate
outputs combine with cursor boundaries, counter limits, terminal readers,
initializer errors, first/second staging-copy rejection, synthetic primitive
unwind and output write/slice/transfer failures. The oracle independently expands
each chunk's geometry into the enclosing progress, error, cleanup and result
trace. A copy failure cannot commit that chunk's cursor; an output failure may
follow a successful staging fill. Such errors preserve the exact intermediate
algorithm effects and request complete destination and thirteen-region owner
clearing. Only total success commits the output counter and reactivates the
reader. Cursor/counter shadows describe algorithm writes before opaque clear
requests, not the contents of actually cleared memory.

All 336 retained-IR mutations reject (twenty-one per path), with sixteen passing
SSA rename controls. They alter guard state, omit handoffs/destructors, swallow
unwind, zero or skip fill work, or remove inner-scratch/full-owner clear requests.
Two synthetic boundary controls and ten malformed/unarmed access rejections
also pass. The mutation harness forbids compiler/runtime subprocesses.

The first mutation run stopped on owner-wipe symbol discovery in Rust 1.98;
the harness's selector was corrected to support both legacy and v0 mangling
without confusing the full-owner wipe with `wipe_permutation_scratch`. All four
mutation shards were rerun using the final harness below. Earlier unversioned
mutation logs are superseded; the unchanged direct-check logs remain valid.
Source/artifact validation still passes. No compiler/native campaign or full
verification sweep was repeated.

Synthetic unwind exercises modeled propagation/cleanup ordering. It does not
assert that an extern-C primitive actually unwinds, nor cover arbitrary
instruction interruptions, abort or signals. Final-bit staging composition,
whole-verifier paths and whole-call register/spill behavior remain outstanding.
Arm runtime evidence remains QEMU, not native qualification. F1 and root
`PENTEST.md` remain open.

Checker SHA-256:
`606896e96aa24d73e22e29b3c50a605a79238217ae91a35aa22b4c53a8c9b741`;
final mutation harness:
`9ce4f40bf7d0e87af969ed898cb285cbd29b543f3c536c3a8f80389d75cd4b51`.
The observation record remains
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
All logs below live under ignored `dist/`, outside Cargo's `target/` directory.

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-filled-squeeze-check-shard-0.log` | `ff18ae6ed8bb4c02ecb8193f76cba337c8728259d2131096c267a972b96cf5f5` |
| `debug-filled-squeeze-check-shard-1.log` | `7da291a397b7862c652ea720947a4ecff4de0482d388c06c2092b00bffa18745` |
| `debug-filled-squeeze-check-shard-2.log` | `3f33b12a07d5b48c3fbbc8d2aeb59d9064d5083a0dc8bf1ec58b6ee0aed8497c` |
| `debug-filled-squeeze-check-shard-3.log` | `0fa5e6069a5db03cf3f952ca5cc5af5a7fb7e0496d2b73799c9a20b58c68e8dd` |
| `debug-filled-squeeze-mutations-v2-shard-0.log` | `6c6afd745a5ec0cf60bcb5c8d9ad424a4a0c6e785d7fcfb0662397c16b222ff4` |
| `debug-filled-squeeze-mutations-v2-shard-1.log` | `c53e14b3633f1f58424e0aa1505841eda6ef92827e06335929e7818491378538` |
| `debug-filled-squeeze-mutations-v2-shard-2.log` | `3fd4e5d9134506a961190c00b59e13b8dc170e364296c852070b67b35eeab676` |
| `debug-filled-squeeze-mutations-v2-shard-3.log` | `f960e43246f190929a466c5a04c612a983c43f56cf6db005eecd9e70c58d51a8` |

### Staging fill inside the guarded debug final-bit squeeze

From the preserved source-matching checkout and absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_filled_final.py "$record"
python3 assurance/register-cleanup/test_debug_filled_final.py "$record"
```

Both accept `--shard 0`, `1`, `2` or `3`; all four shards are required. This
extends the byte composition with the actual final-bit helper and dependencies,
requiring matching definitions at shared boundaries. The 137/138-function
closures interpret staging fill inside the original producer, initializer and
owner guard. The final-shape and staging-geometry oracles independently compose
the expected trace; they do not derive expectations from the model's events.

The matrix covers empty output and all eight valid final-byte widths at selected
one-byte, rate-boundary and multirate lengths, combined with staging cursors,
counter boundaries and inactive readers. Selected initializer errors, inner
copy rejections, synthetic permutation/copy unwind, output-write errors and
missing staging slices exercise failures before and after prefix completion.
The final mask must target the original staging byte. Cursor progress persists
across prefix/tail fills. A successfully completed prefix may commit its counter
before a tail failure; that failure must still request complete destination and
thirteen-region owner clearing and leave the reader inactive. These cursor and
counter observations describe algorithm effects before opaque clearing, not
post-clear memory contents.

The mutations cover guard state, skipped handoffs/destructors, swallowed unwind,
skipped/zero-width fill, missing scratch/owner clears, missing tail masking,
wrong tail width/mask arguments and incomplete staging clearing. Harmless SSA
renames remain positive controls; compiler/runtime subprocesses are forbidden
by the mutation harness.

Scalar, byte-copy, mask and volatile-clear primitive bodies remain opaque here.
Synthetic primitive unwind is a model fault, not a claim that an extern-C call
can unwind, nor coverage of abort, signals or arbitrary interruptions. The
consuming wrapper is not composed with this filled chain yet. Whole-verifier,
register/spill and native-platform qualification remain outstanding. The Arm
runtime record remains QEMU evidence. F1 and root `PENTEST.md` remain open.

All 17,680 cases pass (1,105 per path). These are sixteen portable-reader paths
present in the retained debug portable/accelerated builds, not qualification of
accelerated-reader guards. All 464 retained-IR mutations reject (twenty-nine per
path), with sixteen passing SSA controls. Three synthetic boundary controls and
seventeen malformed/unarmed-access rejections also pass. Every shard exited
successfully. Source/artifact validation, assurance freshness, script inventory,
verification-status regressions, acceptance metadata and documentation links
pass. No production implementation or release-gate policy changed; no compiler,
native campaign or full verification sweep was repeated.

Checker SHA-256:
`8193879bedeab7372d98492ddcd9a1e281a0cba7e82ad5bd3f913b1c8fbaa99f`;
mutation harness:
`7a5e11e558e4aa0482314d511fa8679bf13a779733c46c9e30884dcea7fd4f61`.
The observation record remains
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
Logs live under ignored `dist/`, outside Cargo's `target/` directory. Mutation
shard zero's log preserves the completed process's captured stdout; the other
logs were redirected while their processes ran.

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-filled-final-check-shard-0.log` | `59fcfc664033aec002fc0f266b28307c26a8b7cede28805ff33df7f4a9d16b3b` |
| `debug-filled-final-check-shard-1.log` | `56a824535f71cf8898ff6a729e70989346d0d4efbc1836875becb154ca5c8c47` |
| `debug-filled-final-check-shard-2.log` | `3dcef5f77489e0b62c499754b3b6069b486294ecd029e7c1f23370689d988b08` |
| `debug-filled-final-check-shard-3.log` | `7defa0d68959323a896de602e491e66d6f28a84cc86621638c53f38ef95233a0` |
| `debug-filled-final-mutations-shard-0.log` | `7674e26dbebedae64b293d5c2bb1288b3de3e8391cd7d2c63d2a7aed12076d45` |
| `debug-filled-final-mutations-shard-1.log` | `26095738ac850bf2ca23a34a16ad2a1f19044ab6b9355112014e8e5a91c1d538` |
| `debug-filled-final-mutations-shard-2.log` | `c8f2e33923c22ac74cf91aae57cd2a47bd7a5ec88eaf3fe683f6998f3d5ad5c5` |
| `debug-filled-final-mutations-shard-3.log` | `daf302211393a29fb74b3e5eaf0d5c1149eaec3b1287faba1dd3daed826daf71` |

### Consuming wrapper around the staging-filled debug final-bit chain

From the preserved source-matching checkout and absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_filled_consuming.py "$record"
python3 assurance/register-cleanup/test_debug_filled_consuming.py "$record"
```

Both accept `--shard 0`, `1`, `2` or `3`; all four shards are required. This
composition starts at the actual portable consuming-reader trait bridge and
includes output-shape construction, the guarded producer, final-bit squeezing,
staging fill and the consuming destructor. Shared helper definitions must match.
The original compiler-local reader/result descriptors are used without creating
a replacement reader allocation. Symbolic guard observations are valid only
while that actual producer is active.

The expected trace combines the existing independent staging/final-shape oracles
with explicit producer and consuming lifecycle rules. It does not execute a
second copy of the producer as its own oracle. The matrix adds malformed output
shapes and synthetic constructor unwind to the filled-final scenarios. Rejection
before initialization consumes/clears the owner but does not promise to clear a
destination whose shape was never admitted. On an admitted request, constructor,
producer, prefix/tail effects, error translation and final owner cleanup must
appear in the exact order. Even successful inner reader reactivation is followed
by consuming-owner cleanup; no reusable reader is returned.

The mutation suite combines consuming-handoff/destructor/secret-read regressions
with the inner guard, staging, tail-mask and cleanup mutations. The synthetic
boundary fixture initially omitted the initializer required by its manually
activated squeeze state. That fixture setup was corrected after its test workers
exited; the unchanged direct checker continued running. The final mutation runs
use `mutations-v2` logs; earlier unversioned mutation logs are superseded.

Scalar/copy/mask/volatile primitive bodies remain opaque in this composition.
Cursor/counter shadows record algorithm effects before opaque wipe requests,
not post-clear memory contents. Synthetic unwind is not proof of real extern-C
unwind, abort/signal cleanup or arbitrary-interruption behavior. This remains
portable-reader coverage, not accelerated-reader guard qualification. The Arm
runtime record is QEMU, not native. Whole-verifier and whole-call register/spill
qualification remain outstanding; F1 and root `PENTEST.md` remain open.

All 17,968 composition cases pass (1,123 per path) in 167/168-function closures.
These are sixteen portable-reader paths present in the retained debug
portable/accelerated builds. All four direct-check shards exited successfully.
All 656 retained-IR mutations reject (forty-one per path), with sixteen passing
SSA controls. Six synthetic binding controls and twenty-one malformed/inactive
call rejections also pass. All four final mutation shards exited successfully.
Source/artifact validation, generated-assurance freshness, script inventory,
verification-status regressions, acceptance metadata and documentation links
pass. No production Rust, dependencies, captured implementation or release-gate
policy changed. No compiler/native campaign or full verification sweep repeated.

Checker SHA-256:
`5ffb4153400bca77149a944c7e2e906e7d2b98939961c33e1afed02d83df55e3`;
final mutation harness:
`229c60c663b4e5e13c39fd0c6b624a301c5e31d248a53d102c5833b6623c5646`.
The observation record remains
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
Completed logs live under ignored `dist/`, outside Cargo's `target/` directory.

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-filled-consuming-check-shard-0.log` | `4aa9c556d020a73132e04b26211024bc3cc86cf7ffdf3a3eb1117e53029ea601` |
| `debug-filled-consuming-check-shard-1.log` | `963ac67d5c6b3db2121f115939ee4a04fdd2afc5d3e5c1088435df20f4871bad` |
| `debug-filled-consuming-check-shard-2.log` | `9a6f0d1b39b0c0a7e1181d0e0f63d49d569e0d12740517af6383b4ac78541a9e` |
| `debug-filled-consuming-check-shard-3.log` | `4b798c7f93b4d9d9d55659781594f040a939f09e3fc6d4fc7fa3719a57bd1836` |
| `debug-filled-consuming-mutations-v2-shard-0.log` | `7b87eb0c74d7f810d40b53b9753b0a3d75ae739d51a7356b84c0dca502552f19` |
| `debug-filled-consuming-mutations-v2-shard-1.log` | `63bb12db08a00fb8bbdccf1e99b92d8b88b64f6c74731016bb91d6f3ac967941` |
| `debug-filled-consuming-mutations-v2-shard-2.log` | `462f6d2801903671808901b8e57a19c3ca5e8c16170fbe49ce47152d3f45949f` |
| `debug-filled-consuming-mutations-v2-shard-3.log` | `d0101324ed8e5fdd5846c3a1a281e1aca16112f52ae494a3b4ba43affce24859` |

### Accelerated debug producer and local guard

From the preserved source-matching checkout and absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_accelerated_guard.py "$record"
python3 assurance/register-cleanup/test_debug_accelerated_guard.py "$record"
```

Both accept `--shard 0` through `7`; all eight shards are required. The matrix
covers Rust 1.90/1.98, x86 GNU/Arm musl and 128/256 accelerated debug producers.
Each 22-function closure includes the actual producer, borrowed operation guard,
result/error helpers and owned-region clearing wrappers. Original output,
initializer, mode, length and storage captures must remain bound; the operation
receives the original storage under an armed local guard. Only success changes
the guard completion bit from zero to one.

The independent lifecycle oracle requires staging clearing even on success.
Initialization errors, operation errors and selected synthetic unwind request
terminal storage metadata updates and six exact owned-region clears. Predicate
unwind after a successful operation also clears the returned destination. The
initializer and operation bodies are opaque synthetic boundaries: operation
unwind checks owner cleanup here, not the destination cleanup inside the opaque
operation. Metadata copies and volatile clearing are likewise modeled boundaries.
This does not qualify CPU admission, read-loop contents or physical erasure.

All 10,752 cases pass (1,344 per path). Selected reachable root/local-guard blocks
are exercised, excluding the known pre-transfer initializer unwind arm and
double-panic/unreachable blocks. This is not exhaustive block coverage of all
22 helpers. All 760 mutations reject (94 per Rust 1.90 path, 96 per Rust 1.98
path), with sixteen passing debug-metadata/SSA controls. Mutations cover ABI,
capture/storage provenance, direct payload reads, omitted/duplicate cleanup,
guard completion, result branches and exception propagation. Compiler/runtime
subprocesses are forbidden in the mutation harness.

The initial mutation harness assumed a hash-core artifact field unavailable in
these cases. Its next run assumed an initializer alignment annotation that Rust
1.98 omits. Both harness-only issues were corrected; all eight final `v3` shards
exited successfully. Earlier mutation logs are superseded. The direct checker
was unchanged, so its completed logs were reused. No production Rust, captured
implementation, dependency or release-gate policy changed; no compiler/native
campaign or full sweep was repeated.

Initializer/operation-body composition with the checked guard and reader bridges
remains pending, as do whole-verifier and whole-call register/spill qualification.
Synthetic unwind does not establish real extern-C unwind, abort/signal cleanup
or arbitrary-interruption behavior. Arm runtime evidence remains QEMU, not native.
F1 and root `PENTEST.md` remain open; this is author diagnostic evidence.

Checker SHA-256:
`6ff9b911c619e407ebe7bff449c7b334679dadf5281e5dde8b702deb1e244e2f`;
final mutation harness:
`5f0488da6bad5f527e267ee3ff9df0e3dc6460bc91de5279758b57b0901a731e`.
The observation record remains
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
Completed logs remain under ignored `dist/`, outside Cargo's `target/` directory.

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-accelerated-guard-check-shard-0.log` | `b5829c37c7effe0a2c1aa7c7360eb33398b733e7b105ebdf271ee4a9a73dd945` |
| `debug-accelerated-guard-check-shard-1.log` | `fb0d9ae41b8a6f015de58d742e55f572dda6fb1fe4e54dc31f04d4866b32b41e` |
| `debug-accelerated-guard-check-shard-2.log` | `0f051c918563f746505daaf22660a5a3077d143e1b3ee3d096882c6e8b59dfff` |
| `debug-accelerated-guard-check-shard-3.log` | `b1617711fc74fbbfee928b6cd6358be38c3371e626c62cc756d799e585dc2ce6` |
| `debug-accelerated-guard-check-shard-4.log` | `9fc3d3360d567c6dab8dd28ac3a5324a6896ed489ad899c53767d9fbb3c6cf0b` |
| `debug-accelerated-guard-check-shard-5.log` | `b75ac51b9dba2e3a83f5823e27f4d7e40517e138cbea6f407394b3687ceaaa99` |
| `debug-accelerated-guard-check-shard-6.log` | `8ce79635c3955ca7918005099359f277bd8d2f8e0c109e09558cd097b8dd8d32` |
| `debug-accelerated-guard-check-shard-7.log` | `077c94460194afd83e0c599d156408c08987b1c16f6e1d1e3b11c5c81e41d19e` |
| `debug-accelerated-guard-mutations-v3-shard-0.log` | `e982f33d6e608813caa223d966dcfdaebd66e2aa3640abf46a291a544fa5ed3f` |
| `debug-accelerated-guard-mutations-v3-shard-1.log` | `ce5a36953087182262c5c1bd397ed096cdbcdd3a404bfb8e017650e49d3de9e9` |
| `debug-accelerated-guard-mutations-v3-shard-2.log` | `969a5ddf30591e937091f7c512b94ba318b2288a098bcbf1c1623c143d6cb412` |
| `debug-accelerated-guard-mutations-v3-shard-3.log` | `1e10843dc0f233c05e542263abf0790180a0089ebb8922fe684e94c27934e6b8` |
| `debug-accelerated-guard-mutations-v3-shard-4.log` | `d155a3415ba58457a9c5f770ac47aaf43cb3d6e623268f32c9c604594b7d42e4` |
| `debug-accelerated-guard-mutations-v3-shard-5.log` | `5cbf9e6e9f51df93f3c6f8408a30fa15470339029b731dc60e0cc0d15a404703` |
| `debug-accelerated-guard-mutations-v3-shard-6.log` | `8e8b8bbdd3f891d0acd5b1fe8dba5f4b1ed65a4c44e90c0fd468f39834cfe1b9` |
| `debug-accelerated-guard-mutations-v3-shard-7.log` | `9269bfd3749faa0df3f1368af992d1edfaf4ce899130b5b60e7e138100676a67` |

### Accelerated debug initialization, chunk loop, completion and guard

From the preserved source-matching checkout and absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_accelerated_operation.py "$record"
python3 assurance/register-cleanup/test_debug_accelerated_operation.py "$record"
python3 assurance/register-cleanup/test_debug_exception_phi.py
python3 assurance/register-cleanup/test_debug_accelerated_model.py
```

The first two commands accept `--shard 0` through `7`; all eight shards are
required. This composition includes the actual output initializer, accelerated
operation, chunk/slice helpers, output write/completion and local guard. Shared
hash-core range helpers are loaded from the same retained compiler/target row.
Original captures and armed guard storage must remain bound throughout. Secret
payload access is forbidden outside the modeled primitive boundaries.

The independent expected trace checks clearing-before-shape-validation, empty
and nonempty final-bit shapes, engine preflight, 168-byte staging chunks,
final-chunk-only masks, exact output-prefix progress, per-chunk scratch clearing,
completion/ownership transfer, and final guard cleanup. It covers selected
initial clearing failures, all twelve engine errors, slice/initializer/checked-
subtraction rejection, four output-write errors, completion failures and
synthetic unwind. Failure after initialization clears the original destination
before the guard's terminal metadata updates and six owned-region clear
requests. Success transfers output ownership and still requests staging
clearing. Failure of the initial clearing boundary does not prove destination
erasure; it maps to SecretMemory and requests owner cleanup.

All 31,296 cases pass (3,912 per path) in 79/80-function closures. Every operation
block except panic/unreachable/double-panic arms is exercised; this does not
claim all blocks in every helper are covered. All 1,034 mutations reject:
128 per Rust 1.90 x86 path, 129 per Rust 1.90 Arm path, and 130 per Rust 1.98
path. Twenty-four metadata/SSA/dead-address controls pass. Earlier mutation
attempts exposed two harness assumptions: an unused staging address is a
positive control, not a meaningful mutation, and metadata copies include both
24- and 32-byte descriptors. A null-pointer mutant also exposed a missing
diagnostic precondition; explicit pointer rejection and regression cases were
added. Final direct logs use `check-v2`; mutation logs use `mutations-v4`.
Earlier versions are superseded, not counted as passing evidence.

The Arm output merges exception identities through a phi. The interpreter now
supports only block-entry two-field exception phi values, selecting the actual
predecessor and preserving pointer/selector identity. Four normal/unwind controls
pass and nine wrong-predecessor/identity/syntax cases reject. Seven accelerated
boundary controls pass and thirty malformed binding/guard/payload/width cases
reject. Existing squeeze/counter-model regressions and 1,024 selected existing
guard cases also pass after the interpreter extension.

Engine preflight/read and low-level copy/mask/volatile bodies remain opaque.
The checker qualifies the modeled handoffs and cleanup requests, not actual
CPU admission, digest bytes, physical erasure, register/spill absence or arbitrary
interruptions. Synthetic unwind does not prove real extern-C unwind, abort or
signal cleanup. Outer reader bridges, engine-body composition and whole-verifier
qualification remain outstanding. Arm runtime evidence remains QEMU, not native.
F1 and root `PENTEST.md` remain open; this is author diagnostic evidence.

No production Rust, dependencies, captured implementation or release-gate policy
changed. No compiler/native campaign or full sweep was repeated. Source/artifact
validation, assurance freshness, status/inventory regressions, acceptance metadata
and documentation checks pass. Compiler/runtime subprocesses are forbidden by
the mutation harness. Retained logs remain under ignored `dist/`.

| Diagnostic source | SHA-256 |
| --- | --- |
| `check_debug_accelerated_operation.py` | `0c4e59e12e3edb98a3c79cc09e2b3cc1063aa4667322a357b20c3545aa86632d` |
| `test_debug_accelerated_operation.py` | `070e45b54250a41d55a43f587bfceac6dd2edf72ecf48412c31b8aadb928acc1` |
| `debug_write_model.py` | `bc52e44bbfe162d920b29bf74ad1f5bfb810ddf478b6c8e14efbee682ec6a3ee` |
| `test_debug_exception_phi.py` | `dc60317a0fde5343ff541cae1726b1f8ceb7e2d2f7519a646fc7c6ae2bfdd98b` |
| `test_debug_accelerated_model.py` | `efe1ce8566ebc4f6d7d840e4caeffbf028a432adf882188fd9a24d7f65c56371` |

The observation record remains
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-accelerated-operation-check-v2-shard-0.log` | `f51fe2ed3eb869998963b565ce8e518ec0c71ce477fdf3955efa615d0756f33e` |
| `debug-accelerated-operation-check-v2-shard-1.log` | `8237098102a7c3ef1687b2a8842249d60250afb4ad7edfcc411fb61a86cfec04` |
| `debug-accelerated-operation-check-v2-shard-2.log` | `fbe3f5785834cb540e3222759dd0e1084279b5a51a0369a2571de9e1bd24d891` |
| `debug-accelerated-operation-check-v2-shard-3.log` | `77618ada392cc2340a7078129693eed27957157e1a5b909939639fe4d0e55694` |
| `debug-accelerated-operation-check-v2-shard-4.log` | `966dad9204d9c16fb82e4c4a8f6688354925a0c4b770d83e1085547d2673be9a` |
| `debug-accelerated-operation-check-v2-shard-5.log` | `2248ab4cffed6c95cc7b78a4546d117d5d690950514bf66898269f5580c71cd5` |
| `debug-accelerated-operation-check-v2-shard-6.log` | `5597297b68078fcfd7f5616276df51748ecdd16846946b37488b983b55d8b69b` |
| `debug-accelerated-operation-check-v2-shard-7.log` | `15c582e7cafa7fde529a22997efc0ac8c8b2eccffa8053d2d2f25290961d60d6` |
| `debug-accelerated-operation-mutations-v4-shard-0.log` | `2ca728df390ff159111b5932515d66163366ce2190e177c16096dc92ade28079` |
| `debug-accelerated-operation-mutations-v4-shard-1.log` | `c8e1c5fb8d8f2561429f5819510dd8fd669058724d3e8d207dd204d445324211` |
| `debug-accelerated-operation-mutations-v4-shard-2.log` | `ab0b65ef784a87cf9f0e88c42e016f0a24b8d387c63b657702b45f6efae17edb` |
| `debug-accelerated-operation-mutations-v4-shard-3.log` | `828b4dbfbb6e231b31d7d2e49fea64e70933634c6a0719d9f2925a7991f9016e` |
| `debug-accelerated-operation-mutations-v4-shard-4.log` | `5072f700b3dd678c855a2d3c01f491292e0e6c4898080a23e1960edd60a009f8` |
| `debug-accelerated-operation-mutations-v4-shard-5.log` | `60854fa837fd04b3a7d2e15467846927b477ef84383560db80a228ae77bcd003` |
| `debug-accelerated-operation-mutations-v4-shard-6.log` | `d444ad941cc039fd7cba2ab4a5ef460962b23c4a854fd2b5915af9aa020dd6e2` |
| `debug-accelerated-operation-mutations-v4-shard-7.log` | `736496e6aeb0087178f003fa739dd296f332ae5c4152ea8f30a9dcd433149f1d` |

### Accelerated debug bulk and consuming bridges around the operation

From the preserved source-matching checkout and absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_accelerated_bridges.py "$record"
python3 assurance/register-cleanup/test_debug_accelerated_bridges.py "$record"
```

Both accept `--shard 0` through `7`; all eight shards are required. Each shard
checks both the borrowed bulk reader and consuming final-bit reader against
the actual initializer, operation chunk loop, output write/completion and guard.
The outer reader and producer must agree on compiler/target row, strength and
shared helper definitions. The original reader/result descriptors are used
throughout, with no replacement reader allocation. Guard entry must borrow the
same compiler-local reader that reached the producer.

The independent operation lifecycle/chunk oracle supplies the inner expected
trace, surrounded by explicit outer handoff and ownership rules. A second
execution of the producer is not used as its own oracle. Bulk calls retain the
producer's success/error reuse behavior. Consuming calls additionally request
full owner cleanup before result publication or exception propagation, including
after producer success. Result errors must preserve their exact identity; a
successful result moves the complete original output descriptor exactly twice
through the mapper, without extra, partial or volatile descriptor transfers.

All 28,264 cases pass: 379 bulk and 3,154 consuming cases per path, totaling
3,032 bulk and 25,232 consuming cases across eight paths. Bulk closures contain
84/85 functions; consuming closures contain 87/88. Every selected outer reader
entry/error/unwind block is exercised except unreachable/double-panic arms.
This does not assert complete block coverage of every inner helper.

The existing outer mutation campaigns were rerun with the operation composed:
all 1,012 mutations reject (41 bulk per path, 86 consuming per Rust 1.90 path
and 85 per Rust 1.98 path). Thirty-two metadata/SSA controls pass. Two synthetic
handoff controls and twenty malformed/repeated/inactive binding checks also
pass. All eight direct and eight mutation shards exited successfully. The
mutation harness forbids compiler/runtime subprocess execution.

Engine preflight/read and copy/mask/volatile primitive bodies remain opaque.
The composition qualifies the modeled handoffs, metadata and cleanup requests,
not actual engine admission, digest bytes, physical erasure or register/spill
absence. Synthetic unwind does not establish real extern-C unwind, abort,
signal or arbitrary-interruption cleanup. Engine-body and whole-verifier
composition remain outstanding. Arm runtime evidence remains QEMU, not native.
F1 and root `PENTEST.md` remain open; these are author diagnostics.

No production Rust, shared interpreter, captured implementation, dependency or
release-gate policy changed. No compiler/native campaign or full sweep was
repeated. Source/artifact validation, assurance freshness, inventory/status,
acceptance metadata and documentation checks pass.

Checker SHA-256:
`e04e0eff6d28f2df8fdaf6fe4daef2b2949b9144b7df048db04888ba84b8b228`;
mutation harness:
`14dfb73da022a35b71eec0371365524e3024946c095ff5e4ae5ae580f9ecab00`.
The observation record remains
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
Completed logs remain under ignored `dist/`, outside Cargo's `target/` directory.

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-accelerated-bridges-check-shard-0.log` | `e5db7e84ce8c22c63d69226102e2fa9901253e619f160ae68f06f94e2a5cce07` |
| `debug-accelerated-bridges-check-shard-1.log` | `dd72b08eed7fb2d529427f65b318d1ecfca96510f79c452c6380359890ca7ba4` |
| `debug-accelerated-bridges-check-shard-2.log` | `6dc2a7c674e74ae08d92b3a6ac460d022f023d4824ccb8aeb33d6d675252bbd8` |
| `debug-accelerated-bridges-check-shard-3.log` | `c572bc9d9b5333a2d70d4c8037b78fca42336ea0e201eb5ad4b6f75cf2819523` |
| `debug-accelerated-bridges-check-shard-4.log` | `0e014e30c0e810906dcfca112b1a435b15dd335d6ea1535a62d14a1a22175905` |
| `debug-accelerated-bridges-check-shard-5.log` | `813d8362c3b93149a15209b2459218e2b1a7b8d04860f3955eed859b72537abc` |
| `debug-accelerated-bridges-check-shard-6.log` | `865b7664b0510fda4a5a2aa3fbcf77aafd2e8660b4fb46fd3a481bf29540146d` |
| `debug-accelerated-bridges-check-shard-7.log` | `53bf540a12ef8afcddcb9ce268102f2eabff2ddf14c19ea34b513c784ee0c324` |
| `debug-accelerated-bridges-mutations-shard-0.log` | `effcf31f64751627d595f11fba094825344ed56620d3dc587aa3b5d1d8c7cffa` |
| `debug-accelerated-bridges-mutations-shard-1.log` | `b060bc2cf9358ecd99d5e7c0f00fb370639e2df12d54a21ecb77a344720b4ac4` |
| `debug-accelerated-bridges-mutations-shard-2.log` | `26c73e042c98a2d5549f9a7d622d254ab8c2dc78171b3dff9f0df65ec8db4072` |
| `debug-accelerated-bridges-mutations-shard-3.log` | `69edb748a036f606a4ba0d58f2b9ae5436ab767be31eacff3414138691032315` |
| `debug-accelerated-bridges-mutations-shard-4.log` | `95475872b210aba00f80acb679305a31fc33975a52eebd1552e062431844e710` |
| `debug-accelerated-bridges-mutations-shard-5.log` | `ce01fd6ec4087194f301194102c37245b480be936529917daf0921d60a3bf313` |
| `debug-accelerated-bridges-mutations-shard-6.log` | `9733a887e0eb2f8d5b1beba3069cd31aa9ad9123cf312ab16e5e2bfdff176ec9` |
| `debug-accelerated-bridges-mutations-shard-7.log` | `f085477a6153e923f326cf9ca0cb0b22af4d867619d2bb8fede0a3c3a25c62c4` |

### Accelerated debug engine preflight and reader composition

From the preserved source-matching checkout and absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_accelerated_preflight.py "$record"
python3 assurance/register-cleanup/test_debug_accelerated_preflight.py "$record"
python3 assurance/register-cleanup/test_debug_preflight_model.py
python3 assurance/register-cleanup/test_debug_u64_operations.py
```

The first two accept `--shard 0` through `7`; all eight shards are required.
The nineteen-function same-row preflight closure now executes its actual state
check, backend-error mapping, sixteen-byte counter decoder, checked u128 addition
and result mapping. The CPU session check remains an explicit opaque boundary.
All 19,808 cases pass (1,238 per bridge/path), including 8,784 composed reader
cases. Bulk closures contain 102/103 functions and consuming closures 105/106.

The independent oracle checks terminal/wrong-phase rejection before authority
or counter access, exact backend errors, the full little-endian decoded value,
and output-length overflow at counter/usize boundaries. Every original counter
byte must be read once in order; no engine field may be written by preflight.
Tests include all 128 one-bit counter basis values, nonuniform bytes, all seven
backend errors and selected synthetic session unwind. Large increments are
standalone arithmetic probes, not huge destination allocations. The actual
saturating-multiplication helper is separately checked near overflow; such
oversized offsets are not claimed reachable through the sixteen-byte iterator.
All normal preflight/helper blocks are covered, excluding forbidden panic paths.

The bulk/consuming composition executes the real preflight below the existing
initializer, producer operation and reader bridges. Exact failures and session
unwind follow the independent output/owner-cleanup oracle; consuming success
still requests its additional complete owner cleanup. Existing engine-read
behavior remains synthetic here, so this does not establish output-counter
commit ordering or permutation/copy correctness within that body.

All 1,248 mutations reject: 79 per bridge/path under Rust 1.90 and 77 under
Rust 1.98. Eighty metadata/SSA/no-op controls pass. In particular, removing the
side-effect-free sum-to-unit mapping closure is accepted as equivalent for this
admission check, not misclassified as a security regression. The mutation
harness forbids compiler/runtime subprocess execution. All sixteen final
check/mutation shards exited successfully.

The interpreter gained unsigned-64 bit operations and checked multiplication
using its existing width/poison rules. Focused tests pass 156 arithmetic controls
and fourteen malformed-operand/poison rejections; the preflight boundary model
passes nineteen controls and twenty-four payload/metadata/authority rejections.
Existing counter, squeeze, exception-phi and accelerated-boundary tests pass,
as do 2,744 existing composed-reader quick cases. Source/artifact validation,
assurance freshness, script/status policy, acceptance metadata and doc links
pass. No production Rust, captured implementation, dependency, release-gate
policy, compiler/native campaign or full sweep changed or reran.

Session-check internals, engine read and copy/mask/volatile bodies remain opaque.
This does not qualify scalar counter temporaries, whole-verifier paths, actual
extern-C unwind, arbitrary interruptions or whole-call register/spill cleanup.
Arm runtime evidence remains QEMU, not native. F1 and root `PENTEST.md` remain
open. This is author diagnostic evidence, not independent qualification.

| Diagnostic source | SHA-256 |
| --- | --- |
| `check_debug_accelerated_preflight.py` | `472e324f5ce8cc308dbf446bdbfc07853f48d25ddafc562d24ec2ca42e369d92` |
| `test_debug_accelerated_preflight.py` | `1434291a1472ce9597b1e7a804ab39f0d0168a57b4a4c742b1e5bbf5b3771cc5` |
| `debug_write_model.py` | `80ed3c800d3e0050a1a920e4d6b549f63810b763b64e0472c2e0e8a8757906a6` |
| `test_debug_preflight_model.py` | `a34e7ffc229717d532f68585d579c416713f345c2d769e1f37fa72140e68ceee` |
| `test_debug_u64_operations.py` | `5782d2669e8f6a3d35900d1f5216288098bed4197f3e23895da9ae3ecb719af4` |

The unchanged observation record has SHA-256
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
Logs remain under ignored `dist/`, outside Cargo's `target/` directory.

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-accelerated-preflight-check-shard-0.log` | `47f4e20e35dd9014337198b1771121e1f9356a7a09a814669851d50edacbcc68` |
| `debug-accelerated-preflight-check-shard-1.log` | `30a6c33afe0d8f9cc421f480ffe99aa33678c517795dd656fc785d41a2df01c6` |
| `debug-accelerated-preflight-check-shard-2.log` | `d905be6505cfebeb4f4aed207c7e7bd94c52ed2b2c28f98fc41119184fe25f43` |
| `debug-accelerated-preflight-check-shard-3.log` | `851be79e9acd5f0f22bb4f64a304a5215546d6c986eb877ce7ea8f37d90431c5` |
| `debug-accelerated-preflight-check-shard-4.log` | `c5f0645b516986be727a4add64aa33d4a2b9a258651178dd1ddcd911d4fd9a92` |
| `debug-accelerated-preflight-check-shard-5.log` | `37de7d6a9dd2b2cea0610312ebc49a13daba872138ca8428266decd1de782c8d` |
| `debug-accelerated-preflight-check-shard-6.log` | `6a679be5abcf019c2be3f8f3c543cb352cc85eb6a24103ffacf0dc9139eb1abe` |
| `debug-accelerated-preflight-check-shard-7.log` | `692acb2ead4c2ec528055c1d5deaae7ebca62ca814a6d4f81f7ab822c78932cd` |
| `debug-accelerated-preflight-mutations-shard-0.log` | `52fc667962f0e25f79fe6c68c97ac40990393b797a5cc56727f65491e08dcd3e` |
| `debug-accelerated-preflight-mutations-shard-1.log` | `95563bc1e1273d70a948878ffe7df98054a050206cfdef9c1a187fafc5892525` |
| `debug-accelerated-preflight-mutations-shard-2.log` | `355a1b3853d69419c7b26b9931e163b4a7062868be72c38300b1137bb9bd61bc` |
| `debug-accelerated-preflight-mutations-shard-3.log` | `a676169ebfdc449c91bc7b8068614da236cba96e5f9fd916a99c6d91f2403159` |
| `debug-accelerated-preflight-mutations-shard-4.log` | `a18847c08169c1d206416de240ea243e5c201fd74a15c0e0424c6c7e3cd8ec6b` |
| `debug-accelerated-preflight-mutations-shard-5.log` | `d3d3ff8e58a41b63d554e0c4a16363e78f345e5a9476267523799eafde45cb7a` |
| `debug-accelerated-preflight-mutations-shard-6.log` | `8493a6704b47bb2bd8322ecca1b801561c8824d00cb361abee93da21c5f41200` |
| `debug-accelerated-preflight-mutations-shard-7.log` | `b1cc9facca18712be03c7313a2f2e8e3d2c3cfbe301bb3aaabe3e6eac0bb573f` |

### Accelerated debug engine read and inner operation guard

From the preserved source-matching checkout and absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_accelerated_read.py "$record"
python3 assurance/register-cleanup/test_debug_accelerated_read.py "$record"
python3 assurance/register-cleanup/test_debug_read_bindings.py "$record"
python3 assurance/register-cleanup/test_debug_read_model.py
```

The first two accept `--shard 0` through `7`; all eight shards are required.
All 4,624 read-body cases pass (578 per retained path). Each read closure contains
51/52 functions and shares the previously checked preflight/reader dependencies
in 126/127-function sets. This check executes the engine read body directly,
including actual preflight, counter decoder/writer, permutation adapter, result
and range helpers, and its own operation guard. It does not yet execute that
read body beneath the outer producer/reader bridges.

The independent trace oracle checks:

- All five rates; empty, boundary and multirate output lengths; cursor resets
  at permutations and exact original lane/destination slice boundaries.
- State/session admission before counter use, full-width counter overflow,
  exact seven backend errors, four copy errors and selected boundary unwind.
- Cursor commits only after successful copying and all sixteen counter-byte
  writes only after the complete read succeeds. One-bit/nonuniform byte
  patterns and exact ordered-write traces reject stale/no-op/partial writers.
- Engine terminal-state/reset and four memory-clear requests on error/unwind,
  preserving the original exception. A successful read leaves the engine nonterminal.

Corrupt metadata, injected missing helpers and a changed second counter value
are internal invariant probes, not valid public constructors or evidence of
reachable exploits. Every nonpanic read-body block is covered; this is not a
claim of complete block coverage for every included helper. Failed private
engine reads can have copied a prefix to their destination: destination
transactionality depends on the enclosing owner, not this direct helper check.

CPU session/permutation, slice-splitting, copying and volatile wiping remain
explicit boundaries. This proves modeled metadata effects and clear requests,
not digest bytes, physical erasure, scalar-temporary cleanup, whole-verifier
paths or whole-call register/spill absence. Synthetic unwind does not qualify
actual extern-C unwind, abort, signals or arbitrary interruption. Arm runtime
evidence remains QEMU, not native. F1 and root `PENTEST.md` remain open.

Model tests pass four primitive controls and twenty-nine malformed pointer,
width, phase and payload rejections. ABI-binding tests reject 144 missing,
narrowed or by-value boundaries, with sixteen pointer-attribute controls.
Development corrected null-pointer rejection in the diagnostic and recognition
of Rust 1.98's bare-pointer permutation declaration; neither was a production
defect. No shared interpreter, production Rust, captured implementation,
dependency or release-gate policy changed. No compiler/native campaign or full
sweep was repeated. Source/artifact validation, assurance freshness, script/
status checks, acceptance metadata and documentation links pass.

| Diagnostic source | SHA-256 |
| --- | --- |
| `check_debug_accelerated_read.py` | `32435604df4c8bb00789b8067bbd84f24ce0a58b493b7b4126a037b60514e4e0` |
| `debug_accelerated_read_model.py` | `ce3050d8a38ca521ecefa5e3927ba0ab5bdd7b41023033a7e9207743dc848378` |
| `test_debug_accelerated_read.py` | `0fb564f96476496f8a54e5d077df5b5c4355ace9bee9d84191baae2cb06df42e` |
| `test_debug_read_bindings.py` | `2834139275c746c1164796053c0cd473e1208c502b721311ce994865ab392b00` |
| `test_debug_read_model.py` | `52040a54c2fd54a0d15eed36deee057a5c67a7a21e12cfaa1722a702fbf8465a` |

The unchanged record SHA-256 is
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
Final direct logs are under ignored `dist/`; the initial unversioned development
logs include the corrected ABI-parser failure and are superseded by these.
All eight final mutation shards pass, rejecting 1,534 regressions with forty
positive controls. Removing the success-only, completed guard Drop is a semantic
control because that Drop has no remaining work. The earlier v2 mutation logs
incorrectly expected that removal to fail; the v3 campaign supersedes them.

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-accelerated-read-check-v2-shard-0.log` | `2c6f04c4d85976fd08eda5e5c4cc5ceff535855099f57735dd6da4ca00d066e5` |
| `debug-accelerated-read-check-v2-shard-1.log` | `392afc7fbce6b2b1dca3dcd8a3620088bc5a6bffc69838a5fab5a00a8d8e2d83` |
| `debug-accelerated-read-check-v2-shard-2.log` | `d1a67ad719bae418265cf6c8daf9f5a950d6d63d197bf99f0c477d160590a9db` |
| `debug-accelerated-read-check-v2-shard-3.log` | `7720b414765ae217423a370c145a505ae16d71a7ae8181000b6784ab18e4ee77` |
| `debug-accelerated-read-check-v2-shard-4.log` | `6827a8ea9bfb60438b99a6b5e5e1e14c4b5b641612d4ace64c2026e963e4367f` |
| `debug-accelerated-read-check-v2-shard-5.log` | `5779e573e3e573f1731db2f8dc77bce961add263035b559bb8e7dae1b7ec65c0` |
| `debug-accelerated-read-check-v2-shard-6.log` | `eaccbf270107b514d30a481f08a1e1b793775cf15c99ce1ba23a2821592a30fb` |
| `debug-accelerated-read-check-v2-shard-7.log` | `68d483db884e62d57fd8731f58ed394707f162a69a4f7168c6f61081c924c97b` |
| `debug-accelerated-read-mutations-v3-shard-0.log` | `0c508a5793f78ab05f9fc975b31efd2bc4c01681884318318e0cc75525ac7c82` |
| `debug-accelerated-read-mutations-v3-shard-1.log` | `dab36cf251ca566e6c1712cbf10869d9ba8f33a7fdd281b3e566c5f2cb916629` |
| `debug-accelerated-read-mutations-v3-shard-2.log` | `b706c7c2ce24b8a5015518fdefffb31b89329a052d7caa7d5e3b102722feca7a` |
| `debug-accelerated-read-mutations-v3-shard-3.log` | `bc5ce44868402bacf1cebf6b947df5f8c9b768548a4c944fc947faba53cd8b80` |
| `debug-accelerated-read-mutations-v3-shard-4.log` | `5429b8f8ee8e461d34e84a825c045dd7c83101301a31a44df1913f73c3b55bf5` |
| `debug-accelerated-read-mutations-v3-shard-5.log` | `5b43b54f034cd9c8cd2e4843ace145ed8f261df8c52e6c4313829b4a50b0af86` |
| `debug-accelerated-read-mutations-v3-shard-6.log` | `5f8ae7cc3771da1444707cee0ed037d7c5ab7f245df33f05e12cf8653fcfdcfa` |
| `debug-accelerated-read-mutations-v3-shard-7.log` | `df1629e01e41891f4b2c01cb8d7a11fd37ff321c977ac014fa5b93710c8b16c3` |

### Accelerated debug engine-read/outer-reader composition

From the preserved source-matching checkout and absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_composed_read.py "$record"
python3 assurance/register-cleanup/test_debug_composed_read.py "$record"
python3 assurance/register-cleanup/test_debug_composed_read_model.py
```

The first two accept `--shard 0` through `7`; all eight are required. The checker
also accepts `--quick` for development, not as a substitute for its full matrix.
The new model links the actual engine-read closure beneath the actual bulk and
consuming reader/producer/initializer/guard bodies. It uses one interpreter and
the same original storage allocation throughout, not independent per-chunk
machines. The previous standalone checker and shared interpreter are unchanged.

The oracle checks all five rates, empty and partial output, 168-byte staging
boundaries, multichunk output, exact full-width counter carry and preflight
overflow. Each inner call rechecks session authority; failures at the second
or later call test cleanup after earlier initialized output. Inner permutation,
copy and writer-boundary errors/unwind must preserve their error/exception
identity through the inner engine guard, outer initializer and reader guard.
The actual engine counter and cursor persist between chunk calls. Successful
bulk calls leave nonterminal metadata; consuming calls terminate the owner.
This does not exercise a second external bulk API call on the same reader.

Exact interleaved traces bind original lanes to original staging, final-bit
mask requests to the final chunk, successful staging copies to original output,
per-chunk staging clearing and whole-destination clearing on failure. The
private engine may have copied a partial staging prefix before failure; the
composed outer cleanup, not private helper transactionality, clears it and the
destination. Tests check clearing requests, not physical bytes or residue.

CPU session/permutation, split, copy, mask and volatile primitive bodies remain
explicit opaque boundaries. This is finite-case symbolic metadata execution,
not a general LLVM proof, actual extern-C unwind qualification or whole-verifier
register/spill erasure. It does not qualify abort, signals or arbitrary
interruptions. The retained Arm runtime evidence remains QEMU, not native.
F1 and root `PENTEST.md` remain open. Production Rust, dependency versions,
captured implementation and release-gate policy are unchanged.

The focused model suite passes three controls and twenty-six wrong-alias,
inactive-boundary, width and direct-payload-access rejections. All eight
retained-IR mutation paths reject 224 regressions with thirty-two controls.
These target skipped inner calls, wrong pointers/lengths/counter commits and
lost unwind cleanup/exception propagation, with two metadata/SSA controls per
bridge/path. Mutation execution forbids compiler/runtime subprocesses. All
8,576 full-matrix cases pass: 533 bulk and 539 consuming cases per retained
path, with 126/127-function bulk and 129/130-function consuming closures.
The oracle also checks that all 161 configured fault scenarios actually predict
failure, rather than injecting a fault beyond the last executed call.
Source/artifact validation, assurance freshness, script-layout, verification-
status, acceptance metadata and documentation-link checks pass. No compiler,
native or full verifier sweep was repeated. GitHub is green at `6ec41f52`,
before this local diagnostic checkpoint.

| Diagnostic source | SHA-256 |
| --- | --- |
| `debug_composed_read_model.py` | `5e2c8c85b479961531c16ceabea50c42544e38b4d8bd7d140d733784f6e41ed0` |
| `check_debug_composed_read.py` | `8d114490863b68f5370a2a7d0e2b40ab3d4ba7b568326ecb3a8604542d6566d5` |
| `test_debug_composed_read_model.py` | `d384af1fbf0e20ced78b691bcbea32545b3e20d55dfa8b939f604aaa80cb8fd1` |
| `test_debug_composed_read.py` | `12c3fdf78129bad8e8328d921526403951d4a2e45b0ee86586be82bc6d28cc09` |

The source-matching record remains
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
Raw logs are retained under ignored `dist/`, outside Cargo's `target/` directory.

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-composed-read-check-shard-0.log` | `1d5472f202eabb160c645695af696ab796f29e15ce105dec6bc44693d96cc3a7` |
| `debug-composed-read-check-shard-1.log` | `ac3c6f7018c4ab65250a126d0add202ae2c8d67ddbe678a2bb9df4b73db5d130` |
| `debug-composed-read-check-shard-2.log` | `86f96817e0d34c21bd4ec21da9e76db0b52e93b0dcf7db42dc67cb9fc5241eed` |
| `debug-composed-read-check-shard-3.log` | `0739c99f75de4df4a718c1d98923c860e7632e354c2c9e558b15d343dd01cc22` |
| `debug-composed-read-check-shard-4.log` | `0a413b845c01a691be28a93f89e3b9b58fd9083e23127b805a2d0672a5012be3` |
| `debug-composed-read-check-shard-5.log` | `a26a4d88947779c6673f87cacf0dcf71b427623923742cbffe51e293463f787f` |
| `debug-composed-read-check-shard-6.log` | `945b4a5fd2e611a222caf02e41e00f23b24fb6b16bf1168b0b42d02bb483e5b0` |
| `debug-composed-read-check-shard-7.log` | `ca632f0c582ad3911f2c4389c5f8f2b10265edae741b2fd42074347d789a32aa` |
| `debug-composed-read-mutations-shard-0.log` | `61c0891326602825feb7f48dd14e25edbdcfb7be264ae45256295f6fc0e766cd` |
| `debug-composed-read-mutations-shard-1.log` | `930f0734cadfaddc0a0e3e992d47e950051e93147ab7a708ba686a1ba5543d0a` |
| `debug-composed-read-mutations-shard-2.log` | `4fac7c9a9956e484a4aa83dffde72fa0343ef1a096489d7561c8355b29b15e7b` |
| `debug-composed-read-mutations-shard-3.log` | `db4154d445cfd280bb8cbc91c06c6fd2479c5a6e33903fc7226292f2e4c5b60e` |
| `debug-composed-read-mutations-shard-4.log` | `e1b224c280667b4a8a4f1213acd45f1d340bca2814f089f4684f3cca37f04c9f` |
| `debug-composed-read-mutations-shard-5.log` | `6cbdd3a60991ec666b65dcd7722db9d63c95c4cb50644b226de4e4cf3e1fdf30` |
| `debug-composed-read-mutations-shard-6.log` | `9a5790e0abd5c920700614d6210ee1b56b5601e34844599f82fb188ec5ae1fb1` |
| `debug-composed-read-mutations-shard-7.log` | `b718f45cbd2ad9d9c787a5e02be95d928f249d00eb3d8618394c81dde4664d09` |

### Accelerated debug reader primitive handoffs

From the preserved source-matching checkout with the absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_reader_primitives.py "$record"
python3 assurance/register-cleanup/test_debug_reader_primitives.py "$record"
python3 assurance/register-cleanup/check_debug_primitive_assembly.py "$record"
```

The first two accept `--shard 0` through `7`; all eight are required. The first
also accepts `--quick` for development only. No compiler or native rerun is
needed. Diagnostic copies in the preserved checkout match the sources below;
captured production sources and artifact hashes are unchanged.

The actual `split_at_mut` and unchecked descriptor construction, copy wrapper
and mask wrapper now run in the metadata interpreter. Split descriptors are
read from actual execution, never prefilled. Direct cases cover empty/boundary
splits, equal and unequal copy widths and all byte values in each public mask
position. All 4,896 direct cases pass. Integration beneath both original readers
passes 8,576 cases: 533 bulk and 539 consuming per path, in 132/133-function bulk
and 135/136-function consuming closures. Exact original pointer/length/mask
handoffs and equal-length admission are required before the raw leaf.

All 352 IR mutation executions reject, with thirty-two positive controls;
twelve malformed borrowed-input/alias/recursive-boundary probes also reject
on each shard. Final mutation logs supersede the development run whose expected
count omitted the already-shared copy helper; that helper's length branch and
raw handoff are included in this campaign.

Four same-row copy/mask assembly pairs bind the eight caller paths under Rust
1.90.0 and 1.98.1 on Linux x86_64 and AArch64 musl. Exact instruction contracts
supplement the existing leaf allowlist: development found that the allowlist
alone permitted an inserted load. The exact contracts reject extra operations,
wrong ABI operands, incorrect copy strides/branches, mask prologue mappings,
wide stores, spills/reloads and missing register clearing. All 116 assembly
mutations reject and eight label-renaming controls pass. No production bug or
production-code change is claimed by this diagnostic improvement.

Valid borrowed byte-pointer construction preconditions are explicit assumptions,
not qualification of their panic/check implementation. Raw copy/mask payload
operations remain opaque in LLVM metadata execution; their assembly is checked
separately for the exact normal-return leaf contract. Synthetic caller errors
and unwind bypass the actual wrapper at the injected failure boundary; they do
not imply the raw leaf can return those errors or unwind. CPU session/permutation
and volatile primitive composition remain outstanding. Wrapper/whole-caller
spills, whole-verifier qualification, actual extern-C unwind and arbitrary
interruptions are not covered. Arm runtime observations remain QEMU, not native.
F1 and root `PENTEST.md` remain open. Production Rust, the shared interpreter,
dependencies and release-gate policy are unchanged.

| Diagnostic source | SHA-256 |
| --- | --- |
| `debug_reader_primitives.py` | `7c9a3a99691acb213460a87bb1e9ffe212ded0b605b9b8da616e148a0ad0393e` |
| `check_debug_reader_primitives.py` | `a50479c921a913fd1ce3c8783b6624b5ad629c6977c9655c3f4a43792319ce37` |
| `debug_primitive_contracts.py` | `80306f4ece697270f7e41f389c42da53793da7abc2e28f30842b397190850d2d` |
| `check_debug_primitive_assembly.py` | `ee6cb1d54efc114f6e65ce2b32b3d381d34751e692ede32177d5586e2d847db9` |
| `test_debug_reader_primitives.py` | `b22a0dede007de3f78740a1ede07357ad3f3a22cfbb37634c99e5922a41cf91b` |

Record SHA-256 remains
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
Completed logs below are retained under ignored `dist/`, outside Cargo cleanup.

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-reader-primitives-check-shard-0.log` | `b51b9c4291d3930e72a6eb0817c5d670efa47f7dffa58f60e75bd442a05c7c17` |
| `debug-reader-primitives-check-shard-1.log` | `cdca025a169189f266ab9efa1aa0aa3b75d8ef08c557da0796ad9ee84352166c` |
| `debug-reader-primitives-check-shard-2.log` | `cebd3699980e19540228a46418e843b4b5aa72be4141ca42b64c133aa33d4ec6` |
| `debug-reader-primitives-check-shard-3.log` | `615dccc577a256268e3f4b9c47e9e9b7385af57afb31ebf78bcbdc95095fbb43` |
| `debug-reader-primitives-check-shard-4.log` | `27ecd4123b60b526e00cbb1bb8f4e17bb3504f77bb7230e97478bbdb2341c6c2` |
| `debug-reader-primitives-check-shard-5.log` | `d8175857bb453a13379758f021f76fc6681c9de0319e0d7588f6541d9698649a` |
| `debug-reader-primitives-check-shard-6.log` | `c0cbeb04af57a84ce1bb04053513b446270b4d7750aa7fea333b1bbf2fb5ba60` |
| `debug-reader-primitives-check-shard-7.log` | `e0479411707c391c04676f06dda9fc640e7de27733fd223dc86db19f1ebca41d` |
| `debug-reader-primitives-mutations-final-shard-0.log` | `79cb6d220c70377e9e072beec381df9b9ff2cbbf0c790b330265968657bca436` |
| `debug-reader-primitives-mutations-final-shard-1.log` | `a84c65fb62f5c464bf428a01a26a6a16a3c9df6d6d452971212fc638c112d705` |
| `debug-reader-primitives-mutations-final-shard-2.log` | `47de2d3c321fcd54e0adb59d1e04e24ba45aa379b06b13972b91e3335ed11af6` |
| `debug-reader-primitives-mutations-final-shard-3.log` | `870991b6f4841d13ea630f1aedd2dcf72d2060a7bb1fd2cf4b7150db4edc9396` |
| `debug-reader-primitives-mutations-final-shard-4.log` | `89e997bc60f34c77aecc2e889193939d22b5e8c8ece773435354b97e516d4be6` |
| `debug-reader-primitives-mutations-final-shard-5.log` | `fcb3e50a847d8ca4b934cf1d12df0aa7add785f2e4003173b484251a527471f3` |
| `debug-reader-primitives-mutations-final-shard-6.log` | `447ca1e81fdeaa8562e800026fba6562b6517f004517461062f9628475b0fb9d` |
| `debug-reader-primitives-mutations-final-shard-7.log` | `0e155c60eedeb1479655023118bd70601197713244f108399906660fd61872b4` |
| `debug-reader-primitive-assembly-final.log` | `1451f11f28594a6d610027d3a90a9e2ae0d7be36fd9533197590725612d6a5cb` |

### Accelerated debug readers with actual volatile clearing

From the preserved source-matching checkout, with the absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_reader_clear.py "$record"
python3 assurance/register-cleanup/test_debug_reader_clear.py "$record"
```

Both commands accept `--shard 0` through `7`; all eight are required. They forbid
compiler/runtime subprocesses. This is a focused extension of the preceding
reader/primitive composition, not a repeat of the full reader parameter matrix.
It merges the previously checked six-function clearing closure with the actual
reader closure, requiring the same original clearing symbol and identical shared
helpers from the retained row. Bulk closures contain 137/138 functions and
consuming closures contain 140/141.

The clearing loop, iterator, byte writer and compiler-fence bodies execute against
the original reader storage and output. Their check/write sequence must cover
each original byte exactly once in increasing order with volatile zero, followed
by one SeqCst compiler fence. Valid borrowed byte-pointer precondition return is
still assumed. Every completed clear is matched in order to the independently
checked caller trace, including inner engine cleanup, per-chunk staging, full
failed output and consuming-owner cleanup. The modeled counter bytes become zero
when their original region is cleared. Local descriptor spills are restricted to
frames created inside the active clear, never earlier caller frames or payload.

Seventeen bulk and nineteen consuming cases per path cover empty output, staging
boundaries and multiple chunks; terminal state and counter overflow; session,
permutation and copy failures; later writer unwind; and outer cleanup failures.
All seventeen configured fault scenarios are checked to predict failure, avoiding
vacuous injections beyond the final call. The development late-permutation case
was lengthened to reach that dispatch. Synthetic boundary unwind remains a
caller-cleanup test, not proof of actual extern-C or arbitrary-interruption paths.

Each mutation shard reuses twenty-four retained clearing-body mutations beneath
a real consuming reader, plus metadata removal and local-SSA rename controls.
Fifteen malformed boundary cases reject early/duplicate/weak fences, skipped or
duplicate bytes, wrong original regions, ordinary payload stores, recursive
clearing and writes into earlier caller metadata. Positive controls verify actual
counter-byte updates, empty-slice fencing and helper-local stores; the existing
100-case overlapping-store control checks the reused indexed memory operation.
An initial control renamed an ABI-bound parameter rather than a local SSA value;
the final campaign corrects it. Initial development logs are superseded below.

The exact same-record entry/write and iterator/fence assembly checks documented
above are reused. These finite LLVM traces are not all-length proof, new physical
erasure observations, wrapper/whole-caller spill qualification, native Arm or
Windows evidence. CPU session/permutation bodies, whole-verifier error/unwind
paths and wider caller/worker qualification remain outstanding. F1 and root
`PENTEST.md` remain open. Production Rust, captured artifacts, the shared
interpreter, dependencies and release-gate policy are unchanged. No compiler,
native campaign or full verifier sweep was repeated.

All eight composition and mutation shards exited zero: 288 focused reader cases
completed 3,064 clearing calls, and 192 mutations rejected with sixteen controls.
Retained source/artifact binding, assurance freshness, script-layout/status
regressions, acceptance metadata and documentation links pass. The record remains
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
Completed logs are under ignored `dist/`, outside Cargo cleanup.

| Diagnostic source | SHA-256 |
| --- | --- |
| `debug_reader_clear.py` | `aeea4ead998265c9a676c9b8c342e7e903eebfc577a589be9d4235052fc4dee0` |
| `check_debug_reader_clear.py` | `d659e25d544e6f62ee77e4c18f78d656b3ee967eed1243f9fd4454aacbc662a1` |
| `test_debug_reader_clear.py` | `acce6eb5048f79a433d6a3f38bd93cd2f8673937a23d89dc5f56ff88ccfd1efd` |

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-reader-clear-check-shard-0.log` | `210c9d86393c757d230db89dd213674cbe4fd3fa4eb8776eee2b05c0c298b9c3` |
| `debug-reader-clear-check-shard-1.log` | `e352fcbdba4dff7c89d51406378d7ffbbdc6515f61d049eff658109a31805129` |
| `debug-reader-clear-check-shard-2.log` | `a02d503a39c8b9622e14c78b4495c713d4cc7842c5aba5626dae5d0e70cdb6ca` |
| `debug-reader-clear-check-shard-3.log` | `ba44bcefb7ed901fd9505cd4e2fee144e2783fe4c412c90055a49c52261edb48` |
| `debug-reader-clear-check-shard-4.log` | `e72732cff2503403ec0de0fcfa89b2a5746ec148bcc54af39793444a8c437c9f` |
| `debug-reader-clear-check-shard-5.log` | `02ad4b345d86050807c3fea27d2e50c793efbb8f8869f8c72d245e30735f72a5` |
| `debug-reader-clear-check-shard-6.log` | `1809fa9bc3c38cde827c5f4f4fea8c3544ce79782fd9ab26e6a954e438622be4` |
| `debug-reader-clear-check-shard-7.log` | `fec3e7bbf54899b9278e09887108c811f086e5353dd761b748da6dad40d055e4` |
| `debug-reader-clear-mutations-final-shard-0.log` | `8ff62d26ad89eac5996769eaf72075c5ad6f6158442c4d9374cd98a8313ef6d0` |
| `debug-reader-clear-mutations-final-shard-1.log` | `d58f739dae878d125f630005ebc6eca22cce30a053062748306261b83bbc412b` |
| `debug-reader-clear-mutations-final-shard-2.log` | `c83ad0a668eadf4066a6be395e503b921a939abc145a60b9369c635ebff5fb77` |
| `debug-reader-clear-mutations-final-shard-3.log` | `e3f1f6b2a01162056c11dc2a2ebfd2851868b2f7defb268581b8e73917ea5bf1` |
| `debug-reader-clear-mutations-final-shard-4.log` | `05d6aee063df6fe6e4ad18260aa955d51c1bd09486ba1adc90fc352f22bee081` |
| `debug-reader-clear-mutations-final-shard-5.log` | `4127ce624c53c4ae107db762a85246f6499b894c5a834e358244856c9ea45db5` |
| `debug-reader-clear-mutations-final-shard-6.log` | `d9202e1f7253303d5b99d5cab02e6f94605593760f71185d09e3ce3a3dba8887` |
| `debug-reader-clear-mutations-final-shard-7.log` | `ca0859373cb09d2d5c297c3b7b9756b9553723ef91559ae1034f417037914979` |

### Retained static Keccak authority and operation guard

From the preserved source-matching checkout and absolute record path:

```sh
python3 assurance/register-cleanup/check_debug_keccak_session.py "$record"
python3 assurance/register-cleanup/test_debug_keccak_session.py "$record"
```

The mutation command accepts `--shard 0` through `3`; all four are required.
Both commands forbid compiler/runtime subprocesses. They select the four retained
debug accelerated CPU artifacts and bind their exact check/permutation symbols
to the same-row SHA-3 imports. They validate original borrowed argument and return
types before assembling each 26-function closure. This is static-route coverage:
the captured fixture does not enable the hosted runtime variant.

Actual session/route checks, authority health/generation checks, compiled-target
selection, dispatch, operation guard, scratch wipe wrapper and quarantine execute
in the metadata model. All 800 cases pass (200 per compiler/architecture build).
The matrix covers six kernel identities, all three health states, matching/stale
generations, zero/max generation boundary probes, seven synthetic kernel errors,
selected kernel unwind and health faults injected between admission checks.
Hypothetical internal metadata states do not imply that every state can be
constructed through the safe API. Fault injection does not model concurrent
mutable ownership, signal-safe reentry or arbitrary platform migration.

Every admission failure prevents kernel dispatch. Once dispatch starts, the
operation guard requests all seven exact scratch regions before quarantine on
error/unwind; successful completion avoids quarantine. The original exception
identity propagates, repeated quarantine makes no additional stores, and later
checks reject the quarantined owner. Ordinary Rust metadata accesses cannot
read/write secret scratch or caller state in this model. Kernel payload execution
and the volatile primitive remain explicit boundaries with separate evidence.

All non-abort blocks of the session check/permutation, authority check/quarantine
and scratch wipe roots are exercised, except the x86 WrongOperation branch.
For this retained +avx2 build, other kernels fail architecture/features first.
The Arm +neon,+sha2,+sha3 build exercises that branch. This is not coverage of
every helper block or actual extern-C unwind, abort or interruption behavior.

All 458 IR mutations reject: 115 per x86 build and 114 per Arm build. Eight
metadata/local-SSA controls and ten inactive-feature controls pass. Flipping a
feature bit after its architecture has been rejected is semantically irrelevant;
development correctly reclassified those as controls. Thirteen boundary tests
reject secret payload access, bad aliases, wrong owner/generation, invalid
quarantine writes and poison. Four Boolean-XOR truth-table and two Boolean
aggregate controls cover the local model's narrow scalar extensions. Boolean
`xor i1` is interpreted through its equivalent inequality truth table, without
modifying the retained LLVM or shared interpreter. Other unsupported operations
still fail closed. Rust's two retained symbol-mangling forms remain source-bound
by exact imported identities, not by accepting arbitrary lookalike functions.

This is a standalone CPU-session check, not yet composition with the actual
reader chain. It does not prove secret output bytes, physical erasure, hosted
authority behavior or whole-verifier register/spill cleanup. Existing same-record
kernel/clearing evidence remains separate; Arm runtime evidence is QEMU, not
native. F1 and root `PENTEST.md` remain open. Production Rust, dependencies,
captured sources/artifacts, shared interpreter and release-gate policy are
unchanged. No compiler/native campaign or full sweep was repeated.

Retained source/artifact binding, assurance freshness, script-layout/status
regressions, acceptance metadata and documentation links pass. GitHub is green
at the last pushed `6ec41f52`, not this local checkpoint. The record remains
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
Final logs below are under ignored `dist/`, outside Cargo cleanup.

| Diagnostic source | SHA-256 |
| --- | --- |
| `debug_keccak_session_model.py` | `dd3c45a29a2327af2e28c2631c9966fb0bb331ae95108c83d822eac61709d380` |
| `check_debug_keccak_session.py` | `a700c83a9c83eb2e4346c1d491049ac7d2bfc18447b6d02289050c4a29479ace` |
| `test_debug_keccak_session.py` | `a6c78eafcb4ee8846d6b36d19deeac07c621cca0f81f0c1b75883fa5ec587d4c` |

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-keccak-session-check.log` | `15ae8c193eec21c5b335182c399869eb7c34c945c5a7b33dd98ee7b3fc43fb9a` |
| `debug-keccak-session-mutations-final-shard-0.log` | `debc2cd12e1ff0657402bcd27acc0655b24430cfb9af0902538ffbfe83fa9581` |
| `debug-keccak-session-mutations-final-shard-1.log` | `dbc959acd28af92db65abbde232ce06c97e6860d47e6dcd9cc91b4c12352b6be` |
| `debug-keccak-session-mutations-final-shard-2.log` | `8638edaa8649d17b3320152edd55bcd8ec6e1ad2ff6e908bf9eb726516402d95` |
| `debug-keccak-session-mutations-final-shard-3.log` | `b8d4d4408ad114fe215b4a8080eb2e8f34f3657edca26b8bc158a1fcc965568a` |

### Retained debug reader/static-session composition

Run from the preserved source-matching checkout with the absolute retained record
path; all eight shards are required (omitting `--shard` runs the full matrix):

```sh
python3 assurance/register-cleanup/check_debug_reader_session.py /absolute/path/to/observations.json --shard 0
python3 assurance/register-cleanup/test_debug_reader_session.py /absolute/path/to/observations.json --shard 0
```

This follow-up joins the actual CPU session closure to the reader/volatile-clear
closure by exact same-row imported identities and identical shared helper bodies.
There are 161/162 functions for bulk and 164/165 for consuming-final readers.
Original reader storage holds the borrowed session, scratch and lane array;
public authority metadata remains separate. Kernel payload computation is an
explicit opaque boundary, with its previously recorded evidence reused.

All 168 focused scenarios pass across both strengths, Rust 1.90.0/1.98.1 and
Linux x86/AArch64 retained builds. They execute 656 actual CPU check/permutation
calls and 3,680 volatile clearing calls. The independent reader oracle still
checks the original outer/engine events, cursor/counter results, error values,
guard completion, output publication and original exception identity. A separate
CPU oracle checks call order, exact authority checks, dispatch, seven scratch
regions and error/unwind quarantine. Every requested clear executes its real
byte loop and final fence, including scratch, engine, staging, output and owner
regions. Payload loads and ordinary secret-region stores remain forbidden.

The focused scenarios include empty/single-byte/multi-chunk output, early and
late NotReady/Quarantined/StaleGeneration metadata rejection, kernel errors,
synthetic kernel unwind, outer copy unwind and invalid final-bit width. They do
not claim every cross-product from the earlier standalone matrices was repeated.
No concurrent owner mutation, signal-safe revocation or arbitrary migration is
modeled. The raw kernel boundary cannot establish cryptographic output bytes.

All 72 integration IR mutations reject: nine per path, covering bypassed session,
permutation, authority, dispatch, scratch cleanup and quarantine bodies, a short
scratch clear, altered kernel borrow and lost original exception. Sixteen
metadata/SSA controls pass. Twelve boundary regressions per shard reject payload
reads, invalid borrows, old caller-frame writes, invalid authority updates and
recursive CPU entry. During test development a healthy-only probe accepted a
bypassed authority body; the final tests include a real NotReady rejection as
well as a dispatched unwind. Earlier development logs are not final evidence.

Static-session composition is now checked, but hosted routes, whole-verifier and
wider caller/worker register/spill qualification remain outstanding. Valid raw
pointer precondition returns remain assumptions. Synthetic unwind is not actual
extern-C unwind, abort or interruption qualification. Arm runtime evidence is
QEMU, not native. There is no physical-erasure, independent-verification, FIPS or
military claim. F1 and root `PENTEST.md` remain open.

Production Rust, shared interpreter, source/artifact record, dependencies and
release-gate policy are unchanged. No compiler/native/full campaign was rerun;
diagnostic entry points forbid compiler/runtime subprocesses. Source/artifact
binding, script/status regressions, acceptance metadata, generated assurance
freshness and documentation links pass. GitHub remains green for the last pushed
`6ec41f52`, not this local checkpoint. The record remains
`d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.

| Diagnostic source | SHA-256 |
| --- | --- |
| `debug_reader_session.py` | `25f04b9b066bfd18b5e1aa56583810e1d07bc4ff5acae73872ddb582344d2a71` |
| `check_debug_reader_session.py` | `7c71da29489145477a800087b9c2288112c7bb41f71716c099515db94f658b3a` |
| `test_debug_reader_session.py` | `fdd66a80facdce714fcb9828bdfbaafdd41f214c8b0bb251a458810293db6fb6` |

Completed logs are under ignored `dist/`, outside Cargo cleanup:

| Completed retained log | SHA-256 |
| --- | --- |
| `debug-reader-session-check-shard-0.log` | `9eea3acb70129b6a55530894f2b5a24596ab8588bfd8f56846c899e55067b99f` |
| `debug-reader-session-check-shard-1.log` | `b9b8e87c720779c68ac3ef89dd67df4a0f2a3b8bb70391e65797c02a79519906` |
| `debug-reader-session-check-shard-2.log` | `164805b04544845788855105faa37686cf744a6c3c04c3072106e42ad2579cd5` |
| `debug-reader-session-check-shard-3.log` | `df82e3683d6f1a9c26b7009c1e5afd00487715f19dec905d563d67f203369693` |
| `debug-reader-session-check-shard-4.log` | `f6066adb1875c6267868d12504843b683e2aa2505df185779f183c8cd1b91778` |
| `debug-reader-session-check-shard-5.log` | `3b7c1995f7f807624bc365632c067a0becd023c0030eb1ca745ae7943bd4c02b` |
| `debug-reader-session-check-shard-6.log` | `8b9831c0db18452c93220f95129bb591d5a2f79de9e8e8a15fbd3c8f75358a82` |
| `debug-reader-session-check-shard-7.log` | `9aba41a138d5040c35f4ce17d43e2d15cabdc128cc83d65d15446c17b3169c9a` |
| `debug-reader-session-mutations-final-shard-0.log` | `fa1c7cb77b78e7bb977f3b068f680224dd43e282c860aa413ad73f13d64d24bc` |
| `debug-reader-session-mutations-final-shard-1.log` | `9064bff732c34ec620d9447659748e92c4eab9cf94125cae1a0c238cb7d1e22c` |
| `debug-reader-session-mutations-final-shard-2.log` | `67458b346049f7d0fbf30783dea91a0a6510cffc5e4fa54d3ffd5018320a4c3f` |
| `debug-reader-session-mutations-final-shard-3.log` | `71830d4006a3262edf0585e35bb422b98404284050ff93c74baf84d962b1d5eb` |
| `debug-reader-session-mutations-final-shard-4.log` | `037cd4683fa3363a7bb0577d4fabb5b20d4b89457948d651663eda1320a691ae` |
| `debug-reader-session-mutations-final-shard-5.log` | `9717a4f95e7e7a58ce7b2924c797b22f912b87e48b5a54e882278779f6b38ecf` |
| `debug-reader-session-mutations-final-shard-6.log` | `ba69f7ee652d475eec99064f5da07731526b517a8b75e531c65459ceddf94ffd` |
| `debug-reader-session-mutations-final-shard-7.log` | `89188b2fd44cfec2b4b60090388f43c8873427e1d7e9454947f68086ef0aedba` |
