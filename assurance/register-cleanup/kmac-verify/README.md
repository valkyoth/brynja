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
