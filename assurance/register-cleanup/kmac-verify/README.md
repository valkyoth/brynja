# Scoped KMAC verification-return diagnostics

Development only. Passing these tests does **not** qualify register cleanup or
close F1. No release-gate command, API default or backend admission changes.

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

The current record is `target/kmac-verify-1iopq9b5/observations.json`, SHA-256
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
