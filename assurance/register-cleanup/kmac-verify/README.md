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
