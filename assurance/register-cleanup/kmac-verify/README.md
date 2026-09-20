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
