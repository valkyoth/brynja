# Brynja 0.24.22 Release Notes

Status: locally verified implementation candidate; exceptional pentest and native evidence disposition pending

## Scope and deliverables

- Eight-slot allocation-free ordinary and hardened MD5 batch APIs; canonical
  byte/bit input, inactive/empty distinction, stable order, compression budgets,
  cancellation and whole-output atomicity.
- Private first-party eight-message x86_64 AVX2 and four-message little-endian
  AArch64 NEON candidates. Scalar single/incomplete groups, uneven suffixes and
  padding remain available; reported vector counts reflect actual work.
- Unique two-key non-production evidence gate, distinct-message direct KAT,
  migration revalidation, permanent session quarantine and !Send/!Sync ownership.
- Separate optional `brynja-legacy-md5-std` observation/fallback adapter. Required
  acceleration fails closed; safe host detection cannot mint execution authority.
- Hardened batches reuse registered clearing MD5 owners; typed secret output
  begins cleanup before callbacks and clears all 128 destination bytes on failure,
  cancellation, unwind or Drop. No hardened SIMD route is provided.
- Frozen v0.24.20 corpus, mixed-lane/bit differential and packaged consumers,
  endpoint instruction inspection, production-negative configuration tests,
  targeted Kani/Miri/ASan coverage, policy mutations and native capture tools.

The modern facade only advances to 0.24.22. Neither it nor any changed support
crate is selected for crates.io publication at this internal milestone. The
new adapter remains unpublished 0.1.0. No third-party dependency is introduced;
the existing optional sanitization 2.0.4 admission is unchanged. The Rust
1.90.0–1.98.1 support contract and no_std leaf remain intact.

## Security and evidence limits

Every SIMD candidate remains **unadmitted**. AVX-512 and RISC-V Vector have no
implemented or admitted route; their separate compiler/native/performance
qualification remains required. Feature observation and a non-Send marker do
not prevent OS CPU migration. Admission needs reviewed execution authority,
native correctness/performance/timing evidence and relevant cleanup qualification.

MD5 remains collision-broken, separate from modern/TLS/PKIX/FIPS graphs and
**In progress** until v0.24.23. SIMD is multi-message throughput, not dedicated
single-stream MD5 hardware. Ordinary SIMD inputs must be public. Hardened
portable state clears its owned memory; caller copies, compiler-created copies,
registers, spills, caches, dumps, swap, DMA, moves, forget, abort and termination
retain the documented limits. No independent cryptographic review, FIPS
validation or military/classified deployment approval is claimed.

## Local verification

Completed on 2026-09-07:

- Complete repository gate, workspace tests, strict Clippy, documentation and
  package checks; all 12 stable compiler lanes from Rust 1.90.0 to 1.98.1 and
  three bare-metal targets.
- Frozen 20-case legacy corpus, 936 mixed-lane/bit batches and 16 explicit lane
  permutations through AVX2 locally and NEON under QEMU. Arbitrary-state/block
  kernel comparisons, faulted KATs, cancellation and quarantine tests pass on
  both compiler endpoints and both instruction backends.
- Eight rejected evidence-build configurations plus an external `cfg(test)`
  consumer on both compiler endpoints; packaged batch/host/secret consumers,
  36 MD5 CPU policy mutations and 44 workspace-policy regressions.
- All three MD5 Kani harnesses, including the two new full-width work-budget
  proofs. The repository inventories 29 harnesses; this is not a claim that all
  29 were rerun for this milestone.
- Full focused MD5 Miri group on nightly-2026-09-07, including portable batch
  lifecycle, all active masks, budgets, cancellation and recoverable unwinding.
  Miri does not execute the ISA candidates. AddressSanitizer additionally
  passes the actual AVX2 library suite; LeakSanitizer is disabled because the
  local environment's ptrace restrictions prevent its execution.
- Rust 1.90.0/1.98.1 emitted AVX2/NEON instruction checks and the existing MD5
  owner MIR/LLVM/assembly cleanup checks. Hardened batches compose those same
  registered clearing owners, not a new SIMD secret-state representation.
- Current tooling/advisory checks, cargo-audit, cargo-deny and matching SBOM.
  Dynamic-analysis tooling advances to nightly-2026-09-07; stable remains
  Rust 1.98.1 and sanitization remains exact-pinned 2.0.4.
- Release selection check and dry run: zero packages selected for publication.

These are local automated checks, not an independent cryptographic review.
Exact-commit native records are collected after the owner pentest; QEMU never
substitutes for native performance/timing approval. Both candidates remain
unadmitted regardless of these results.

## Release workflow

The new low-level code triggers an exceptional pentest before any signed tag.
After clean retest and local release checks, commit the report and wait for
green GitHub/CodeQL plus explicit owner tag permission. No crates.io publication
is scheduled at v0.24.22; the next ordinary public checkpoint is v0.25.0.
