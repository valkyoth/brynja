# Brynja v0.24.35

Status: implementation and focused verification passed; exceptional pentest
and native high-level execution collection remain pending. Not tag-ready.

## SHA-3 and SHAKE ordinary CPU integration

- Default-off `static-execution` and `runtime-execution` leaf features connect
  all four SHA-3 hashes and both SHAKE XOFs to the existing AVX2/Arm SHA3 kernels.
- Complete byte/bit one-shot, absorbing, consuming finalization and incremental
  output APIs preserve exact identity, domain separation and selected route.
- Backend failures never authorize fallback. Updates and caller-scratch reads
  preserve state/output transactionally, including late permutation failures.
- Reader convenience methods use bounded 168-byte stack scratch; caller-scratch
  methods provide arbitrary-sized transactional reads without allocation.
- No new unsafe code, instruction kernel or third-party dependency. The optional
  first-party CPU edge leaves portable defaults and hardened APIs unchanged.
- cSHAKE CPU integration and hardened Keccak remain later milestones. This
  single-state vectorized permutation does not claim multi-message SIMD.

See [API usage, routes and evidence](../docs/sha3-ordinary-execution.md).

Implementation checks passed: the impact-selected repository gate (its final
metadata tail resumed after documentation corrections), all-feature/default
tests, package consumers and compiled mutations, native AMD AVX2, supplemental
AArch64 QEMU static/hosted execution, targeted Miri/ASan, the ten existing SHA-3
Kani proofs, Rust 1.90.0 compatibility/bare-metal checks, emitted instructions
under Rust 1.90.0/1.98.1 and fresh tooling/dependency checks. No CPU-instruction
proof or new full supported-platform qualification is implied.

The facade advances to 0.24.35 with no crates.io publication; the next public
checkpoint remains v0.25.2. Independent verification and FIPS validation remain
absent. Ordinary execution is public-data-only and makes no erasure guarantee.
