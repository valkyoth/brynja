# Brynja v0.24.46

Development milestone: SHA-512-family multibuffer SIMD. Not yet released.

- Adds default-off ordinary `brynja-hash-sha2::batch512` and hosted
  `brynja-crypto-cpu-std::sha512_batch` APIs.
- Four bounded caller-owned slots support SHA-384/512, named /224 and /256,
  and every validated general SHA-512/t parameter with separate IVs and typed
  digest identity. AVX2 executes four independent lanes; NEON executes two.
- Mixed identities, unequal lengths, bit tails, inactive slots and scalar
  remainder/padding work preserve order and exact canonical output widths.
- Public outputs commit atomically. Finite work and cancellation controls
  include general-t IV derivation; genuine integrity failures quarantine the
  authority while routine request rejection preserves reuse.
- Portable defaults, existing SHA-224/256 batching and ordinary/hardened
  single-stream APIs remain unchanged. No new external dependency is added.
- Clarifies caller-asserted public classification, the intentionally public
  unsafe platform-provider import, and the distinction between recoverable
  unwinding and panic-abort termination. No partial zeroization claim is added.

See the [API and security contract](../docs/sha512-batch-execution.md).
This is caller-classified public data only, without secret-state erasure.
It is not independent cryptographic review, FIPS validation or authorization
for military/classified deployment. Native performance is workload-specific;
dedicated instructions may outperform SIMD. Hardened multibuffer ownership
remains a later milestone.

Exceptional pentest/retest, fresh AMD/Intel/Linux Arm/Apple native qualification
and final release checks remain pending. The existing release workflow is
unchanged, and this internal milestone selects no crates for publication.
