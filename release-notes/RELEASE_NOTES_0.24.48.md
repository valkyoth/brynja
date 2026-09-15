# Brynja v0.24.48

Development in progress: hardened multibuffer hash owners. Not released; no
crates selected for publication. The SHA-224/256 CPU foundation is implemented;
complete secret-bearing batch hashing and qualification remain pending.

## Scope

- Distinct clearing owners for SHA-224/256, the complete SHA-512 family including
  general SHA-512/t, and SHA-3/SHAKE/cSHAKE independent-message batching.
- Default-off AVX2/NEON execution with typed secret outputs and explicit public
  declassification. Ordinary non-erasing owners cannot substitute.
- Eligible batched ParallelHash leaves with bounded scheduling, exact leaf/root
  identity, deterministic merge and failure cleanup.
- Destructor, mutation, ownership, scalar/SIMD, compiler-cleanup and fresh native
  evidence before any claim of completion.

The [design](../docs/hardened-multibuffer-owners.md) records the implementation
order and acceptance obligations. No release-gate or publication rule changes.

## Opening changes

Version metadata and downstream fixture pins advance to v0.24.48. Two rustdoc
comments now quote `Keccak-f[1600]` as code instead of an unresolved link. This
does not change executable Rust, kernels, algorithm domains or dispatch.

## Limitations

The new `brynja-crypto-cpu/sha256-hardened-batch` feature supplies distinct
Authority/Session/Workspace types and clearing AVX2/NEON compression kernels.
It enables only the existing first-party clearing dependency. Workspace cleanup
covers all packed initial words, schedule, working words and six temporaries,
including inactive lanes. Backend errors, checked counter overflow and unwind
quarantine authority without committing caller state. Raw caller states/blocks
remain caller-owned; complete leaf hashing, typed destinations, wide SHA-2,
Keccak and ParallelHash integration are not supplied by this foundation.

Batch shape, configured limits and scheduling are public; callers must pad when
traffic-analysis resistance is required. Explicit clearing cannot guarantee
erasure of registers, compiler-created copies, caches, swap, dumps or DMA storage.
Drop requires normal return or recoverable unwinding, not abort/forced termination
or `mem::forget`. Independent cryptographic review, FIPS validation and military
deployment approval are not claimed.
