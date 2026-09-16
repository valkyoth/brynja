# Brynja v0.24.48

Development in progress: hardened multibuffer hash owners. Not released; no
crates selected for publication. The narrow and wide SHA-2 CPU and leaf batch
APIs, Keccak CPU/leaf batching and distinct hosted adapters are implemented;
ParallelHash integration and qualification remain pending.

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
remain caller-owned at this low-level boundary.

`brynja-hash-sha2/hardened-batch-execution` adds the separate `hardened_batch`
module. It handles SHA-224/256 canonical arbitrary-bit input, mixed identity,
inactive slots and uneven lengths through clearing storage. Exact-width secret
destination borrows move into a non-copying output owner and clear on failure
or Drop; public output requires explicit declassification and commits atomically.
Budgets include padding; routine rejection/cancellation permits executor reuse,
while backend/invariant failures and unwind quarantine it.

`brynja-crypto-cpu/sha512-hardened-batch` and the leaf
`brynja-hash-sha2/hardened-batch512-execution` extend these contracts through
distinct wide owners and kernels: four AVX2 lanes or two NEON lanes, SHA-384,
SHA-512, named /224 and /256, and all 510 general SHA-512/t parameters. Secret
outputs preserve exact parameter identity and canonical final bits. Finite work
includes general IV derivation as well as padding. Ordinary batch storage and
public digest importers are not used for secret state. ParallelHash integration
and full qualification are still pending. Keccak now
has a distinct default-off `brynja-crypto-cpu/keccak-hardened-batch` permutation
foundation with four AVX2 or two NEON lanes. Word/byte state entry points clear
all packed state, parity, delta and rho/pi/chi staging on every exit and commit
caller state only after health/accounting validation.

`brynja-hash-sha3/hardened-batch-execution` adds distinct SHA-3/SHAKE/cSHAKE
leaf batching with four optional slots, per-lane domains/rates and arbitrary-bit
messages/customization/output. Virtual framing cursors and clearing scalar
tails avoid ordinary batch storage. Secret outputs retain exact identity and
bit count; every supplied secret destination clears on failure, while public
destinations remain unchanged on failure. Entire caller staging and owned
workspace clear on every exit, including unused capacity. Finite budgets count
prefix, padding and squeezing work. Required eligibility is checked before
secret processing; routine rejection permits reuse, backend/invariant/unwind
failures revoke execution. This feature does not enable ordinary batching.

The three separate hosted `sha256-hardened-batch`, `sha512-hardened-batch` and
`keccak-hardened-batch` features borrow those exact clearing leaf executors.
They never enable ordinary batch features. Portable avoids probing; Prefer may
select portable only on initial unavailability, not after KAT/health failure.
Generic x86 remains portable/unavailable without a build-specialized AVX2
deployment. Allowlisted little-endian AArch64 uses the OS NEON feature ABI;
cached detection does not prove arbitrary migration safety. CPU revocation
affects every borrowed accelerated executor, not unrelated portable executors.

Batch shape, configured limits and scheduling are public; callers must pad when
traffic-analysis resistance is required. Explicit clearing cannot guarantee
erasure of registers, compiler-created copies, caches, swap, dumps or DMA storage.
Drop requires normal return or recoverable unwinding, not abort/forced termination
or `mem::forget`. Independent cryptographic review, FIPS validation and military
deployment approval are not claimed.
