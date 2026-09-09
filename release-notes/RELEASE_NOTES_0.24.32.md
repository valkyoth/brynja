# Brynja v0.24.32

Status: owner retest and fresh native observations passed on 0c6cee49;
final local release checks passed. Awaiting green GitHub/CodeQL and explicit
owner tag approval. No tag or crates.io publication authorized.

## Hosted runtime feature safety

- Add default-off `runtime-execution` APIs in the dependency-free no_std CPU
  leaf and its separate optional std adapter. No facade/default dependency,
  cryptographic algorithm, external package or legacy admission changes.
- Expose explicit Portable, Prefer and Require selection with observable
  unavailable-feature/OS-state, architecture and migration dispositions.
- Authorize complete AArch64 feature bundles using reviewed Linux/Android,
  Apple and Windows system-feature interfaces. Generic x86 and unreviewed
  platforms remain portable/error, not current-core-CPUID-authorized.
- Keep the unsafe platform-proof constructor separate from the safe hosted
  API. No safe detector injection, boolean attestation or report conversion.
- Execute real kernel startup KATs before issuing borrowed sessions. Reject
  stale generations, testing, quarantine and wrong-operation calls before
  state mutation. KAT failure never silently falls back, even in Prefer mode.
- Add public packaged consumers, debug/release behavior checks, compiled
  lifecycle/selection mutants, compiler endpoint tests and generic AArch64
  QEMU execution without evidence cfg or target-feature specialization.
- Extend focused CPU-owner Miri/ASan coverage; leave unchanged algorithm
  evidence separate from the newly reviewed hosted authority boundary.
- Pentest hardening: require explicit borrowed `PublicData` classification at
  static and hosted raw kernel calls, with packaged compile-negative tests for
  every state/block argument. This marker cannot establish data provenance.
- Make availability selection a single private permit-boundary decision.
  Regression tests preserve exact Prefer/Require dispositions without masking
  kernel errors or quarantined startup health. Document non-reentrant use.

See [the complete hosted contract](../docs/hosted-cpu-execution.md) for platform
sources, usage, repeatable checks and limitations. The facade advances to
0.24.32; support crates retain their current versions until publication.
Every release publication flag stays false; the next checkpoint is v0.25.2.

The [final verification report](../security/pentest/v0.24.32.md#final-release-verification)
records the repository gate, twelve-compiler matrix, full registered Miri
coverage, AddressSanitizer, all 29 Kani harnesses, native observations and
publication-policy checks. Release finalization changes documentation and its
bindings only; it does not change the reviewed Rust or dependency graph.

## Boundaries

These are ordinary raw SHA-256/SHA-512 compression and Keccak permutation
APIs, not high-level hash integration (v0.24.33) or hardened secret processing.
The OS/hypervisor must preserve its advertised process instruction ABI.
Thread-bound ownership and passing tests do not establish migration safety.
Quarantine is permanent for one owner, not a global/FIPS module failure latch.
No register, spill, stack, cache or platform-storage erasure is provided.

Rust 1.90's Windows detector has SHA2 but no SHA3/SHA512 detection. That older
compiler reports unavailable rather than bypassing detection. Generic x86
requires a future reviewed hosted scheduler adapter or the existing explicit
target-specialized static API; no affinity change is forced on callers.

QEMU and cross-compilation are not native measurements. Fresh Intel, AWS Arm,
Apple M2 and local AMD observations are in the
[native archive](../assurance/hosted-cpu-observations/v0.24.32/README.md).
Arm/Mac each executed three hosted kernels; Intel/AMD verified safe fallback.
The observations do not establish heterogeneous-CPU or VM migration safety. No
independent cryptographic review or FIPS validation is claimed.
