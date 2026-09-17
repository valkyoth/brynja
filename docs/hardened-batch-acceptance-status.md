# Hardened multibuffer acceptance status

Development checkpoint: v0.24.48, 2026-09-17. This is an index of the existing
acceptance work, not a new gate, approval, or replacement for its raw results.
The [design and detailed evidence](hardened-multibuffer-owners.md) and
[development review record](../security/pentest/v0.24.48.md) retain the individual
checks, source revisions, assumptions and failed attempts.

## Implemented scope

Distinct clearing CPU, leaf and hosted owners exist for narrow SHA-2, the complete
SHA-512 family and all eight SHA-3/SHAKE/cSHAKE identities. Scheduled, streaming
and threaded ParallelHash use these owners without relabeling ordinary storage.
The exported APIs and package examples are implemented, not proposed names.
Ordinary APIs remain public-data-only; their non-erasing storage is unchanged.
The [platform contract](hardened-batch-platform-contract.md) distinguishes
compiler-baseline admission from runtime observation and external unsafe import.

## Development evidence map

“Passed” below refers to the recorded implementation-author development runs,
not an independently reviewed or source-current release receipt. A production,
test, toolchain or relevant tooling change requires reassessing the affected
evidence. Do not substitute this table for checking that binding.

| Acceptance area | Recorded coverage and entry point | Disposition |
| --- | --- | --- |
| Public API and feature isolation | [Extracted-package check](../scripts/cryptography/check-hardened-batch-package.py): six crates' tests/examples, eight first-party dependencies, 129 ownership negatives, 16 ordinary-owner substitutions/conversions | Passed development runs; default-off hardened-only graph checked |
| Narrow SHA-2 correctness | [Independent bit oracle](../scripts/cryptography/check-hardened-sha256-batch-oracle.py): 896 portable/prefer/require native cases | Passed local AVX2; generic portable also checked |
| Wide SHA-2 correctness | [Independent oracle](../scripts/cryptography/check-hardened-sha512-batch-oracle.py): 14,282 cases including all 510 general-t parameters | Passed local AVX2; typed parameter identity retained |
| Keccak-family correctness | [Independent oracle](../scripts/cryptography/check-hardened-keccak-batch-oracle.py): 800 cases across eight identities | Passed local AVX2; bit framing, variable output and cleanup checked |
| ParallelHash integration | [Local oracle](../scripts/cryptography/check-parallelhash-local-batch-oracle.py) and [threaded oracle](../scripts/cryptography/check-parallelhash-batch-oracle.py): 2,240 and 1,680 cases, respectively | Passed local AVX2 and separate generic campaigns; exact work/identity and clearing checked |
| Lifecycle and real dispatch | Family tests, per-region probes and compiled omission/dispatch mutants; package check repeats 11 compiled mutations with SIMD enabled | Passed development campaigns, including emulated NEON; emulation is not native qualification |
| Memory-model checks | Focused pinned Miri owner/error/unwind tests, including all four threaded coordinator identities at three launch positions | Recorded passes; neither exhaustive thread scheduling nor native SIMD proof |
| Bounded invariants | [Batch-control Kani checks](../scripts/assurance/check-hardened-batch-kani.py) and [ParallelHash proofs](../scripts/assurance/check-parallel-batch-kani.py), with real-source mutations | Passed within stated bounds and modeled-consumer assumptions |
| Emitted cleanup | SHA-2/SHA-3 workspace, output and ParallelHash compiler checkers linked in the design | Passed recorded Rust 1.90.0/1.98.1 x86 Linux, Arm Linux and Apple Arm matrices; explicit limits below |
| Sanitizers | [ASan/LSan driver](../scripts/cryptography/check-hardened-batch-asan.py): six layers, 117 tests, forced leak detection and fatal exits | Passed local AVX2; driver enforcement regressions passed |
| Workload timing | [Leaf benchmark](../scripts/cryptography/check-hardened-batch-bench.py), 640 rows; [threaded benchmark](../scripts/cryptography/check-parallelhash-batch-bench.py), 96 rows | Local native and generic runs passed output/work/cleanup checks; slower outcomes retained |
| Native collection tooling | [Four-lane runtime collector](hardened-batch-native-collection.md), 484 tamper regressions and a real 14-step AMD smoke run | Collector tested; final owner-reviewed native records still pending |

The compiler matrix includes abort/unwind builds; that does not imply destructors
run on abort. Its checks cover specific emitted functions, their owned regions,
cleanup calls, arguments and control-flow paths. They do not prove arbitrary
caller/alias provenance, every exceptional call-site correspondence, linked
unwinder/CFI restoration, or all possible scheduler behavior. Kani does not prove
whole hashes, arbitrary-length streaming or thread joining. Functional and
unwind tests supply separate evidence; they do not turn bounded proofs into
universal guarantees. Keep these limitations visible during owner review.

Timing compares hardened portable and selected batching, and local scheduled
portable against threaded ParallelHash. It does not compare every dedicated
single-stream hardware implementation, establish constant-time machine behavior,
or promise a crossover/speedup. Those are not conclusions of these measurements.

## Reconciliation checks

The 2026-09-17 reconciliation additionally passed:

- All four no-std crates with the new hardened batch features on
  `thumbv7em-none-eabi` and `wasm32-unknown-unknown`, at both Rust 1.90.0 and 1.98.1.
  These are compilation checks, not runtime SIMD evidence on those targets.
- Formatting and all-feature/all-target Clippy for all six feature-owning crates,
  using the repository's existing `chunks_exact_to_as_chunks` style allowance.
- Combined all-feature unit, integration and documentation tests for those six
  crates on Rust 1.98.1. This generic build checks feature coexistence; it is not
  a replacement for the separate required-SIMD native campaigns.
- Both workspace feature-graph policies, API-profile register, unsafe-source
  policy, committed SBOM, review-hash metadata, verification-status, script
  inventory, assurance policy, roadmap and documentation-link checks.

The crate list and exact feature selections are also centralized in the existing
[package checker](../scripts/cryptography/check-hardened-batch-package.py).
No release script, publication rule, verifier selector or gate was changed.

## Remaining hand-off

1. Obtain the exceptional owner pentest/retest against the selected committed
   source. The ledger remains `RETEST REQUIRED` / `PENDING`; zero recorded open
   findings is not a PASS verdict. Address any finding and test its remediation.
2. Collect and review fresh AMD, Intel, AWS Arm and Apple runtime records against
   the agreed source. The local collector smoke record is not final approval.
   Its bundle explicitly excludes Miri, Kani, sanitizers and compiler inspection;
   preserve those separate obligations in the final verification.
3. Run the unchanged release workflow on the settled candidate, including its
   evidence-binding, documentation, package and selected-verifier checks. Retain
   the existing owner-approval behavior for a broader/full sweep.
4. Wait for green GitHub checks and explicit owner authorization before tagging.

There is no independent cryptographic review, FIPS validation or military
approval claim. Registers, compiler-created copies, platform storage, abort,
forced termination and deliberately forgotten owners retain their documented
limits. This checkpoint does not authorize routing secrets through ordinary
batching or changing process-wide deployment policy.
