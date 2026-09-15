# Keccak multibuffer native observations

Capture commit: `e7beb698792eb21d96283204431fe0ded12fa242`.
Collection and project review completed on 2026-09-15; final release checks and
GitHub approval remain pending. The [index](../security/keccak-batch-native.json)
binds the original records by SHA-256. All four lanes match the same 260-input
source snapshot and Rust 1.98.1 host compiler.

Each lane passed actual kernel execution (1,024 calls), 512 API comparisons,
1,024 independent outputs in each of portable/prefer/required modes, malformed
requests, 23 packaged ownership/classification negatives, ten compiled mutants,
the correct-output scalar-only false-route mutant, and emitted SIMD inspection.
All 128 benchmark shapes passed with seven paired samples and checked outputs.

## Performance disposition

Ratios are portable median time divided by selected median time; values below
one mean batching was slower. These ranges cover the full hardware lane width
(four AVX2 states or two NEON states), all eight identities, and four input sizes
per identity. Other lane counts and individual medians remain in each JSON.

| Native lane | Full-width SIMD / portable speed ratio |
| --- | --- |
| Local AMD Ryzen 9 9950X3D, AVX2 | 1.146–1.357× |
| AWS Intel Xeon Platinum 8488C, AVX2 | 0.784–1.177× |
| AWS Arm Neoverse-V1, NEON | 0.560–0.765× |
| Apple M2 Pro, NEON | 0.679–0.840× |

The Arm results do not establish a performance benefit for these workloads.
Intel is workload-dependent. No universal crossover threshold or automatic
preference is justified. Features remain default-off, the threshold remains
caller-selected, and portable execution remains available. No kernel or test was
changed to improve these measurements. This benchmark compares batch-selected
execution to portable execution, not to dedicated single-state SHA-3 instructions.

## Shared evidence refresh

The changed shared CPU manifest invalidated earlier single-state source bindings.
Fresh SHA-2, Keccak, KMAC, TupleHash and ParallelHash records were collected on
Linux Intel, Linux Arm, Apple M2 and local AMD at the same commit. All twenty
shared records passed the existing compiler/source/route/result validators.
The existing three-platform indexes use Intel, AWS Arm and Apple; supplementary
AMD records are retained alongside them without changing the required lane set.

- [SHA-2](../security/sha2-hardened-native.json)
- [Keccak](../security/keccak-hardened-native.json)
- [KMAC](../security/kmac-execution-native.json)
- [TupleHash](../security/tuplehash-execution-native.json)
- [ParallelHash](../security/parallelhash-execution-native.json)

Capture-time README and contract status labels are retained as source-bound
historical inputs; this dated report records the subsequent native disposition.
No release-gate rule was added or weakened.

These are project-reviewed, operator-self-attested observations, not independent
cryptographic verification, provider attestation, migration or physical
side-channel qualification, military approval, or FIPS validation. Ordinary
batch storage still does not erase secrets. PublicData is only a caller assertion;
the documented limitation is not fixed by these tests. Separate hardened owners
remain planned for v0.24.48. See the [pentest record](../security/pentest/v0.24.47.md).
