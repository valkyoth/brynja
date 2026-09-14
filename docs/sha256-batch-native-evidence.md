# SHA-224/256 multibuffer native observations

Capture commit: `fe89ab576c465dd2005a31ca1585b881be8e8921`.
Status: all four ordinary batch captures reviewed; final release verification
and refresh of older shared native records remain pending.

The [index](../security/sha256-batch-native.json) binds the original, unmodified
JSON bytes. All four records match the same 190-file source snapshot and Rust
1.98.1 compiler revision. Platform attestation is operator-supplied, not proof
of a physical machine, migration safety, independent review or FIPS validation.

Each lane passed six portable and six vector batch tests, hosted selection,
384 independent oracle batches including 128 required-SIMD batches, 24 packaged
ownership/authority negatives, six algorithm/output mutants, three native
route-substitution mutants, the fixture overflow injection and exact SIMD
assembly inspection. AVX2 recorded 2,358 test vector calls; NEON recorded 6,547.

## Performance disposition

Seven-sample medians cover eight messages of 64, 128, 1,024 and 16,384 bytes for
each identity. Ratios below are portable time divided by SIMD time across those
eight measured workloads, not universal speedup promises.

| Lane | SIMD versus portable | Dedicated-instruction comparison |
| --- | --- | --- |
| Local AMD / AVX2 | 1.45–2.92× | SIMD also faster in this capture; machine/workload-specific |
| AWS Intel / AVX2 | 1.50–3.59× | Mixed-target build substantially penalizes the dedicated baseline; see diagnostic below |
| AWS Neoverse-V1 / NEON | 1.16–1.48× | Dedicated SHA is faster for every measured shape |
| Apple M2 Pro / NEON | 1.31–2.19× | Dedicated SHA is faster for every measured shape |

NEON has a measured benefit over portable code, but these Arm observations do
not justify preferring it over existing dedicated SHA instructions. Selection
remains explicit and default-off; callers should measure their workloads.

### Intel mixed-target caveat

The captured executable uses `+avx,+avx2,+sha,+sse2`. Its dedicated single-stream
SHA comparison was abnormally slow, and a repeat with that same bundle retained
the slowdown. A supplemental run of the same source/fixture with only
`+sha,+sse2` restored much faster dedicated SHA performance. For SHA-256 at
1,024 bytes/message, the original combined-build dedicated median was about
36 ms, versus about 0.95 ms in the SHA-only diagnostic (64 eight-message
iterations per sample). The diagnostic runs selected portable mode; it is not
another SIMD qualification record.

This demonstrates sensitivity to the build feature combination, not a general
25–59× advantage of SIMD over SHA instructions. The exact machine-code cause
has not been established; no AVX/SSE-transition explanation is claimed as proven.
Keep this as a performance follow-up for the mixed-feature deployment profile;
do not advertise the raw mixed-build comparison as an intrinsic algorithm gain.
No correctness mismatch occurred, and neither kernels nor dispatch were changed
to collect these observations.

## Remaining release work

The existing native gates reject older SHA-2, Keccak, KMAC, TupleHash and
ParallelHash captures because shared manifest/source inputs changed. The narrow
facade-version-only carry-forward does not cover these changes. Fresh records
are needed under the existing rules; SHA-1 and both MD5 native checks still pass.
No gate, approval rule or publication policy is changed by this evidence import.
