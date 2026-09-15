# SHA-512-family multibuffer native observations

Capture commit: `49ca105c335e4179705ced2fb77ca99c2c5444cf`.
Status: all four ordinary batch captures and fifteen shared native refresh
records reviewed; final release checks remain pending.

The [index](../security/sha512-batch-native.json) binds the original JSON bytes
by SHA-256. AMD, Intel, AWS Arm and Apple M2 records match the same 204-file
source snapshot and Rust 1.98.1 compiler revision. Captures are operator
self-attestation, not independent cryptographic verification, proof of provider
identity, migration safety, physical side-channel qualification or FIPS validation.

Each lane passed hosted selection, nine portable and nine vector-enabled batch
tests, 4,846 independent oracle batches in portable/preferred modes and 4,590
full-width required-SIMD batches. Packaged tests retained all 24 negative
ownership/classification/authority checks, the positive public unsafe signature
check, eight algorithm/output mutants, three vector-route/commit mutants,
malformed input checks and fixture-counter overflow rejection. Exact emitted
kernel inspection confirmed AVX2 or NEON SIMD instructions.

## Performance disposition

Seven-sample medians cover four independent SHA-384 or SHA-512 messages at
128, 256, 1,024 and 16,384 bytes per message. The ratios below are portable time
divided by SIMD time across those eight shapes, not universal speedup claims.

| Lane | SIMD versus portable | Dedicated SHA-512 comparison |
| --- | --- | --- |
| Local AMD / AVX2 | 1.18–1.58× | Not available in this x86 profile |
| AWS Intel / AVX2 | 1.26–2.02× | Not available in this x86 profile |
| AWS Arm / NEON | 0.957–0.961×; no benefit in these measurements | Dedicated faster at 256 bytes and above; slower at 128 bytes |
| Apple M2 Pro / NEON | 1.15–1.45× | Dedicated instructions faster than SIMD |

The AWS Arm no-benefit result is retained: SIMD was roughly 4–5% slower than
portable execution for these shapes. Neither Arm capture justifies preferring
SIMD over the existing dedicated SHA-512 route. API selection remains explicit
and default-off; callers should measure their own workload and build profile.
No kernel, dispatch policy, workload threshold or benchmark was changed to
improve these observations.

## Shared native refresh and remaining release work

The existing native gates reject earlier SHA-2, Keccak, KMAC, TupleHash and
ParallelHash records because the shared CPU manifest changed. Those five
families were freshly captured on Linux Intel, Linux Arm and Apple at the same
commit. All fifteen records passed their existing source, compiler, platform,
route and result validators. The original JSON bytes are retained with their
SHA-256 hashes and project-reviewed CPU identities in the existing indexes:

- [SHA-2](../security/sha2-hardened-native.json): 197 bound inputs per lane.
- [Keccak](../security/keccak-hardened-native.json): 246 bound inputs per lane.
- [KMAC](../security/kmac-execution-native.json): 289 bound inputs per lane.
- [TupleHash](../security/tuplehash-execution-native.json): 290 bound inputs per lane.
- [ParallelHash](../security/parallelhash-execution-native.json): 334 bound inputs per lane.

SHA-1 and ordinary/hardened MD5 native validation still passes without refresh.
This is the unchanged source-binding policy, not an added gate.

The ordinary public-data provenance and non-erasure limitation remains tracked
in the [pentest report](../security/pentest/v0.24.46.md). Functional native
evidence does not resolve it. Hardened multibuffer ownership remains a separate
milestone. Final release verification and GitHub approval are not established
by this collection report; no tag or publication is authorized here.
