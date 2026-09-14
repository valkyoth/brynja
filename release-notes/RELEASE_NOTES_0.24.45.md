# Brynja v0.24.45

Status: release candidate; exceptional pentest and project-owned native review
complete. Final release verification and green GitHub checks are required before tagging.

Adds default-off independent-message SHA-224/SHA-256 batching: eight-lane AVX2
and four-lane AArch64 NEON. Caller-owned eight-slot batches support mixed
identities, inactive lanes, unequal lengths and canonical arbitrary-bit tails.
Eligible common prefixes run SIMD; remaining work and padding are scalar.

Public-data-only classification, finite compression budgets, cancellation,
transactional outputs and sealed thread-bound authority are explicit. Routine
request rejection preserves reuse; integrity failures and unwind quarantine.
Reports distinguish actual vector and scalar work. A supplied backend failure
never silently switches to portable. Workload thresholds are caller-selected
from measurements, not inferred from vector width.

On x86-64, the Cargo feature alone does not activate AVX2. Generic builds use
portable execution in hosted Prefer mode and return Unavailable in Require
mode. AVX2 needs a target-specialized executable and its CPU/OS deployment
contract; current-core CPUID is not treated as lifetime migration authority.

Development acceptance includes lane/oracle comparisons, package and ownership
negatives, algorithm/output mutations, actual dispatch accounting and separate
Linux/Apple SIMD code-generation checks. Fresh native correctness and benchmark
records and the owner pentest are recorded in the
[native evidence review](../docs/sha256-batch-native-evidence.md) and
[pentest report](../security/pentest/v0.24.45.md). Four batch lanes cover AMD,
Intel, AWS Arm and Apple M2; fifteen refreshed shared-native records cover
SHA-2, Keccak, KMAC, TupleHash and ParallelHash on Intel, AWS Arm and Apple M2.
These records supersede the pending-collection status in the source-bound
development contract preserved from the capture commit.

SIMD outperformed portable hashing on the measured full-width workloads, but
dedicated SHA instructions were faster than NEON on both Arm platforms. The
Intel mixed-target executable penalized its dedicated-SHA comparison; the
review preserves that diagnostic instead of claiming a universal SIMD speedup.

Portable defaults, dedicated single-stream APIs, secret-bearing hardened APIs,
legacy isolation and external dependencies remain unchanged. No source-owned
zeroization is claimed for ordinary SIMD. No independent cryptographic review,
FIPS validation, migration proof or military approval is claimed.

No crates.io publication is scheduled. Existing release gates, approvals and
detached-runner workflow are unchanged. See the [batch API contract](../docs/sha256-batch-execution.md).
