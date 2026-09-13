# Brynja v0.24.43

Status: implementation and development checks complete. Exceptional pentest/retest, fresh native
qualification and final release/GitHub checks remain required before tagging.

Adds default-off ordinary MD5 batch execution, separate from the unchanged
unadmitted candidate APIs. AVX2 handles eight independent messages; little-endian
AArch64 NEON handles four. Explicit static or hosted platform authority and an
actual startup KAT are required. Generic hosted x86-64 remains portable unless
the binary explicitly opts into complete AVX2 target specialization.

Portable, Prefer and Require modes preserve stable eight-slot order, inactive
versus empty identities, unequal lengths and canonical arbitrary-bit tails.
Full-width common message prefixes use SIMD; suffixes and all padding use scalar
compression. Require rejects no-vector workloads before output/work mutation.
Reports reflect actual vector/scalar compression blocks, not claimed capability.
Backend failures never silently fall back. Public-output failures are atomic;
backend revocation and recoverable callback unwinding quarantine the executor.

The API requires explicit public-data classification and cannot return secret
output or expose its raw session. Authorities/executors are thread-bound and
non-cloneable. Ordinary SIMD scratch is not secret-cleanup-qualified; portable
hardened defaults are unchanged and hardened MD5 SIMD belongs to v0.24.44.
Static feature selection is a deployment contract, not a runtime probe. Cached
OS detection does not guarantee arbitrary hotplug or hypervisor migration safety.

Passing development assurance includes all activity masks and bit tails, an independent bit-level
oracle, external-package ownership/classification rejection, compiled
output/accounting mutations, negative native-evidence schemas, scoped Miri,
actual AVX2 ASan/LSan and NEON QEMU execution. The selected MD5/legacy verifier
suite, compatibility matrix, scoped repository gate and packaged README
examples passed. These do not replace pending pentest or native qualification.
Short native x86-64/AArch64 CI jobs require real operational route markers.
Fresh AMD/Intel/AWS Arm/Apple M2 evidence remains a fail-closed tag prerequisite.

MD5 remains collision-broken legacy compatibility, absent from the modern
facade. Nothing claims independent cryptographic verification, side-channel
qualification, FIPS validation or military suitability. No new external
dependency, default activation or crates.io publication is introduced.

See [ordinary MD5 execution](../docs/legacy-md5-execution.md) and the
[pending pentest record](../security/pentest/v0.24.43.md).
