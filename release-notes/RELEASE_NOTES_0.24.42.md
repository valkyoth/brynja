# Brynja v0.24.42

Status: development in progress. Exceptional owner pentest/retest, fresh native
qualification, final scoped release checks and GitHub checks remain required.
These notes do not authorize a tag or publication.

Adds default-off hardened legacy SHA-1 acceleration with distinct authority,
executor and affine stream APIs. Static x86 SHA/SSE2 and little-endian AArch64
NEON/SHA1 kernels use owner-backed schedules and scratch. The optional hosted
adapter exposes supported AArch64 OS authority without enabling generic x86
current-core detection as a migration-safe guarantee.

Byte/arbitrary-bit one-shot and streaming hashing provide typed secret output,
explicit public declassification, consuming finalization/cancellation, checked
length preflight and permanent revocation. Ordinary authority cannot convert to
secret authority. Defaults and original candidate admission remain unchanged.

Six existing SHA-1 owner regions and one new 16-byte lane region are cleared
through mandatory compiler-resistant clearing. Failure/unwind guards clear
owned state and secret destinations; public-output errors are transactional.
The seven-region inventory and residual limits are documented in the
[hardened contract](../docs/legacy-sha1-hardened-execution.md).

Development checks include 529 NIST bit vectors, million-byte input, an
independent 1,135-message bit oracle, 512 arbitrary-state/block kernel cases,
18 ownership doctests, 22 packaged ownership/classification negatives, 10
debug/release output/padding/revocation mutants and 10 compiled cleanup removals.
Feature-enabled compiler checks cover both supported endpoints, both instruction
architectures and abort/unwind profiles. Miri and actual-instruction ASan are
scoped to changed SHA-1 and dependent legacy acceptance, not unrelated hashes.

SHA-1 remains collision-broken and outside modern facade/TLS/PKIX/FIPS graphs.
No external dependency is introduced. Internal source clearing is not a claim
about registers, spills, compiler copies, caches, dumps, DMA, swap, abort or caller
copies. No independent cryptographic review, FIPS validation, timing proof or
military-deployment approval exists. This internal milestone publishes zero crates.
