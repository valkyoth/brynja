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
internal length admission and permanent revocation. Ordinary authority cannot convert to
secret authority. Defaults and original candidate admission remain unchanged.

Six existing SHA-1 owner regions and one new 16-byte lane region are cleared
through mandatory compiler-resistant clearing. Failure/unwind guards clear
owned state and secret destinations; public-output errors are transactional.
The seven-region inventory and residual limits are documented in the
[hardened contract](../docs/legacy-sha1-hardened-execution.md).

Development checks include 529 NIST bit vectors, million-byte input, an
independent 1,135-message bit oracle, 512 arbitrary-state/block kernel cases,
18 ownership doctests, 24 packaged ownership/classification negatives, 10
debug/release output/padding/revocation mutants and 10 compiled cleanup removals.
Feature-enabled compiler checks cover both supported endpoints, both instruction
architectures and abort/unwind profiles. Miri and actual-instruction ASan are
scoped to changed SHA-1 and dependent legacy acceptance, not unrelated hashes.

Pentest follow-up adds short native x86-64/AArch64 CI lanes, explicit required
hardware-test mode, and compiled missing-feature regressions. The local native
SHA-NI sanitizer rerun passed with LeakSanitizer enabled (`detect_leaks=1`).
Static authority documentation explicitly states that its callback is a
compile-time constant, not runtime detection or migration protection.
The sanitizer gate now forces leak detection and nonzero ASan/LSan error exits,
overriding ambient disabling/suppression settings. Missing LSan support fails
the gate; policy and driver regressions enforce this without a long CI run.

Native collection also exposed Apple's valid inlining of the hardened kernel.
The compiler checker now scopes evidence to its unique secret-authority caller
when no standalone kernel exists, requiring the complete instruction set in
both that caller's LLVM and assembly. Regression tests reject unrelated-function
evidence and ambiguous symbols; all seven owned-region cleanup checks remain.
This correction changes assurance tooling only, not production cryptography.

A later pentest correctly identified a retained-length oracle in the new
hardened stream's hypothetical byte/bit capacity checks. Those public methods
are removed; actual update/finalization overflow checks remain internal and
unchanged. Packaged consumers reject both removed methods, and source policy
rejects unreviewed public stream queries. This does not claim traffic-analysis
resistance or length hiding through actual-input processing time/errors.
The old candidate-admission flag is explicitly distinguished from the separately
opted-in operational authorities, as required by the acceleration contract.
Earlier native records remain historical; the changed source needs fresh review
and capture before tagging.

SHA-1 remains collision-broken and outside modern facade/TLS/PKIX/FIPS graphs.
No external dependency is introduced. Internal source clearing is not a claim
about registers, spills, compiler copies, caches, dumps, DMA, swap, abort or caller
copies. No independent cryptographic review, FIPS validation, timing proof or
military-deployment approval exists. This internal milestone publishes zero crates.
