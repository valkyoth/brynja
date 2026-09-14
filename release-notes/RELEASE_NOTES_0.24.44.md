# Brynja v0.24.44

Status: development in progress. Exceptional pentest/retest, fresh native
qualification, final release checks and GitHub/CodeQL are required before tagging.

Adds separate default-off hardened MD5 batch SIMD: eight-lane x86 AVX2 and
four-lane little-endian AArch64 NEON, clearing packed state/schedules/round
temporaries, affine batch ownership, typed secret outputs and explicit public
declassification. Static and hosted Portable/Prefer/Require selection is explicit;
ordinary APIs, portable defaults and legacy/modern isolation remain unchanged.

All active/inactive storage clears on normal destruction, errors, cancellation
and recoverable unwind. Secret destinations clear on failure; public destinations
are transactional. Failed batches cannot be reused and quarantine their executor.
Unequal suffixes and all padding remain scalar; reports account actual work.
Batch dimensions/lengths are public and not traffic-analysis protection.

This addresses the implementation work deferred from v0.24.43, but the historical
finding is not claimed closed before retest and evidence. The old internal-only
exception cannot authorize this release. No crates.io publication is scheduled.

MD5 remains collision-broken. No independent cryptographic verification, FIPS
validation or military approval is claimed. Registers, compiler copies/spills,
caches, caller copies, platform storage, mem::forget and abort/termination remain
outside complete-erasure guarantees. Static target features are a deployment
obligation, not runtime probing; cached hosted detection is not migration proof.

Development validation passed (not the final release gate):

- All 2,048 activity-mask/bit-tail cases on native AVX2 and emulated NEON;
  independent public/secret oracle comparisons on both routes.
- Packaged ownership/classification negatives and compiled algorithm, route and
  whole-region cleanup mutations; exact work and failure-output checks.
- Focused Miri and enforced native AVX2 AddressSanitizer/LeakSanitizer.
- Rust 1.90.0/1.98.1 MIR, LLVM and SIMD assembly checks for abort and unwind;
  Apple-target emitted-code compatibility (not native Apple execution).
- Workspace all-feature compilation, scoped strict Clippy and crate README checks.

Both ordinary and hardened MD5 native indexes are pending fresh four-lane
qualification. Historical captures remain unchanged and cannot qualify the new
source closure.

See [hardened MD5 execution](../docs/legacy-md5-hardened-execution.md).
