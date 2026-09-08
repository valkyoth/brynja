# Brynja 0.24.27 Release Notes

Status: candidate; awaiting owner pentest

## Scope

Freeze general SHA-512/t private-state and typed-output lifecycle closure over
the callable v0.24.26 APIs. Production hash algorithms, public signatures,
dependency versions and CPU admissions are unchanged. The default-off
`general-sha512-t` leaf feature remains portable and allocation-independent.

The [lifecycle contract](../docs/sha512-t-lifecycle.md) inventories all eight
source-declared private regions (1170 bytes), typed output, borrowed inputs,
public t/IV/length metadata and transient values outside the erasure claim.
Borrowed preflight/update rejection preserves the live state. Consuming success,
error, cancellation, recoverable unwind and Drop destroy the owned state.
Every secret-output error clears the entire supplied destination; explicit
declassification clears the old owner after creating the deliberate public copy.

## Evidence

- All 510 parameters and destination widths 0–65: 33,660 ownership/bounds cases.
- All four secret-output routes, untouched caller input/red zones, continuation
  after preflight rejection, early Drop/cancel and unwind destination cleanup.
- Synthetic near-limit rejection compares every owned byte, including error
  precedence and non-mutating zero-length updates.
- An isolated test-only destructor observer reads live storage inside Drop,
  verifies exactly one state destruction across terminal and one-shot routes,
  and poisons every region to prevent already-zero storage hiding missing wipes.
- Debug/release compiled negative controls remove each of eight clearing calls
  and bypass cancel/public-finalizer ownership: 20 executed mutant failures.
- Existing all-t IV/digest oracle, ownership compile failures, source-bound
  endpoint MIR/LLVM/assembly checks and scoped Miri/ASan remain required.

Actual completed checks and limitations are recorded in the
[candidate pentest report](../security/pentest/v0.24.27.md). The observer only
exists in a temporary assurance copy; it is not shipped in the production crate.

## Limits and release flow

General SHA-512/t remains **In progress** through v0.24.28 package acceptance
and v0.24.29 final evidence. The six named SHA-2 APIs retain their existing status.
No whole-construction proof, independent cryptographic review, FIPS validation,
arbitrary-t protocol approval or hardware acceleration admission is claimed.
Ordinary states do not zeroize. Hardened cleanup covers owned storage, not
registers, compiler-created copies/spills, caches, swap, dumps, DMA or caller
copies. Forget, abort, double-panic termination and power loss can prevent Drop.

Facade version 0.24.27 advances for this internal milestone; all support versions
and sanitization 2.1.0 stay unchanged. Zero crates publish. The next scheduled
crates.io checkpoint remains v0.25.2. Obtain exceptional pentest/retest, complete
release checks, commit the report, wait for green GitHub/CodeQL and explicit tag
permission. This candidate does not change that release flow.
