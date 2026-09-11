# Brynja v0.24.36

Status: implementation, focused verification, owner-supplied exceptional
pentest/retest, three-host native collection and the approved full local
release sweep complete. Tagging awaits green GitHub/CodeQL and explicit owner permission.

## cSHAKE CPU and hosted sponge APIs

- Default-off ordinary cSHAKE128/256 supports byte/arbitrary-bit X/N/S,
  one-shot and streaming input, incremental XOF and consuming final-bit output.
- Empty N/S preserves SHAKE equivalence; all bytepad, absorb, padding and output
  permutations retain the selected route. Initialization keeps typed backend
  errors and never retries them using portable execution.
- Explicit public-data classification applies to message, name and customization.
  Successful setup/message/output counts and route/work reports remain observable.
- Caller-owned scratch provides arbitrary-sized transactional output. Failure
  preserves output and retained state; scratch may change. Inline output is bounded.
- `brynja-crypto-cpu-std/sponge-execution` adds an optional first-party SHA-3
  dependency and caller-owned `sponge::Sponge` constructors for all eight ordinary
  SHA-3/SHAKE/cSHAKE algorithms. Portable/preferred/required selection is explicit.
- No new third-party dependency, unsafe code, kernel or implicit acceleration.
  Default `no_std` leaves, facade and protocol graphs stay unchanged.
- Pentest remediation distinguishes an unclassified prefix-encoding failure
  (`PrefixEncoding`) from an actual backend or overflow error. Regression tests
  and compiled mutants preserve error identity; wrong-architecture hosted
  rejection is documented and tested without changing platform authority.

See the [API and evidence guide](../docs/cshake-ordinary-execution.md).

Verification passed: workspace tests, strict Clippy, 628 cSHAKE oracle/official
cases plus retained SHA-3/SHAKE acceptance, package-only consumers, typed-input
and ownership negatives, compiled algorithm/route/error mutants, native AVX2,
supplemental AArch64 QEMU, focused Miri/ASan and Rust 1.90 compatibility.
The freshness gate advanced Miri/ASan to `nightly-2026-09-11`; stable Rust remains
1.98.1 and Kani's verifier host remains 1.90.0. This tool update requires explicit
owner approval before the full gate; the approved sweep after native collection
passed. It covered the Rust 1.90.0–1.98.1 matrix, full Miri/AddressSanitizer,
all 29 Kani harnesses, repository/package policies, current dependency advisories,
SBOM and official standards freshness. Reference-only IANA metadata and two
stale assurance-inventory labels were corrected and regression-tested; no
cryptographic source or native input changed after the clean retest/capture.
CI then caught stale downstream bindings from the late IANA refresh. The complete
surface/requirements metadata chain was repaired and its full regression suite
rerun; six requirement revisions record source-hash changes without scope changes.

Ordinary execution remains public-data-only and non-erasing. Hardened Keccak
acceleration is a later milestone. Previous native kernel/high-level observations
do not count as fresh cSHAKE execution evidence. [New cSHAKE observations](../assurance/cshake-execution-observations/v0.24.36/README.md)
and refreshed strict SHA-2 hardened records now cover Intel, AWS Arm and Mac M2.

The facade advances to 0.24.36, with **zero crates.io publications** selected.
The next public checkpoint remains v0.25.2. There is no independent cryptographic
sign-off or FIPS validation.
