# Brynja v0.24.36

Status: implementation and focused verification complete. Exceptional pentest,
fresh native collection, approved full release checks and green GitHub/CodeQL are pending.

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
owner approval before the full gate; no full-gate PASS is claimed yet.

Ordinary execution remains public-data-only and non-erasing. Hardened Keccak
acceleration is a later milestone. Previous native kernel/high-level observations
do not count as fresh cSHAKE execution evidence. The new hosted package closure
also requires refreshing the strict SHA-2 hardened native records before tagging.

The facade advances to 0.24.36, with **zero crates.io publications** selected.
The next public checkpoint remains v0.25.2. There is no independent cryptographic
sign-off or FIPS validation.
