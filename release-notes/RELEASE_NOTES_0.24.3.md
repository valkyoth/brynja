# Brynja 0.24.3 Release Notes

Status: voluntary pentest and remediation retest passed; final local gate,
hosted GitHub and CodeQL, and signed tag pending; no crates.io publication is
selected

Brynja 0.24.3 freezes package-external portable acceptance for all four SHA-3
digests and both SHAKE XOFs before any acceleration or native evidence work.
This remains the byte-oriented portable acceptance milestone. The SHA-3/SHAKE
family remains **In progress** through v0.24.11: v0.24.4 adds byte-oriented
backend evidence, while v0.24.6-v0.24.11 make API completeness machine-readable
and close arbitrary-bit, hardened secret-bearing, internal sanitization, and
combined downstream acceptance.

## Added

- A standalone allocation-free `no_std` consumer using only documented
  `brynja-hash-sha3` and `brynja::crypto` public APIs.
- Twenty-four fixed-output results covering SHA3-224, SHA3-256, SHA3-384, and
  SHA3-512 over official empty and 1,600-bit examples plus independent text,
  real-file, exact-rate, and multi-rate expectations.
- Ten SHAKE128/SHAKE256 outputs covering official examples, zero-length
  output, exact input rates, 257-byte real-file output, and 343-byte arbitrary-
  tail output across multiple squeeze permutations.
- Twenty leaf-and-facade incremental XOF runs with irregular input and output partitioning,
  checked failure-before-mutation, and domain-separation negatives.
- Exact sixteen-package archive creation in an empty Cargo home followed by
  safe extraction and an offline version-only consumer run.
- Negative fixtures for six output corruptions, missing public behavior,
  hidden features, false execution-path claims, invalid phase transitions,
  private permutation access, and incomplete package contents.
- Standalone Clippy enforcement with warnings denied in the local repository
  gate and hosted CI; policy fixtures reject removal of either binding.
- A roadmap-wide API-profile and secret-state audit. New fail-closed milestones
  require every primitive, construction, and protocol consumer to dispose of
  all safe operation shapes explicitly and register every Brynja-owned secret
  field, temporary, lifecycle edge, sanitization symbol, evidence artifact,
  caller handoff, and residual gap.
- Separate ordinary public-data and hardened secret-bearing SHA-2/SHA-3/SHAKE
  profiles, canonical arbitrary-bit APIs, and final package-external acceptance
  before either expanded family returns to **Fully implemented** status.
- Sealed hardened capabilities that downstream crates cannot implement, forge,
  or assert; recoverable-unwind and adjacent-cleanup-failure coverage with
  non-panicking all-region attempts; and explicit `mem::forget`, abort, forced-
  termination, power-loss, register, cache, OS and crash-image residuals.
- Typed secret-derived output rules: callers must explicitly declassify public
  output or provide a secret-owned destination; failures leave output unchanged
  or clear every unavoidable partial secret write, including incremental XOFs.
- Separately locked RustCrypto-trait, synchronous I/O, and asynchronous I/O
  companion-adapter milestones before the final public API freeze.

## Verification

- The frozen consumer runs from repository paths and independently assembled
  package archives while retaining `default-features = false` throughout.
- Rust 1.90.0 through 1.98.0 run the same public consumer.
- Every promised OS-less target checks the fixture library as `no_std`.
- Existing FIPS 202 vectors, differential campaigns, Kani bounds, Miri,
  AddressSanitizer, documentation examples, package checks, dependency policy,
  advisory policy, and SBOM remain mandatory repository gates.
- The pentest-reported Low assurance-control gap is closed: the fixture's
  declared forbidden Clippy lints are now executed, and its existing warning
  is corrected. Independent retest of exact candidate
  `c7bd354e5bcf9a816c366cf24d0d88347771afc5` passed with zero open findings.

## Security Boundaries

This milestone adds no production cryptographic code, unsafe Rust, foreign
code, assembly, dependency, runtime detection, accelerated candidate, or
backend admission. The only execution path accepted here is the existing
portable safe-Rust implementation. Raw Keccak-f[1600] remains private.

SHA-3 and SHAKE currently remain ordinary unkeyed public-data functions. A
caller can clear its own buffers but cannot clear private sponge state. The
planned hardened owner therefore uses Brynja's admitted sanitization boundary
to destroy every Brynja-owned lane, partial buffer, suffix, squeeze state,
temporary, failure, recoverable-unwind, and `Drop` copy before any keyed or
secret-bearing use is admitted. Hardened authority is sealed and secret-derived
output stays typed until explicit declassification. `mem::forget`, abort,
forced termination, power loss, register, spill, cache, OS, compiler-copy, crash-snapshot,
independent-review, and FIPS 140-3 validation claims remain absent. Protocols
must also bound caller-selected XOF output for their own semantics.

## Release Process

Version 0.24.3 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates.io packages. Because it
changes only acceptance tooling, documentation, and the facade version, it has
no scheduled pentest and no exceptional security trigger. A voluntary review
was nevertheless completed; its Low assurance-control finding is remediated
and the retest passed. The full cumulative delta remains subject to the
scheduled backwards-looking v0.25.0 assessment. The exact report-bearing
candidate must pass the complete local gate plus hosted GitHub and CodeQL
before the signed tag is authorized.
