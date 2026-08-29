# Brynja 0.24.3 Release Notes

Status: implementation and local verification complete; pentest, hosted GitHub
and CodeQL, and signed tag pending; no scheduled pentest or crates.io
publication is required by policy

Brynja 0.24.3 freezes package-external portable acceptance for all four SHA-3
digests and both SHAKE XOFs before any acceleration or native evidence work.
The SHA-3/SHAKE family remains **In progress** until v0.24.4 reruns this
unchanged consumer through every admitted backend.

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

## Verification

- The frozen consumer runs from repository paths and independently assembled
  package archives while retaining `default-features = false` throughout.
- Rust 1.90.0 through 1.98.0 run the same public consumer.
- Every promised OS-less target checks the fixture library as `no_std`.
- Existing FIPS 202 vectors, differential campaigns, Kani bounds, Miri,
  AddressSanitizer, documentation examples, package checks, dependency policy,
  advisory policy, and SBOM remain mandatory repository gates.

## Security Boundaries

This milestone adds no production cryptographic code, unsafe Rust, foreign
code, assembly, dependency, runtime detection, accelerated candidate, or
backend admission. The only execution path accepted here is the existing
portable safe-Rust implementation. Raw Keccak-f[1600] remains private.

SHA-3 and SHAKE remain ordinary unkeyed functions. They make no secret-state,
register, spill, stack, cache, crash-snapshot, independent-review, or FIPS
140-3 validation claim. Protocols must bound caller-selected XOF output for
their own semantics.

## Release Process

Version 0.24.3 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates.io packages. Because it
changes only acceptance tooling, documentation, and the facade version, it has
no scheduled pentest and no exceptional security trigger. A voluntary review
may still be recorded. The full cumulative delta remains subject to the
scheduled backwards-looking v0.25.0 assessment. The exact committed candidate
must pass the complete local gate plus hosted GitHub and CodeQL before the
signed tag is authorized.
