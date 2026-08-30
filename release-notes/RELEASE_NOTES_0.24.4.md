# Brynja 0.24.4 Release Notes

Status: implementation candidate complete; exceptional pentest, qualifying
native observations, final repository gate, hosted GitHub and CodeQL, and
signed tag pending; no crates.io publication is selected

Brynja 0.24.4 adds two isolated, first-party Rust Keccak-f[1600] acceleration
candidates for the six frozen byte-oriented SHA-3/SHAKE functions. x86_64 uses
AVX2 vector operations. AArch64 uses the architecture's dedicated SHA3
instructions. Both candidates remain unadmitted, ordinary users continue to
receive only the portable implementation, and RISC-V is explicitly scalar-only
because the pinned ratified authorities contain no qualifying Keccak route.

## Added

- A zero-dependency `no_std` x86_64 AVX2 Keccak-f[1600] candidate isolated in
  a 111-line intrinsic module.
- A zero-dependency `no_std` AArch64 SHA3 candidate using `eor3`, `rax1`, and
  `bcax`, isolated in a 116-line intrinsic module.
- Caller-owned, thread-bound candidate sessions with exact backend identity,
  complete feature bundles, direct zero-state KAT, health generations, and
  permanent quarantine.
- A repository-only forced-candidate fixture that compares 80 fixed-output
  and 28 XOF results across all six FIPS 202 byte-oriented identities, every
  rate boundary, multi-block inputs, zero output, and multi-permutation tails.
- A 1,024-state direct permutation differential corpus against an independent
  portable reference.
- Rust 1.90.0 and 1.98.0 emitted-instruction gates plus supplemental AArch64
  QEMU execution.
- Machine-readable source hashes, unsafe inventory, candidate dispositions,
  RISC-V scalar-only decision, and zero-admission ledger updates.

## Verification

- The local AMD x86_64 candidate passes its direct KAT, 1,024-state
  permutation differential, and complete six-identity fixture.
- The AArch64 candidate passes the same six-identity fixture under QEMU's
  explicit feature model; QEMU remains supplemental and cannot establish a
  native, performance, migration, or side-channel claim.
- Rust 1.90.0 and 1.98.0 emit AVX2 operations for x86_64 and the exact AArch64
  SHA3 instructions for the Arm candidate.
- The unchanged v0.24.3 semantic corpus remains mandatory through the portable
  public fixture. Only its exact facade-version pin advances to 0.24.4.
- Qualifying native Intel, Apple M2, and AWS Arm observations remain pending
  until the assessed exact commit is available; every candidate therefore
  stays unadmitted.

## Security Boundaries

The candidates are inaccessible to ordinary construction. Evidence-only
construction is compile-configuration gated, architecture checked, thread
bound, and KAT gated. A failed KAT permanently quarantines that session before
caller state can be processed. The kernels use only first-party Rust
intrinsics, fixed arrays, fixed 24-round work, and no allocation, FFI, external
assembly, native object, build script, pointer-length API, I/O, or global
registry.

This milestone does not claim register, spill, stack, cache, crash-image, or
secret-state erasure. The current SHA-3/SHAKE APIs remain for ordinary unkeyed
public-data use; their separate hardened owner remains planned. It also makes
no independent cryptographic-review, CPU-backend admission, performance,
side-channel, general hardware-support, or FIPS 140-3 validation claim. The
family remains **In progress** through v0.24.11.

## Release Process

Version 0.24.4 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates.io packages. New unsafe
intrinsic paths trigger an exceptional pentest before tagging. After the
implementation candidate and any remediation are assessed, commit-bound native
observations are collected where qualifying hardware exists; all affected
evidence must be rerun if production or fixture semantics change. The final
report-bearing candidate must pass the complete local gate plus hosted GitHub
and CodeQL before the signed tag is authorized.
