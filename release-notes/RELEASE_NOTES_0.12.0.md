# Brynja v0.12.0 Development Milestone

Status: implementation complete; awaiting exceptional pentest

Brynja v0.12.0 implements the first reusable constant-time foundation in
`brynja-core`, advances the `brynja` facade to 0.12.0, and selects no crate for
crates.io publication. Because constant-time code is an explicit material
security trigger, the candidate requires an exceptional pentest before its
signed development tag.

## Implemented

- normalized, private one-byte `Choice` and `CtMask` representations;
- constant-time equality, conditional selection, and conditional swap for
  `u8`, `u16`, `u32`, `u64`, `u128`, `usize`, and compile-time-sized byte
  arrays;
- one explicitly named `Choice::expose_public` declassification operation and
  no ordinary comparison or formatting traits on decision and mask values;
- an explicit compiler barrier with two sequentially consistent compiler
  fences around an optimization barrier; and
- facade re-exports without dynamic allocation, operating-system services,
  third-party dependencies, or new unsafe code.

## Verification Evidence

- exhaustive equality and byte-mask selection over all 65,536 byte pairs;
- both choices for every word selection and swap plus every tested array
  mismatch position, empty arrays, and representation invariants;
- compile-fail documentation for ordinary equality, formatting, and mask
  construction;
- a hash-locked source policy with twelve negative fixtures; and
- optimized LLVM IR and assembly equality, selection, and swap witnesses for
  all six unsigned widths plus fixed 32-byte arrays and the compiler barrier
  across Rust 1.90.0 through 1.97.1 and the nine promised targets, with a
  machine-checked evidence matrix and five negative fixtures.

## Current Limits

The implementation covers unsigned fixed-width words and compile-time-sized
byte arrays only. It does not cover dynamic slices, secret-dependent lengths,
signed values, arbitrary downstream composition, or protocol-level timing.
Compiler output inspection is not a mathematical proof, statistical timing
measurement, independent cryptographic review, or platform
microarchitectural guarantee. Brynja remains incomplete, must not secure
application traffic, has no independent cryptographic or protocol
verification, and is not FIPS 140-3 validated.

## Release Process

v0.12.0 is an internal development milestone in the cumulative range after
v0.10.0 through v0.15.0 and selects no crates for crates.io publication. Its
first constant-time code meets the exceptional-pentest trigger. Only after the
assessment and any remediation are committed with a PASS/PASS report, the full
gate passes, and GitHub and CodeQL are green may the signed `v0.12.0` tag be
created.
