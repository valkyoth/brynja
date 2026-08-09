# Brynja v0.12.0 Development Milestone

Status: pentest PASS; awaiting GitHub and CodeQL

Brynja v0.12.0 implements the first reusable constant-time foundation in
`brynja-core`, advances the `brynja` facade to 0.12.0, and selects no crate for
crates.io publication. Because constant-time code is an explicit material
security trigger, the candidate received an exceptional assessment and a green
retest before its signed development tag.

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
- a hash-locked source policy with fourteen negative fixtures; and
- optimized LLVM IR and assembly equality, selection, and swap witnesses for
  all six unsigned widths plus fixed 32-byte arrays and the compiler barrier
  across Rust 1.90.0 through 1.97.1 and the nine promised targets, with a
  machine-checked evidence matrix, six matrix/binding fixtures, all eighteen
  RISC-V conditional forms, and ten focused target-assembly regression fixtures.

## Pentest Finding And Remediation

The initial exceptional assessment found one High timing vulnerability on
RV32. LLVM converted word masking into `select`, then rustc 1.97.1 emitted
secret-dependent branches and, for `u128`, choice-dependent load addresses.
The old assembly gate verified function labels but did not inspect their
bodies.

Every expanded word and array mask now crosses the non-inlined optimization
barrier before XOR/AND selection. Word selectors are always inlined into their
evidence roots. The validator extracts each concrete function body and rejects
target-specific conditional branches outside a backward fixed-array public
loop; RV32 also rejects direct memory operands based on the ABI `Choice`
register. Permanent fixtures reproduce the original branch and secret-address
classes plus x86_64, AArch64, and fixed-loop classification regressions. Local
verification passes.

Retest found one Medium assurance-control bypass rather than an active code
side channel: a synthetic backward fixed-array branch directly on the RV32
ABI `Choice` register passed as a public loop. The validator now rejects direct
`Choice`-register branches before classifying a backedge, and the sixth fixture
reproduces that exact bypass. Transitive register-taint analysis remains
outside the bounded emitted-code claim. That signed follow-up candidate then
underwent another repository-owner retest.

A second retest found another Medium assurance-control bypass, not an active
code side channel: numeric argument-register aliases, omitted `bgt`-family
pseudoinstructions, compressed conditional branches, and numeric aliases in
memory operands could evade the textual scanner. The gate now canonicalizes
`x10` through `x17`, classifies all eighteen RISC-V conditional forms, covers
compressed integer loads/stores, and reproduces all four variants. The
repository-owner retest of exact signed third candidate
`7ce43fffdf81a349c7c44aae33b229d077d4512d` passed with zero open findings.

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
first constant-time code meets the exceptional-pentest trigger. The green
retest is committed in a PASS/PASS report. Only after the full gate passes,
GitHub and CodeQL are green, and the repository owner explicitly authorizes it
may the signed `v0.12.0` tag be created.
