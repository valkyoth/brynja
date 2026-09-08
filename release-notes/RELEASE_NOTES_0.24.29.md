# Brynja v0.24.29

Status: implementation candidate; fresh exceptional owner pentest and native evidence disposition required.

## General SHA-512/t final evidence and ordinary CPU integration

The ordinary general SHA-512/t API now exposes explicit CPU byte/bit one-shot,
update and consuming finalization operations under both optional features. It
reuses existing AArch64 SHA-512 and RV64 Zknh kernels; no kernel, unsafe code,
admission or hardened CPU path is added. IV derivation remains portable.
This final implementation pass also replays the
frozen all-510-parameter, 4590-case package-external ordinary/hardened byte/bit
consumer and retains the lifecycle, compiler-cleanup and negative controls.

- New isolated block/round work probe covers 12,240 cases per debug/release
  profile with four hook-removal and two shortened-round mutants per profile.
- Consumer checks fixed object-size ceilings and non-mutating length preflight
  for all 510 t. These are not whole-stack or compiler-temporary bounds.
- New opt-in hosted profiling executable reports 50 fixed, bounded performance
  rows and checks both ordinary and typed-secret outputs and output clearing.
- Exact-source local evidence binds the complete first-party Rust dependency
  closure, compiler identity and performance results; it never grants CPU,
  independent-review or FIPS approval.
- Missing/incomplete/duplicated rows, false timing claims, bad sample counts,
  invalid durations and instrumentation drift are rejected by regression tests.

See [commands, coverage and limits](../docs/sha512-t-final-evidence.md).
General SHA-512/t remains **In progress** until the final exceptional pentest
and reviewed native AWS Arm/Mac evidence disposition pass. Then its portable
implementation row can become Fully implemented;
independent cryptographic review and FIPS validation stay negative.

## Release and residual limits

The facade version becomes internal 0.24.29. Support versions and dependencies
are unchanged; all crates remain non-publishing. The next scheduled public
checkpoint remains v0.25.2. No TLS engine or CPU admission is introduced.

Source-level fixed work and local timings do not establish constant-time
behavior on every compiler/CPU. Hardened ownership clears source-declared owned
memory, not registers, compiler copies/spills, caches, swap, dumps, DMA, abort,
forget, termination or caller-created copies. No classified-deployment claim.

Actual completed checks are in the [pentest report](../security/pentest/v0.24.29.md).
Commit the candidate for owner review, obtain a clean exceptional pentest,
finish release checks and commit the PASS report, wait for green GitHub/CodeQL,
then obtain explicit tag permission. Do not publish this internal milestone.
