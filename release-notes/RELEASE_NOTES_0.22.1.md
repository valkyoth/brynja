# Brynja 0.22.1 Release Notes

Status: implementation candidate; native backend admission evidence and release gates pending

Brynja 0.22.1 is an internal development milestone. It selects zero crates.io
packages. The signed v0.20.0 checkpoint remains the latest published release,
and every v0.22.1 change remains inside the cumulative v0.20.0-to-v0.25.0
assessment range.

## Added

- A zero-dependency `no_std` x86_64 SHA-extension compression candidate in
  `brynja-crypto-cpu`.
- A zero-dependency `no_std` AArch64 NEON/SHA2 compression candidate in the
  same isolated package.
- Static complete-feature selection, direct startup `abc` KAT, caller-owned
  thread-bound health generations, permanent session quarantine, exact backend
  reporting, and one-block safe compression.
- An optional `cpu` edge in `brynja-hash-sha2` that preserves the existing
  scalar-owned streaming state, padding, checked length, finalization, digest,
  and exhaustion behavior.
- Separate opt-in `std` runtime detection in `brynja-crypto-cpu-std`, with
  reusable opportunistic scalar fallback and fail-closed required mode.
- Official-vector, padding-boundary, arbitrary-partition, forced-backend,
  unsupported-architecture, KAT-corruption, quarantine, selection-reuse, and
  required/fallback tests.
- Generated-code gates requiring `sha256rnds2` for x86_64 and `sha256h` plus
  `sha256h2` for AArch64.
- Supplemental AArch64 musl execution under QEMU that forces the candidate and
  differentially checks all implementation-chain boundary and partition cases.
- Non-authorizing native candidate execution on detected GitHub-hosted x86_64,
  macOS Arm, and Linux Arm runners; these CI observations catch portability
  faults but do not satisfy the separate trusted-runner admission contract.
- A clean-commit-bound detached native runner for local AMD, SSH-hosted Intel
  and AWS Arm, plus transferable Apple M2 bundles. It persists local job state,
  survives SSH disconnects, retrieves successful results, and validates source,
  lane, accelerated execution, emitted instructions, file inventory, symlinks,
  and checksums locally before accepting a non-authorizing candidate bundle.

## Security Boundaries

Both kernels are implemented candidates but remain unadmitted while complete
commit-bound native correctness, emitted-code, side-channel, and performance
evidence is unavailable for all named lanes. Ordinary builds cannot execute
them. Static selection returns no session, runtime-attested construction rejects
the unadmitted identity, opportunistic mode uses scalar, and required mode
fails closed. Repository evidence builds can exercise candidates explicitly
without granting admission authority.

The implementation uses Rust intrinsics only. It contains no C module, foreign
ABI, external assembly, native object, build script, allocation, I/O, global
registry, third-party detector, or protocol dependency. Cross-compilation and
generated assembly support portability review but do not substitute for native
M2 or AWS Arm execution evidence.

## Deliberate Exclusions

No accelerated backend is admitted by this candidate. Intel-native, Apple M2,
AWS Arm, statistically meaningful side-channel, complete performance, and
authenticated evidence records remain pending. SHA-224, SHA-384, SHA-512,
HMAC, register or spill erasure, independent cryptographic verification, FIPS
140-3 validation, and final SHA-256 chain acceptance remain absent. Runtime
admission also requires a reviewed proof that a standard-library feature
observation remains valid across every later scheduled compression call; the
thread-bound type alone does not prevent the operating system from migrating
that thread to an incompatible logical CPU.

## Release Process

This milestone introduces new unsafe cryptographic kernels and therefore meets
the project's exceptional pentest trigger even though no crates.io publication
is selected. Tagging requires a committed passing assessment, complete local
tag gate, and green GitHub and CodeQL after the native-evidence disposition is
settled.
