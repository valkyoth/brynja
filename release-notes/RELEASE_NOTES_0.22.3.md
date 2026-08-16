# Brynja 0.22.3

Status: implementation candidate; internal development tag; no crates.io publication

Brynja 0.22.3 closes the SHA-256 implementation chain with a runnable
downstream acceptance boundary. Portable SHA-256 is now exposed as a complete,
usable public API through both `brynja-hash-sha2` and `brynja-crypto`.

## Added

- Add a standalone public-only `no_std` consumer with no external dependency.
- Exercise empty, short text, binary, file-like, multi-block, and one-million-
  byte authoritative SHA-256 inputs.
- Exercise one-shot and deliberately irregular streaming updates through both
  documented public crate surfaces.
- Verify scalar execution and enumerate every accelerated backend identity.
  All three accelerated candidates remain unadmitted and are explicitly
  reported as skipped.
- Add `Sha256::check_additional_bytes` as a non-mutating public preflight for
  the exact SHA-256 message-length limit and deterministic exhaustion error.
- Package the complete first-party dependency chain, safely extract it, replace
  path dependencies with version-only dependencies, and execute the same
  consumer entirely offline against those package artifacts.
- Run the acceptance fixture across Rust 1.90.0 through 1.97.1, hosted CI
  systems, and the promised bare-metal compile matrix.

## Negative acceptance

Executable broken fixtures demonstrate that the gate rejects:

- a corrupted authoritative digest;
- a missing documented public export;
- false accelerated-backend reporting;
- a bypassed message-length exhaustion check;
- an unadmitted or nonexistent CPU feature; and
- altered packaged source contents.

## Security and verification status

Portable SHA-256 is implemented and its public usability acceptance passes.
No cryptographic or protocol code has been independently reviewed. No CPU
backend is admitted, no register-erasure guarantee is made, and Brynja is not
FIPS 140-3 validated. The new length preflight does not mutate hashing state;
ordinary `update` calls retain the same checked length-before-mutation rule.

This milestone adds no new algorithm, protocol, dependency, unsafe block, FFI,
C implementation, runtime detector, or provider authority.

## Release process

Version 0.22.3 is an internal development milestone inside the cumulative
v0.20.0-to-v0.25.0 range. It selects no crate for crates.io publication and has
no scheduled pentest unless the exceptional-trigger classifier requires one.
The signed tag is created only after the complete local gate and hosted GitHub
and CodeQL checks are green.
