# v0.24.51 — Apple Silicon resident/clearing profiles

Status: development candidate; independent pentest and release qualification
pending. Internal milestone only; no crates.io packages selected.

This release adds separate, default-off `macos_resident` APIs on native
Apple Silicon macOS. It does **not** enable macOS in `brynja-strict` and does
**not** claim core-dump exclusion. Unsupported targets and unavailable resources
reject instead of falling back. Intel Mac and other Apple OSes are out of scope.

## Implemented scope

- SHA-224/256/384/512, named and general SHA-512/t; SHA-3, SHAKE and cSHAKE.
- KMAC/KMACXOF and TupleHash/TupleHashXOF with borrowed canonical bit inputs.
- Explicit Arm SHA2/SHA512/Keccak routes; NEON SHA-2 and Keccak batching.
- Bounded ParallelHash/ParallelHashXOF workers, including explicit Arm roots
  and single-state or NEON leaf execution with declared scalar tails.
- Separate compatibility-only SHA-1 and MD5 hosted adapters. Their broken
  collision resistance is unchanged; they are not modern authentication APIs.

Guarded, locked, non-inherited mappings and native joined worker stacks are
acquired before processing inputs. Secret state stays inside owned worker
storage; output is a clearing affine loan. Recoverable errors and unwinding
join before stack clearing. Join failure aborts rather than releasing borrowed
storage while a worker could still use it. Explicit accelerated routes never
silently fall back after authority failure. These are bounded whole-request
sessions, not arbitrary user callback or persistent streaming interfaces.

## Evidence and limits

Development tests cover extracted-package independent oracles, arbitrary bits,
scalar and real Arm/NEON execution, owned storage placement, faults, unwinding,
compiled mutations, ownership negatives and optimized Darwin compiler artifacts.
The test host is an Apple M2 Pro on macOS 27.0.1 with Rust 1.99.1. These author
checks do not constitute independent review or general platform qualification.
See [the contract and coverage](../docs/macos-resident-profile.md).

Core dumps, OS/TLS and panic-hook storage, caller inputs and copies, fatal abort,
hibernation, snapshots and arbitrary register capture remain outside the
guarantee. Instrumented runs are diagnostic, not residency evidence. Applications
must establish instruction/deployment support, avoid fork/native thread
cancellation and not revoke active memory protections. No process-wide security
policy is changed. Strict construction failure must not trigger fallback to
this weaker, explicitly selected profile.

## Release controls

MSRV remains Rust 1.90.0; the default full-check and cross-target compiler is
1.99.1. Historical observations keep their actual compiler/source identities.
Support-crate versions, publication selection, existing gate policy and evidence
reuse rules are unchanged. This candidate still requires the exceptional
independent pentest, applicable final verification, GitHub checks and explicit
tag authorization. No independent cryptographic verification or certification
is claimed.
