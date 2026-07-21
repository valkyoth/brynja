# Brynja Implementation Plan

Status: planning document

## Objective

Build a dependency-free, `no_std`, first-party TLS ecosystem in Rust through
small, independently reviewable releases. The modern `brynja` facade reaches
serious production readiness only at `1.0.0`; package presence, compilation,
test count, or interoperability alone never establishes that claim.

## Non-Negotiable Constraints

- Rust `1.90.0` MSRV and current stable Rust for full release evidence.
- No third-party runtime, build, development, fuzz, test, or tooling crates in
  Cargo manifests.
- `no_std` production crates with no assumed allocator, OS, socket, clock,
  filesystem, or entropy source.
- No Rust source file over 500 lines. Split modules before 450 lines so tests
  and review changes have room.
- Unsafe Rust remains forbidden until a versioned need, proof obligation,
  isolated crate/module, audit, and explicit policy change are approved.
- Modern and historical engines have separate packages, APIs, configuration,
  state machines, caches, ticket keys, and connection paths.
- Every externally controlled length, count, retry, allocation, transcript,
  certificate chain, fragment, and work unit has a caller-visible bound.
- Every release stops for an exact-commit pentest before tagging.

## Workspace Architecture

```text
brynja
├── brynja-core
├── brynja-crypto
├── brynja-pki
└── brynja-tls
    ├── optional brynja-quic-tls
    ├── optional brynja-dtls
    └── optional brynja-platform

brynja-historical (never a brynja dependency)
├── brynja-tls11
├── brynja-tls10
├── brynja-ssl3
├── brynja-ssl2
├── brynja-wtls
├── brynja-pct
└── brynja-snp
```

`brynja-ssl1-research` is reconstruction research and can never claim secure
transport. Repository-only test, interoperability, task, and proof packages
are permanently excluded from normal application dependency graphs.

## Implementation Order

1. Freeze policies, standards provenance, requirements ledgers, bounded error
   domains, and test infrastructure.
2. Implement cryptographic primitives separately, from official vectors
   outward, with constant-time and differential evidence before TLS consumes
   them.
3. Implement strict DER and X.509 validation with explicit time, trust-anchor,
   algorithm, path, name, revocation, and resource policies.
4. Implement TLS 1.3 as a typed state machine around a strict codec, transcript,
   key schedule, record layer, alerts, resumption, and key update.
5. Admit a hardened, explicitly configured TLS 1.2 engine without fallback or
   renegotiation.
6. Add facade, platform, QUIC, DTLS, and advanced extension boundaries without
   weakening the core.
7. Run complete conformance, fuzzing, model, side-channel, platform, resource,
   interoperability, external audit, and remediation phases.
8. Freeze the exact `1.0.0` package set and promote an unchanged, approved
   release candidate.

## Test Architecture

Every module begins with positive, negative, boundary, and invariant tests.
Parsers add truncation at every byte, length confusion, duplicate/unknown
field, non-canonical encoding, maximum-work, and trailing-data cases. State
machines test every legal transition and prove illegal messages fail closed
without emitting secrets or application data.

The repository will maintain:

- official RFC, NIST, and algorithm vectors with source provenance;
- generated exhaustive tests for small domains;
- deterministic mutation and structured fuzz harnesses without Cargo
  dependencies;
- differential tests against at least two independent mature implementations,
  confined to repository tools;
- network interoperability tests with packet captures and expected alerts;
- compile tests for every promised Rust version and target tier;
- restart, replay, reordering, loss, fragmentation, exhaustion, and
  cancellation tests;
- secret-lifetime, redaction, zeroization, and error-path tests;
- Kani/Miri/sanitizer or equivalent evidence where the tool can run without
  weakening the dependency policy.

## Security Review Loop

For each version: implement only the listed scope, update requirements and
threat model, add adversarial tests, run local checks, produce an SBOM, review
all source-file lengths and unsafe/dependency surfaces, write release notes,
stop, and hand the exact commit to pentest. Findings are fixed and retested
before a permanent PASS report is committed.

## Platform Strategy

Core crates expose pure transformations and caller-owned buffers. Entropy,
monotonic/wall time, trust stores, sockets, persistent ticket storage,
anti-replay storage, concurrency, and acceleration enter through narrow traits
in `brynja-platform`. This keeps Linux, Windows, BSD, macOS, Android, iOS,
bare-metal targets, and future Aesynx support from becoming conditional logic
inside protocol state machines.

## Completion Definition

`1.0.0` requires complete assigned standards coverage, no unresolved
critical/high findings, audited first-party cryptography and PKI, sustained
cross-platform interoperability, quantitative resource ceilings,
reproducible packages, exact SBOM/provenance, frozen public APIs, operational
guides, and an unchanged exact release candidate approved by pentest.

