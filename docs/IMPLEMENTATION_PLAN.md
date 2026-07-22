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
  repository Cargo manifests. Brynja does not use `cargo-fuzz` or
  `libfuzzer-sys`; pinned external process tools drive first-party harness
  binaries. Adding any assurance crate requires an explicit future policy
  change and can never affect a shipped package graph.
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
- Production admission requires reviewed zeroization of complete owned secret
  memory regions; a weaker owned-region claim cannot pass the `1.0.0` gate.
- Every release stops for an exact-commit pentest before tagging.

## Workspace Architecture

```text
brynja
├── brynja-core
├── brynja-crypto
├── future exact-build FIPS module artifact (never a feature)
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

1. Freeze policy enforcement, standards provenance, requirements ledgers,
   bounded domains, caller-owned arenas, and adversarial test infrastructure.
2. Freeze production owned-memory zeroization and constant-time operations;
   separate entropy from secure randomness and wall from monotonic time;
   define pending-provider effects; and design the FIPS-aware provider boundary
   without making a validation claim.
3. Implement and independently audit cryptographic primitives from official
   vectors outward with per-compiler and per-target constant-time evidence.
4. Implement bounded identity containers, DER, X.509 path construction, split
   RFC 5280 validation, revocation, CT policy, and an independent PKI audit.
5. Exercise an internal deterministic Sans-I/O contract, then implement
   one-pass highest-version negotiation and audit TLS 1.3 as a typed state
   machine over explicit effects.
6. Admit a hardened, explicitly configured TLS 1.2 engine without fallback or
   renegotiation.
7. Implement QUIC TLS and key-derivation ownership, path-bound one-pass DTLS,
   standardized PQ hybrids, and the predesigned exact-build FIPS module and
   approved-only TLS profile.
8. Freeze the public Sans-I/O facade and add each optional protocol facility as
   a separate bounded module without repeating earlier ALPN, SNI, exporter, or
   channel-binding work.
9. Run complete conformance, fuzzing, formal, memory, side-channel, platform,
   resource, interoperability, external audit, and remediation phases.
10. Freeze the exact `1.0.0` package set and promote an unchanged, approved
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
- deterministic mutation, corpus replay, and stdin harness binaries driven by
  pinned external process tools; `cargo-fuzz` and `libfuzzer-sys` are excluded;
- differential tests against at least two independent mature implementations,
  confined to repository tools;
- network interoperability tests with packet captures and expected alerts;
- compile tests for every promised Rust version and target tier;
- restart, replay, reordering, loss, fragmentation, exhaustion, and
  cancellation tests;
- secret-lifetime, redaction, zeroization, and error-path tests;
- pinned external Kani, Miri, sanitizer, process-level fuzz, and equivalent
  assurance tools that do not weaken repository Cargo dependency policy.

## Security Review Loop

For each version: implement only the listed scope, update requirements and
threat model, add adversarial tests, run local checks, produce an SBOM, review
all source-file lengths and unsafe/dependency surfaces, write release notes,
stop, and hand the exact commit to pentest. Findings are fixed and retested
before a permanent PASS report is committed.

## Platform Strategy

Core crates expose pure transformations, caller-owned non-overlapping arenas,
opaque path tokens, and deterministic effects. Raw entropy and initialized
secure randomness are different contracts; wall and monotonic time are
non-interchangeable. Trust stores, transports, stateful and stateless ticket
storage, anti-replay state, concurrency, pending operations, and acceleration
enter through narrow traits in `brynja-platform`. Linux, Windows, BSD, macOS,
Android, iOS, and bare-metal remain outside protocol conditional logic. Aesynx
requires a stable adapter contract and executable target-ABI or emulator gate
for v1; real-hardware qualification may follow without weakening that contract.

## Completion Definition

`1.0.0` requires complete assigned standards coverage, no unresolved
critical/high findings, audited first-party cryptography and PKI, sustained
cross-platform interoperability, quantitative resource ceilings,
reproducible packages, exact SBOM/provenance, frozen public APIs, operational
guides, and an unchanged exact release candidate approved by pentest.
