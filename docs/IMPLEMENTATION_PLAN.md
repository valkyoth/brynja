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
├── future brynja-tls-handshake (shared recordless TLS 1.3 state machine)
├── brynja-tls (stream records plus shared handshake)
├── optional brynja-quic-tls (shared handshake plus QUIC profile)
├── optional brynja-dtls (independent datagram state machine)
└── optional brynja-platform (downstream implementations only)

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

All protocol-facing capability and effect traits live in `brynja-core` or
another upstream `no_std` interface crate. `brynja-platform` implements those
contracts and is never a protocol-engine dependency. Stream TLS and QUIC share
one record-independent TLS 1.3 handshake implementation; DTLS may reuse codecs,
transcripts, certificate processing, and key-schedule components but owns its
state machine, epochs, fragmentation, paths, and retransmission.

## Implementation Order

1. Freeze policy enforcement, standards provenance, requirements ledgers,
   bounded domains, caller-owned arenas, and adversarial test infrastructure.
2. Freeze production owned-memory zeroization and constant-time operations;
   separate entropy from secure randomness and wall from monotonic time;
   define pending-provider effects; and design the FIPS-aware provider boundary
   without making a validation claim.
3. Implement and independently audit cryptographic primitives from official
   vectors outward with per-compiler and per-target constant-time evidence.
   RSA signing accepts validated imported keys; first-party RSA key generation
   is outside v1.
4. Implement bounded identity containers, DER, X.509 path construction, split
   RFC 5280 validation, revocation, CT policy, and an independent PKI audit.
5. Extract the shared recordless TLS handshake and exercise an unstable
   deterministic Sans-I/O contract, then implement and audit TLS 1.3.
6. Admit and audit hardened TLS 1.2, then integrate symmetric one-pass routing
   only after both target engines exist; never retry another engine.
7. Implement QUIC TLS and key-derivation ownership, QUIC resumption and
   zero-RTT, path-bound one-pass DTLS, version-specific DTLS CIDs, explicit
   DTLS early-data exclusion, standardized PQ hybrid policies, and the
   predesigned exact-build FIPS module and approved-only TLS profile.
8. Add each planned v1 optional protocol facility against the unstable internal
   model without repeating ALPN, SNI, exporter, or channel-binding work. Prove
   optional modules cannot change the validated FIPS closure, then pass a
   cross-feature composition gate before freezing facade and Sans-I/O actions.
9. Qualify caller-provided host integration and the Aesynx ABI/emulator against
   the final public interface, then run complete conformance, fuzzing, formal,
   memory, side-channel, platform, resource, interoperability, external audit,
   and remediation phases.
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
- cross-feature typestate, transcript, rotation, storage, cancellation,
  pre-authentication resource, and validated-dependency-closure tests;
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

Upstream core interface crates expose pure transformations, caller-owned
non-overlapping arenas, opaque path tokens, and deterministic effects. Raw
entropy and initialized secure randomness are different contracts; wall and
monotonic time are
non-interchangeable. Trust stores, transports, stateful and stateless ticket
storage, anti-replay state, concurrency, pending operations, and acceleration
enter through narrow upstream traits that `brynja-platform` may implement;
protocol engines never depend on that downstream crate. For v1, host and kernel
applications provide entropy implementations and Brynja ships no built-in OS
entropy FFI. Linux, Windows, BSD, macOS, Android, iOS, and bare-metal remain
outside protocol conditional logic. Aesynx requires a stable adapter contract
and executable target-ABI or emulator gate
for v1; real-hardware qualification may follow without weakening that contract.

## Completion Definition

`1.0.0` requires complete assigned standards coverage, no unresolved
critical/high findings, audited first-party cryptography and PKI, sustained
cross-platform interoperability, quantitative resource ceilings,
reproducible packages, exact SBOM/provenance, frozen public APIs, operational
guides, and an unchanged exact release candidate approved by pentest.
