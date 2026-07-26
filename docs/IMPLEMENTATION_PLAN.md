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
├── future brynja-fips-module (exact validated artifact; never a feature)
├── future brynja-fips (downstream approved-only selection facade)
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
state machine, epochs, fragmentation, paths, and retransmission. The upstream
interface also owns a bounded, caller-drained SecurityEvent action schema;
protocol engines and providers emit events but cannot call logging code,
allocate for events, block on consumers, or let observation affect state.
Events may be explicitly untimestamped until a caller clock exists, dropped
counts saturate visibly, and identifiers cannot expose handles, peer identities,
or stable cross-connection correlation values. SecurityEvent is an audit-only
duplicate: approval, external-key destruction, authentication, ECH, early-data,
anti-replay, and policy outcomes remain authoritative in exhaustive mandatory
results, single-consumption completion tokens, and engine state even when every
event is ignored or dropped.

FIPS support uses package and type boundaries, not an additive Cargo feature.
`brynja-fips-module` is the exact cryptographic module artifact submitted for
validation. The separate `brynja-fips` facade remains outside that boundary and
offers the easy client and server entry points, but it constructs them only from
a certificate-bound manifest and matching validated-module handle. Ordinary
`brynja` configuration can never acquire a FIPS claim through feature unification.

## Implementation Order

1. Freeze policy enforcement, standards provenance, requirements ledgers,
   including RFC 5705, RFC 9258, RFC 9266, and RFC 9848 ownership, bounded
   domains, caller-owned arenas, and adversarial test infrastructure. Generate
   a machine-readable decision register for every relevant protocol and IANA
   surface so an extension, message, algorithm, or standards change cannot
   remain unclassified.
2. Freeze production owned-memory zeroization and constant-time operations;
   separate entropy from secure randomness and wall from monotonic time;
   define pending-provider effects; and design the FIPS-aware provider boundary
   without making a validation claim. Freeze authoritative mandatory security
   outcomes first, then a secret-free, format-safe, allocation-free audit-event
   schema with optional caller timestamps and later enrichment, deterministic
   ordering, bounded capacity, saturating dropped-event accounting, and
   non-correlating identifiers.
3. Implement and independently audit cryptographic primitives from official
   vectors outward with per-compiler and per-target constant-time evidence. Each
   arithmetic or cryptographic milestone introduces its applicable proof harness
   beside the implementation; v0.155.0 completes coverage and publishes gaps
   rather than introducing the models for the first time. Classify claims as
   symbolic full-width, sound limb-count-parameterized, or reduced-width
   algorithm/harness validation, and treat production-width vectors and
   differentials as evidence rather than proof of equivalence. At v0.155.0,
   generate a deterministic machine-readable register mapping each primitive,
   exact implementation symbol, property, supported width or parameter,
   verification method, evidence, assumptions, and residual gaps.
   RSA signing accepts validated imported keys; first-party RSA key generation
   is outside v1.
4. Implement bounded identity containers, DER, X.509 path construction, split
   RFC 5280 validation, revocation, CT policy, and an independent PKI audit.
5. Extract the shared recordless TLS handshake and exercise an unstable
   deterministic Sans-I/O contract, then implement and audit TLS 1.3. External
   PSKs use RFC 9258 import and domain separation only for TLS 1.3-derived TLS,
   DTLS 1.3, and QUIC profiles whenever provisioned key material could cross
   protocol or deployment domains; hardened TLS 1.2 and DTLS 1.2 never gain PSK
   cipher suites. Channel binding admits only tls-exporter, with exact TLS 1.2
   and TLS 1.3 exporter constructions and typed, authorized, zeroized output.
6. Admit and audit hardened TLS 1.2, then integrate symmetric one-pass routing
   only after both target engines exist; never retry another engine.
7. Implement QUIC TLS and key-derivation ownership, separately gated QUIC
   resumption and zero-RTT, path-bound one-pass DTLS, version-specific DTLS CIDs, explicit
   DTLS early-data exclusion, and standardized PQ hybrid policies. For FIPS,
   first freeze a current overall Security Level 1 requirement baseline and the
   separate module architecture. Implement SP 800-90B entropy and health tests,
   SP 800-90A DRBGs, the selected SP 800-90C RBG construction, mandatory typed
   per-service indicators, SSP services, linked pre-operational and conditional
   self-tests, and the permanent error state. Only then freeze module-specific
   audit-event duplication and the exact artifact, and bind ACVTS/CAVP, ESV,
   CMVP documentation, lab, remediation, issuance, and closure evidence to it.
   The approved-only TLS profile, certificate-bound manifest, separate ergonomic
   `brynja-fips` facade, and deployment/revalidation lifecycle follow without
   conflating connection failure with a FIPS-defined module error state.
8. Add each planned v1 optional protocol facility against the unstable internal
   model without repeating ALPN, SNI, exporter, or channel-binding work. ECH
   treats caller-resolved ECHConfigList input as hostile and separately types
   intended origin, caller-asserted provenance, generation, lifetime, and
   Required, Preferred, or GREASE-only policy; Required never falls through to
   public SNI. Precompressed send artifacts are invalidated on every encoded
   input change. ECH tickets bind inner identity, policy, and configuration
   generation. Split ECH origin policy from hostile configuration lifecycle and
   split compressed-certificate artifact validation from send negotiation.
   Prove optional modules cannot change the validated FIPS closure,
   then generate all pairwise feature and protocol-applicability cases plus
   security-critical higher-order combinations before freezing facade and
   Sans-I/O actions. Freeze those actions as exhaustive EngineV1, EventV1, and
   ActionV1 interfaces: applications cannot ignore mandatory effects, and any
   new mandatory effect requires V2 interfaces and a major SemVer release;
   only bounded secret-free observational SecurityEvent audit values may evolve
   non-exhaustively. Authentication, ECH, early-data, anti-replay, policy,
   approval, and destruction outcomes always remain mandatory and authoritative.
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
- TLS 1.3-derived external-PSK importer domain separation plus negative TLS 1.2
  and DTLS 1.2 PSK-suite construction tests, exact exporter and tls-exporter
  channel binding, ECH origin/cache generation, canonical certificate
  compression round-trip, and ECH inner-identity ticket-binding tests;
- exhaustive SecurityEvent schema, redaction, formatting, ordering, caller-time,
  timestamp-free boot and later enrichment, delayed or absent drain, saturating
  overflow reporting, identifier non-correlation, non-reentrancy, and
  state-independence tests across protocol engines and the final FIPS module;
  suppress every event and prove accepted/rejected, approved/non-approved,
  authentication, ECH, early-data, anti-replay, policy, latching, zeroization,
  and destruction-complete outcomes remain unambiguous in mandatory state,
  results, and single-consumption tokens;
- cross-feature typestate, transcript, rotation, storage, cancellation,
  pre-authentication resource, and validated-dependency-closure tests;
- generated pairwise optional-feature and stream TLS, DTLS, and QUIC
  applicability matrices plus targeted ECH, RPK, hybrid, resumption, early-data,
  FIPS, compression, OCSP, SCT, HRR, padding, transcript, and downgrade cases;
- secret-lifetime, redaction, zeroization, and error-path tests;
- exhaustive mandatory EngineV1, EventV1, and ActionV1 handling, fail-closed
  unknown-action fixtures, and compile failures for wildcard ignore paths;
- formal protocol and resource models for zeroization, obsolete keys, X.509
  work ceilings, and pending-token consumption, plus separate cryptographic
  arithmetic models for limbs, Montgomery operations, fields, scalars, points,
  ladders, groups, ML-KEM, HKDF exhaustion, and AEAD failure atomicity with
  harnesses introduced beside each implementation and classified as full-width,
  limb-count-parameterized, or reduced-width algorithm/harness validation;
  production-width vectors and independent-process differentials remain evidence,
  not equivalence proofs, and residual proof gaps remain explicit;
- schema, deterministic-regeneration, symbol-resolution, uniqueness,
  completeness, evidence-reference, supported-parameter, and residual-gap tests
  for the v0.155.0 machine-readable cryptographic claim register;
- current FIPS 140-3 requirement/assertion, guidance, RFG, transition, caveat,
  security-policy, algorithm, ESV, artifact, lab, certificate, operational
  environment, approved-profile, manifest, facade, claim, update, and
  revalidation fixtures, including compile failures for every mixed or
  incomplete `brynja-fips` configuration;
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
An ordinary caller entropy implementation never inherits FIPS validation.
`brynja-fips` accepts only the entropy source and SP 800-90C construction named
by the exact validated-module manifest and tested operational environment.

## Completion Definition

`1.0.0` requires complete assigned standards coverage, no unresolved
critical/high findings, audited first-party cryptography and PKI, sustained
cross-platform interoperability, quantitative resource ceilings,
reproducible packages, exact SBOM/provenance, frozen public APIs, operational
guides, and an unchanged exact release candidate approved by pentest. Any FIPS
claim additionally requires the exact issued certificate, caveats, operational
environment, immutable module artifact, and separate `brynja-fips` facade
defined by the Phase 4 gates.
