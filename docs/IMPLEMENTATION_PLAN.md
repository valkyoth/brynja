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
- Unsafe Rust is denied by default. The v0.11.0 exception permits one
  machine-inventoried volatile-store block in one private module; every other
  unsafe site, assembly, and FFI boundary remains forbidden.
- Modern and legacy engines have separate packages, APIs, configuration,
  state machines, caches, ticket keys, and connection paths.
- Every legacy implementation package uses the
  `brynja-legacy-<protocol>` prefix so manifests, lockfiles, SBOMs, and
  policy tools expose the risk without requiring feature inspection.
- `brynja-tls` is an evergreen facade and one-pass modern-version router;
  version-specific state machines remain in version-named packages.
- Every externally controlled length, count, retry, allocation, transcript,
  certificate chain, fragment, and work unit has a caller-visible bound.
- Production admission requires reviewed zeroization of complete owned secret
  memory regions; a weaker owned-region claim cannot pass the `1.0.0` gate.
- Every version completes the automated tag gate, is committed with all of its
  evidence, waits for green GitHub and CodeQL, and requires explicit user
  authorization before its immutable signed tag. Every fifth-minor public
  checkpoint, exceptional high-risk checkpoint, production candidate, and
  major trust gate additionally stops for pentest and commits the current
  cumulative report before tagging or crates.io publication.

## Workspace Architecture

```text
brynja
├── brynja-core
├── brynja-crypto
├── future brynja-fips-module (exact validated artifact; never a feature)
├── future brynja-fips (downstream approved-only selection facade)
├── brynja-pki
├── brynja-tls (evergreen facade and one-pass modern-version router)
│   ├── brynja-tls13 (TLS 1.3 stream records and adapter)
│   │   └── brynja-tls13-handshake (shared recordless state machine)
│   ├── brynja-tls12 (isolated hardened TLS 1.2 engine)
│   └── future brynja-tlsNN (one package per admitted TLS generation)
├── optional brynja-quic-tls (TLS 1.3 handshake plus QUIC profile)
├── optional brynja-dtls (independent datagram state machine)
├── optional brynja-platform (downstream implementations only)
└── future brynja-sanitization (explicit downstream adapter only)

brynja-legacy (never a brynja dependency)
├── brynja-legacy-tls11
├── brynja-legacy-tls10
├── brynja-legacy-ssl3
├── brynja-legacy-ssl2
├── brynja-legacy-wtls
├── brynja-legacy-pct
└── brynja-legacy-snp
```

`brynja-research-ssl1` is reconstruction research and can never
claim secure transport. Repository-only test, interoperability, task, and proof
packages are permanently excluded from normal application dependency graphs.

All protocol-facing capability and effect traits live in `brynja-core` or
another upstream `no_std` interface crate. `brynja-platform` implements those
contracts and is never a protocol-engine dependency. `brynja-tls` owns only the
stable public facade, pre-routing negotiation policy, and one-pass selection
between independently versioned modern engines. `brynja-tls13` owns TLS 1.3
stream records and consumes `brynja-tls13-handshake`; QUIC consumes that same
record-independent handshake without acquiring stream records or multi-version
routing. `brynja-tls12` retains an independent hardened TLS 1.2 state machine.
DTLS may reuse codecs, transcripts, certificate processing, and key-schedule
components but owns its state machine, epochs, fragmentation, paths, and
retransmission. The upstream interface also owns a bounded, caller-drained
SecurityEvent action schema;
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

`brynja-sanitization` is a conditional, separately selected downstream adapter,
not a feature or dependency of any Brynja facade or protocol engine. Admission
requires the v0.11.1 review of the latest stable first-party `sanitization`
release; implementation at v0.11.2 uses an exact pin, disables default
features, and rejects any activated `zeroize` or other third-party dependency.
Adapter-owned wrappers avoid orphan-rule workarounds. One protocol-neutral
adapter serves modern and legacy applications with the same destruction
semantics; a `brynja-legacy-sanitization` split is rejected unless a later
numbered review proves an irreducible and safe need. Brynja's own complete
owned-region destruction primitive remains mandatory. The adapter stays
outside `brynja-fips-module`; using it in application code cannot inherit or
satisfy a FIPS validation claim.

A newer TLS generation does not automatically make an older generation
legacy. Admission of TLS 1.N requires a new version-specific package,
requirements closure, audit line, and explicit router milestone. Retirement
requires a separate numbered security-boundary milestone justified by current
standards and cryptographic evidence. That milestone removes the engine from
the modern graph, disables modern negotiation before any fallback can occur,
freezes and deprecates the former modern package, and—only where controlled
interoperability remains justified—creates a new
`brynja-legacy-tls1N` package with an independent API, warnings, audit,
pentest, and release line. Code never changes classification silently in place.

## Implementation Order

1. Freeze policy enforcement, standards provenance, requirements ledgers,
   complete current updated-by and obsoleted-by closure, bounded domains,
   caller-owned arenas, and adversarial test infrastructure. Generate a
   machine-readable decision register for every relevant protocol and IANA
   surface, then map every applicable normative statement and invariant to its
   disposition, milestone, planned target or actual code or boundary, positive
   and negative tests, and evidence lifecycle so a standards change cannot
   remain unclassified or silently weaken behavior. Keep RFC 9850 key logging in
   a separately compiled test-support artifact that production crates and
   features cannot reach.
2. Freeze production owned-memory zeroization; review and, only if admitted,
   add the optional downstream `brynja-sanitization` adapter without changing
   the mandatory core primitive; then freeze constant-time operations;
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
4. Implement bounded identity containers, DER, and the current RFC 5280 update
   closure: strict algorithm identifiers, current internationalized names,
   bounded policy graphs, CRL issuer key usage, noRevAvail, current OCSP
   nonces, Must-Staple, the optional RFC 9919 SHA-256 lightweight OCSP client
   profile over caller-owned transport and cache, strictly versioned CT, path
   construction, revocation, and an independent PKI audit.
5. Implement the shared recordless TLS 1.3 handshake in
   `brynja-tls13-handshake`, connect it to the `brynja-tls13` stream engine,
   and exercise an unstable deterministic Sans-I/O contract before the
   version-neutral `brynja-tls` router admits it. Then implement and audit TLS
   1.3. External
   PSKs use RFC 9258 import and domain separation only for TLS 1.3-derived TLS,
   DTLS 1.3, and QUIC profiles whenever provisioned key material could cross
   protocol or deployment domains; apply RFC 9257 key strength, pairwise role,
   peer-identity, provisioning, rotation, and deletion requirements, and reject
   certificate-with-external-PSK mode. Hardened TLS 1.2 and DTLS 1.2 never gain
   PSK cipher suites. Channel binding admits only tls-exporter, with exact TLS
   1.2 and TLS 1.3 exporter constructions and typed, authorized, zeroized output.
6. Admit and audit hardened TLS 1.2 in `brynja-tls12` under the current
   MD5/SHA-1 and obsolete key-exchange deprecations and the TLS-only RFC 9851
   feature freeze, require the RFC 9846-renamed Extended Main Secret while
   preserving its wire label, then integrate symmetric one-pass routing only
   after both target engines exist; never retry another engine.
7. Implement QUIC TLS and key-derivation ownership, separately gated QUIC
   resumption and zero-RTT, path-bound one-pass DTLS, version-specific DTLS
   CIDs, RFC 9853 return-routability checks, explicit DTLS early-data
   exclusion, and standardized PQ hybrid policies. For FIPS,
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
   model without repeating ALPN, SNI, exporter, or channel-binding work.
   Complete HPKE Base mode with bounded secret export, ordered-delivery and
   loss invalidation, role separation, context destruction, and explicit
   rejection of unadmitted modes before ECH consumes it. ECH
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

- the v0.4.0 bounded first-party raw-stdin mutation and canonical-JSON
  differential harness contract, deterministic evidence, and ARMv7E-M,
  RV32IMAC, and x86_64 OS-less compile matrix;
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
- deterministic source-closure, protocol-surface, normative-requirement,
  obsolete-authority, errata, IANA-drift, orphan-owner, source-to-code,
  source-to-test, and documented-boundary fixtures;
- current PKIX internationalization, policy-graph exhaustion, noRevAvail,
  CRL-issuer key usage, OCSP nonce, Must-Staple, unsigned-certificate, and
  version-separated CT fixtures;
- lightweight OCSP request, SHA-256 CertID, responder, nextUpdate, nonce/time,
  caller-transport, URI, cache, and forged-HTTP-metadata fixtures;
- external-PSK length, provenance, pairwise role, identity, collision, rotation,
  parent-destruction, reflection, combined-certificate, and privacy fixtures;
- TLS 1.2 feature-freeze registry dates, exceptions, DTLS separation, and
  forbidden PQC-backport fixtures plus production key-log isolation fixtures;
- RFC 9853 DTLS return-routability loss, migration, rebinding, path-binding,
  timer, PMTU, and amplification tests plus HPKE exporter, role, ordering,
  loss-invalidation, unsupported-mode, and context-destruction tests;
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
- exact-pin, feature-unification, dependency-direction, modern/legacy
  equivalence, and FIPS-boundary tests for any admitted sanitization adapter;
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

Stable release Rust and verifier Rust are separate evidence dimensions.
Brynja releases on the latest pinned stable compiler and supports its complete
promised stable matrix. Kani follows the documented compatible pairing used by
`base64-ng`: currently `cargo-kani 0.67.0` with Rust 1.90.0. A policy check or
incompatible-tool skip is not a proof, never holds back stable Rust, and cannot
support a formal-verification claim before scoped harnesses and results exist.

## Security Review Loop

For each version: advance the `brynja` facade to the roadmap version, implement
only the listed scope, update requirements and threat model, add adversarial
tests, run the complete automated tag gate, produce an SBOM, review all
source-file lengths and unsafe/dependency surfaces, write release notes, commit
all files, and wait for green GitHub and CodeQL before the user authorizes the
signed tag. Development milestones stop there without crates.io publication.
At each scheduled or exceptional public checkpoint, ask the user for a
backwards-looking pentest of every change after the prior public tag through the
current candidate. Keep that report current while findings are fixed and
retested; commit implementation and the final PASS report together. Any later
CI-driven fix must update the report in the same commit and pass CI again before
tagging and publication.

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
guides, and a green release candidate with a current committed PASS pentest
report. Any FIPS
claim additionally requires the exact issued certificate, caveats, operational
environment, immutable module artifact, and separate `brynja-fips` facade
defined by the Phase 4 gates.
