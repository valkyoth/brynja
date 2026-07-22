# Brynja Version Plan

Status: reconciled planning sequence

This document defines the intended order and exclusive scope of Brynja releases
through `1.0.0`. Each version is a small implementation stop that must be
completed and verified before adjacent capability begins. A version may be
split further whenever review scope grows; unrelated work must never be merged
to preserve numbering.

[RELEASE_PLAN.md](RELEASE_PLAN.md) is the normative source for each release's
Goal, Deliverables, Verification, and Exit criteria. It is maintained
one-for-one with this sequence: each release repeats its exact title and scope,
and the repository validator rejects numbering, ordering, title, or scope drift.

## Admission Rules For Every Version

Every milestone retains `no_std` production packages, no third-party crates in
repository Cargo manifests, bounded hostile-input processing, explicit secret
lifetimes, negative and adversarial tests, all supported Rust and target
evidence, an SBOM, clean CI, and exact-commit review. Pinned assurance tools run
outside shipped package graphs and do not relax the crate dependency rule.

Capability claims are limited to completed, tested, and independently reviewed
scope. The modern facade never depends on historical packages. FIPS is an
exact-build artifact and operational-environment claim, not a Cargo feature. PQ
hybrids remain experimental until standards and code points are final.

## Phase 0: Repository, Effects, And Wire Foundations

Repository enforcement and bounded core types come first. Constant-time operations, entropy, secure randomness, clocks, pending providers, and a FIPS-aware architecture are frozen before any cryptographic or protocol implementation consumes them.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.1.0` | Workspace Foundation | Preserve the existing workspace foundation with no cryptographic or protocol security claim. |
| `0.2.0` | Release And Isolation Enforcement | Fix exact-HEAD pentest comparison, validate all-feature graphs and every package class, add negative modern/historical isolation fixtures, and document protected release controls. |
| `0.3.0` | Requirements And Standards Ledger | Build the requirements ledger for RFC 9846, RFC 5280, RFC 9001, RFC 9147, RFC 9180, applicable NIST standards and errata, and frozen IANA snapshots; map every normative requirement. |
| `0.4.0` | Assurance Harness And Bare-Metal Matrix | Establish mutation and differential harnesses, true bare-metal targets, and pinned external assurance-tool policy without adding any third-party crate to repository Cargo manifests. |
| `0.5.0` | Error Alert And Exhaustion Domains | Freeze non-secret error, alert, close, provider-failure, and resource-exhaustion domains; prohibit secret-bearing formatting and ambiguous failure collapse. |
| `0.6.0` | Bounded Numeric And Resource Domains | Introduce checked bounded integers, counts, lengths, sequence numbers, epochs, and immutable resource and work budgets. |
| `0.7.0` | Borrowed Read Cursor | Implement a borrowed read cursor with exact consumption, truncation-at-every-byte coverage, and no indexing panics. |
| `0.8.0` | Transactional Write Cursor | Implement caller-buffer write cursors with transactional encode-or-no-mutation behavior. |
| `0.9.0` | Caller-Owned Workspace And Arena Model | Define caller-owned workspaces and non-overlapping secret, plaintext, transcript, certificate, and output arenas with overlap rules, high-water tracking, and allocation counters. |
| `0.10.0` | Secret Lifetime And Zeroization Contract | Define non-cloneable and non-serializable secret ownership, transition/error/cancellation/provider-failure/drop destruction, external secret-store duties, accelerator-handle destruction, and optimizer-resistant zeroization evidence or an explicit weaker claim. |
| `0.11.0` | Constant-Time Foundation | Implement constant-time equality, choice and mask types, conditional select/swap, fixed-width secret operations, compiler-barrier strategy, and rules forbidding secret-dependent control flow, indexing, loop counts, and error timing. |
| `0.12.0` | Provider Capabilities And Opaque Handles | Define crypto, signature, KEM, and AEAD capability traits with opaque key handles, frozen capabilities, transactional key installation, and no implicit software fallback. |
| `0.13.0` | Entropy And Secure-Random Contracts | Separate caller-provided raw entropy from initialized secure randomness; type security strength, purpose, retryable/permanent failure, fork/reseed rules, clone prohibition, and test-only providers that production configuration cannot construct. |
| `0.14.0` | Wall And Monotonic Clock Contracts | Define non-interchangeable typed wall time for PKI and typed monotonic time for timers, freshness, tickets, and replay policy with checked arithmetic and explicit unavailable-time behavior. |
| `0.15.0` | Pending Operations And Accelerator Lifecycle | Define resumable provider tokens, certificate/signature/accelerator requests, cancellation, key-handle destruction, retry semantics, backpressure, and failure-atomic state transitions. |
| `0.16.0` | FIPS-Aware Provider Architecture | Freeze approved/non-approved service separation, self-test and permanent-failure hooks, dispatch, service indicators, SSP boundaries, deterministic module-build expectations, operational-environment assumptions, and sealed-provider exclusions without making a validation claim. |
| `0.17.0` | TLS And DTLS Record Framing | Separate TLS and DTLS record framing codecs and make modern parsers reject unknown or legacy versions deterministically. |
| `0.18.0` | Bounded DER Reader | Implement a non-recursive DER tag/length/value reader with definite, minimal, overflow-safe, depth-, node-, size-, and work-bounded parsing. |
| `0.19.0` | Canonical ASN.1 Primitives | Add canonical ASN.1 integer, bit/octet string, OID, Boolean, string, sequence/set, and time primitives with malformed and non-canonical corpora. |

## Phase 1: First-Party Cryptography, Identity Formats, And PKI

Constant-time foundations precede all algorithms. The cryptographic substrate receives an independent audit before identity and PKI consumption; bounded identity loading and split RFC 5280 validators then receive their own audit gate before TLS.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.20.0` | SHA-256 | Implement streaming and fixed-message SHA-256 with official vectors, boundary lengths, and exhaustion handling. |
| `0.21.0` | SHA-384 And SHA-512 | Implement SHA-384 and SHA-512 with official vectors and checked length and exhaustion behavior. |
| `0.22.0` | Keccak SHA-3 And SHAKE | Implement Keccak-f[1600], SHA3-256/512, and SHAKE128/256 as the required ML-KEM foundation. |
| `0.23.0` | HMAC | Implement HMAC-SHA-256/384/512 with constant-time verification and misuse tests. |
| `0.24.0` | HKDF And TLS Labels | Implement HKDF extract/expand and TLS HKDF-Expand-Label with all input and output limits explicit. |
| `0.25.0` | Portable AES | Implement portable constant-time AES-128/256 without secret-indexed tables; require layered emitted-code and statistical evidence for every admitted compiler and target. |
| `0.26.0` | GHASH | Implement constant-time GHASH finite-field arithmetic and a bounded incremental interface. |
| `0.27.0` | AES-GCM | Implement AES-GCM seal/open with nonce and usage limits and no plaintext release before authentication. |
| `0.28.0` | ChaCha20 | Implement ChaCha20 with checked counters and deterministic exhaustion closure. |
| `0.29.0` | Poly1305 And ChaCha20-Poly1305 | Implement Poly1305 and ChaCha20-Poly1305 with constant-time tag verification and withheld unauthenticated plaintext. |
| `0.30.0` | Fixed-Limb Arithmetic | Implement fixed-limb RSA and ECC arithmetic with no attacker-selected allocation, normalization schedule, or limb count. |
| `0.31.0` | X25519 | Implement X25519 using a fixed ladder, low-order handling, and explicit non-FIPS classification. |
| `0.32.0` | P-256 | Implement P-256 ECDH and ECDSA, complete point validation, and explicit deterministic and randomized nonce policy using the secure-random contract. |
| `0.33.0` | P-384 | Implement P-384 ECDH and ECDSA with separate vectors, side-channel evidence, and review. |
| `0.34.0` | RSA-PSS Verification | Implement strict RSA public-key decoding and RSA-PSS verification with unambiguous parameters and modulus and exponent policy. |
| `0.35.0` | RSA PKCS1 v1.5 Verification | Implement strict RSASSA-PKCS1-v1_5 certificate-signature verification for SHA-256/384/512 with complete padding, exact DigestInfo, no trailing bytes, and no SHA-1 or MD5 aliases; keep TLS CertificateVerify and signing excluded. |
| `0.36.0` | RSA-PSS Private Operations | Implement blinded fixed-schedule RSA-PSS private operations and CRT consistency checks, or freeze an external-signer-only production scope. |
| `0.37.0` | Ed25519 | Implement Ed25519 signing and verification with canonical encoding, small-order and malleability rejection, official vectors, and constant-time secret operations. |
| `0.38.0` | Version-One Algorithm Decisions | Freeze explicit v1 admission or exclusion for P-521, Ed448, finite-field DHE, AES-CCM, SHA-1 certificate chains, PKCS1 v1.5 signing, encrypted private-key containers, and every unimplemented algorithm family. |
| `0.39.0` | Cryptographic Substrate Audit Gate | Complete independent cryptographic-substrate review, per-target constant-time evidence, and remediation before PKI or TLS consumption. |
| `0.40.0` | PEM Base64 And Chain Containers | Implement bounded strict Base64 and PEM armor plus certificate-chain containers with label, count, size, whitespace, trailing-data, and resource policies. |
| `0.41.0` | Private-Key Input Formats | Implement bounded unencrypted PKCS#8, SEC1 EC, and PKCS1 RSA private-key decoding with algorithm/key consistency and secret-arena ownership; keep encrypted PKCS#8 an explicit v1 non-goal unless separately versioned. |
| `0.42.0` | X.509 Decoder | Decode X.509 Certificate, TBSCertificate, and SPKI while preserving the exact original signed byte slice and rejecting ambiguous algorithms. |
| `0.43.0` | Service Identity And Extensions | Validate SAN/service identity, ASCII A-label DNS inputs, wildcards, IP, email and URI names, critical and duplicate extensions, and caller-owned international-name normalization policy. |
| `0.44.0` | Bounded Path Construction | Build bounded deterministic paths using caller-supplied pools, loop detection, and hard depth, candidate, comparison, and work limits with no automatic network fetch. |
| `0.45.0` | Core Chain Validation | Validate chain signatures, validity, basic constraints, path length, key usage, and extended key usage. |
| `0.46.0` | Name Constraints | Validate DNS, IP, email, URI, and directory-name constraints with explicit subtree, comparison, normalization, and work budgets. |
| `0.47.0` | Certificate Policy Processing | Implement certificate policies, mappings, anyPolicy, inhibition, policy constraints, and bounded policy-tree processing. |
| `0.48.0` | Trust Anchors Cross-Signing And Algorithms | Define trust-anchor inputs, cross-signing and alternate-path semantics, deterministic selection, distrust policy, and per-position algorithm constraints. |
| `0.49.0` | CRL Validation | Validate base, delta, and indirect CRLs with issuer authorization, freshness, distribution-point, reason, entry, and work ceilings. |
| `0.50.0` | OCSP Validation | Validate stapled and offline OCSP responses, responder authorization, freshness, nonce, issuer and serial matching, and explicit hard/soft-fail policy. |
| `0.51.0` | SCT Parsing And Certificate Transparency Policy | Implement bounded SCT certificate-entry parsing and an explicit Certificate Transparency verification/provider policy; fail closed when CT is required and no admitted verifier exists. |
| `0.52.0` | PKI Audit Gate | Complete PKI adversarial, differential, fuzz, path-complexity, revocation, and external audit campaigns with clean remediation. |

## Phase 2: Internal Sans-I/O, Modern TLS 1.3, And Explicit TLS 1.2

An unstable internal effects model is exercised before TLS state machines. TLS 1.3 completes and is audited first; TLS 1.2 remains an explicitly selected ECDHE-plus-AEAD profile with no retry fallback.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.53.0` | Internal Sans-I/O Execution Contract | Define an explicitly unstable deterministic Event-to-Action driver for consumed input, output workspace, timers, entropy/time, certificate/signature/accelerator requests, application data, backpressure, resumable operations, cancellation, and terminal states. |
| `0.54.0` | TLS Record Protection | Implement TLS record protection, checked sequence exhaustion, inner content-type and padding validation, transactional state changes, and fragmentation boundaries. |
| `0.55.0` | TLS 1.3 Handshake Codec | Implement the complete TLS 1.3 handshake codec with duplicate, ordering, extension-context, unknown/GREASE-extension, compatibility ChangeCipherSpec, and resource rules. |
| `0.56.0` | Transcript And Key Schedule | Implement transcript and key-schedule states with immediate destruction of obsolete early, handshake, master, exporter, and resumption secrets. |
| `0.57.0` | TLS 1.3 Opening Flight | Implement ClientHello, versions, groups, signatures, key shares, HelloRetryRequest, cookies, GREASE tolerance, and downgrade invariants. |
| `0.58.0` | TLS 1.3 Authenticated Server Flight | Implement ServerHello through the authenticated server flight, certificate presentation, and the sole ALPN and SNI negotiation implementation. |
| `0.59.0` | Certificate Negotiation And Selection | Implement signature_algorithms_cert, certificate_authorities, oid_filters, certificate/public-key compatibility, bounded identity selection, and deterministic external-signer requests. |
| `0.60.0` | Stapled Status And SCT Transport | Implement status_request and stapled OCSP transport plus bounded SCT transport and handoff to the admitted PKI and CT policies. |
| `0.61.0` | Client Authentication And Finished | Implement client authentication, CertificateVerify, Finished, authenticated application-data transition, and explicit rejection of post-handshake authentication for v1. |
| `0.62.0` | Alerts Closure And Cancellation | Complete alerts, close-notify, illegal-message handling, backpressure, cancellation, provider failure, terminal states, and terminal secret and handle destruction. |
| `0.63.0` | Tickets And Resumption PSKs | Implement session tickets and resumption PSK binders with protocol-specific ticket-key, cache, external-storage secrecy, rotation, and lifetime domains. |
| `0.64.0` | External PSKs And PSK Modes | Separate external from resumption PSKs, require hardened psk_dhe_ke by default, type identity and binder policy, and prohibit silent psk_ke or cross-domain fallback. |
| `0.65.0` | Zero-RTT | Implement opt-in 0-RTT with anti-replay storage, freshness, deterministic rejection, secret lifetime, and application side-effect guidance. |
| `0.66.0` | TLS KeyUpdate | Implement KeyUpdate with traffic-secret transition, immediate obsolete-key destruction, request coalescing policy, and long-lived key and record limits. |
| `0.67.0` | Exporters And Channel Binding | Implement exporters and channel binding exactly once with context separation, transcript binding, authorization timing, and secret-output policy. |
| `0.68.0` | TLS 1.3 Suite Completion | Admit only AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, and ChaCha20-Poly1305/SHA-256 for the initial TLS 1.3 profile. |
| `0.69.0` | TLS 1.3 Conformance And Interoperability | Pass official vectors, truncation and fragmentation matrices, independent peer implementations, state-model and fuzz gates, and provider fault injection. |
| `0.70.0` | TLS 1.3 Audit Gate | Complete an external TLS 1.3 audit and clean remediation retest. |
| `0.71.0` | TLS 1.2 Policy Boundary | Freeze an explicit TLS 1.2 ECDHE-plus-AEAD policy with EMS required and static RSA, CBC, SHA-1 signing, compression, renegotiation, and automatic fallback excluded. |
| `0.72.0` | TLS 1.2 PRF Records And Downgrade Defense | Implement the TLS 1.2 PRF, record nonces, EMS transcript binding, downgrade sentinel, and SCSV and renegotiation-info rejection rules. |
| `0.73.0` | TLS 1.2 ECDHE State Machines | Implement isolated ECDHE_ECDSA and ECDHE_RSA TLS 1.2 client and server state machines. |
| `0.74.0` | TLS 1.2 Suite Completion | Admit only the six ECDSA/RSA combinations over AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305. |
| `0.75.0` | TLS 1.2 Resumption And Interoperability | Complete TLS 1.2 resumption, protocol-specific tickets, extension hardening, interop, and downgrade corpora. |
| `0.76.0` | TLS 1.2 Audit Gate | Complete a separate TLS 1.2 external audit while retaining explicit configuration and independent disablement. |

## Phase 3: QUIC TLS, DTLS, And Post-Quantum Work

The QUIC integration consumes ordered bytes and emits TLS effects without owning transport recovery. DTLS receives explicit header, record-number, replay, CID, flight, and amplification stops. ML-KEM follows SHA-3 and enters protocols only through exact standardized hybrids.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.77.0` | QUIC Ownership And Encryption Levels | Define distinct QUIC encryption levels and secret install/discard events; consume ordered bytes supplied by QUIC and exclude packet processing, offsets, retransmission, packet numbers, loss recovery, Retry, key phase, TLS records, and TLS KeyUpdate. |
| `0.78.0` | QUIC Transport Parameters | Implement bounded syntactic transport-parameter parsing and transcript binding while exposing typed values for QUIC-owned semantic enforcement. |
| `0.79.0` | QUIC Sans-I/O Handshake | Implement per-level TLS handshake input/output, alerts, pending providers, bounded future-level data, secret events, and deterministic rejection of late data. |
| `0.80.0` | Optional QUIC CRYPTO Reassembly Helper | Provide an explicitly optional bounded CRYPTO-offset reassembly helper with conflict and exhaustion handling that is not used implicitly and does not implement retransmission or loss recovery. |
| `0.81.0` | QUIC Conformance And Audit | Pass RFC 9001 vectors plus loss, reorder, discard, 0-RTT, interoperability, ownership-boundary, and external review gates. |
| `0.82.0` | DTLS Unified Headers And Epochs | Implement DTLS 1.3 unified headers, epochs, compact sequence reconstruction, AEAD nonce construction, and checked sequence exhaustion. |
| `0.83.0` | DTLS Record-Number Encryption | Implement record-number encryption and authenticated reconstruction-failure handling with official vectors and no replay-window mutation before authentication. |
| `0.84.0` | DTLS Replay And Epoch-Key Lifetimes | Implement fixed replay windows across epoch transitions, bounded previous/future retention, transactional key installation, and immediate obsolete-key destruction. |
| `0.85.0` | DTLS Connection IDs | Implement bounded optional connection IDs and CID updates with routing/privacy policy, replay and migration invariants, or record their explicit exclusion if standards evidence cannot meet the gate. |
| `0.86.0` | DTLS Fragmentation And Reassembly | Implement caller-owned bounded handshake fragmentation and reassembly with canonical transcript messages and overlap and conflicting-fragment rejection. |
| `0.87.0` | DTLS Flights ACKs And Timers | Implement deterministic flights, ACK processing, typed timer actions, cached retransmission, checked backoff, and congestion limits. |
| `0.88.0` | DTLS Address Validation And Amplification Defense | Implement cookies, address validation, amplification budgets, deterministic PMTU policy, and cheap rejection before expensive cryptography. |
| `0.89.0` | DTLS 1.3 State Machines | Complete DTLS 1.3 client and server states, key updates, duplicate idempotence, terminal cleanup, and provider cancellation. |
| `0.90.0` | Hardened DTLS 1.2 | Implement DTLS 1.2 using only the admitted TLS 1.2 ECDHE-plus-AEAD profile and isolated epoch, replay, ticket, and downgrade state. |
| `0.91.0` | DTLS Conformance And Audit | Pass loss, reorder, duplicate, fragmentation, replay, CID, hostile-load, fuzz, interoperability, and external audit gates. |
| `0.92.0` | ML-KEM Arithmetic And Encoding | Implement ML-KEM polynomial, NTT, sampling, and canonical encoding and decoding foundations. |
| `0.93.0` | ML-KEM Key Generation And Encapsulation | Implement ML-KEM-512/768/1024 key generation and encapsulation with FIPS 203, errata, randomness, stack, and applicable SP 800-227 checks. |
| `0.94.0` | ML-KEM Decapsulation And Implicit Rejection | Implement constant-time ML-KEM decapsulation and implicit rejection with malformed-ciphertext, failure-path, and side-channel campaigns. |
| `0.95.0` | Standard Hybrid Groups | Implement only final standardized X25519MLKEM768, P256MLKEM768, and P384MLKEM1024 encodings, component order, lengths, identifiers, and combiner behavior. |
| `0.96.0` | Hybrid Protocol Integration | Complete hybrid TLS, DTLS, and QUIC transcript, resource, fragmentation, downgrade, required-policy, and interoperability gates with no classical-only fallback. |
| `0.97.0` | PQ Standards And Audit Gate | Complete PQ external review and standards freeze; admit final RFC groups or keep draft work experimental and outside stable and FIPS claims. |

## Phase 4: FIPS Module Instantiation And Validation

This phase instantiates and validates the architecture frozen at 0.16.0. PKI and protocol state machines remain outside the narrow exact-build cryptographic module, and no FIPS 140-3 claim exists before accredited validation.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.98.0` | FIPS Module Boundary | Instantiate the exact binary and artifact boundary, operational environments, ports, services, roles, SSP inventory, compiler/linker/CPU inputs, and approved and non-approved exclusions. |
| `0.99.0` | Approved Provider And Service Indicator | Implement the sealed approved-only provider and unambiguous per-service approved indicator with no additive fips feature or construction before self-test success. |
| `0.100.0` | FIPS Self-Tests And Failure Latch | Implement integrity, CAST/KAT, pairwise-consistency, required conditional tests, permanent failure latch, and deterministic fault-injection evidence. |
| `0.101.0` | SSP Lifecycle And Zeroization Services | Define SSP entry, output, storage, high-water lifetime, external storage, accelerator handle, and zeroization services with completion indications and secret-free status events. |
| `0.102.0` | Entropy And DRBG Boundary | Implement the SP 800-90 entropy and DRBG boundary, health tests, security-strength mapping, reseed and fork behavior, failure model, and platform entropy evidence. |
| `0.103.0` | ACVTS And CAVP Evidence | Complete ACVTS and CAVP campaigns for every approved implementation, dispatch path, parameter set, and operational environment. |
| `0.104.0` | CMVP Submission Artifacts | Produce the CMVP Security Policy, finite-state model, service and SSP inventory, entropy assessment, source-to-object trace, and reproducible module artifacts. |
| `0.105.0` | Accredited FIPS Evaluation | Complete accredited-lab FIPS 140-3 evaluation, remediation, retest, and certificate and caveat recording; make no validation claim before issuance. |
| `0.106.0` | Boundary And Package Audit | Complete the final modern, historical, experimental, and FIPS dependency-boundary, symbol, dispatch, feature, and package-content audit. |

## Phase 5: Stable Integration, Optional Modules, Assurance, And General Availability

Stable public integration follows exercised internal contracts. Previously implemented ALPN, SNI, exporters, and channel binding are not repeated. Record Size Limit, Raw Public Keys, HPKE, ECH, delegated credentials, and certificate compression each receive independent bounded stops before final assurance.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.107.0` | Facade Configuration Typestates | Freeze facade typestates for exact modern versions, suites, trust, identity, resources, revocation, PSK, 0-RTT, CT, and provider policy; expose no raw crypto re-export or legacy-version range. |
| `0.108.0` | Stable Sans-I/O API | Promote the exercised internal effects model into the stable deterministic client and server Event-to-Action API with consumed/produced counts, backpressure, pending operations, cancellation, and compile-fail misuse tests. |
| `0.109.0` | Host Platform Adapters | Add host adapters for raw entropy, secure randomness, separate wall and monotonic clocks, opaque-key accelerators, and transport and storage examples plus async integration guidance. |
| `0.110.0` | Zero-Allocation And Resource Proof | Prove the caller-owned zero-allocation profile with exact workspace sizes, non-overlapping arenas, stack ceilings, concurrency limits, and hostile-load budgets. |
| `0.111.0` | Aesynx Qualification | Qualify the Aesynx target and entropy, randomness, time, transport, storage, and accelerator adapters with boot-to-handshake and lifecycle tests when the target is available. |
| `0.112.0` | Operational State Rotation | Complete session cache, ticket-key and resumption-PSK rotation, anti-replay storage, certificate and private-key rotation, trust-anchor rotation, and transactional failure recovery. |
| `0.113.0` | Record Size Limit | Implement Record Size Limit negotiation and enforcement with directional limits, fragmentation, buffering, peer-violation, and interoperability tests. |
| `0.114.0` | Raw Public Keys | Implement Raw Public Keys with a dedicated pinning and trust-provider contract, identity and rotation policy, negotiation, and proof that RPK never silently bypasses X.509 requirements. |
| `0.115.0` | HPKE KEM And Context Foundation | Implement HPKE DHKEM X25519 and P-256 context derivation, labeled HKDF operations, public-key validation, domain separation, and bounded context state. |
| `0.116.0` | HPKE Base Mode | Implement RFC 9180 HPKE base mode with admitted AEADs, sequence and nonce exhaustion, seal/open failure atomicity, official vectors, and independent differential tests. |
| `0.117.0` | ECH Configuration And Suite Selection | Implement bounded ECHConfig parsing, version and suite selection, public-name policy, key configuration, GREASE inputs, and resource limits. |
| `0.118.0` | ECH Protocol Integration | Implement inner and outer ClientHello construction, outer-extension references, AAD, acceptance confirmation, retry configurations, HRR interaction, GREASE, padding, transcript binding, and downgrade/resource tests. |
| `0.119.0` | Delegated Credentials | Implement delegated credentials as an independent optional module with authorization, lifetime, signature, selection, revocation interaction, and downgrade policy. |
| `0.120.0` | Certificate Compression Provider | Implement certificate compression through a bounded caller-provided decompression provider with transcript preservation, exact output length, ratio, CPU-work, workspace, algorithm-selection, and no-peer-admission-before-authentication rules; first-party zlib, Brotli, and Zstandard remain separate future work. |
| `0.121.0` | Formal Harnesses | Complete Kani or equivalent harnesses for cursors, lengths, state reachability, exhaustion, replay, transactional transitions, and secret-release invariants using pinned external tools. |
| `0.122.0` | Fuzz And Differential Campaign | Complete parser and state fuzzing, deterministic mutation, differential corpora, and crash minimization without adding third-party crates to repository Cargo manifests or shipped graphs. |
| `0.123.0` | Memory And Side-Channel Evidence | Complete Miri and sanitizer evidence plus compiler/target constant-time assembly, zeroization-store survival, cache/branch, and statistical side-channel matrices. |
| `0.124.0` | Sustained Platform And Hostile-Load Qualification | Sustain Linux, Windows, macOS, BSD, Android, iOS, bare-metal, and available Aesynx qualification under concurrency, provider failure, resource exhaustion, and hostile load. |
| `0.125.0` | Consolidated External Audits | Complete exact-commit external crypto, PKI, TLS, DTLS, QUIC, PQ, FIPS-boundary, optional-module, and systems-integration audits. |
| `0.126.0` | Audit Remediation And Clean Retest | Remediate every admitted finding, add permanent regressions, and obtain clean independent retests with no unresolved critical or high findings. |
| `0.127.0` | Public API Requirements And Documentation Freeze | Freeze public APIs, features, package inventory, requirements ledger, admitted algorithms and extensions, migration guidance, deployment profiles, incident procedures, limitations, and non-goals. |
| `0.128.0` | Clean-Room Release Rehearsal | Pass reproducible clean-room builds, package installation, artifact comparison, rollback, key-compromise, incident, and disaster-recovery exercises. |
| `1.0.0-rc.1` | Exact Production Candidate | Build final artifacts once and freeze source, compiler, flags, archives, SBOM, checksums, provenance, documentation, and the pentested exact commit. |
| `1.0.0` | First Serious Production-Ready Brynja TLS Release | Promote only the byte-identical approved candidate without rebuild, source change, metadata drift, or expanded capability claim. |

## Independent Historical Package Sequence

`H0.N.0` is planning shorthand: each historical crate uses its own normal
SemVer `0.N.0` line and never inherits the facade version. Repeat the sequence
independently for TLS 1.1, TLS 1.0, SSL 3, SSL 2, WTLS, PCT, and SNP. SSL 1
remains research-only and unpublished.

| Historical stage | Exclusive scope |
| --- | --- |
| `H0.1.0` | Authenticate sources and rights, track errata, publish conspicuous insecurity warnings, and define the protocol-specific threat model. |
| `H0.2.0` | Implement only the protocol-specific bounded wire codec. |
| `H0.3.0` | Implement an isolated state machine with no shared modern configuration, negotiation, credentials, caches, tickets, or fallback. |
| `H0.4.0` | Bind audited shared primitives and isolate required weak primitives in a historical-only crypto package. |
| `H0.5.0` | Complete controlled client-only interoperability and containment evidence. |
| `H0.6.0` | Add server interoperability only when separately justified, with amplification and hostile-load review. |
| `H0.7.0` | Require separate listeners, policy, credentials, storage, diagnostics, and process-containment guidance. |
| `H0.8.0` | Complete a protocol-specific external audit and pentest and verify every warning and non-fallback property. |

`1.0.0` means the frozen modern requirements ledger is complete and its exact
artifacts passed every applicable gate. It does not mean every historical
protocol, draft extension, compression algorithm, platform adapter, or future
TLS feature exists.
