# Brynja Version Plan

Status: reconciled planning sequence

This document defines the intended order and exclusive scope of Brynja releases
through `1.0.0`. Each version is a small implementation stop that must be
completed and verified before adjacent capability begins. Split a version
further whenever review scope grows; never combine unrelated work to preserve
numbering.

[RELEASE_PLAN.md](RELEASE_PLAN.md) is normative for every release's Goal,
Deliverables, Verification, and Exit criteria. It is maintained one-for-one
with this sequence: each release repeats its exact title and scope, and the
validator rejects numbering, ordering, title, or scope drift.

## Admission Rules For Every Version

Every milestone retains `no_std` production packages, no third-party crates in
repository Cargo manifests, bounded hostile-input processing, mandatory
owned-region secret destruction for production, negative and adversarial tests,
all supported Rust and target evidence, an SBOM, clean CI, and exact-commit
review. Brynja does not use `cargo-fuzz` or `libfuzzer-sys`; pinned external
process tools drive first-party harness binaries without relaxing dependency
policy.

Capability claims are limited to completed, tested, and independently reviewed
scope. Protocol selection is one-pass negotiation, never fallback. The modern
facade never depends on historical packages. FIPS is an exact-build artifact,
operational-environment, and configured-service claim, not a Cargo feature. PQ
hybrids remain experimental until standards and code points are final.

## Phase 0: Repository, Effects, Memory, And Wire Foundations

Repository enforcement and bounded core types come first. Production zeroization, constant-time operations, entropy, clocks, provider effects, and a FIPS-aware architecture are designed before any cryptographic engine consumes them.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.1.0` | Workspace Foundation | Preserve the existing workspace foundation with no cryptographic or protocol security claim. |
| `0.2.0` | Release And Isolation Enforcement | Fix exact-HEAD pentest comparison, validate all-feature graphs and every package class, add negative modern and historical isolation fixtures, and document protected release controls. |
| `0.3.0` | Requirements And Standards Ledger | Build the requirements ledger for RFC 9846, RFC 5280, RFC 9001, RFC 9147, RFC 9180, applicable NIST standards and errata, and frozen IANA snapshots; map every normative requirement. |
| `0.4.0` | Assurance Harness And Bare-Metal Matrix | Establish first-party mutation and differential harnesses, true bare-metal targets, and pinned external assurance-tool policy without adding third-party crates to repository Cargo manifests. |
| `0.5.0` | Error Alert And Exhaustion Domains | Freeze non-secret error, alert, close, provider-failure, and resource-exhaustion domains; prohibit secret-bearing formatting and ambiguous failure collapse. |
| `0.6.0` | Bounded Numeric And Resource Domains | Introduce checked bounded integers, counts, lengths, sequence numbers, epochs, and immutable resource and work budgets. |
| `0.7.0` | Borrowed Read Cursor | Implement a borrowed read cursor with exact consumption, truncation-at-every-byte coverage, and no indexing panics. |
| `0.8.0` | Transactional Write Cursor | Implement caller-buffer write cursors with transactional encode-or-no-mutation behavior. |
| `0.9.0` | Caller-Owned Workspace And Arena Model | Define caller-owned workspaces and non-overlapping secret, plaintext, transcript, certificate, and output arenas with overlap rules, high-water tracking, and allocation counters. |
| `0.10.0` | Secret Lifetime And Destruction Contract | Define non-cloneable and non-serializable secret ownership, transition, error, cancellation, provider-failure and drop destruction, immediate obsolete-secret cleanup, external-store and accelerator duties, and a mandatory production guarantee for the complete owned memory region. |
| `0.11.0` | Owned-Memory Zeroization Primitive | After explicit unsafe-policy approval, implement the smallest isolated first-party primitive needed to preserve zeroization stores through optimization; define proof obligations, cache and DMA completion duties, MIR, LLVM and assembly evidence for every supported compiler and target, and precise exclusions for registers, copies, dumps, and physical memory. |
| `0.12.0` | Constant-Time Foundation | Implement constant-time equality, choice and mask types, conditional select and swap, fixed-width secret operations, compiler barriers, and rules forbidding secret-dependent control flow, indexing, loop counts, and error timing. |
| `0.13.0` | Provider Capabilities And Opaque Handles | Define crypto, signature, KEM, and AEAD capability traits with opaque key handles, frozen capabilities, transactional key installation, exact-operation token binding, and no implicit software fallback. |
| `0.14.0` | Entropy And Secure-Random Contracts | Separate caller-provided raw entropy from initialized secure randomness; type security strength, purpose, retryable and permanent failure, fork and reseed rules, clone prohibition, and test-only providers that production configuration cannot construct. |
| `0.15.0` | Wall And Monotonic Clock Contracts | Define non-interchangeable typed wall time for PKI and typed monotonic time for timers, freshness, tickets, and replay policy with checked arithmetic and explicit unavailable-time behavior. |
| `0.16.0` | Pending Operations And Accelerator Lifecycle | Define resumable provider tokens, certificate, signature and accelerator requests, cancellation, key-handle destruction, retry semantics, backpressure, and failure-atomic state transitions. |
| `0.17.0` | FIPS-Aware Provider Architecture | Freeze approved and non-approved service separation, self-test and permanent-failure hooks, dispatch, service indicators, SSP boundaries, deterministic module-build expectations, operational-environment assumptions, and sealed-provider exclusions without making a validation claim. |
| `0.18.0` | TLS And DTLS Record Framing | Keep record framing independent of protocol selection and fallback; ignore TLSPlaintext legacy_record_version where required, validate TLSCiphertext constants where applicable, preserve bytes, and leave version choice exclusively to typed handshake policy. |
| `0.19.0` | Bounded DER Reader | Implement a non-recursive DER tag, length and value reader with definite, minimal, overflow-safe, depth-, node-, size-, and work-bounded parsing. |
| `0.20.0` | Canonical ASN.1 Primitives | Add canonical ASN.1 integer, bit and octet string, OID, Boolean, string, sequence and set, and time primitives with malformed and non-canonical corpora. |

## Phase 1: First-Party Cryptography, Identity Formats, And PKI

Arithmetic, group operations, key agreement, and signatures are separate stops. Every ephemeral-key stop owns generation, non-reuse, provider binding, consistency, invalid-secret handling, and immediate destruction. Crypto and PKI each retain independent audit gates.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.21.0` | SHA-256 | Implement streaming and fixed-message SHA-256 with official vectors, boundary lengths, and exhaustion handling. |
| `0.22.0` | SHA-384 And SHA-512 | Implement SHA-384 and SHA-512 with official vectors and checked length and exhaustion behavior. |
| `0.23.0` | Keccak SHA-3 And SHAKE | Implement Keccak-f[1600], SHA3-256 and SHA3-512, and SHAKE128 and SHAKE256 as the required ML-KEM foundation. |
| `0.24.0` | HMAC | Implement HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with constant-time verification and misuse tests. |
| `0.25.0` | HKDF And TLS Labels | Implement HKDF extract and expand and TLS HKDF-Expand-Label with all input and output limits explicit. |
| `0.26.0` | Portable AES | Implement portable constant-time AES-128 and AES-256 without secret-indexed tables; require layered emitted-code and statistical evidence for every admitted compiler and target. |
| `0.27.0` | GHASH | Implement constant-time GHASH finite-field arithmetic and a bounded incremental interface. |
| `0.28.0` | AES-GCM | Implement AES-GCM seal and open with nonce and usage limits and no plaintext release before authentication. |
| `0.29.0` | ChaCha20 | Implement ChaCha20 with checked counters and deterministic exhaustion closure. |
| `0.30.0` | Poly1305 And ChaCha20-Poly1305 | Implement Poly1305 and ChaCha20-Poly1305 with constant-time tag verification and withheld unauthenticated plaintext. |
| `0.31.0` | Fixed-Limb RSA Arithmetic | Implement fixed-limb unsigned arithmetic, Montgomery operations, modular exponentiation, and RSA-size policies with no attacker-selected allocation, normalization schedule, or limb count. |
| `0.32.0` | Prime-Field And ECC Arithmetic | Implement fixed-width prime-field arithmetic, inversion, square roots, scalar primitives, and complete-formula foundations needed by admitted curves, separate from RSA limbs. |
| `0.33.0` | X25519 Field And Ladder | Implement X25519 field encoding, canonical decoding policy, clamping, fixed Montgomery ladder, and low-order input handling. |
| `0.34.0` | X25519 ECDH Lifecycle | Implement unbiased ephemeral input generation, no private-key reuse, imported public and private consistency policy, all-zero shared-secret rejection, immediate scalar destruction, and provider-token binding to group, connection, and transcript. |
| `0.35.0` | P-256 Group Operations | Implement P-256 point decoding, on-curve and subgroup validation, complete group operations, fixed-schedule scalar multiplication, and official group vectors. |
| `0.36.0` | P-256 ECDH Lifecycle | Implement unbiased P-256 private-scalar generation, no ephemeral reuse, imported key consistency, invalid shared-secret handling, immediate scalar destruction, and exact group, connection, and transcript provider-token binding. |
| `0.37.0` | P-256 ECDSA | Implement P-256 ECDSA signing and verification, strict encoding, low-S policy decision, and deterministic and randomized nonce policy using the secure-random contract. |
| `0.38.0` | P-384 Group Operations | Implement P-384 point decoding, on-curve and subgroup validation, complete group operations, fixed-schedule scalar multiplication, and official group vectors. |
| `0.39.0` | P-384 ECDH Lifecycle | Implement unbiased P-384 private-scalar generation, no ephemeral reuse, imported key consistency, invalid shared-secret handling, immediate scalar destruction, and exact group, connection, and transcript provider-token binding. |
| `0.40.0` | P-384 ECDSA | Implement P-384 ECDSA signing and verification with strict encoding, nonce policy, vectors, per-target side-channel evidence, and independent review. |
| `0.41.0` | RSA-PSS Verification | Implement strict RSA public-key decoding and RSA-PSS verification with unambiguous parameters and modulus and exponent policy. |
| `0.42.0` | RSA PKCS1 v1.5 Verification | Implement strict RSASSA-PKCS1-v1_5 certificate-signature verification for SHA-256, SHA-384 and SHA-512 with complete padding, exact DigestInfo, no trailing bytes, and no SHA-1 or MD5 aliases; keep TLS CertificateVerify and signing excluded. |
| `0.43.0` | RSA-PSS Private Operations | Implement blinded fixed-schedule RSA-PSS private operations and CRT consistency checks, or freeze an external-signer-only production scope. |
| `0.44.0` | Ed25519 | Implement Ed25519 signing and verification with canonical encoding, small-order and malleability rejection, official vectors, and constant-time secret operations. |
| `0.45.0` | Version-One Algorithm Decisions | Freeze explicit v1 admission or exclusion for P-521, Ed448, finite-field DHE, AES-CCM, SHA-1 certificate chains, PKCS1 v1.5 signing, encrypted private-key containers, ML-DSA, SLH-DSA, and every unimplemented algorithm family. |
| `0.46.0` | Cryptographic Substrate Audit Gate | Complete independent cryptographic-substrate review, per-target constant-time and zeroization evidence, and remediation before PKI or TLS consumption. |
| `0.47.0` | PEM Base64 And Chain Containers | Implement bounded strict Base64 and PEM armor plus certificate-chain containers with label, count, size, whitespace, trailing-data, and resource policies. |
| `0.48.0` | Private-Key Input Formats | Implement bounded unencrypted PKCS#8, SEC1 EC, and PKCS1 RSA private-key decoding with algorithm and key consistency and secret-arena ownership; keep encrypted PKCS#8 an explicit v1 non-goal unless separately versioned. |
| `0.49.0` | X.509 Decoder | Decode X.509 Certificate, TBSCertificate, and SPKI while preserving the exact original signed byte slice and rejecting ambiguous algorithms. |
| `0.50.0` | Service Identity And Extensions | Validate SAN and service identity, ASCII A-label DNS inputs, wildcards, IP, email and URI names, critical and duplicate extensions, and caller-owned international-name normalization policy. |
| `0.51.0` | Bounded Path Construction | Build bounded deterministic paths using caller-supplied pools, loop detection, and hard depth, candidate, comparison, and work limits with no automatic network fetch. |
| `0.52.0` | Core Chain Validation | Validate chain signatures, validity, basic constraints, path length, key usage, and extended key usage. |
| `0.53.0` | Name Constraints | Validate DNS, IP, email, URI, and directory-name constraints with explicit subtree, comparison, normalization, and work budgets. |
| `0.54.0` | Certificate Policy Processing | Implement certificate policies, mappings, anyPolicy, inhibition, policy constraints, and bounded policy-tree processing. |
| `0.55.0` | Trust Anchors Cross-Signing And Algorithms | Define trust-anchor inputs, cross-signing and alternate-path semantics, deterministic selection, distrust policy, and per-position algorithm constraints. |
| `0.56.0` | CRL Validation | Validate base, delta, and indirect CRLs with issuer authorization, freshness, distribution-point, reason, entry, and work ceilings. |
| `0.57.0` | OCSP Validation | Validate stapled and offline OCSP responses, responder authorization, freshness, nonce, issuer and serial matching, and explicit hard and soft-fail policy. |
| `0.58.0` | Certificate Transparency Contract | Implement bounded SCT parsing and define verifier ownership, log identities and list updates, signed-entry reconstruction, timestamp validity, log disqualification, duplicate handling, and distinct-log and operator policy; fail closed when CT is required and no admitted verifier exists. |
| `0.59.0` | PKI Audit Gate | Complete PKI adversarial, differential, fuzz, path-complexity, revocation, Certificate Transparency, and external audit campaigns with clean remediation. |

## Phase 2: Internal Sans-I/O, Modern TLS 1.3, And Explicit TLS 1.2

The effects model is exercised before protocol engines. A ClientHello is parsed once and transferred to exactly one modern TLS engine; selection is never retry fallback. TLS 1.2 signaling and renegotiation behavior are split into their own compliance stop.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.60.0` | Internal Sans-I/O Execution Contract | Define an explicitly unstable deterministic Event-to-Action driver for consumed input, output workspace, timers, entropy and time, certificate, signature and accelerator requests, application data, backpressure, resumable operations, path tokens, cancellation, and terminal states. |
| `0.61.0` | TLS Record Protection | Implement TLS record protection, checked sequence exhaustion, inner content-type and padding validation, transactional state changes, and fragmentation boundaries without performing protocol selection. |
| `0.62.0` | TLS 1.3 Handshake Codec | Implement the complete TLS 1.3 handshake codec with duplicate, ordering, extension-context, unknown and GREASE extension, compatibility ChangeCipherSpec, and resource rules. |
| `0.63.0` | Transcript And Key Schedule | Implement transcript and key-schedule states with immediate destruction of obsolete early, handshake, master, exporter, and resumption secrets. |
| `0.64.0` | ClientHello Construction And Offers | Implement bounded ClientHello construction and parsing for supported versions, groups, signature schemes, key shares, GREASE, SNI, ALPN, extension ordering, and exact original-byte preservation. |
| `0.65.0` | HelloRetryRequest And Cookies | Implement HelloRetryRequest validation, transcript message_hash transformation, selected-group rules, cookies, second-ClientHello invariants, and retry resource ceilings. |
| `0.66.0` | One-Pass Modern TLS Version Selector | Parse one ClientHello once, safely skip unknown future offered versions, reject recognized legacy versions by policy, intersect configured TLS 1.3 and hardened TLS 1.2, choose the highest, apply downgrade sentinels when selecting TLS 1.2, preserve original bytes, and transfer credentials, tickets, PSKs and state into exactly one typed engine with no retry after failure. |
| `0.67.0` | TLS 1.3 Authenticated Server Flight | Implement ServerHello through the authenticated server flight, certificate presentation, and the sole ALPN and SNI negotiation implementation. |
| `0.68.0` | Certificate Negotiation And Selection | Implement signature_algorithms_cert, certificate_authorities, oid_filters, certificate and public-key compatibility, bounded identity selection, and deterministic external-signer requests. |
| `0.69.0` | Stapled Status And SCT Transport | Implement status_request and stapled OCSP transport plus bounded SCT transport and handoff to admitted PKI and Certificate Transparency policies. |
| `0.70.0` | Client Authentication And Finished | Implement client authentication, CertificateVerify, Finished, authenticated application-data transition, and explicit rejection of post-handshake authentication for v1. |
| `0.71.0` | Alerts Closure And Cancellation | Complete alerts, close-notify, illegal-message handling, backpressure, cancellation, provider failure, terminal states, and terminal secret and handle destruction. |
| `0.72.0` | Stateful Tickets And Resumption PSKs | Implement stateful cache tickets and resumption PSK binders with protocol-specific cache, key, external-storage secrecy, rotation, lifetime, and identity domains. |
| `0.73.0` | Stateless Ticket Protection | Implement an optional versioned AEAD ticket envelope binding protocol version, suite, SNI, ALPN, client-authentication state, PSK and early-data policy, issue and expiry time, key identifier, rotation generation, and deployment domain with nonce uniqueness and uniform failures. |
| `0.74.0` | External PSKs And PSK Modes | Separate external from resumption PSKs, require hardened psk_dhe_ke by default, type identity and binder policy, and prohibit silent psk_ke or cross-domain fallback. |
| `0.75.0` | Zero-RTT | Implement opt-in 0-RTT with anti-replay storage, freshness, deterministic rejection, secret lifetime, and application side-effect guidance. |
| `0.76.0` | TLS KeyUpdate | Implement KeyUpdate with traffic-secret transition, immediate obsolete-key destruction, request coalescing policy, and long-lived key and record limits. |
| `0.77.0` | Exporters And Channel Binding | Implement exporters and channel binding exactly once with context separation, transcript binding, authorization timing, and secret-output policy. |
| `0.78.0` | TLS 1.3 Suite Completion | Admit only AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, and ChaCha20-Poly1305/SHA-256 for the initial TLS 1.3 profile. |
| `0.79.0` | TLS 1.3 Conformance And Interoperability | Pass official vectors, truncation and fragmentation matrices, independent peer implementations, state-model and fuzz gates, and provider fault injection. |
| `0.80.0` | TLS 1.3 Audit Gate | Complete an external TLS 1.3 audit and clean remediation retest. |
| `0.81.0` | TLS 1.2 Policy Boundary | Freeze an explicit TLS 1.2 ECDHE-plus-AEAD policy with EMS required and static RSA, CBC, SHA-1 signing, compression, renegotiation, and automatic fallback excluded. |
| `0.82.0` | TLS 1.2 PRF And Key Block | Implement the TLS 1.2 PRF, master secret, EMS master-secret input, key-block expansion, label separation, and length limits. |
| `0.83.0` | TLS 1.2 Record Nonces And Protection | Implement admitted TLS 1.2 AEAD record nonces, additional data, sequence exhaustion, limits, fragmentation, and failure-atomic open. |
| `0.84.0` | TLS 1.2 EMS Transcript Binding | Implement Extended Master Secret transcript selection, session-hash rules, resumption consistency, and mandatory EMS failure behavior. |
| `0.85.0` | TLS 1.2 Signaling And Renegotiation Semantics | Accept TLS_EMPTY_RENEGOTIATION_INFO_SCSV only as initial secure-renegotiation signaling, accept empty renegotiation_info where required, emit inappropriate_fallback for TLS_FALLBACK_SCSV only when a higher enabled version exists, apply downgrade sentinels, and reject every subsequent renegotiation attempt. |
| `0.86.0` | TLS 1.2 ECDHE State Machines | Implement isolated ECDHE_ECDSA and ECDHE_RSA TLS 1.2 client and server state machines entered only by the one-pass modern selector. |
| `0.87.0` | TLS 1.2 Suite Completion | Admit only the six ECDSA and RSA combinations over AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305. |
| `0.88.0` | TLS 1.2 Resumption And Interoperability | Complete TLS 1.2 stateful and stateless resumption, protocol-specific tickets, extension hardening, interop, and downgrade corpora. |
| `0.89.0` | TLS 1.2 Audit Gate | Complete a separate TLS 1.2 external audit while retaining explicit configuration and independent disablement. |

## Phase 3: QUIC TLS, DTLS, And Post-Quantum Work

TLS emits typed QUIC traffic secrets; the integration may expand packet keys while transport retains Initial salts and packet ownership. DTLS binds all path-sensitive state to opaque caller tokens and selects 1.3 or 1.2 once. PQ authentication exclusions are intentional.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.90.0` | QUIC Ownership And Encryption Levels | Define distinct QUIC encryption levels and secret install and discard events; consume ordered bytes supplied by QUIC and exclude packet processing, offsets, retransmission, packet numbers, loss recovery, Retry, key phase, TLS records, and TLS KeyUpdate. |
| `0.91.0` | QUIC Key-Derivation Boundary | Have TLS emit typed handshake and application traffic secrets; optionally derive quic key, quic iv and quic hp in brynja-quic-tls; keep version-specific Initial salts and secrets, packet protection, Retry integrity, key phase, and quic ku in the QUIC transport; verify all admitted derivations with RFC 9001 vectors. |
| `0.92.0` | QUIC Transport Parameters | Implement bounded syntactic transport-parameter parsing and transcript binding while exposing typed values for QUIC-owned semantic enforcement. |
| `0.93.0` | QUIC Sans-I/O Handshake | Implement per-level TLS handshake input and output, alerts, pending providers, bounded future-level data, traffic-secret events, and deterministic rejection of late data. |
| `0.94.0` | Optional QUIC CRYPTO Reassembly Helper | Provide an explicitly optional bounded CRYPTO-offset reassembly helper with conflict and exhaustion handling that is not used implicitly and does not implement retransmission or loss recovery. |
| `0.95.0` | QUIC Conformance And Audit | Pass RFC 9001 vectors plus loss, reorder, discard, 0-RTT, key-derivation, interoperability, ownership-boundary, and external review gates. |
| `0.96.0` | DTLS Path Identity Contract | Introduce an opaque caller-provided path token binding cookie state, amplification accounting, CID routing, migration, PMTU, timers, and datagram metadata so packets cannot transfer validation or budgets between paths. |
| `0.97.0` | DTLS Unified Headers And Epochs | Implement DTLS 1.3 unified headers, epochs, compact sequence reconstruction, AEAD nonce construction, and checked sequence exhaustion. |
| `0.98.0` | DTLS Record-Number Encryption | Implement record-number encryption and authenticated reconstruction-failure handling with official vectors and no replay-window mutation before authentication. |
| `0.99.0` | DTLS Replay And Epoch-Key Lifetimes | Implement fixed replay windows across epoch transitions, bounded previous and future retention, transactional key installation, and immediate obsolete-key destruction. |
| `0.100.0` | DTLS Connection IDs | Implement bounded optional connection IDs and CID updates with path-token routing, privacy, replay and migration invariants, or record their explicit exclusion if standards evidence cannot meet the gate. |
| `0.101.0` | DTLS Fragmentation And Reassembly | Implement caller-owned bounded handshake fragmentation and reassembly with canonical transcript messages and overlap and conflicting-fragment rejection. |
| `0.102.0` | DTLS Flights ACKs And Timers | Implement deterministic flights, ACK processing, typed timer actions, cached retransmission, checked backoff, congestion limits, and path-token ownership. |
| `0.103.0` | DTLS Address Validation And Amplification Defense | Implement path-bound cookies, address validation, amplification budgets, deterministic PMTU policy, and cheap rejection before expensive cryptography. |
| `0.104.0` | DTLS 1.3 State Machines | Complete DTLS 1.3 client and server states, key updates, duplicate idempotence, terminal cleanup, and provider cancellation. |
| `0.105.0` | One-Pass DTLS Version Selector | Parse one ClientHello once, safely skip unknown future versions, choose the highest configured DTLS 1.3 or hardened DTLS 1.2 version, preserve transcript and path state, and enter exactly one typed engine with no credentials, tickets, epochs, replay windows, or state crossing domains and no retry after failure. |
| `0.106.0` | Hardened DTLS 1.2 | Implement DTLS 1.2 using only the admitted TLS 1.2 ECDHE-plus-AEAD profile and isolated epoch, replay, ticket, path, and downgrade state. |
| `0.107.0` | DTLS Conformance And Audit | Pass loss, reorder, duplicate, fragmentation, replay, path-token, CID, version-selection, hostile-load, fuzz, interoperability, and external audit gates. |
| `0.108.0` | ML-KEM Arithmetic And Encoding | Implement ML-KEM polynomial, NTT, sampling, and canonical encoding and decoding foundations. |
| `0.109.0` | ML-KEM Key Generation And Encapsulation | Implement ML-KEM-512, ML-KEM-768 and ML-KEM-1024 key generation and encapsulation with FIPS 203, errata, randomness, stack, and applicable SP 800-227 checks. |
| `0.110.0` | ML-KEM Decapsulation And Implicit Rejection | Implement constant-time ML-KEM decapsulation and implicit rejection with malformed-ciphertext, failure-path, and side-channel campaigns. |
| `0.111.0` | Standard Hybrid Groups | Implement only final standardized X25519MLKEM768, P256MLKEM768, and P384MLKEM1024 encodings, component order, lengths, identifiers, and combiner behavior. |
| `0.112.0` | Hybrid Protocol Integration | Complete hybrid TLS, DTLS, and QUIC transcript, resource, fragmentation, downgrade, required-policy, and interoperability gates with no classical-only fallback. |
| `0.113.0` | PQ Standards And Audit Gate | Complete PQ external review and standards freeze; keep ML-DSA and SLH-DSA excluded from v1 authentication unless a separately reviewed final standard, TLS mapping, and interoperability milestone is added. |

## Phase 4: FIPS Module Instantiation, Validation, And TLS Profile

This phase instantiates the architecture frozen before crypto, validates its exact operational environments, then adds a facade profile that makes non-approved configuration unrepresentable.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.114.0` | FIPS Module Boundary | Instantiate the exact binary and artifact boundary, operational environments, ports, services, roles, SSP inventory, compiler, linker and CPU inputs, and approved and non-approved exclusions. |
| `0.115.0` | Approved Provider And Service Indicator | Implement the sealed approved-only provider and unambiguous per-service approved indicator with no additive fips feature or construction before self-test success. |
| `0.116.0` | FIPS Self-Tests And Failure Latch | Implement integrity, CAST and KAT, pairwise-consistency, required conditional tests, permanent failure latch, and deterministic fault-injection evidence. |
| `0.117.0` | SSP Lifecycle And Zeroization Services | Define SSP entry, output, storage, high-water lifetime, external storage, accelerator handle, cache and DMA completion, and zeroization services with completion indications and secret-free status events. |
| `0.118.0` | SP 800-90 Entropy And DRBG Boundary | Select SP 800-90A DRBGs; validate SP 800-90B entropy sources and health tests; satisfy SP 800-90C construction rules; and define prediction resistance, personalization, fork, reseed, security-strength, and catastrophic-failure semantics. |
| `0.119.0` | ACVTS And CAVP Evidence | Complete ACVTS and CAVP campaigns for every approved implementation, dispatch path, parameter set, and operational environment. |
| `0.120.0` | CMVP Submission Artifacts | Produce the CMVP Security Policy, finite-state model, service and SSP inventory, entropy assessment, source-to-object trace, and reproducible module artifacts. |
| `0.121.0` | Accredited FIPS Evaluation | Complete accredited-lab FIPS 140-3 evaluation, remediation, retest, and certificate and caveat recording; make no validation claim before issuance. |
| `0.122.0` | Boundary And Package Audit | Complete the final modern, historical, experimental, and FIPS dependency-boundary, symbol, dispatch, feature, and package-content audit. |
| `0.123.0` | Approved-Only TLS Operating Profile | Implement a facade-level approved-only profile that rejects X25519, Ed25519, ChaCha20, HPKE, ECH, experimental hybrids, and every service not admitted by the exact validated module and operational environment. |

## Phase 5: Stable Integration, Optional Modules, Assurance, And General Availability

Stable public integration follows exercised internal contracts. Aesynx v1 completion is an executable ABI and emulator contract; real-hardware qualification may follow. Optional modules are independent, and ECH client, server, and retry behavior are separate stops.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.124.0` | Facade Configuration Typestates | Freeze facade typestates for exact modern versions, one-pass selection, suites, trust, identity, resources, revocation, PSK, zero-RTT, Certificate Transparency, FIPS profile, and provider policy; expose no raw crypto re-export or legacy-version range. |
| `0.125.0` | Stable Sans-I/O API | Promote the exercised internal effects model into the stable deterministic client and server Event-to-Action API with consumed and produced counts, path tokens, backpressure, pending operations, cancellation, and compile-fail misuse tests. |
| `0.126.0` | Host Platform Adapters | Add host adapters for raw entropy, secure randomness, separate wall and monotonic clocks, opaque-key accelerators, and transport and storage examples plus async integration guidance. |
| `0.127.0` | Zero-Allocation And Resource Proof | Prove the caller-owned zero-allocation profile with exact workspace sizes, non-overlapping arenas, stack ceilings, concurrency limits, and hostile-load budgets. |
| `0.128.0` | Aesynx ABI And Emulator Qualification | Make the stable Aesynx adapter contract a v1 requirement and pass an executable target-ABI or emulator harness for entropy, randomness, time, transport, storage, acceleration, boot-to-handshake, and lifecycle behavior; allow real-hardware qualification after v1 without weakening the contract. |
| `0.129.0` | Operational State Rotation | Complete session cache, stateless ticket-key and resumption-PSK rotation, anti-replay storage, certificate and private-key rotation, trust-anchor and CT log-list updates, and transactional failure recovery. |
| `0.130.0` | Record Size Limit | Implement Record Size Limit negotiation and enforcement with directional limits, fragmentation, buffering, peer-violation, and interoperability tests. |
| `0.131.0` | Raw Public Keys | Implement Raw Public Keys with a dedicated pinning and trust-provider contract, identity and rotation policy, negotiation, and proof that RPK never silently bypasses X.509 requirements. |
| `0.132.0` | HPKE KEM And Context Foundation | Implement HPKE DHKEM X25519 and P-256 context derivation, labeled HKDF operations, public-key validation, domain separation, and bounded context state. |
| `0.133.0` | HPKE Base Mode | Implement RFC 9180 HPKE base mode with admitted AEADs, sequence and nonce exhaustion, seal and open failure atomicity, official vectors, and independent differential tests. |
| `0.134.0` | ECH Configuration And Suite Selection | Implement bounded ECHConfig parsing, version and suite selection, public-name policy, key configuration, GREASE inputs, and resource limits. |
| `0.135.0` | ECH Client Construction | Implement client inner and outer ClientHello construction, outer-extension references, AAD inputs, GREASE, padding, transcript preservation, and configuration and resource policy. |
| `0.136.0` | ECH Server Opening And Acceptance | Implement server configuration lookup, HPKE opening, inner and outer consistency checks, acceptance confirmation, identity selection, uniform rejection, and no fallback to attacker-modified state. |
| `0.137.0` | ECH HRR Retry And Rotation | Implement ECH HelloRetryRequest interaction, retry configurations, configuration rotation, second-ClientHello invariants, downgrade detection, and client and server interoperability. |
| `0.138.0` | Delegated Credentials | Implement delegated credentials as an independent optional module with authorization, lifetime, signature, selection, revocation interaction, and downgrade policy. |
| `0.139.0` | Certificate Compression Provider | Treat decompression as strictly bounded hostile pre-authentication work; retain wire CompressedCertificate bytes for the transcript, pass decompressed Certificate bytes to PKI, release no identity or application data before decompression, X.509, CertificateVerify and Finished succeed, and terminate on provider error, overrun, short output, trailing compressed data, or algorithm mismatch. |
| `0.140.0` | Formal Harnesses | Complete Kani or equivalent harnesses for cursors, lengths, state reachability, exhaustion, replay, transactional transitions, one-pass selectors, and secret-release invariants using pinned external tools. |
| `0.141.0` | External-Process Fuzz And Differential Campaign | Do not use cargo-fuzz or libfuzzer-sys; drive first-party corpus and stdin harness binaries with pinned external process-level mutation and instrumentation, deterministic replay, differential corpora, and crash minimization without third-party repository crates. |
| `0.142.0` | Memory And Side-Channel Evidence | Complete Miri and sanitizer evidence plus compiler and target constant-time assembly, owned-region zeroization-store survival, cache and branch, and statistical side-channel matrices. |
| `0.143.0` | Sustained Platform And Hostile-Load Qualification | Sustain Linux, Windows, macOS, BSD, Android, iOS, bare-metal, and Aesynx ABI or emulator qualification under concurrency, provider failure, resource exhaustion, and hostile load. |
| `0.144.0` | Consolidated External Audits | Complete exact-commit external crypto, PKI, TLS, DTLS, QUIC, PQ, FIPS-boundary and profile, optional-module, zeroization, and systems-integration audits. |
| `0.145.0` | Audit Remediation And Clean Retest | Remediate every admitted finding, add permanent regressions, and obtain clean independent retests with no unresolved critical or high findings. |
| `0.146.0` | Public API Requirements And Documentation Freeze | Freeze public APIs, features, package inventory, requirements ledger, admitted algorithms and extensions, migration guidance, deployment profiles, incident procedures, limitations, and non-goals. |
| `0.147.0` | Clean-Room Release Rehearsal | Pass reproducible clean-room builds, package installation, artifact comparison, rollback, key-compromise, incident, and disaster-recovery exercises. |
| `1.0.0-rc.1` | Exact Production Candidate | Build final artifacts once and freeze source, compiler, flags, archives, SBOM, checksums, provenance, documentation, and the pentested exact commit. |
| `1.0.0` | First Serious Production-Ready Brynja TLS Release | Promote only the byte-identical approved candidate without rebuild, source change, metadata drift, or expanded capability claim. |

## Independent Historical Package Sequence

`H0.N.0` is planning shorthand: each historical crate uses its own SemVer
`0.N.0` line and never inherits the facade version. Repeat the sequence for
TLS 1.1, TLS 1.0, SSL 3, SSL 2, WTLS, PCT, and SNP. SSL 1 remains
research-only and unpublished.

| Historical stage | Exclusive scope |
| --- | --- |
| `H0.1.0` | Authenticate sources and rights, track errata, publish conspicuous insecurity warnings, and define the protocol-specific threat model. |
| `H0.2.0` | Implement only the protocol-specific bounded wire codec. |
| `H0.3.0` | Implement an isolated state machine with no shared modern configuration, negotiation, credentials, caches, tickets, or fallback. |
| `H0.4.0` | Bind audited shared primitives and isolate required weak primitives in a historical-only crypto package. |
| `H0.5.0` | Complete controlled client-only interoperability and containment evidence. |
| `H0.6.0` | Add server interoperability only when separately justified, with amplification and hostile-load review. |
| `H0.7.0` | Require separate listeners, paths, policy, credentials, storage, diagnostics, and process-containment guidance. |
| `H0.8.0` | Complete a protocol-specific external audit and pentest and verify every warning and non-fallback property. |

`1.0.0` means the frozen modern requirements ledger is complete and its exact
artifacts passed every applicable gate. It does not mean every historical
protocol, draft extension, compression algorithm, physical platform, or future
TLS feature exists.
