# Brynja Version Plan

Status: reconciled planning sequence

This document defines the exclusive, ordered Brynja release line through
`1.0.0`. Each version is an independently reviewable implementation stop.
Split growing work; never merge unrelated scope to preserve numbering.

[RELEASE_PLAN.md](RELEASE_PLAN.md) is normative for Goal, Deliverables,
Verification, and Exit criteria. It repeats every exact title and scope; the
validator rejects numbering, ordering, title, or scope drift.

## Admission Rules For Every Version

Every milestone retains `no_std` production packages, no third-party crates in
repository Cargo manifests, bounded hostile-input and pre-authentication work,
mandatory owned-region secret destruction, adversarial tests, supported Rust
and target evidence, SBOM, clean CI, and exact-commit review.

Protocol and optional-module dependency direction is downstream from frozen
interfaces and validated provider ports. Early negotiation policy is distinct
from final engine routing. Optional features pass a composition gate before
public API freeze. FIPS module catastrophic failure is distinct from terminating
a connection that violates its approved-only profile.

## Phase 0: Repository, Effects, Memory, And Wire Foundations

Generated standards scope and upstream dependency direction precede implementation.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.1.0` | Workspace Foundation | Preserve the existing workspace foundation with no cryptographic or protocol security claim. |
| `0.2.0` | Release And Isolation Enforcement | Fix exact-HEAD pentest comparison, validate all-feature graphs and every package class, add negative modern and historical isolation fixtures, and document protected release controls. |
| `0.3.0` | Requirements And Standards Ledger | Generate the requirements and source ledger from every admitted algorithm, encoding, extension, and protocol milestone; include RFC 5077, RFC 5705, RFC 5746, RFC 6962 or RFC 9162, RFC 7468, RFC 8410, RFC 5958 or the chosen PKCS#8 authority, RFC 9146 when DTLS 1.2 CID is admitted, RFC 9258, RFC 9266, applicable NIST standards and errata, frozen IANA snapshots, and the final ECDHE-ML-KEM RFC and code points before admission. |
| `0.4.0` | Assurance Harness And Bare-Metal Matrix | Establish first-party mutation and differential harnesses, true bare-metal targets, and pinned external assurance-tool policy without adding third-party crates to repository Cargo manifests. |
| `0.5.0` | Error Alert And Exhaustion Domains | Freeze non-secret error, alert, close, provider-failure, and resource-exhaustion domains; prohibit secret-bearing formatting and ambiguous failure collapse. |
| `0.6.0` | Bounded Numeric And Resource Domains | Introduce checked bounded integers, counts, lengths, sequence numbers, epochs, and immutable resource and work budgets. |
| `0.7.0` | Borrowed Read Cursor | Implement a borrowed read cursor with exact consumption, truncation-at-every-byte coverage, and no indexing panics. |
| `0.8.0` | Transactional Write Cursor | Implement caller-buffer write cursors with transactional encode-or-no-mutation behavior. |
| `0.9.0` | Caller-Owned Workspace And Arena Model | Define caller-owned workspaces and non-overlapping secret, plaintext, transcript, certificate, and output arenas with overlap rules, high-water tracking, and allocation counters. |
| `0.10.0` | Secret Lifetime And Destruction Contract | Define non-cloneable and non-serializable secret ownership, transition, error, cancellation, provider-failure and drop destruction, immediate obsolete-secret cleanup, external-store and accelerator duties, and a mandatory production guarantee for the complete owned memory region. |
| `0.11.0` | Owned-Memory Zeroization Primitive | After explicit unsafe-policy approval, implement the smallest isolated first-party primitive needed to preserve zeroization stores through optimization; define proof obligations, cache and DMA completion duties, MIR, LLVM and assembly evidence for every supported compiler and target, and precise exclusions for registers, copies, dumps, and physical memory. |
| `0.12.0` | Constant-Time Foundation | Implement constant-time equality, choice and mask types, conditional select and swap, fixed-width secret operations, compiler barriers, and rules forbidding secret-dependent control flow, indexing, loop counts, and error timing. |
| `0.13.0` | Provider Capabilities And Opaque Handles | Define all protocol-facing crypto, signature, KEM, AEAD, entropy, clock, path, storage, and pending-operation contracts in upstream no_std interface modules such as brynja-core, with opaque handles, frozen capabilities, transactional installation, exact-operation token binding, and no implicit fallback; brynja-platform only implements downstream contracts. |
| `0.14.0` | Entropy And Secure-Random Contracts | Separate caller-provided raw entropy from initialized secure randomness; type security strength, purpose, retryable and permanent failure, fork and reseed rules, clone prohibition, and test-only providers that production configuration cannot construct. |
| `0.15.0` | Wall And Monotonic Clock Contracts | Define non-interchangeable typed wall time for PKI and typed monotonic time for timers, freshness, tickets, and replay policy with checked arithmetic and explicit unavailable-time behavior. |
| `0.16.0` | Pending Operations And Accelerator Lifecycle | Define resumable provider tokens, certificate, signature and accelerator requests, cancellation, key-handle destruction, retry semantics, backpressure, and failure-atomic state transitions. |
| `0.17.0` | FIPS-Aware Provider Architecture | Freeze approved and non-approved service separation, self-test and permanent-failure hooks, dispatch, service indicators, SSP boundaries, deterministic module-build expectations, operational-environment assumptions, and sealed-provider exclusions without making a validation claim. |
| `0.18.0` | TLS And DTLS Record Framing | Keep record framing independent of protocol selection and fallback; ignore TLSPlaintext legacy_record_version where required, validate TLSCiphertext constants where applicable, preserve bytes, and leave version choice exclusively to typed handshake policy. |
| `0.19.0` | Bounded DER Reader | Implement a non-recursive DER tag, length and value reader with definite, minimal, overflow-safe, depth-, node-, size-, and work-bounded parsing. |
| `0.20.0` | Canonical ASN.1 Primitives | Add canonical ASN.1 integer, bit and octet string, OID, Boolean, string, sequence and set, and time primitives with malformed and non-canonical corpora. |

## Phase 1: First-Party Cryptography, Identity Formats, And PKI

AEADs, import-only RSA signing, and explicit algorithm exclusions pass independent crypto and PKI gates.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.21.0` | SHA-256 | Implement streaming and fixed-message SHA-256 with official vectors, boundary lengths, and exhaustion handling. |
| `0.22.0` | SHA-384 And SHA-512 | Implement SHA-384 and SHA-512 with official vectors and checked length and exhaustion behavior. |
| `0.23.0` | Keccak SHA-3 And SHAKE | Implement Keccak-f[1600], SHA3-256 and SHA3-512, and SHAKE128 and SHAKE256 as the required ML-KEM foundation. |
| `0.24.0` | HMAC | Implement HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with constant-time verification and misuse tests. |
| `0.25.0` | HKDF And TLS Labels | Implement HKDF extract and expand and TLS HKDF-Expand-Label with all input and output limits explicit. |
| `0.26.0` | Portable AES | Implement portable constant-time AES-128 and AES-256 without secret-indexed tables; require layered emitted-code and statistical evidence for every admitted compiler and target. |
| `0.27.0` | GHASH | Implement constant-time GHASH finite-field arithmetic and a bounded incremental interface. |
| `0.28.0` | AES-GCM | Implement AES-GCM seal and open with nonce and usage limits, authenticate ciphertext before any caller-visible decryption, permit only exact in-place or disjoint buffers, reject partial overlap, and leave the complete destination unchanged on authentication failure. |
| `0.29.0` | ChaCha20 | Implement ChaCha20 with checked counters and deterministic exhaustion closure. |
| `0.30.0` | Poly1305 And ChaCha20-Poly1305 | Implement Poly1305 and ChaCha20-Poly1305 with constant-time tag verification, authenticate ciphertext before caller-visible decryption, permit only exact in-place or disjoint buffers, reject partial overlap, and leave the complete destination unchanged on failure. |
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
| `0.43.0` | RSA-PSS Private Operations | Implement blinded fixed-schedule first-party RSA-PSS private operations for strictly validated imported keys, with CRT consistency, fault detection, immediate blinding and intermediate destruction, and external-signer support; v1 does not generate RSA keys. |
| `0.44.0` | Ed25519 | Implement Ed25519 signing and verification with canonical encoding, small-order and malleability rejection, official vectors, and constant-time secret operations. |
| `0.45.0` | Version-One Algorithm Decisions | Freeze explicit v1 admission or exclusion for P-521, Ed448, finite-field DHE, AES-CCM, SHA-1 certificate chains, PKCS1 v1.5 signing, encrypted private-key containers, first-party RSA key generation, ML-DSA, SLH-DSA, and every unimplemented algorithm family. |
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

## Phase 2: Shared Handshake, Internal Sans-I/O, And Modern TLS

Shared handshake ownership, separate negotiation policy, audited engines, and final symmetric routing remain ordered.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.60.0` | Shared Recordless TLS Handshake Boundary | Create an upstream no_std brynja-tls-handshake crate containing the single record-independent TLS 1.3 handshake state machine consumed by brynja-tls and brynja-quic-tls; stream TLS owns records, QUIC owns transport, and DTLS may reuse codecs, transcript, certificate and key-schedule components but retains its own state machine, epochs, fragmentation, and retransmission. |
| `0.61.0` | Internal Sans-I/O Execution Contract | Define an explicitly unstable deterministic Event-to-Action driver for consumed input, output workspace, timers, entropy and time, certificate, signature and accelerator requests, application data, backpressure, resumable operations, path tokens, cancellation, and terminal states. |
| `0.62.0` | TLS Record Protection | Implement TLS record protection, checked sequence exhaustion, inner content-type and padding validation, transactional state changes, and fragmentation boundaries without performing protocol selection. |
| `0.63.0` | TLS 1.3 Handshake Codec | Implement the complete TLS 1.3 handshake codec with duplicate, ordering, extension-context, unknown and GREASE extension, compatibility ChangeCipherSpec, and resource rules. |
| `0.64.0` | Transcript And Key Schedule | Implement transcript and key-schedule states with immediate destruction of obsolete early, handshake, master, exporter, and resumption secrets. |
| `0.65.0` | ClientHello Construction And Offers | Implement bounded ClientHello construction and parsing for supported versions, groups, signature schemes, key shares, GREASE, SNI, ALPN, extension ordering, and exact original-byte preservation. |
| `0.66.0` | HelloRetryRequest And Cookies | Implement HelloRetryRequest validation, transcript message_hash transformation, selected-group rules, cookies, second-ClientHello invariants, and retry resource ceilings. |
| `0.67.0` | TLS Version Negotiation Codec And Policy | Implement shared offer and selection parsing and policy without routing into an engine: servers evaluate one ClientHello, clients evaluate one ServerHello, unknown future offered versions are skipped safely, recognized legacy versions are rejected by policy, highest-version and downgrade-sentinel rules are typed, and exact transcript bytes are preserved. |
| `0.68.0` | TLS 1.3 Authenticated Server Flight | Implement ServerHello through the authenticated server flight, certificate presentation, and the sole ALPN and SNI negotiation implementation. |
| `0.69.0` | Certificate Negotiation And Selection | Implement signature_algorithms_cert, certificate_authorities, oid_filters, certificate and public-key compatibility, bounded identity selection, and deterministic external-signer requests. |
| `0.70.0` | Stapled Status And SCT Transport | Implement status_request and stapled OCSP transport plus bounded SCT transport and handoff to admitted PKI and Certificate Transparency policies. |
| `0.71.0` | Client Authentication And Finished | Implement client authentication, CertificateVerify, Finished, authenticated application-data transition, and explicit rejection of post-handshake authentication for v1. |
| `0.72.0` | Alerts Closure And Cancellation | Complete alerts, close-notify, illegal-message handling, backpressure, cancellation, provider failure, terminal states, and terminal secret and handle destruction. |
| `0.73.0` | Stateful Tickets And Resumption PSKs | Implement stateful cache tickets and resumption PSK binders with protocol-specific cache and identity domains, constant-work unknown-identity handling where possible, single-use pending operations, concurrency and crash-consistency contracts, external-storage secrecy, rotation, and lifetime policy. |
| `0.74.0` | Stateless Ticket Protection | Implement an optional versioned AEAD ticket envelope binding protocol version, suite, SNI, ALPN, client-authentication state, PSK and early-data policy, issue and expiry time, key identifier, rotation generation, and deployment domain with nonce uniqueness and uniform failures. |
| `0.75.0` | External PSKs And PSK Importer | Separate external from resumption PSKs; implement RFC 9258 imported identities and derived imported PSKs with protocol, KDF, context, application, ALPN, and deployment-domain separation; require the importer whenever one provisioned external key could cross TLS, DTLS, QUIC, ALPN, application, or deployment domains; allow raw external PSKs only when callers attest unique provisioning per protocol and deployment context; require hardened psk_dhe_ke by default; perform constant-work unknown-identity and binder handling; type single-use pending lookup operations; and forbid silent psk_ke, cross-domain fallback, or binder-failure fallback. |
| `0.76.0` | Zero-RTT | Implement opt-in zero-RTT with an atomic anti-replay check-and-insert contract, concurrency and crash consistency, single-use pending storage operations, freshness, deterministic rejection, secret lifetime, and application side-effect guidance. |
| `0.77.0` | TLS KeyUpdate | Implement KeyUpdate with traffic-secret transition, immediate obsolete-key destruction, request coalescing policy, and long-lived key and record limits. |
| `0.78.0` | Exporters And TLS-Exporter Channel Binding | Implement the RFC 5705 exporter for TLS 1.2 and the RFC 9846 exporter for TLS 1.3, then admit only the RFC 9266 tls-exporter channel binding with exact label, context, transcript, and protocol-version rules; exclude tls-unique for TLS 1.3 and tls-server-end-point for v1; release outputs only after protocol-specific authorization as typed, non-formatting secrets with explicit ownership, use, and zeroization policy. |
| `0.79.0` | TLS 1.3 Suite Completion | Admit only AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, and ChaCha20-Poly1305/SHA-256 for the initial TLS 1.3 profile. |
| `0.80.0` | TLS 1.3 Conformance And Interoperability | Pass official vectors, truncation and fragmentation matrices, independent peer implementations, state-model and fuzz gates, and provider fault injection. |
| `0.81.0` | TLS 1.3 Audit Gate | Complete an external TLS 1.3 audit and clean remediation retest. |
| `0.82.0` | TLS 1.2 Policy Boundary | Freeze an explicit TLS 1.2 ECDHE-plus-AEAD policy with EMS required and static RSA, CBC, SHA-1 signing, compression, renegotiation, and automatic fallback excluded. |
| `0.83.0` | TLS 1.2 PRF And Key Block | Implement the TLS 1.2 PRF, master secret, EMS master-secret input, key-block expansion, label separation, and length limits. |
| `0.84.0` | TLS 1.2 Record Nonces And Protection | Implement admitted TLS 1.2 AEAD record nonces, additional data, sequence exhaustion, limits, fragmentation, and failure-atomic open. |
| `0.85.0` | TLS 1.2 EMS Transcript Binding | Implement Extended Master Secret transcript selection, session-hash rules, resumption consistency, and mandatory EMS failure behavior. |
| `0.86.0` | TLS 1.2 Signaling And Renegotiation Semantics | Accept TLS_EMPTY_RENEGOTIATION_INFO_SCSV only as initial secure-renegotiation signaling, accept empty renegotiation_info where required, emit inappropriate_fallback for TLS_FALLBACK_SCSV only when a higher enabled version exists, apply downgrade sentinels, and reject every subsequent renegotiation attempt. |
| `0.87.0` | TLS 1.2 ECDHE State Machines | Implement isolated ECDHE_ECDSA and ECDHE_RSA TLS 1.2 client and server state machines entered only by the one-pass modern selector. |
| `0.88.0` | TLS 1.2 Suite Completion | Admit only the six ECDSA and RSA combinations over AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305. |
| `0.89.0` | TLS 1.2 Resumption And Interoperability | Complete TLS 1.2 stateful and stateless resumption, protocol-specific tickets, extension hardening, interop, and downgrade corpora. |
| `0.90.0` | TLS 1.2 Audit Gate | Complete a separate TLS 1.2 external audit while retaining explicit configuration and independent disablement. |
| `0.91.0` | Integrated One-Pass Modern TLS Router | After both TLS 1.3 and hardened TLS 1.2 engines exist, integrate symmetric one-pass routing: one server ClientHello or one client ServerHello selects exactly one highest acceptable offered engine, validates downgrade sentinels, transfers original transcript bytes and version-domain state once, and never retries another engine or crosses credentials, tickets, PSKs, caches, or secrets after failure. |
| `0.92.0` | Modern Multi-Version Routing Audit Gate | Complete client and server cross-version, downgrade, unknown-version, transcript-preservation, domain-separation, no-retry, interoperability, differential, fuzz, and external audit campaigns for the integrated TLS router. |

## Phase 3: QUIC TLS, DTLS, And Post-Quantum Work

QUIC resumption is transport-aware, DTLS early data is excluded for v1, CID behavior is version-specific, and hybrid policy is explicit.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.93.0` | QUIC Ownership And Encryption Levels | Define distinct QUIC encryption levels and secret install and discard events; consume ordered bytes supplied by QUIC and exclude packet processing, offsets, retransmission, packet numbers, loss recovery, Retry, key phase, TLS records, and TLS KeyUpdate. |
| `0.94.0` | QUIC-Specific TLS Profile | Implement the recordless QUIC TLS profile with no ChangeCipherSpec, EndOfEarlyData, TLS KeyUpdate, or record compatibility mode; enforce handshake-message legality per encryption level, TLS alert to QUIC CRYPTO_ERROR mapping, required ALPN negotiation and failure, and typed handshake and application secret events. |
| `0.95.0` | QUIC Key-Derivation Boundary | Have TLS emit typed handshake and application traffic secrets; optionally derive quic key, quic iv and quic hp in brynja-quic-tls; keep version-specific Initial salts and secrets, packet protection, Retry integrity, key phase, and quic ku in the QUIC transport; verify all admitted derivations with RFC 9001 vectors. |
| `0.96.0` | QUIC Transport Parameters | Implement bounded syntactic transport-parameter parsing and transcript binding while exposing typed values for QUIC-owned semantic enforcement. |
| `0.97.0` | QUIC Sans-I/O Handshake | Implement per-level TLS handshake input and output, alerts, pending providers, bounded future-level data, traffic-secret events, and deterministic rejection of late data. |
| `0.98.0` | QUIC Resumption And Zero-RTT Profile | Distinguish TLS handshake completion from QUIC handshake confirmation; emit typed completion, confirmation and key-discard events; deliver NewSessionTicket only after handshake completion; require max_early_data_size 0xffffffff; bind remembered QUIC transport parameters, ALPN and application state to tickets; map invalid early-data values to the correct QUIC error; expose deterministic acceptance and rejection; enforce ticket privacy and non-reuse policy; and leave the transport in control of zero-RTT byte quantity. |
| `0.99.0` | Optional QUIC CRYPTO Reassembly Helper | Provide an explicitly optional bounded CRYPTO-offset reassembly helper with conflict and exhaustion handling that is not used implicitly and does not implement retransmission or loss recovery. |
| `0.100.0` | QUIC Conformance And Audit | Pass RFC 9001 vectors plus loss, reorder, discard, 0-RTT, key-derivation, interoperability, ownership-boundary, and external review gates. |
| `0.101.0` | DTLS Path Identity Contract | Introduce an opaque caller-provided path token binding cookie state, amplification accounting, CID routing, migration, PMTU, timers, and datagram metadata so packets cannot transfer validation or budgets between paths. |
| `0.102.0` | DTLS Version Negotiation Codec And Policy | Implement shared DTLS offer and selection parsing and policy without routing into an engine: one ClientHello or ServerHello is evaluated, unknown future versions are skipped, recognized legacy versions are rejected, the highest configured version and downgrade policy are typed, and transcript plus opaque path identity are preserved. |
| `0.103.0` | DTLS Unified Headers And Epochs | Implement DTLS 1.3 unified headers, epochs, compact sequence reconstruction, AEAD nonce construction, and checked sequence exhaustion. |
| `0.104.0` | DTLS Record-Number Encryption | Implement record-number encryption and authenticated reconstruction-failure handling with official vectors and no replay-window mutation before authentication. |
| `0.105.0` | DTLS Replay And Epoch-Key Lifetimes | Implement fixed replay windows across epoch transitions, bounded previous and future retention, transactional key installation, and immediate obsolete-key destruction. |
| `0.106.0` | DTLS 1.2 Connection IDs | Implement RFC 9146 DTLS 1.2 connection-ID negotiation and its version-specific record construction with opaque path-token routing, privacy, replay, rebinding, migration, PMTU, and amplification invariants; do not accept DTLS 1.3 CID-update messages. |
| `0.107.0` | DTLS 1.3 Connection-ID Updates | Implement DTLS 1.3 connection IDs, NewConnectionId and RequestConnectionId post-handshake updates with bounded active and retired IDs, opaque path-token routing, collision, privacy, replay, migration, rotation, PMTU, and amplification invariants. |
| `0.108.0` | DTLS Fragmentation And Reassembly | Implement caller-owned bounded handshake fragmentation and reassembly with canonical transcript messages and overlap and conflicting-fragment rejection. |
| `0.109.0` | DTLS Flights ACKs And Timers | Implement deterministic flights, ACK processing, typed timer actions, cached retransmission, checked backoff, congestion limits, and path-token ownership. |
| `0.110.0` | DTLS Address Validation And Amplification Defense | Implement path-bound cookies, address validation, amplification budgets, deterministic PMTU policy, and cheap rejection before expensive cryptography. |
| `0.111.0` | DTLS 1.3 State Machines | Complete DTLS 1.3 client and server states, key updates, duplicate idempotence, terminal cleanup, and provider cancellation. |
| `0.112.0` | DTLS 1.3 Early-Data Exclusion | Reject DTLS 1.3 early data for v1: never offer or accept it, never derive or retain epoch 1 application-data keys, reject EndOfEarlyData on wire and in transcript, and test reordered or duplicated early records, address validation, amplification accounting, ticket policy, and deterministic peer failure independently from record replay. |
| `0.113.0` | Hardened DTLS 1.2 | Implement DTLS 1.2 using only the admitted TLS 1.2 ECDHE-plus-AEAD profile and isolated epoch, replay, ticket, path, and downgrade state. |
| `0.114.0` | Integrated One-Pass DTLS Router | After both DTLS engines exist, integrate symmetric one-pass routing: one server ClientHello or one client ServerHello enters exactly one highest acceptable offered engine, preserves transcript and opaque path state, validates downgrade policy, and never retries or crosses credentials, tickets, epochs, replay windows, CIDs, or secrets after failure. |
| `0.115.0` | DTLS Conformance And Audit | Pass loss, reorder, duplicate, fragmentation, replay, path-token, CID, version-selection, hostile-load, fuzz, interoperability, and external audit gates. |
| `0.116.0` | ML-KEM Arithmetic And Encoding | Implement ML-KEM polynomial, NTT, sampling, and canonical encoding and decoding foundations. |
| `0.117.0` | ML-KEM Key Generation And Encapsulation | Implement ML-KEM-512, ML-KEM-768 and ML-KEM-1024 key generation and encapsulation with FIPS 203, errata, randomness, stack, and applicable SP 800-227 checks. |
| `0.118.0` | ML-KEM Decapsulation And Implicit Rejection | Implement constant-time ML-KEM decapsulation and implicit rejection with malformed-ciphertext, failure-path, and side-channel campaigns. |
| `0.119.0` | Standard Hybrid Groups | Implement only final standardized X25519MLKEM768, P256MLKEM768, and P384MLKEM1024 encodings, component order, lengths, identifiers, and combiner behavior. |
| `0.120.0` | Hybrid Protocol Integration | Implement explicit HybridRequired and HybridPreferred policies: Required fails if no admitted hybrid is negotiated; Preferred may select an offered admitted classical group through ordinary one-pass negotiation when the peer lacks hybrids; every selected hybrid must complete both components and partial failure never degrades to its classical component. |
| `0.121.0` | PQ Standards And Audit Gate | Complete PQ external review and standards freeze; keep ML-DSA and SLH-DSA excluded from v1 authentication unless a separately reviewed final standard, TLS mapping, and interoperability milestone is added. |

## Phase 4: FIPS Module Instantiation, Validation, And TLS Profile

Architecture is frozen before implementation; exact artifact identity is frozen only after all module components and self-tests exist. Connection failure remains distinct from the module catastrophic-failure latch.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.122.0` | FIPS Module Architecture Freeze | Freeze the architectural boundary, dependency allowlist, approved and non-approved services, ports, roles, SSP inventory, operational-environment design, build-reproducibility contract, and downstream optional-module constraints without claiming or freezing an exact binary, source identity, dispatch table, dependency closure, or validation artifact. |
| `0.123.0` | SP 800-90 Entropy And DRBG Boundary | Select SP 800-90A DRBGs; validate SP 800-90B entropy sources and health tests; satisfy SP 800-90C construction rules; and define prediction resistance, personalization, fork, reseed, security-strength, and catastrophic-failure semantics. |
| `0.124.0` | Approved Provider And Service Indicator | Implement the sealed approved-only provider and unambiguous per-service approved indicator with no additive fips feature or construction before self-test success. |
| `0.125.0` | SSP Lifecycle And Zeroization Services | Define SSP entry, output, storage, high-water lifetime, external storage, accelerator handle, cache and DMA completion, and zeroization services with completion indications and secret-free status events. |
| `0.126.0` | FIPS Self-Tests And Failure Latch | After the final DRBG, provider, SSP and algorithm implementations are linked, implement module integrity, algorithm and DRBG KATs, pairwise-consistency and conditional tests, permanent failure latching, and deterministic fault-injection evidence over the complete module contents. |
| `0.127.0` | Exact FIPS Module Artifact Freeze | After the DRBG, approved provider, service indicators, SSP services, algorithms, and self-tests are final and linked, instantiate and freeze the exact binary, source identity, build inputs, compiler and linker configuration, symbols, dispatch tables, dependency closure, operational-environment mappings, and reproducible artifact hashes; all ACVTS, CAVP, CMVP, and later closure evidence must name this exact artifact. |
| `0.128.0` | ACVTS And CAVP Evidence | Complete ACVTS and CAVP campaigns for every approved implementation, dispatch path, parameter set, and operational environment. |
| `0.129.0` | CMVP Submission Artifacts | Produce the CMVP Security Policy, finite-state model, service and SSP inventory, entropy assessment, source-to-object trace, and reproducible module artifacts. |
| `0.130.0` | Accredited FIPS Evaluation | Complete accredited-lab FIPS 140-3 evaluation, remediation, retest, and certificate and caveat recording; make no validation claim before issuance. |
| `0.131.0` | Boundary And Package Audit | Complete the final modern, historical, experimental, and FIPS dependency-boundary, symbol, dispatch, feature, and package-content audit. |
| `0.132.0` | Approved-Only TLS Operating Profile | Implement a facade approved-only connection profile enforcing minimum key and security strengths, admitted suite, group, signature and certificate combinations, approved entropy and key-generation provenance, resumption, external PSK and zero-RTT policy, and aggregated per-service indicators; invoking a non-approved service terminates the connection and invalidates its approved configuration claim, while the module permanent latch remains reserved for FIPS-defined integrity, self-test, and catastrophic failures. |

## Phase 5: Optional Modules, Composition, Stable Integration, Assurance, And General Availability

Receive and send compression, post-validation closure, and cross-feature composition complete before public API freeze.

| Version | Milestone | Exclusive scope and completion context |
| --- | --- | --- |
| `0.133.0` | Operational State Rotation | Complete session cache, stateless ticket-key and resumption-PSK rotation, anti-replay storage, certificate and private-key rotation, trust-anchor and CT log-list updates, and transactional failure recovery. |
| `0.134.0` | Record Size Limit | Implement Record Size Limit negotiation and enforcement with directional limits, fragmentation, buffering, peer-violation, and interoperability tests. |
| `0.135.0` | Raw Public Keys | Implement Raw Public Keys with a dedicated pinning and trust-provider contract, identity and rotation policy, negotiation, and proof that RPK never silently bypasses X.509 requirements. |
| `0.136.0` | HPKE KEM And Context Foundation | Implement HPKE DHKEM X25519 and P-256 context derivation, labeled HKDF, public-key validation, domain separation, and bounded contexts strictly downstream of validated provider ports, with no symbol, dependency, feature, dispatch, build-input, or source change to a validated FIPS module. |
| `0.137.0` | HPKE Base Mode | Implement RFC 9180 HPKE base mode with admitted AEADs, sequence and nonce exhaustion, seal and open failure atomicity, official vectors, and independent differential tests. |
| `0.138.0` | ECH Configuration Bootstrap And Suite Selection | Keep DNS, SVCB, HTTPS resolution, network access, and caching caller-owned; accept bounded ECHConfigList bytes with authenticated origin metadata, cache generation, and lifetime; implement bounded ECHConfig parsing, version and suite selection, public-name policy, key configuration, GREASE inputs, origin binding, retry-configuration precedence, and stale-generation replacement without hidden I/O or global cache state. |
| `0.139.0` | ECH Client Construction | Implement client inner and outer ClientHello construction, outer-extension references, AAD inputs, GREASE, padding, transcript preservation, and configuration and resource policy. |
| `0.140.0` | ECH Server Opening And Acceptance | Implement server configuration lookup, HPKE opening, inner and outer consistency checks, acceptance confirmation, identity selection, uniform rejection, and no fallback to attacker-modified state. |
| `0.141.0` | ECH HRR Retry And Rotation | Implement ECH HelloRetryRequest interaction, retry configurations, configuration rotation, second-ClientHello invariants, downgrade detection, and client and server interoperability. |
| `0.142.0` | Delegated Credentials | Implement delegated credentials as an independent optional module with authorization, lifetime, signature, selection, revocation interaction, and downgrade policy. |
| `0.143.0` | Certificate Compression Receive Provider | Treat decompression as strictly bounded hostile pre-authentication work; retain wire CompressedCertificate bytes for the transcript, pass decompressed Certificate bytes to PKI, release no identity or application data before decompression, X.509, CertificateVerify and Finished succeed, and terminate on provider error, overrun, short output, trailing compressed data, or algorithm mismatch. |
| `0.144.0` | Certificate Compression Send Artifacts | Support sending compressed server and client-authentication certificates through caller-supplied precompressed artifacts verified at configuration by decompressing and byte-comparing with the complete canonical Certificate message, including certificate_request_context and every per-certificate extension; advertise only algorithms with a usable receive provider, send only peer-advertised algorithms, preserve transcript bytes, and enforce exact algorithm, input, output, identity, request-context, extension, and rotation binding. |
| `0.145.0` | Validated FIPS Closure Preservation Gate | After HPKE, ECH and every optional module exists, prove they remain downstream of validated provider ports and cannot add module symbols, dependencies, features, dispatch entries, build inputs, non-approved algorithms, or source changes; any module change invalidates prior artifact identity and validation claims and requires a new validation line. |
| `0.146.0` | Optional-Feature Composition Gate | Define and test ECH with tickets, resumption, imported and raw external PSKs, zero-RTT, inner identity, ALPN, certificates, client authentication and delegated credentials; bind every ECH resumption ticket to the authenticated inner identity and applicable ECH policy and configuration generation, rejecting stale or mismatched tickets without outer-identity fallback; test RPK with delegated credentials and client authentication; compression with RPK, delegated credentials and client certificates; Record Size Limit with large certificates and DTLS fragmentation; protocol applicability; approved-only exclusions; compile-time incompatible typestates; and cross-feature cancellation, rotation, transcript, storage and resource exhaustion. |
| `0.147.0` | Facade Configuration Typestates | After every planned v1 optional module has exercised the internal effects model, freeze facade typestates for exact versions, integrated one-pass routing, suites, trust, RPK, ECH, delegated credentials, compression, resources, revocation, PSK, zero-RTT, Certificate Transparency, FIPS profile, and providers with no raw crypto re-export or legacy range. |
| `0.148.0` | Stable Sans-I/O API | After every planned v1 optional module has exercised it, freeze the deterministic client and server Event-to-Action API including ECH key and configuration lookup, decompression, RPK trust, delegated-credential selection, path tokens, pending providers, consumed and produced counts, backpressure, cancellation, and compile-fail exhaustiveness tests. |
| `0.149.0` | Caller-Provided Host Capability Integration | Keep protocol-facing contracts upstream and require caller-provided entropy and OS integration for v1; provide no built-in OS entropy FFI. Supply reviewed examples for safe std clocks, transport and storage and for caller or kernel entropy, while documenting that any future Windows, macOS, BSD, mobile, or bare-metal unsafe adapter requires its own crate, versioned unsafe and FFI milestone, audit, and platform evidence. |
| `0.150.0` | Zero-Allocation And Resource Proof | Prove the caller-owned zero-allocation profile with exact workspace sizes, non-overlapping arenas, stack ceilings, concurrency limits, and hostile-load budgets. |
| `0.151.0` | Aesynx ABI And Emulator Qualification | Make the stable Aesynx adapter contract a v1 requirement and pass an executable target-ABI or emulator harness for entropy, randomness, time, transport, storage, acceleration, boot-to-handshake, and lifecycle behavior; allow real-hardware qualification after v1 without weakening the contract. |
| `0.152.0` | Formal Harnesses | Complete Kani or equivalent harnesses for cursors, lengths, state reachability, exhaustion, replay, transactional transitions, one-pass selectors, and secret-release invariants using pinned external tools. |
| `0.153.0` | External-Process Fuzz And Differential Campaign | Do not use cargo-fuzz or libfuzzer-sys; drive first-party corpus and stdin harness binaries with pinned external process-level mutation and instrumentation, deterministic replay, differential corpora, and crash minimization without third-party repository crates. |
| `0.154.0` | Memory And Side-Channel Evidence | Complete Miri and sanitizer evidence plus compiler and target constant-time assembly, owned-region zeroization-store survival, cache and branch, and statistical side-channel matrices. |
| `0.155.0` | Sustained Platform And Hostile-Load Qualification | Sustain Linux, Windows, macOS, BSD, Android, iOS, bare-metal, and Aesynx ABI or emulator qualification under concurrency, provider failure, resource exhaustion, and hostile load. |
| `0.156.0` | Consolidated External Audits | Complete exact-commit external crypto, PKI, TLS, DTLS, QUIC, PQ, FIPS-boundary and profile, optional-module, zeroization, and systems-integration audits. |
| `0.157.0` | Audit Remediation And Clean Retest | Remediate every admitted finding, add permanent regressions, and obtain clean independent retests with no unresolved critical or high findings. |
| `0.158.0` | Public API Requirements And Documentation Freeze | Freeze public APIs, features, package inventory, requirements ledger, admitted algorithms and extensions, migration guidance, deployment profiles, incident procedures, limitations, and non-goals. |
| `0.159.0` | Clean-Room Release Rehearsal | Pass reproducible clean-room builds, package installation, artifact comparison, rollback, key-compromise, incident, and disaster-recovery exercises. |
| `1.0.0-rc.1` | Exact Production Candidate | Build final artifacts once and freeze source, compiler, flags, archives, SBOM, checksums, provenance, documentation, and the pentested exact commit. |
| `1.0.0` | First Serious Production-Ready Brynja TLS Release | Promote only the byte-identical approved candidate without rebuild, source change, metadata drift, or expanded capability claim. |

## Independent Historical Package Sequence

Each historical crate uses its own SemVer `0.N.0` line. TLS 1.1, TLS 1.0,
SSL 3, SSL 2, WTLS, PCT, and SNP separately pass source, codec, state,
primitive, client, optional server, containment, and external audit/pentest
stages. SSL 1 remains research-only and unpublished. Historical work never
blocks or inherits modern `1.0.0`.

| Historical stage | Exclusive scope |
| --- | --- |
| `H0.1.0` | Authenticate sources and rights, track errata, publish conspicuous insecurity warnings, and define the protocol-specific threat model. |
| `H0.2.0` | Implement only the protocol-specific bounded wire codec. |
| `H0.3.0` | Implement isolated state with no shared modern configuration, negotiation, credentials, caches, tickets, paths, or fallback. |
| `H0.4.0` | Bind audited shared primitives and isolate required weak primitives in a historical-only crypto package. |
| `H0.5.0` | Complete controlled client-only interoperability and containment evidence. |
| `H0.6.0` | Add server interoperability only when separately justified, with amplification and hostile-load review. |
| `H0.7.0` | Require separate listeners, paths, policy, credentials, storage, diagnostics, and process containment. |
| `H0.8.0` | Complete a protocol-specific external audit and pentest and verify every warning and non-fallback property. |
