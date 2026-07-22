# Brynja Version Plan

Status: revised planning sequence

This document defines the intended order and scope of Brynja releases through
`1.0.0`. Each version is an exclusive implementation stop: it must finish and
verify only its named boundary before adjacent work begins. A version may be
split into smaller reviewable patches or milestones, but unrelated scopes must
not be merged merely to preserve numbering.

[RELEASE_PLAN.md](RELEASE_PLAN.md) remains the normative source for each
release's Goal, Deliverables, Verification, and Exit criteria. Its existing
numbering predates this revision. Before implementation beyond `0.1.0`, it must
be reconciled one-for-one with this plan and its structural validators must be
strengthened. Until that reconciliation is committed, the stricter requirement
or gate in either document applies.

## Admission Rules For Every Version

Every milestone must retain `no_std` production packages, zero shipped
third-party dependencies, bounded hostile-input processing, explicit secret
lifetimes, negative and adversarial tests, supported Rust and target evidence,
an SBOM, clean CI, and an exact-commit security review. Capability claims are
limited to completed, tested, and independently reviewed scope.

The production facade must never depend on historical protocol packages. FIPS
is an artifact and operational-environment claim, not a Cargo feature. PQ hybrid
groups remain experimental until their standards and code points are final.

## Phase 0: Repository, Boundaries, And Wire Foundations

This phase turns repository policy into executable evidence, then establishes
the bounded types and codecs on which every parser and state machine depends.

| Version | Exclusive scope and completion context |
| --- | --- |
| `0.1.0` | Preserve the existing workspace foundation with no cryptographic or protocol security claim. |
| `0.2.0` | Fix exact-HEAD pentest comparison, validate all-feature graphs and every package class, add negative isolation fixtures, and document protected release controls. |
| `0.3.0` | Build the requirements ledger for RFC 9846, RFC 5280, RFC 9001, RFC 9147, applicable NIST standards and errata, and frozen IANA snapshots; map every normative requirement. |
| `0.4.0` | Establish repository-only mutation and differential harnesses, true bare-metal targets, and separate production-versus-assurance dependency policies without adding shipped dependencies. |
| `0.5.0` | Freeze non-secret error, alert, close, and resource-exhaustion domains; prohibit secret-bearing formatting and ambiguous failure collapse. |
| `0.6.0` | Introduce checked bounded integers, counts, lengths, sequence numbers, epochs, and immutable resource budgets. |
| `0.7.0` | Implement a borrowed read cursor with exact consumption, truncation-at-every-byte coverage, and no indexing panics. |
| `0.8.0` | Implement caller-buffer write cursors with transactional encode-or-no-mutation behavior. |
| `0.9.0` | Define caller-owned workspaces and scratch regions, overlap rules, high-water tracking, and allocation counters. |
| `0.10.0` | Define secret ownership and destruction types, redaction, cancellation behavior, immediate lifetime transitions, and an explicitly approved zeroization strategy. |
| `0.11.0` | Define crypto, signature, KEM, and AEAD capability traits with opaque key handles and frozen provider capabilities. |
| `0.12.0` | Separate TLS and DTLS record framing codecs and make modern parsers reject unknown or legacy versions deterministically. |
| `0.13.0` | Implement a non-recursive DER tag/length/value reader with definite, minimal, overflow-safe, depth-, node-, and work-bounded parsing. |
| `0.14.0` | Add canonical ASN.1 integer, bit/octet string, OID, Boolean, string, sequence/set, and time primitives with malformed and non-canonical corpora. |

## Phase 1: First-Party Cryptography And PKI

Hash and sponge foundations precede KDFs and PQ work. TLS cannot consume the
cryptographic substrate until its dedicated audit gate passes; PKI likewise
receives its own adversarial and external review before handshake admission.

| Version | Exclusive scope and completion context |
| --- | --- |
| `0.15.0` | Implement streaming and fixed-message SHA-256 with official vectors, boundary lengths, and exhaustion handling. |
| `0.16.0` | Implement SHA-384 and SHA-512 with official vectors and checked length/exhaustion behavior. |
| `0.17.0` | Implement Keccak-f[1600], SHA3-256/512, and SHAKE128/256 as the required ML-KEM foundation. |
| `0.18.0` | Implement HMAC-SHA-256/384/512 with constant-time verification and misuse tests. |
| `0.19.0` | Implement HKDF extract/expand and TLS HKDF-Expand-Label with all input and output limits explicit. |
| `0.20.0` | Implement portable constant-time AES-128/256 without secret-indexed tables; require emitted-code and statistical evidence. |
| `0.21.0` | Implement constant-time GHASH finite-field arithmetic and a bounded incremental interface. |
| `0.22.0` | Implement AES-GCM seal/open with nonce and usage limits and no plaintext release before authentication. |
| `0.23.0` | Implement ChaCha20 with checked counters and deterministic exhaustion closure. |
| `0.24.0` | Implement Poly1305 and ChaCha20-Poly1305 with constant-time tag verification and withheld unauthenticated plaintext. |
| `0.25.0` | Implement fixed-limb RSA/ECC arithmetic with no attacker-selected allocation, normalization schedule, or limb count. |
| `0.26.0` | Implement X25519 using a fixed ladder, low-order handling, and explicit non-FIPS classification. |
| `0.27.0` | Implement P-256 ECDH and ECDSA, complete point validation, and an explicit deterministic/randomized nonce policy. |
| `0.28.0` | Implement P-384 ECDH and ECDSA with separate vectors, side-channel evidence, and review. |
| `0.29.0` | Implement strict RSA public-key decoding and RSA-PSS verification with unambiguous parameters and modulus/exponent policy. |
| `0.30.0` | Implement blinded, fixed-schedule RSA-PSS private operations and CRT consistency checks, or freeze an external-signer-only production scope. |
| `0.31.0` | Freeze signature-scheme negotiation and the certificate/public-key compatibility matrix. |
| `0.32.0` | Complete independent cryptographic-substrate review and remediate every admitted finding before TLS consumption. |
| `0.33.0` | Decode X.509 Certificate, TBSCertificate, and SPKI while preserving the exact original signed byte slice. |
| `0.34.0` | Validate SAN/service identity, wildcards, IP and URI names, critical extensions, and duplicate-extension rejection. |
| `0.35.0` | Build bounded deterministic paths using caller-supplied pools, loop detection, and hard depth/candidate/work limits. |
| `0.36.0` | Complete RFC 5280 validation for signatures, validity, path length, KU/EKU, basic/name constraints, policy, algorithms, and trust anchors. |
| `0.37.0` | Validate base, delta, and indirect CRLs with issuer, freshness, distribution-point, entry, and work ceilings. |
| `0.38.0` | Validate stapled/offline OCSP responses, responder authorization, freshness, nonce, matching, and explicit hard/soft-fail policy. |
| `0.39.0` | Complete PKI adversarial, differential, and fuzz campaigns plus an external PKI audit and remediation gate. |

## Phase 2: Modern TLS 1.3 And Explicit TLS 1.2

TLS 1.3 is completed and audited first. TLS 1.2 is a separately selectable,
hardened modern compatibility profile; it is never an automatic retry target
and cannot name CBC, static RSA, SHA-1 signing, compression, or renegotiation.

| Version | Exclusive scope and completion context |
| --- | --- |
| `0.40.0` | Implement TLS record protection, checked sequence exhaustion, inner content-type/padding validation, and fragmentation boundaries. |
| `0.41.0` | Implement the complete TLS 1.3 handshake codec with duplicate, ordering, and extension-context rules. |
| `0.42.0` | Implement transcript and key-schedule states with immediate destruction of obsolete early, handshake, master, exporter, and resumption secrets. |
| `0.43.0` | Implement ClientHello, versions, groups, signatures, key shares, HelloRetryRequest, cookies, and downgrade invariants. |
| `0.44.0` | Implement ServerHello through the authenticated server flight, certificate selection, ALPN, and SNI policy. |
| `0.45.0` | Implement client authentication, CertificateVerify, Finished, and the authenticated application-data transition. |
| `0.46.0` | Complete alerts, close-notify, illegal-message handling, cancellation, terminal states, and terminal secret destruction. |
| `0.47.0` | Implement session tickets and PSK binders with protocol-specific ticket-key, cache, and rotation domains. |
| `0.48.0` | Implement opt-in 0-RTT with an anti-replay store contract, freshness, deterministic rejection, and side-effect guidance. |
| `0.49.0` | Implement TLS KeyUpdate, exporters, channel binding, and long-lived key/record usage limits. |
| `0.50.0` | Admit all three TLS 1.3 suites: AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, and ChaCha20-Poly1305/SHA-256. |
| `0.51.0` | Pass official vectors, truncation/fragmentation matrices, two independent peer implementations, and state-model/fuzz gates. |
| `0.52.0` | Complete an external TLS 1.3 audit and clean remediation retest. |
| `0.53.0` | Freeze the explicit TLS 1.2 ECDHE+AEAD policy with EMS required and all weak or ambiguous constructions excluded. |
| `0.54.0` | Implement the TLS 1.2 PRF, record nonces, EMS transcript binding, downgrade sentinel, and secure renegotiation/SCSV rejection rules. |
| `0.55.0` | Implement isolated ECDHE_ECDSA and ECDHE_RSA TLS 1.2 client/server state machines. |
| `0.56.0` | Admit only the six ECDSA/RSA combinations over AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305. |
| `0.57.0` | Complete TLS 1.2 resumption, ticket isolation, extension hardening, interop, and downgrade corpora. |
| `0.58.0` | Complete a separate TLS 1.2 external audit; retain explicit configuration and independent disablement. |

## Phase 3: QUIC TLS, DTLS, And Post-Quantum Work

QUIC receives TLS handshake bytes and secrets but never a TLS record layer or
TLS retransmission. DTLS owns bounded replay, reassembly, flight, timer, and
amplification state. ML-KEM follows SHA-3 and enters protocol integrations only
through exact standardized hybrid groups.

| Version | Exclusive scope and completion context |
| --- | --- |
| `0.59.0` | Define distinct QUIC encryption-level and secret-install/discard types; forbid TLS versions below 1.3 and TLS KeyUpdate. |
| `0.60.0` | Implement strict QUIC transport-parameter parsing, validation, and transcript binding. |
| `0.61.0` | Implement QUIC Sans-I/O handshake actions, ordered CRYPTO offsets, bounded future-level buffering, and alert mapping. |
| `0.62.0` | Pass QUIC vectors plus loss, reorder, discard, 0-RTT, interoperability, and external review gates. |
| `0.63.0` | Implement DTLS epochs, compact headers, sequence reconstruction, AEAD nonces, and fixed authenticated replay windows. |
| `0.64.0` | Implement caller-owned bounded fragmentation/reassembly with overlap and conflicting-fragment rejection. |
| `0.65.0` | Implement deterministic flights, ACKs, typed timer actions, cached retransmission, backoff, and congestion limits. |
| `0.66.0` | Implement cookies, address validation, amplification budgets, and deterministic PMTU/backoff policy. |
| `0.67.0` | Complete DTLS 1.3 client/server states, epoch retention, exhaustion closure, and protocol-specific key updates. |
| `0.68.0` | Implement hardened DTLS 1.2 using only the admitted TLS 1.2 ECDHE+AEAD profile. |
| `0.69.0` | Pass DTLS loss/reorder/duplicate, fuzz, interoperability, hostile-load, and external audit gates. |
| `0.70.0` | Implement ML-KEM polynomial, NTT, sampling, and canonical encoding/decoding foundations. |
| `0.71.0` | Implement ML-KEM-512/768/1024 key generation and encapsulation with FIPS 203 and applicable SP 800-227 checks. |
| `0.72.0` | Implement constant-time ML-KEM decapsulation and implicit rejection with malformed-ciphertext and side-channel campaigns. |
| `0.73.0` | Implement only the exact predefined X25519MLKEM768, P256MLKEM768, and P384MLKEM1024 group encodings and combiner order. |
| `0.74.0` | Complete hybrid TLS/DTLS/QUIC resource, fragmentation, downgrade, transcript-binding, and interoperability gates. |
| `0.75.0` | Complete PQ external review and standards freeze; admit final RFC groups or keep draft work experimental and outside the GA compatibility promise. |

## Phase 4: FIPS Artifact Boundary And Historical Isolation

FIPS work defines and validates a narrow exact-build cryptographic module; PKI
and protocol state machines stay outside it. Passing vectors or CAVP alone must
never be described as FIPS 140-3 validation. Historical engines advance on
independent package versions and do not block the modern line.

| Version | Exclusive scope and completion context |
| --- | --- |
| `0.76.0` | Freeze the FIPS module/artifact boundary, exact operational environments, ports, services, roles, SSP inventory, build inputs, and non-approved exclusions. |
| `0.77.0` | Implement a sealed approved-only provider and unambiguous per-service approved indicator; do not expose an additive `fips` feature. |
| `0.78.0` | Implement integrity, CAST/KAT, pairwise-consistency, permanent failure latch, and deterministic fault-injection evidence. |
| `0.79.0` | Define SSP entry, output, storage, lifetime, and zeroization services with secret-free auditable status events. |
| `0.80.0` | Define the SP 800-90 entropy/DRBG boundary, health tests, reseed/failure behavior, and platform entropy evidence. |
| `0.81.0` | Complete ACVTS/CAVP campaigns for every approved implementation and parameter set. |
| `0.82.0` | Produce the CMVP Security Policy, finite-state model, source-to-object trace, and reproducible module artifacts. |
| `0.83.0` | Complete accredited-lab FIPS 140-3 evaluation, remediation, retest, and certificate/caveat recording; make no validation claim before issuance. |
| `0.84.0` | Complete the final modern/historical/FIPS dependency-boundary and package-content audit. |

### Independent Historical Package Sequence

`H0.N.0` below is planning shorthand: each historical crate uses its own normal
SemVer `0.N.0` release and never inherits the facade version. Repeat the line
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
| `H0.8.0` | Complete a protocol-specific external audit/pentest and verify all publication warnings and non-fallback properties. |

## Phase 5: Stable Integration, Assurance, And General Availability

Only after the cryptographic, PKI, protocol, isolation, and FIPS boundaries are
settled does Brynja freeze its application-facing Sans-I/O interface. The final
sequence gathers sustained multi-platform evidence, external reviews, clean
retests, and byte-identical release artifacts.

| Version | Exclusive scope and completion context |
| --- | --- |
| `0.85.0` | Freeze facade typestates for exact modern versions, suites, trust, identity, resources, revocation, and 0-RTT policy; expose no raw crypto re-export. |
| `0.86.0` | Freeze the deterministic Sans-I/O client/server `Event -> Action` contract, backpressure, cancellation, pending crypto, and compile-fail misuse suite. |
| `0.87.0` | Add host adapters for OS entropy, secure randomness, separate wall/monotonic clocks, and transport/storage examples plus async guidance. |
| `0.88.0` | Prove the zero-allocation profile with caller-owned buffers, exact workspace sizes, stack ceilings, concurrency limits, and hostile-load budgets. |
| `0.89.0` | Qualify the Aesynx target and its entropy/time/transport/accelerator adapters with boot-to-handshake and lifecycle tests when the target is available. |
| `0.90.0` | Complete session cache, ticket-key rotation, anti-replay storage, certificate rotation, and trust-anchor rotation contracts. |
| `0.91.0` | Complete ALPN, SNI, record-size-limit, raw public keys, exporters, and channel-binding behavior in bounded optional modules. |
| `0.92.0` | Complete ECH, delegated credentials, and certificate compression as independently bounded optional modules, admitting only finalized standards. |
| `0.93.0` | Complete Kani proofs for cursors, lengths, state reachability, exhaustion, replay windows, and secret-release invariants. |
| `0.94.0` | Complete isolated parser/state fuzzing, deterministic mutation, differential corpora, and crash minimization without adding shipped dependencies. |
| `0.95.0` | Complete Miri/sanitizer/UB evidence and compiler/target constant-time assembly plus statistical side-channel matrices. |
| `0.96.0` | Sustain Linux, Windows, macOS, BSD, mobile, bare-metal, and available Aesynx qualification under concurrency and hostile load. |
| `0.97.0` | Complete exact-commit external crypto, PKI, TLS, DTLS, QUIC, FIPS-boundary, and systems-integration audits. |
| `0.98.0` | Remediate and cleanly retest every admitted finding; freeze public API, features, requirements, migration guidance, and incident procedures. |
| `0.99.0` | Pass a reproducible clean-room release rehearsal, installation, rollback, key-compromise, and disaster-recovery exercises. |
| `1.0.0-rc.1` | Build final artifacts once and freeze source, compiler, flags, archives, SBOM, checksums, provenance, documentation, and the pentested exact commit. |
| `1.0.0` | Promote only the byte-identical approved candidate without rebuild, source change, metadata drift, or expanded capability claim. |

`1.0.0` means the frozen modern requirements ledger is complete and its exact
artifacts have passed every applicable gate. It does not mean every historical
protocol, draft extension, platform adapter, or future TLS feature exists.
