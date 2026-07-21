# Brynja Release Plan To 1.0

Status: planning document

This plan is intentionally granular. Brynja processes hostile input and will eventually protect authentication material and application plaintext, so every milestone must be small enough to review, test, pentest, and stop safely.

Tags use `v0.N.0` for review milestones, `v1.0.0-rc.N` for exact production candidates, and `v1.0.0` for the first serious production-ready modern TLS release. Add patch releases or split a milestone whenever its scope grows.

## Release Principles

Every release requires a single bounded goal, standards and requirements trace, negative and adversarial tests, known limitations, release notes, zero external Cargo dependencies, no_std evidence, source-file length enforcement, SBOM, clean local and CI gates, CodeQL Default review, and a completed pentest for the exact reviewed implementation commit.

No milestone may claim cryptographic security from self-tests alone. Official vectors, differential testing, interoperability, resource testing, side-channel review, formal evidence where useful, external audit, and pentest complement one another; none substitutes for the others.

## Required Milestone Format

Every milestone contains Status, Goal, Deliverables, Verification, and Exit criteria. Repository-wide checks are additive to release-specific checks.

## Pentest Before Tags

A tag is forbidden until `scripts/checks.sh`, `cargo deny check`, `cargo audit`, latest-tool checks, SBOM comparison, release notes, GitHub CI, CodeQL Default review, package checks, and the version gate pass. A permanent pentest report must name the exact 40-character reviewed commit, date, tester, scope, and `Status: PASS`.

Implementation stops before pentest. Findings may be kept temporarily in ignored root `PENTEST.md`, then must be fixed, documented, tested, removed, and cleanly retested. Tags and publishing happen only when explicitly requested.

## Modern And Historical Versioning

The modern facade never depends on historical packages. Historical crates use independent versions and security reviews; their availability never expands a modern Brynja security claim. `brynja-ssl1-research` is permanently outside the production claim.

## Phase 0: Repository And Evidence Foundation

### v0.1.0 - Repository foundation

Status: awaiting pentest

Goal: complete one reviewable implementation pass for repository foundation without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- policy fixture tests, negative script tests, clean package inspection, and deliberate failure tests for every gate;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.1.0 implementation stop reached. Run pentest for this exact commit.`

### v0.2.0 - Release readiness gate

Status: planned

Goal: complete one reviewable implementation pass for release readiness gate without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- policy fixture tests, negative script tests, clean package inspection, and deliberate failure tests for every gate;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.2.0 implementation stop reached. Run pentest for this exact commit.`

### v0.3.0 - Standards and requirements ledger

Status: planned

Goal: complete one reviewable implementation pass for standards and requirements ledger without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- policy fixture tests, negative script tests, clean package inspection, and deliberate failure tests for every gate;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.3.0 implementation stop reached. Run pentest for this exact commit.`

### v0.4.0 - Test and adversarial harness foundation

Status: planned

Goal: complete one reviewable implementation pass for test and adversarial harness foundation without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- policy fixture tests, negative script tests, clean package inspection, and deliberate failure tests for every gate;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.4.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 1: Bounded Core Domains

### v0.5.0 - Stable error and alert domains

Status: planned

Goal: complete one reviewable implementation pass for stable error and alert domains without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- unit, boundary, compile-fail, no_std target, resource-budget, and API-invariant tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.5.0 implementation stop reached. Run pentest for this exact commit.`

### v0.6.0 - Wire cursor and bounded codec foundation

Status: planned

Goal: complete one reviewable implementation pass for wire cursor and bounded codec foundation without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- unit, boundary, compile-fail, no_std target, resource-budget, and API-invariant tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.6.0 implementation stop reached. Run pentest for this exact commit.`

### v0.7.0 - Secret ownership and lifetime policy

Status: planned

Goal: complete one reviewable implementation pass for secret ownership and lifetime policy without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- unit, boundary, compile-fail, no_std target, resource-budget, and API-invariant tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.7.0 implementation stop reached. Run pentest for this exact commit.`

### v0.8.0 - Provider and capability contracts

Status: planned

Goal: complete one reviewable implementation pass for provider and capability contracts without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- unit, boundary, compile-fail, no_std target, resource-budget, and API-invariant tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.8.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 2: First-Party Cryptographic Substrate

### v0.9.0 - SHA-256 core

Status: planned

Goal: complete one reviewable implementation pass for sha-256 core without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.9.0 implementation stop reached. Run pentest for this exact commit.`

### v0.10.0 - SHA-384 and SHA-512 core

Status: planned

Goal: complete one reviewable implementation pass for sha-384 and sha-512 core without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.10.0 implementation stop reached. Run pentest for this exact commit.`

### v0.11.0 - HMAC

Status: planned

Goal: complete one reviewable implementation pass for hmac without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.11.0 implementation stop reached. Run pentest for this exact commit.`

### v0.12.0 - HKDF

Status: planned

Goal: complete one reviewable implementation pass for hkdf without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.12.0 implementation stop reached. Run pentest for this exact commit.`

### v0.13.0 - AES block cipher

Status: planned

Goal: complete one reviewable implementation pass for aes block cipher without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.13.0 implementation stop reached. Run pentest for this exact commit.`

### v0.14.0 - GHASH and AES-GCM

Status: planned

Goal: complete one reviewable implementation pass for ghash and aes-gcm without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.14.0 implementation stop reached. Run pentest for this exact commit.`

### v0.15.0 - ChaCha20

Status: planned

Goal: complete one reviewable implementation pass for chacha20 without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.15.0 implementation stop reached. Run pentest for this exact commit.`

### v0.16.0 - Poly1305 and ChaCha20-Poly1305

Status: planned

Goal: complete one reviewable implementation pass for poly1305 and chacha20-poly1305 without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.16.0 implementation stop reached. Run pentest for this exact commit.`

### v0.17.0 - Bounded big-integer arithmetic

Status: planned

Goal: complete one reviewable implementation pass for bounded big-integer arithmetic without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.17.0 implementation stop reached. Run pentest for this exact commit.`

### v0.18.0 - X25519

Status: planned

Goal: complete one reviewable implementation pass for x25519 without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.18.0 implementation stop reached. Run pentest for this exact commit.`

### v0.19.0 - P-256

Status: planned

Goal: complete one reviewable implementation pass for p-256 without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.19.0 implementation stop reached. Run pentest for this exact commit.`

### v0.20.0 - P-384

Status: planned

Goal: complete one reviewable implementation pass for p-384 without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.20.0 implementation stop reached. Run pentest for this exact commit.`

### v0.21.0 - RSA verification

Status: planned

Goal: complete one reviewable implementation pass for rsa verification without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.21.0 implementation stop reached. Run pentest for this exact commit.`

### v0.22.0 - Cryptographic substrate audit gate

Status: planned

Goal: complete one reviewable implementation pass for cryptographic substrate audit gate without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official known-answer vectors, malformed inputs, differential oracles, constant-time review, and bounded-work tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.22.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 3: PKI And Certificate Validation

### v0.23.0 - Strict DER length and tag codec

Status: planned

Goal: complete one reviewable implementation pass for strict der length and tag codec without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official and adversarial certificate fixtures, truncation boundaries, differential decisions, corpus mutation, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.23.0 implementation stop reached. Run pentest for this exact commit.`

### v0.24.0 - ASN.1 primitive domains

Status: planned

Goal: complete one reviewable implementation pass for asn.1 primitive domains without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official and adversarial certificate fixtures, truncation boundaries, differential decisions, corpus mutation, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.24.0 implementation stop reached. Run pentest for this exact commit.`

### v0.25.0 - PEM boundary

Status: planned

Goal: complete one reviewable implementation pass for pem boundary without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official and adversarial certificate fixtures, truncation boundaries, differential decisions, corpus mutation, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.25.0 implementation stop reached. Run pentest for this exact commit.`

### v0.26.0 - X.509 certificate decoder

Status: planned

Goal: complete one reviewable implementation pass for x.509 certificate decoder without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official and adversarial certificate fixtures, truncation boundaries, differential decisions, corpus mutation, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.26.0 implementation stop reached. Run pentest for this exact commit.`

### v0.27.0 - Service identity and names

Status: planned

Goal: complete one reviewable implementation pass for service identity and names without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official and adversarial certificate fixtures, truncation boundaries, differential decisions, corpus mutation, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.27.0 implementation stop reached. Run pentest for this exact commit.`

### v0.28.0 - Path construction

Status: planned

Goal: complete one reviewable implementation pass for path construction without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official and adversarial certificate fixtures, truncation boundaries, differential decisions, corpus mutation, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.28.0 implementation stop reached. Run pentest for this exact commit.`

### v0.29.0 - Certificate signature validation

Status: planned

Goal: complete one reviewable implementation pass for certificate signature validation without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official and adversarial certificate fixtures, truncation boundaries, differential decisions, corpus mutation, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.29.0 implementation stop reached. Run pentest for this exact commit.`

### v0.30.0 - Constraints usage and policy validation

Status: planned

Goal: complete one reviewable implementation pass for constraints usage and policy validation without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official and adversarial certificate fixtures, truncation boundaries, differential decisions, corpus mutation, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.30.0 implementation stop reached. Run pentest for this exact commit.`

### v0.31.0 - Revocation and status boundaries

Status: planned

Goal: complete one reviewable implementation pass for revocation and status boundaries without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official and adversarial certificate fixtures, truncation boundaries, differential decisions, corpus mutation, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.31.0 implementation stop reached. Run pentest for this exact commit.`

### v0.32.0 - PKI conformance and audit gate

Status: planned

Goal: complete one reviewable implementation pass for pki conformance and audit gate without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official and adversarial certificate fixtures, truncation boundaries, differential decisions, corpus mutation, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.32.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 4: TLS 1.3 Core Engine

### v0.33.0 - TLS record codec

Status: planned

Goal: complete one reviewable implementation pass for tls record codec without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.33.0 implementation stop reached. Run pentest for this exact commit.`

### v0.34.0 - TLS 1.3 handshake codec

Status: planned

Goal: complete one reviewable implementation pass for tls 1.3 handshake codec without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.34.0 implementation stop reached. Run pentest for this exact commit.`

### v0.35.0 - Transcript and key schedule

Status: planned

Goal: complete one reviewable implementation pass for transcript and key schedule without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.35.0 implementation stop reached. Run pentest for this exact commit.`

### v0.36.0 - TLS 1.3 client opening flight

Status: planned

Goal: complete one reviewable implementation pass for tls 1.3 client opening flight without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.36.0 implementation stop reached. Run pentest for this exact commit.`

### v0.37.0 - TLS 1.3 server authenticated flight

Status: planned

Goal: complete one reviewable implementation pass for tls 1.3 server authenticated flight without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.37.0 implementation stop reached. Run pentest for this exact commit.`

### v0.38.0 - TLS 1.3 client authentication

Status: planned

Goal: complete one reviewable implementation pass for tls 1.3 client authentication without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.38.0 implementation stop reached. Run pentest for this exact commit.`

### v0.39.0 - PSK tickets and zero-RTT

Status: planned

Goal: complete one reviewable implementation pass for psk tickets and zero-rtt without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.39.0 implementation stop reached. Run pentest for this exact commit.`

### v0.40.0 - Alerts and state closure

Status: planned

Goal: complete one reviewable implementation pass for alerts and state closure without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.40.0 implementation stop reached. Run pentest for this exact commit.`

### v0.41.0 - Streaming fragmentation and backpressure

Status: planned

Goal: complete one reviewable implementation pass for streaming fragmentation and backpressure without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.41.0 implementation stop reached. Run pentest for this exact commit.`

### v0.42.0 - TLS 1.3 official vectors

Status: planned

Goal: complete one reviewable implementation pass for tls 1.3 official vectors without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.42.0 implementation stop reached. Run pentest for this exact commit.`

### v0.43.0 - TLS 1.3 interoperability

Status: planned

Goal: complete one reviewable implementation pass for tls 1.3 interoperability without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.43.0 implementation stop reached. Run pentest for this exact commit.`

### v0.44.0 - TLS 1.3 fuzz and model gate

Status: planned

Goal: complete one reviewable implementation pass for tls 1.3 fuzz and model gate without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.44.0 implementation stop reached. Run pentest for this exact commit.`

### v0.45.0 - TLS 1.3 external audit gate

Status: planned

Goal: complete one reviewable implementation pass for tls 1.3 external audit gate without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.45.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 5: Hardened TLS 1.2

### v0.46.0 - TLS 1.2 policy boundary

Status: planned

Goal: complete one reviewable implementation pass for tls 1.2 policy boundary without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.46.0 implementation stop reached. Run pentest for this exact commit.`

### v0.47.0 - TLS 1.2 record and PRF

Status: planned

Goal: complete one reviewable implementation pass for tls 1.2 record and prf without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.47.0 implementation stop reached. Run pentest for this exact commit.`

### v0.48.0 - TLS 1.2 ECDHE handshakes

Status: planned

Goal: complete one reviewable implementation pass for tls 1.2 ecdhe handshakes without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.48.0 implementation stop reached. Run pentest for this exact commit.`

### v0.49.0 - TLS 1.2 resumption and extension hardening

Status: planned

Goal: complete one reviewable implementation pass for tls 1.2 resumption and extension hardening without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.49.0 implementation stop reached. Run pentest for this exact commit.`

### v0.50.0 - TLS 1.2 conformance and interoperability

Status: planned

Goal: complete one reviewable implementation pass for tls 1.2 conformance and interoperability without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.50.0 implementation stop reached. Run pentest for this exact commit.`

### v0.51.0 - TLS 1.2 audit gate

Status: planned

Goal: complete one reviewable implementation pass for tls 1.2 audit gate without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transcripts, alert-exact failures, fragmentation matrices, state coverage, mature-peer interoperability, fuzzing, and downgrade tests;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.51.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 6: Facade Platform And Operations

### v0.52.0 - Configuration typestates

Status: planned

Goal: complete one reviewable implementation pass for configuration typestates without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- configuration compile tests, native and cross-target checks, cancellation and failure injection, concurrency fixtures, and quantitative budgets;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.52.0 implementation stop reached. Run pentest for this exact commit.`

### v0.53.0 - Runtime-neutral client API

Status: planned

Goal: complete one reviewable implementation pass for runtime-neutral client api without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- configuration compile tests, native and cross-target checks, cancellation and failure injection, concurrency fixtures, and quantitative budgets;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.53.0 implementation stop reached. Run pentest for this exact commit.`

### v0.54.0 - Runtime-neutral server API

Status: planned

Goal: complete one reviewable implementation pass for runtime-neutral server api without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- configuration compile tests, native and cross-target checks, cancellation and failure injection, concurrency fixtures, and quantitative budgets;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.54.0 implementation stop reached. Run pentest for this exact commit.`

### v0.55.0 - Transport and async integration boundary

Status: planned

Goal: complete one reviewable implementation pass for transport and async integration boundary without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- configuration compile tests, native and cross-target checks, cancellation and failure injection, concurrency fixtures, and quantitative budgets;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.55.0 implementation stop reached. Run pentest for this exact commit.`

### v0.56.0 - Entropy and time platform adapters

Status: planned

Goal: complete one reviewable implementation pass for entropy and time platform adapters without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- configuration compile tests, native and cross-target checks, cancellation and failure injection, concurrency fixtures, and quantitative budgets;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.56.0 implementation stop reached. Run pentest for this exact commit.`

### v0.57.0 - Optional allocation profile

Status: planned

Goal: complete one reviewable implementation pass for optional allocation profile without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- configuration compile tests, native and cross-target checks, cancellation and failure injection, concurrency fixtures, and quantitative budgets;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.57.0 implementation stop reached. Run pentest for this exact commit.`

### v0.58.0 - Session cache and ticket operations

Status: planned

Goal: complete one reviewable implementation pass for session cache and ticket operations without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- configuration compile tests, native and cross-target checks, cancellation and failure injection, concurrency fixtures, and quantitative budgets;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.58.0 implementation stop reached. Run pentest for this exact commit.`

### v0.59.0 - Certificate and trust rotation

Status: planned

Goal: complete one reviewable implementation pass for certificate and trust rotation without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- configuration compile tests, native and cross-target checks, cancellation and failure injection, concurrency fixtures, and quantitative budgets;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.59.0 implementation stop reached. Run pentest for this exact commit.`

### v0.60.0 - Safe diagnostics and observability

Status: planned

Goal: complete one reviewable implementation pass for safe diagnostics and observability without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- configuration compile tests, native and cross-target checks, cancellation and failure injection, concurrency fixtures, and quantitative budgets;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.60.0 implementation stop reached. Run pentest for this exact commit.`

### v0.61.0 - Platform portability gate

Status: planned

Goal: complete one reviewable implementation pass for platform portability gate without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- configuration compile tests, native and cross-target checks, cancellation and failure injection, concurrency fixtures, and quantitative budgets;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.61.0 implementation stop reached. Run pentest for this exact commit.`

### v0.62.0 - Performance and denial-of-service budgets

Status: planned

Goal: complete one reviewable implementation pass for performance and denial-of-service budgets without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- configuration compile tests, native and cross-target checks, cancellation and failure injection, concurrency fixtures, and quantitative budgets;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.62.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 7: QUIC TLS And DTLS

### v0.63.0 - QUIC encryption levels and secrets

Status: planned

Goal: complete one reviewable implementation pass for quic encryption levels and secrets without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transport vectors, loss/reorder/duplication simulation, amplification and replay tests, interoperability, fuzzing, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.63.0 implementation stop reached. Run pentest for this exact commit.`

### v0.64.0 - QUIC transport parameters

Status: planned

Goal: complete one reviewable implementation pass for quic transport parameters without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transport vectors, loss/reorder/duplication simulation, amplification and replay tests, interoperability, fuzzing, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.64.0 implementation stop reached. Run pentest for this exact commit.`

### v0.65.0 - QUIC handshake interface

Status: planned

Goal: complete one reviewable implementation pass for quic handshake interface without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transport vectors, loss/reorder/duplication simulation, amplification and replay tests, interoperability, fuzzing, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.65.0 implementation stop reached. Run pentest for this exact commit.`

### v0.66.0 - QUIC TLS conformance and audit

Status: planned

Goal: complete one reviewable implementation pass for quic tls conformance and audit without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transport vectors, loss/reorder/duplication simulation, amplification and replay tests, interoperability, fuzzing, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.66.0 implementation stop reached. Run pentest for this exact commit.`

### v0.67.0 - DTLS record epochs and replay windows

Status: planned

Goal: complete one reviewable implementation pass for dtls record epochs and replay windows without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transport vectors, loss/reorder/duplication simulation, amplification and replay tests, interoperability, fuzzing, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.67.0 implementation stop reached. Run pentest for this exact commit.`

### v0.68.0 - DTLS flights and reassembly

Status: planned

Goal: complete one reviewable implementation pass for dtls flights and reassembly without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transport vectors, loss/reorder/duplication simulation, amplification and replay tests, interoperability, fuzzing, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.68.0 implementation stop reached. Run pentest for this exact commit.`

### v0.69.0 - DTLS cookies and denial-of-service defense

Status: planned

Goal: complete one reviewable implementation pass for dtls cookies and denial-of-service defense without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transport vectors, loss/reorder/duplication simulation, amplification and replay tests, interoperability, fuzzing, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.69.0 implementation stop reached. Run pentest for this exact commit.`

### v0.70.0 - DTLS 1.3 state machine

Status: planned

Goal: complete one reviewable implementation pass for dtls 1.3 state machine without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transport vectors, loss/reorder/duplication simulation, amplification and replay tests, interoperability, fuzzing, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.70.0 implementation stop reached. Run pentest for this exact commit.`

### v0.71.0 - Hardened DTLS 1.2

Status: planned

Goal: complete one reviewable implementation pass for hardened dtls 1.2 without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transport vectors, loss/reorder/duplication simulation, amplification and replay tests, interoperability, fuzzing, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.71.0 implementation stop reached. Run pentest for this exact commit.`

### v0.72.0 - DTLS conformance interoperability and audit

Status: planned

Goal: complete one reviewable implementation pass for dtls conformance interoperability and audit without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- official transport vectors, loss/reorder/duplication simulation, amplification and replay tests, interoperability, fuzzing, and resource ceilings;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.72.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 8: Modern Extensions And Scope Closure

### v0.73.0 - Raw public keys

Status: planned

Goal: complete one reviewable implementation pass for raw public keys without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- normative requirement fixtures, negotiation and downgrade tests, privacy and resource adversaries, feature matrices, and independent interoperability;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.73.0 implementation stop reached. Run pentest for this exact commit.`

### v0.74.0 - Delegated credentials

Status: planned

Goal: complete one reviewable implementation pass for delegated credentials without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- normative requirement fixtures, negotiation and downgrade tests, privacy and resource adversaries, feature matrices, and independent interoperability;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.74.0 implementation stop reached. Run pentest for this exact commit.`

### v0.75.0 - Certificate compression

Status: planned

Goal: complete one reviewable implementation pass for certificate compression without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- normative requirement fixtures, negotiation and downgrade tests, privacy and resource adversaries, feature matrices, and independent interoperability;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.75.0 implementation stop reached. Run pentest for this exact commit.`

### v0.76.0 - Encrypted ClientHello

Status: planned

Goal: complete one reviewable implementation pass for encrypted clienthello without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- normative requirement fixtures, negotiation and downgrade tests, privacy and resource adversaries, feature matrices, and independent interoperability;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.76.0 implementation stop reached. Run pentest for this exact commit.`

### v0.77.0 - Post-quantum agility boundary

Status: planned

Goal: complete one reviewable implementation pass for post-quantum agility boundary without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- normative requirement fixtures, negotiation and downgrade tests, privacy and resource adversaries, feature matrices, and independent interoperability;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.77.0 implementation stop reached. Run pentest for this exact commit.`

### v0.78.0 - Exporters and channel binding

Status: planned

Goal: complete one reviewable implementation pass for exporters and channel binding without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- normative requirement fixtures, negotiation and downgrade tests, privacy and resource adversaries, feature matrices, and independent interoperability;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.78.0 implementation stop reached. Run pentest for this exact commit.`

### v0.79.0 - Key update and long-lived connection hardening

Status: planned

Goal: complete one reviewable implementation pass for key update and long-lived connection hardening without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- normative requirement fixtures, negotiation and downgrade tests, privacy and resource adversaries, feature matrices, and independent interoperability;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.79.0 implementation stop reached. Run pentest for this exact commit.`

### v0.80.0 - Modern protocol completeness review

Status: planned

Goal: complete one reviewable implementation pass for modern protocol completeness review without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- normative requirement fixtures, negotiation and downgrade tests, privacy and resource adversaries, feature matrices, and independent interoperability;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.80.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 9: Production Assurance And Admission

### v0.81.0 - Complete parser fuzz campaign

Status: planned

Goal: complete one reviewable implementation pass for complete parser fuzz campaign without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.81.0 implementation stop reached. Run pentest for this exact commit.`

### v0.82.0 - Complete state-machine model campaign

Status: planned

Goal: complete one reviewable implementation pass for complete state-machine model campaign without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.82.0 implementation stop reached. Run pentest for this exact commit.`

### v0.83.0 - Formal cryptographic invariant evidence

Status: planned

Goal: complete one reviewable implementation pass for formal cryptographic invariant evidence without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.83.0 implementation stop reached. Run pentest for this exact commit.`

### v0.84.0 - Memory and undefined-behavior evidence

Status: planned

Goal: complete one reviewable implementation pass for memory and undefined-behavior evidence without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.84.0 implementation stop reached. Run pentest for this exact commit.`

### v0.85.0 - Side-channel assessment

Status: planned

Goal: complete one reviewable implementation pass for side-channel assessment without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.85.0 implementation stop reached. Run pentest for this exact commit.`

### v0.86.0 - Complete differential campaign

Status: planned

Goal: complete one reviewable implementation pass for complete differential campaign without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.86.0 implementation stop reached. Run pentest for this exact commit.`

### v0.87.0 - Complete interoperability campaign

Status: planned

Goal: complete one reviewable implementation pass for complete interoperability campaign without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.87.0 implementation stop reached. Run pentest for this exact commit.`

### v0.88.0 - Resource exhaustion and hostile-load campaign

Status: planned

Goal: complete one reviewable implementation pass for resource exhaustion and hostile-load campaign without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.88.0 implementation stop reached. Run pentest for this exact commit.`

### v0.89.0 - Sustained platform qualification

Status: planned

Goal: complete one reviewable implementation pass for sustained platform qualification without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.89.0 implementation stop reached. Run pentest for this exact commit.`

### v0.90.0 - External cryptography audit

Status: planned

Goal: complete one reviewable implementation pass for external cryptography audit without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.90.0 implementation stop reached. Run pentest for this exact commit.`

### v0.91.0 - External PKI audit

Status: planned

Goal: complete one reviewable implementation pass for external pki audit without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.91.0 implementation stop reached. Run pentest for this exact commit.`

### v0.92.0 - External TLS QUIC and DTLS audit

Status: planned

Goal: complete one reviewable implementation pass for external tls quic and dtls audit without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.92.0 implementation stop reached. Run pentest for this exact commit.`

### v0.93.0 - Consolidated audit remediation

Status: planned

Goal: complete one reviewable implementation pass for consolidated audit remediation without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.93.0 implementation stop reached. Run pentest for this exact commit.`

### v0.94.0 - Public API and documentation freeze

Status: planned

Goal: complete one reviewable implementation pass for public api and documentation freeze without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.94.0 implementation stop reached. Run pentest for this exact commit.`

### v0.95.0 - Production release rehearsal

Status: planned

Goal: complete one reviewable implementation pass for production release rehearsal without expanding adjacent capability claims.

Deliverables:

- implement and document only the named scope, with explicit input, state, resource, secret, and failure invariants;
- update normative requirement mappings, threat-model delta, security controls, current status, known limitations, and release notes;
- keep every Rust source file within 500 lines, all production crates no_std, and all Cargo dependency classes empty.

Verification:

- the named full-workspace assurance campaign with reproducible reports, permanent regressions, clean reruns, and independent reviewer sign-off;
- full local checks, every promised Rust version and target, dependency policy, advisory scan, SBOM drift, package contents, documentation links, and modern/historical graph isolation.

Exit criteria:

- the named goal has reviewable evidence, no unsupported capability is advertised, and limitations are explicit;
- `v0.95.0 implementation stop reached. Run pentest for this exact commit.`

## v1.0.0-rc.1 - Exact Production Candidate

Status: planned

Goal: produce the actual `1.0.0`-versioned modern Brynja artifacts once and test, audit, pentest, and preserve those exact bytes.

Deliverables:

- promote only approved modern production crates and keep historical/repository-only packages outside the production artifact set;
- freeze manifests, lockfile, APIs, features, docs, SBOM, checksums, provenance, source archives, and platform artifacts;
- require a new `rc.N` commit and complete review cycle for any byte or metadata change.

Verification:

- rerun every `0.81.0..=0.95.0` campaign against the exact candidate;
- independent clean-room reproduction, downstream compatibility, package install, rollback, incident, and sustained interoperability exercises;
- external cryptography, PKI, and protocol audits plus exact-candidate pentest with clean retests and no unresolved critical or high findings.

Exit criteria:

- exact artifacts are approved for an unchanged stable tag;
- `v1.0.0-rc.1 implementation stop reached. Run pentest for this exact commit.`

## v1.0.0 - First Serious Production-Ready Brynja TLS Release

Status: planned

Goal: publish the unchanged approved candidate as the first serious production-ready modern Brynja TLS crate.

Deliverables:

- publish the exact approved modern package set in dependency order with checksums, SBOM, provenance, audit and pentest references, platform matrix, guidance, and limitations;
- leave every historical package separate and outside the stable modern facade claim.

Verification:

- prove `v1.0.0` resolves to the unchanged approved `v1.0.0-rc.N` commit and all package/archive checksums are identical;
- validate registry artifacts, documentation, ownership, incident contacts, and metadata without rebuilding different bytes.

Exit criteria:

- the stable tag points to the unchanged approved candidate and every production claim matches evidence;
- `v1.0.0 implementation stop reached. Run pentest for this exact commit.`
