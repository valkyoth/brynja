# Brynja Release Plan To 1.0

Status: normative planning document

This plan is intentionally granular. Brynja processes hostile input and will
eventually protect authentication material and application plaintext, so every
milestone must be small enough to review, test, pentest, and stop safely.

## Version-Plan Synchronization

[VERSION_PLAN.md](VERSION_PLAN.md) defines the exclusive scope and ordering of
the modern release line. Every release section below repeats that text as
`Plan scope:`. `scripts/check-release-plan.py` compares the documents and
fails on a missing, reordered, duplicated, or altered version or scope.

Tags use `v0.N.0` for review milestones, `v1.0.0-rc.N` for exact production
candidates, and `v1.0.0` for the first serious production-ready modern TLS
release. Split work into an additional milestone or patch release whenever a
scope is no longer independently reviewable; never combine adjacent scopes to
preserve a date or version number.

## Release Principles

Every release requires mapped normative requirements, immutable resource limits,
negative and adversarial tests, documented limitations, release notes, zero
external dependencies in shipped packages, `no_std` evidence, source-file
length enforcement, SBOM comparison, clean local and CI gates, CodeQL Default
review, and a completed pentest for the exact reviewed implementation commit.

Self-tests do not establish cryptographic security. Official vectors,
differential and interoperability tests, resource analysis, compiler-output and
side-channel review, formal evidence where useful, external audit, and pentest
are complementary evidence.

The modern facade never depends on historical packages. FIPS is never an
additive Cargo feature or a claim inferred from algorithm vectors. Draft PQ
groups remain experimental and outside the stable compatibility promise until
the relevant standard and code points are final.

## Required Milestone Contract

Every milestone contains, in order, Status, Plan scope, Goal, Deliverables,
Verification, and Exit criteria. Deliverables must name state, input, resource,
secret, failure, and package boundaries applicable to the scope. Verification
must include positive, negative, boundary, and deliberate-failure evidence.

Repository-wide checks are additive to milestone checks. A completed milestone
does not admit adjacent capability and does not broaden claims made by an
earlier package.

## Pentest Before Every Tag

A tag is forbidden until `scripts/checks.sh`, `cargo deny check`,
`cargo audit --deny warnings`, latest-tool checks, SBOM comparison, release
notes, GitHub CI, CodeQL Default review, package checks, and the version-specific
release gate pass. The permanent pentest report must name the exact 40-character
`git rev-parse HEAD`, date, tester, scope, and `Status: PASS`; the gate must
compare that commit byte-for-byte with HEAD.

Implementation stops before pentest. Findings may be kept temporarily in the
ignored root `PENTEST.md`, then must be fixed, documented, regression-tested,
removed, and cleanly retested. Tags and publishing happen only when explicitly
requested.

## Historical Package Release Line

Historical packages use independent SemVer lines and never block or inherit the
modern facade's `1.0.0` claim. Repeat the following stages separately for TLS
1.1, TLS 1.0, SSL 3, SSL 2, WTLS, PCT, and SNP. SSL 1 remains research-only and
unpublished.

| Stage | Required result |
| --- | --- |
| `H0.1.0` | Authenticate sources and rights, record errata, publish conspicuous insecurity warnings, and freeze the protocol threat model. |
| `H0.2.0` | Implement only the protocol-specific bounded wire codec. |
| `H0.3.0` | Implement a state machine with no shared modern configuration, negotiation, credentials, caches, tickets, or fallback. |
| `H0.4.0` | Bind audited shared primitives and keep all required weak primitives in a historical-only crypto package. |
| `H0.5.0` | Complete controlled client-only interoperability and containment evidence. |
| `H0.6.0` | Add server interoperability only when separately justified and reviewed for amplification and hostile load. |
| `H0.7.0` | Require separate listeners, policy, credentials, storage, diagnostics, and process-containment guidance. |
| `H0.8.0` | Complete a protocol-specific external audit and pentest and verify all warnings and non-fallback properties. |

## Phase 0: Repository, Boundaries, And Wire Foundations

Repository policy becomes executable before bounded core types and hostile-input codecs are admitted.

### v0.1.0 - Workspace Foundation

Status: awaiting pentest

Plan scope: Preserve the existing workspace foundation with no cryptographic or protocol security claim.

Goal: complete the **Workspace Foundation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- make the repository policy executable through fail-closed scripts, fixtures, immutable evidence inputs, and documented ownership or approval boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- exercise policy scripts with positive and deliberately broken fixtures, including dependency, feature, metadata, evidence, and release-state failures;
- inspect clean archives, locked source material, CI permissions, branch/tag assumptions, and reproducibility inputs;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- repository evidence and enforcement agree, and deliberate violations fail before a release artifact can be produced;
- `v0.1.0 implementation stop reached. Run pentest for this exact commit.`

### v0.2.0 - Release And Isolation Enforcement

Status: planned

Plan scope: Fix exact-HEAD pentest comparison, validate all-feature graphs and every package class, add negative isolation fixtures, and document protected release controls.

Goal: complete the **Release And Isolation Enforcement** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- make the repository policy executable through fail-closed scripts, fixtures, immutable evidence inputs, and documented ownership or approval boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- exercise policy scripts with positive and deliberately broken fixtures, including dependency, feature, metadata, evidence, and release-state failures;
- inspect clean archives, locked source material, CI permissions, branch/tag assumptions, and reproducibility inputs;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- repository evidence and enforcement agree, and deliberate violations fail before a release artifact can be produced;
- `v0.2.0 implementation stop reached. Run pentest for this exact commit.`

### v0.3.0 - Requirements And Standards Ledger

Status: planned

Plan scope: Build the requirements ledger for RFC 9846, RFC 5280, RFC 9001, RFC 9147, applicable NIST standards and errata, and frozen IANA snapshots; map every normative requirement.

Goal: complete the **Requirements And Standards Ledger** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- make the repository policy executable through fail-closed scripts, fixtures, immutable evidence inputs, and documented ownership or approval boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- exercise policy scripts with positive and deliberately broken fixtures, including dependency, feature, metadata, evidence, and release-state failures;
- inspect clean archives, locked source material, CI permissions, branch/tag assumptions, and reproducibility inputs;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- repository evidence and enforcement agree, and deliberate violations fail before a release artifact can be produced;
- `v0.3.0 implementation stop reached. Run pentest for this exact commit.`

### v0.4.0 - Assurance Harness And Bare-Metal Matrix

Status: planned

Plan scope: Establish repository-only mutation and differential harnesses, true bare-metal targets, and separate production-versus-assurance dependency policies without adding shipped dependencies.

Goal: complete the **Assurance Harness And Bare-Metal Matrix** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- make the repository policy executable through fail-closed scripts, fixtures, immutable evidence inputs, and documented ownership or approval boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- exercise policy scripts with positive and deliberately broken fixtures, including dependency, feature, metadata, evidence, and release-state failures;
- inspect clean archives, locked source material, CI permissions, branch/tag assumptions, and reproducibility inputs;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- repository evidence and enforcement agree, and deliberate violations fail before a release artifact can be produced;
- `v0.4.0 implementation stop reached. Run pentest for this exact commit.`

### v0.5.0 - Error Alert And Exhaustion Domains

Status: planned

Plan scope: Freeze non-secret error, alert, close, and resource-exhaustion domains; prohibit secret-bearing formatting and ambiguous failure collapse.

Goal: complete the **Error Alert And Exhaustion Domains** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, transactional mutation rules, and secret-free error behavior before downstream consumption;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, and no-mutation-on-error tests;
- test zero-sized and maximum-sized workspaces, aliasing or overlap rejection, malformed encodings, cancellation, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the bounded core contract is reviewable, deterministic, panic-free for hostile input, and exposes no adjacent protocol capability;
- `v0.5.0 implementation stop reached. Run pentest for this exact commit.`

### v0.6.0 - Bounded Numeric And Resource Domains

Status: planned

Plan scope: Introduce checked bounded integers, counts, lengths, sequence numbers, epochs, and immutable resource budgets.

Goal: complete the **Bounded Numeric And Resource Domains** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, transactional mutation rules, and secret-free error behavior before downstream consumption;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, and no-mutation-on-error tests;
- test zero-sized and maximum-sized workspaces, aliasing or overlap rejection, malformed encodings, cancellation, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the bounded core contract is reviewable, deterministic, panic-free for hostile input, and exposes no adjacent protocol capability;
- `v0.6.0 implementation stop reached. Run pentest for this exact commit.`

### v0.7.0 - Borrowed Read Cursor

Status: planned

Plan scope: Implement a borrowed read cursor with exact consumption, truncation-at-every-byte coverage, and no indexing panics.

Goal: complete the **Borrowed Read Cursor** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, transactional mutation rules, and secret-free error behavior before downstream consumption;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, and no-mutation-on-error tests;
- test zero-sized and maximum-sized workspaces, aliasing or overlap rejection, malformed encodings, cancellation, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the bounded core contract is reviewable, deterministic, panic-free for hostile input, and exposes no adjacent protocol capability;
- `v0.7.0 implementation stop reached. Run pentest for this exact commit.`

### v0.8.0 - Transactional Write Cursor

Status: planned

Plan scope: Implement caller-buffer write cursors with transactional encode-or-no-mutation behavior.

Goal: complete the **Transactional Write Cursor** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, transactional mutation rules, and secret-free error behavior before downstream consumption;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, and no-mutation-on-error tests;
- test zero-sized and maximum-sized workspaces, aliasing or overlap rejection, malformed encodings, cancellation, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the bounded core contract is reviewable, deterministic, panic-free for hostile input, and exposes no adjacent protocol capability;
- `v0.8.0 implementation stop reached. Run pentest for this exact commit.`

### v0.9.0 - Caller-Owned Workspace Model

Status: planned

Plan scope: Define caller-owned workspaces and scratch regions, overlap rules, high-water tracking, and allocation counters.

Goal: complete the **Caller-Owned Workspace Model** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, transactional mutation rules, and secret-free error behavior before downstream consumption;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, and no-mutation-on-error tests;
- test zero-sized and maximum-sized workspaces, aliasing or overlap rejection, malformed encodings, cancellation, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the bounded core contract is reviewable, deterministic, panic-free for hostile input, and exposes no adjacent protocol capability;
- `v0.9.0 implementation stop reached. Run pentest for this exact commit.`

### v0.10.0 - Secret Lifetime And Zeroization Contract

Status: planned

Plan scope: Define secret ownership and destruction types, redaction, cancellation behavior, immediate lifetime transitions, and an explicitly approved zeroization strategy.

Goal: complete the **Secret Lifetime And Zeroization Contract** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, transactional mutation rules, and secret-free error behavior before downstream consumption;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, and no-mutation-on-error tests;
- test zero-sized and maximum-sized workspaces, aliasing or overlap rejection, malformed encodings, cancellation, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the bounded core contract is reviewable, deterministic, panic-free for hostile input, and exposes no adjacent protocol capability;
- `v0.10.0 implementation stop reached. Run pentest for this exact commit.`

### v0.11.0 - Provider Capabilities And Opaque Handles

Status: planned

Plan scope: Define crypto, signature, KEM, and AEAD capability traits with opaque key handles and frozen provider capabilities.

Goal: complete the **Provider Capabilities And Opaque Handles** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, transactional mutation rules, and secret-free error behavior before downstream consumption;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, and no-mutation-on-error tests;
- test zero-sized and maximum-sized workspaces, aliasing or overlap rejection, malformed encodings, cancellation, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the bounded core contract is reviewable, deterministic, panic-free for hostile input, and exposes no adjacent protocol capability;
- `v0.11.0 implementation stop reached. Run pentest for this exact commit.`

### v0.12.0 - TLS And DTLS Record Framing

Status: planned

Plan scope: Separate TLS and DTLS record framing codecs and make modern parsers reject unknown or legacy versions deterministically.

Goal: complete the **TLS And DTLS Record Framing** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, transactional mutation rules, and secret-free error behavior before downstream consumption;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, and no-mutation-on-error tests;
- test zero-sized and maximum-sized workspaces, aliasing or overlap rejection, malformed encodings, cancellation, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the bounded core contract is reviewable, deterministic, panic-free for hostile input, and exposes no adjacent protocol capability;
- `v0.12.0 implementation stop reached. Run pentest for this exact commit.`

### v0.13.0 - Bounded DER Reader

Status: planned

Plan scope: Implement a non-recursive DER tag/length/value reader with definite, minimal, overflow-safe, depth-, node-, and work-bounded parsing.

Goal: complete the **Bounded DER Reader** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, transactional mutation rules, and secret-free error behavior before downstream consumption;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, and no-mutation-on-error tests;
- test zero-sized and maximum-sized workspaces, aliasing or overlap rejection, malformed encodings, cancellation, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the bounded core contract is reviewable, deterministic, panic-free for hostile input, and exposes no adjacent protocol capability;
- `v0.13.0 implementation stop reached. Run pentest for this exact commit.`

### v0.14.0 - Canonical ASN.1 Primitives

Status: planned

Plan scope: Add canonical ASN.1 integer, bit/octet string, OID, Boolean, string, sequence/set, and time primitives with malformed and non-canonical corpora.

Goal: complete the **Canonical ASN.1 Primitives** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, transactional mutation rules, and secret-free error behavior before downstream consumption;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, and no-mutation-on-error tests;
- test zero-sized and maximum-sized workspaces, aliasing or overlap rejection, malformed encodings, cancellation, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the bounded core contract is reviewable, deterministic, panic-free for hostile input, and exposes no adjacent protocol capability;
- `v0.14.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 1: First-Party Cryptography And PKI

Hash, sponge, KDF, symmetric, public-key, and PKI work advances behind separate audit gates before TLS consumption.

### v0.15.0 - SHA-256

Status: planned

Plan scope: Implement streaming and fixed-message SHA-256 with official vectors, boundary lengths, and exhaustion handling.

Goal: complete the **SHA-256** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.15.0 implementation stop reached. Run pentest for this exact commit.`

### v0.16.0 - SHA-384 And SHA-512

Status: planned

Plan scope: Implement SHA-384 and SHA-512 with official vectors and checked length/exhaustion behavior.

Goal: complete the **SHA-384 And SHA-512** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.16.0 implementation stop reached. Run pentest for this exact commit.`

### v0.17.0 - Keccak SHA-3 And SHAKE

Status: planned

Plan scope: Implement Keccak-f[1600], SHA3-256/512, and SHAKE128/256 as the required ML-KEM foundation.

Goal: complete the **Keccak SHA-3 And SHAKE** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.17.0 implementation stop reached. Run pentest for this exact commit.`

### v0.18.0 - HMAC

Status: planned

Plan scope: Implement HMAC-SHA-256/384/512 with constant-time verification and misuse tests.

Goal: complete the **HMAC** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.18.0 implementation stop reached. Run pentest for this exact commit.`

### v0.19.0 - HKDF And TLS Labels

Status: planned

Plan scope: Implement HKDF extract/expand and TLS HKDF-Expand-Label with all input and output limits explicit.

Goal: complete the **HKDF And TLS Labels** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.19.0 implementation stop reached. Run pentest for this exact commit.`

### v0.20.0 - Portable AES

Status: planned

Plan scope: Implement portable constant-time AES-128/256 without secret-indexed tables; require emitted-code and statistical evidence.

Goal: complete the **Portable AES** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.20.0 implementation stop reached. Run pentest for this exact commit.`

### v0.21.0 - GHASH

Status: planned

Plan scope: Implement constant-time GHASH finite-field arithmetic and a bounded incremental interface.

Goal: complete the **GHASH** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.21.0 implementation stop reached. Run pentest for this exact commit.`

### v0.22.0 - AES-GCM

Status: planned

Plan scope: Implement AES-GCM seal/open with nonce and usage limits and no plaintext release before authentication.

Goal: complete the **AES-GCM** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.22.0 implementation stop reached. Run pentest for this exact commit.`

### v0.23.0 - ChaCha20

Status: planned

Plan scope: Implement ChaCha20 with checked counters and deterministic exhaustion closure.

Goal: complete the **ChaCha20** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.23.0 implementation stop reached. Run pentest for this exact commit.`

### v0.24.0 - Poly1305 And ChaCha20-Poly1305

Status: planned

Plan scope: Implement Poly1305 and ChaCha20-Poly1305 with constant-time tag verification and withheld unauthenticated plaintext.

Goal: complete the **Poly1305 And ChaCha20-Poly1305** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.24.0 implementation stop reached. Run pentest for this exact commit.`

### v0.25.0 - Fixed-Limb Arithmetic

Status: planned

Plan scope: Implement fixed-limb RSA/ECC arithmetic with no attacker-selected allocation, normalization schedule, or limb count.

Goal: complete the **Fixed-Limb Arithmetic** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.25.0 implementation stop reached. Run pentest for this exact commit.`

### v0.26.0 - X25519

Status: planned

Plan scope: Implement X25519 using a fixed ladder, low-order handling, and explicit non-FIPS classification.

Goal: complete the **X25519** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.26.0 implementation stop reached. Run pentest for this exact commit.`

### v0.27.0 - P-256

Status: planned

Plan scope: Implement P-256 ECDH and ECDSA, complete point validation, and an explicit deterministic/randomized nonce policy.

Goal: complete the **P-256** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.27.0 implementation stop reached. Run pentest for this exact commit.`

### v0.28.0 - P-384

Status: planned

Plan scope: Implement P-384 ECDH and ECDSA with separate vectors, side-channel evidence, and review.

Goal: complete the **P-384** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.28.0 implementation stop reached. Run pentest for this exact commit.`

### v0.29.0 - RSA-PSS Verification

Status: planned

Plan scope: Implement strict RSA public-key decoding and RSA-PSS verification with unambiguous parameters and modulus/exponent policy.

Goal: complete the **RSA-PSS Verification** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.29.0 implementation stop reached. Run pentest for this exact commit.`

### v0.30.0 - RSA-PSS Private Operations

Status: planned

Plan scope: Implement blinded, fixed-schedule RSA-PSS private operations and CRT consistency checks, or freeze an external-signer-only production scope.

Goal: complete the **RSA-PSS Private Operations** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.30.0 implementation stop reached. Run pentest for this exact commit.`

### v0.31.0 - Signature Compatibility Matrix

Status: planned

Plan scope: Freeze signature-scheme negotiation and the certificate/public-key compatibility matrix.

Goal: complete the **Signature Compatibility Matrix** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.31.0 implementation stop reached. Run pentest for this exact commit.`

### v0.32.0 - Cryptographic Substrate Audit Gate

Status: planned

Plan scope: Complete independent cryptographic-substrate review and remediate every admitted finding before TLS consumption.

Goal: complete the **Cryptographic Substrate Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- record algorithm parameters, key and nonce domains, usage ceilings, secret lifetimes, constant-time obligations, and provider boundaries in the requirements ledger;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official known-answer and boundary vectors, negative and misuse tests, differential checks against two independent implementations where available, and per-target no_std tests;
- review emitted MIR/LLVM/assembly and run statistical or microarchitectural tests appropriate to the primitive, including malformed inputs and exhaustion paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the primitive's admitted parameter sets have traceable functional and side-channel evidence, with no TLS use before the cryptographic audit gate;
- `v0.32.0 implementation stop reached. Run pentest for this exact commit.`

### v0.33.0 - X.509 Decoder

Status: planned

Plan scope: Decode X.509 Certificate, TBSCertificate, and SPKI while preserving the exact original signed byte slice.

Goal: complete the **X.509 Decoder** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind every parser and validator decision to original signed bytes, explicit algorithm policy, caller-supplied trust material, and immutable depth, count, size, and work budgets;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER and certificate corpora, truncation tests, differential validation, path-search exhaustion, and deterministic tie-breaking tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, cycles, constraint interactions, stale or unauthorized revocation data, and budget exhaustion;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- PKI processing is fail-closed, bounded, deterministic, and independently reviewed before any handshake treats a peer as authenticated;
- `v0.33.0 implementation stop reached. Run pentest for this exact commit.`

### v0.34.0 - Service Identity And Extensions

Status: planned

Plan scope: Validate SAN/service identity, wildcards, IP and URI names, critical extensions, and duplicate-extension rejection.

Goal: complete the **Service Identity And Extensions** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind every parser and validator decision to original signed bytes, explicit algorithm policy, caller-supplied trust material, and immutable depth, count, size, and work budgets;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER and certificate corpora, truncation tests, differential validation, path-search exhaustion, and deterministic tie-breaking tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, cycles, constraint interactions, stale or unauthorized revocation data, and budget exhaustion;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- PKI processing is fail-closed, bounded, deterministic, and independently reviewed before any handshake treats a peer as authenticated;
- `v0.34.0 implementation stop reached. Run pentest for this exact commit.`

### v0.35.0 - Bounded Path Construction

Status: planned

Plan scope: Build bounded deterministic paths using caller-supplied pools, loop detection, and hard depth/candidate/work limits.

Goal: complete the **Bounded Path Construction** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind every parser and validator decision to original signed bytes, explicit algorithm policy, caller-supplied trust material, and immutable depth, count, size, and work budgets;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER and certificate corpora, truncation tests, differential validation, path-search exhaustion, and deterministic tie-breaking tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, cycles, constraint interactions, stale or unauthorized revocation data, and budget exhaustion;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- PKI processing is fail-closed, bounded, deterministic, and independently reviewed before any handshake treats a peer as authenticated;
- `v0.35.0 implementation stop reached. Run pentest for this exact commit.`

### v0.36.0 - RFC 5280 Validation

Status: planned

Plan scope: Complete RFC 5280 validation for signatures, validity, path length, KU/EKU, basic/name constraints, policy, algorithms, and trust anchors.

Goal: complete the **RFC 5280 Validation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind every parser and validator decision to original signed bytes, explicit algorithm policy, caller-supplied trust material, and immutable depth, count, size, and work budgets;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER and certificate corpora, truncation tests, differential validation, path-search exhaustion, and deterministic tie-breaking tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, cycles, constraint interactions, stale or unauthorized revocation data, and budget exhaustion;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- PKI processing is fail-closed, bounded, deterministic, and independently reviewed before any handshake treats a peer as authenticated;
- `v0.36.0 implementation stop reached. Run pentest for this exact commit.`

### v0.37.0 - CRL Validation

Status: planned

Plan scope: Validate base, delta, and indirect CRLs with issuer, freshness, distribution-point, entry, and work ceilings.

Goal: complete the **CRL Validation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind every parser and validator decision to original signed bytes, explicit algorithm policy, caller-supplied trust material, and immutable depth, count, size, and work budgets;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER and certificate corpora, truncation tests, differential validation, path-search exhaustion, and deterministic tie-breaking tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, cycles, constraint interactions, stale or unauthorized revocation data, and budget exhaustion;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- PKI processing is fail-closed, bounded, deterministic, and independently reviewed before any handshake treats a peer as authenticated;
- `v0.37.0 implementation stop reached. Run pentest for this exact commit.`

### v0.38.0 - OCSP Validation

Status: planned

Plan scope: Validate stapled/offline OCSP responses, responder authorization, freshness, nonce, matching, and explicit hard/soft-fail policy.

Goal: complete the **OCSP Validation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind every parser and validator decision to original signed bytes, explicit algorithm policy, caller-supplied trust material, and immutable depth, count, size, and work budgets;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER and certificate corpora, truncation tests, differential validation, path-search exhaustion, and deterministic tie-breaking tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, cycles, constraint interactions, stale or unauthorized revocation data, and budget exhaustion;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- PKI processing is fail-closed, bounded, deterministic, and independently reviewed before any handshake treats a peer as authenticated;
- `v0.38.0 implementation stop reached. Run pentest for this exact commit.`

### v0.39.0 - PKI Audit Gate

Status: planned

Plan scope: Complete PKI adversarial, differential, and fuzz campaigns plus an external PKI audit and remediation gate.

Goal: complete the **PKI Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind every parser and validator decision to original signed bytes, explicit algorithm policy, caller-supplied trust material, and immutable depth, count, size, and work budgets;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER and certificate corpora, truncation tests, differential validation, path-search exhaustion, and deterministic tie-breaking tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, cycles, constraint interactions, stale or unauthorized revocation data, and budget exhaustion;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- PKI processing is fail-closed, bounded, deterministic, and independently reviewed before any handshake treats a peer as authenticated;
- `v0.39.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 2: Modern TLS 1.3 And Explicit TLS 1.2

TLS 1.3 completes first; TLS 1.2 remains a separately configured ECDHE-plus-AEAD compatibility profile with no automatic fallback.

### v0.40.0 - TLS Record Protection

Status: planned

Plan scope: Implement TLS record protection, checked sequence exhaustion, inner content-type/padding validation, and fragmentation boundaries.

Goal: complete the **TLS Record Protection** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- encode the TLS 1.3 state, transcript, secret, record, configuration, and failure invariants as closed types with caller-owned storage and deterministic Sans-I/O actions;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, message truncation and fragmentation matrices, illegal-order and duplicate-message tests, transcript/key-schedule checks, and independent-peer interoperability;
- exercise downgrade, replay, binder, ticket, zero-RTT, key-limit, backpressure, cancellation, alert, and terminal-secret-destruction paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished handshake states or unauthenticated output;
- `v0.40.0 implementation stop reached. Run pentest for this exact commit.`

### v0.41.0 - TLS 1.3 Handshake Codec

Status: planned

Plan scope: Implement the complete TLS 1.3 handshake codec with duplicate, ordering, and extension-context rules.

Goal: complete the **TLS 1.3 Handshake Codec** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- encode the TLS 1.3 state, transcript, secret, record, configuration, and failure invariants as closed types with caller-owned storage and deterministic Sans-I/O actions;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, message truncation and fragmentation matrices, illegal-order and duplicate-message tests, transcript/key-schedule checks, and independent-peer interoperability;
- exercise downgrade, replay, binder, ticket, zero-RTT, key-limit, backpressure, cancellation, alert, and terminal-secret-destruction paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished handshake states or unauthenticated output;
- `v0.41.0 implementation stop reached. Run pentest for this exact commit.`

### v0.42.0 - Transcript And Key Schedule

Status: planned

Plan scope: Implement transcript and key-schedule states with immediate destruction of obsolete early, handshake, master, exporter, and resumption secrets.

Goal: complete the **Transcript And Key Schedule** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- encode the TLS 1.3 state, transcript, secret, record, configuration, and failure invariants as closed types with caller-owned storage and deterministic Sans-I/O actions;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, message truncation and fragmentation matrices, illegal-order and duplicate-message tests, transcript/key-schedule checks, and independent-peer interoperability;
- exercise downgrade, replay, binder, ticket, zero-RTT, key-limit, backpressure, cancellation, alert, and terminal-secret-destruction paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished handshake states or unauthenticated output;
- `v0.42.0 implementation stop reached. Run pentest for this exact commit.`

### v0.43.0 - TLS 1.3 Opening Flight

Status: planned

Plan scope: Implement ClientHello, versions, groups, signatures, key shares, HelloRetryRequest, cookies, and downgrade invariants.

Goal: complete the **TLS 1.3 Opening Flight** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- encode the TLS 1.3 state, transcript, secret, record, configuration, and failure invariants as closed types with caller-owned storage and deterministic Sans-I/O actions;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, message truncation and fragmentation matrices, illegal-order and duplicate-message tests, transcript/key-schedule checks, and independent-peer interoperability;
- exercise downgrade, replay, binder, ticket, zero-RTT, key-limit, backpressure, cancellation, alert, and terminal-secret-destruction paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished handshake states or unauthenticated output;
- `v0.43.0 implementation stop reached. Run pentest for this exact commit.`

### v0.44.0 - TLS 1.3 Authenticated Server Flight

Status: planned

Plan scope: Implement ServerHello through the authenticated server flight, certificate selection, ALPN, and SNI policy.

Goal: complete the **TLS 1.3 Authenticated Server Flight** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- encode the TLS 1.3 state, transcript, secret, record, configuration, and failure invariants as closed types with caller-owned storage and deterministic Sans-I/O actions;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, message truncation and fragmentation matrices, illegal-order and duplicate-message tests, transcript/key-schedule checks, and independent-peer interoperability;
- exercise downgrade, replay, binder, ticket, zero-RTT, key-limit, backpressure, cancellation, alert, and terminal-secret-destruction paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished handshake states or unauthenticated output;
- `v0.44.0 implementation stop reached. Run pentest for this exact commit.`

### v0.45.0 - TLS 1.3 Client Authentication And Finished

Status: planned

Plan scope: Implement client authentication, CertificateVerify, Finished, and the authenticated application-data transition.

Goal: complete the **TLS 1.3 Client Authentication And Finished** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- encode the TLS 1.3 state, transcript, secret, record, configuration, and failure invariants as closed types with caller-owned storage and deterministic Sans-I/O actions;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, message truncation and fragmentation matrices, illegal-order and duplicate-message tests, transcript/key-schedule checks, and independent-peer interoperability;
- exercise downgrade, replay, binder, ticket, zero-RTT, key-limit, backpressure, cancellation, alert, and terminal-secret-destruction paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished handshake states or unauthenticated output;
- `v0.45.0 implementation stop reached. Run pentest for this exact commit.`

### v0.46.0 - Alerts Closure And Cancellation

Status: planned

Plan scope: Complete alerts, close-notify, illegal-message handling, cancellation, terminal states, and terminal secret destruction.

Goal: complete the **Alerts Closure And Cancellation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- encode the TLS 1.3 state, transcript, secret, record, configuration, and failure invariants as closed types with caller-owned storage and deterministic Sans-I/O actions;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, message truncation and fragmentation matrices, illegal-order and duplicate-message tests, transcript/key-schedule checks, and independent-peer interoperability;
- exercise downgrade, replay, binder, ticket, zero-RTT, key-limit, backpressure, cancellation, alert, and terminal-secret-destruction paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished handshake states or unauthenticated output;
- `v0.46.0 implementation stop reached. Run pentest for this exact commit.`

### v0.47.0 - Tickets And PSK Binders

Status: planned

Plan scope: Implement session tickets and PSK binders with protocol-specific ticket-key, cache, and rotation domains.

Goal: complete the **Tickets And PSK Binders** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- encode the TLS 1.3 state, transcript, secret, record, configuration, and failure invariants as closed types with caller-owned storage and deterministic Sans-I/O actions;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, message truncation and fragmentation matrices, illegal-order and duplicate-message tests, transcript/key-schedule checks, and independent-peer interoperability;
- exercise downgrade, replay, binder, ticket, zero-RTT, key-limit, backpressure, cancellation, alert, and terminal-secret-destruction paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished handshake states or unauthenticated output;
- `v0.47.0 implementation stop reached. Run pentest for this exact commit.`

### v0.48.0 - Zero-RTT

Status: planned

Plan scope: Implement opt-in 0-RTT with an anti-replay store contract, freshness, deterministic rejection, and side-effect guidance.

Goal: complete the **Zero-RTT** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- encode the TLS 1.3 state, transcript, secret, record, configuration, and failure invariants as closed types with caller-owned storage and deterministic Sans-I/O actions;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, message truncation and fragmentation matrices, illegal-order and duplicate-message tests, transcript/key-schedule checks, and independent-peer interoperability;
- exercise downgrade, replay, binder, ticket, zero-RTT, key-limit, backpressure, cancellation, alert, and terminal-secret-destruction paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished handshake states or unauthenticated output;
- `v0.48.0 implementation stop reached. Run pentest for this exact commit.`

### v0.49.0 - Key Update Exporters And Channel Binding

Status: planned

Plan scope: Implement TLS KeyUpdate, exporters, channel binding, and long-lived key/record usage limits.

Goal: complete the **Key Update Exporters And Channel Binding** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- encode the TLS 1.3 state, transcript, secret, record, configuration, and failure invariants as closed types with caller-owned storage and deterministic Sans-I/O actions;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, message truncation and fragmentation matrices, illegal-order and duplicate-message tests, transcript/key-schedule checks, and independent-peer interoperability;
- exercise downgrade, replay, binder, ticket, zero-RTT, key-limit, backpressure, cancellation, alert, and terminal-secret-destruction paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished handshake states or unauthenticated output;
- `v0.49.0 implementation stop reached. Run pentest for this exact commit.`

### v0.50.0 - TLS 1.3 Suite Completion

Status: planned

Plan scope: Admit all three TLS 1.3 suites: AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, and ChaCha20-Poly1305/SHA-256.

Goal: complete the **TLS 1.3 Suite Completion** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- encode the TLS 1.3 state, transcript, secret, record, configuration, and failure invariants as closed types with caller-owned storage and deterministic Sans-I/O actions;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, message truncation and fragmentation matrices, illegal-order and duplicate-message tests, transcript/key-schedule checks, and independent-peer interoperability;
- exercise downgrade, replay, binder, ticket, zero-RTT, key-limit, backpressure, cancellation, alert, and terminal-secret-destruction paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished handshake states or unauthenticated output;
- `v0.50.0 implementation stop reached. Run pentest for this exact commit.`

### v0.51.0 - TLS 1.3 Conformance And Interoperability

Status: planned

Plan scope: Pass official vectors, truncation/fragmentation matrices, two independent peer implementations, and state-model/fuzz gates.

Goal: complete the **TLS 1.3 Conformance And Interoperability** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- encode the TLS 1.3 state, transcript, secret, record, configuration, and failure invariants as closed types with caller-owned storage and deterministic Sans-I/O actions;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, message truncation and fragmentation matrices, illegal-order and duplicate-message tests, transcript/key-schedule checks, and independent-peer interoperability;
- exercise downgrade, replay, binder, ticket, zero-RTT, key-limit, backpressure, cancellation, alert, and terminal-secret-destruction paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished handshake states or unauthenticated output;
- `v0.51.0 implementation stop reached. Run pentest for this exact commit.`

### v0.52.0 - TLS 1.3 Audit Gate

Status: planned

Plan scope: Complete an external TLS 1.3 audit and clean remediation retest.

Goal: complete the **TLS 1.3 Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- encode the TLS 1.3 state, transcript, secret, record, configuration, and failure invariants as closed types with caller-owned storage and deterministic Sans-I/O actions;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, message truncation and fragmentation matrices, illegal-order and duplicate-message tests, transcript/key-schedule checks, and independent-peer interoperability;
- exercise downgrade, replay, binder, ticket, zero-RTT, key-limit, backpressure, cancellation, alert, and terminal-secret-destruction paths;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished handshake states or unauthenticated output;
- `v0.52.0 implementation stop reached. Run pentest for this exact commit.`

### v0.53.0 - TLS 1.2 Policy Boundary

Status: planned

Plan scope: Freeze the explicit TLS 1.2 ECDHE+AEAD policy with EMS required and all weak or ambiguous constructions excluded.

Goal: complete the **TLS 1.2 Policy Boundary** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- keep TLS 1.2 independently selectable and restricted to ECDHE plus AEAD with EMS, protocol-specific ticket types, and no retry fallback from TLS 1.3;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run TLS 1.2 vectors, transcript and nonce tests, admitted-suite interoperability, extension matrices, resumption tests, and explicit-disablement checks;
- prove rejection of static RSA, CBC, SHA-1 signatures, compression, renegotiation, weak groups, downgrade ambiguity, and cross-version state reuse;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the hardened TLS 1.2 profile is isolated, explicitly configured, independently disableable, and covered by its own audit evidence;
- `v0.53.0 implementation stop reached. Run pentest for this exact commit.`

### v0.54.0 - TLS 1.2 PRF Records And Downgrade Defense

Status: planned

Plan scope: Implement the TLS 1.2 PRF, record nonces, EMS transcript binding, downgrade sentinel, and secure renegotiation/SCSV rejection rules.

Goal: complete the **TLS 1.2 PRF Records And Downgrade Defense** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- keep TLS 1.2 independently selectable and restricted to ECDHE plus AEAD with EMS, protocol-specific ticket types, and no retry fallback from TLS 1.3;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run TLS 1.2 vectors, transcript and nonce tests, admitted-suite interoperability, extension matrices, resumption tests, and explicit-disablement checks;
- prove rejection of static RSA, CBC, SHA-1 signatures, compression, renegotiation, weak groups, downgrade ambiguity, and cross-version state reuse;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the hardened TLS 1.2 profile is isolated, explicitly configured, independently disableable, and covered by its own audit evidence;
- `v0.54.0 implementation stop reached. Run pentest for this exact commit.`

### v0.55.0 - TLS 1.2 ECDHE State Machines

Status: planned

Plan scope: Implement isolated ECDHE_ECDSA and ECDHE_RSA TLS 1.2 client/server state machines.

Goal: complete the **TLS 1.2 ECDHE State Machines** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- keep TLS 1.2 independently selectable and restricted to ECDHE plus AEAD with EMS, protocol-specific ticket types, and no retry fallback from TLS 1.3;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run TLS 1.2 vectors, transcript and nonce tests, admitted-suite interoperability, extension matrices, resumption tests, and explicit-disablement checks;
- prove rejection of static RSA, CBC, SHA-1 signatures, compression, renegotiation, weak groups, downgrade ambiguity, and cross-version state reuse;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the hardened TLS 1.2 profile is isolated, explicitly configured, independently disableable, and covered by its own audit evidence;
- `v0.55.0 implementation stop reached. Run pentest for this exact commit.`

### v0.56.0 - TLS 1.2 Suite Completion

Status: planned

Plan scope: Admit only the six ECDSA/RSA combinations over AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.

Goal: complete the **TLS 1.2 Suite Completion** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- keep TLS 1.2 independently selectable and restricted to ECDHE plus AEAD with EMS, protocol-specific ticket types, and no retry fallback from TLS 1.3;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run TLS 1.2 vectors, transcript and nonce tests, admitted-suite interoperability, extension matrices, resumption tests, and explicit-disablement checks;
- prove rejection of static RSA, CBC, SHA-1 signatures, compression, renegotiation, weak groups, downgrade ambiguity, and cross-version state reuse;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the hardened TLS 1.2 profile is isolated, explicitly configured, independently disableable, and covered by its own audit evidence;
- `v0.56.0 implementation stop reached. Run pentest for this exact commit.`

### v0.57.0 - TLS 1.2 Resumption And Interoperability

Status: planned

Plan scope: Complete TLS 1.2 resumption, ticket isolation, extension hardening, interop, and downgrade corpora.

Goal: complete the **TLS 1.2 Resumption And Interoperability** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- keep TLS 1.2 independently selectable and restricted to ECDHE plus AEAD with EMS, protocol-specific ticket types, and no retry fallback from TLS 1.3;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run TLS 1.2 vectors, transcript and nonce tests, admitted-suite interoperability, extension matrices, resumption tests, and explicit-disablement checks;
- prove rejection of static RSA, CBC, SHA-1 signatures, compression, renegotiation, weak groups, downgrade ambiguity, and cross-version state reuse;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the hardened TLS 1.2 profile is isolated, explicitly configured, independently disableable, and covered by its own audit evidence;
- `v0.57.0 implementation stop reached. Run pentest for this exact commit.`

### v0.58.0 - TLS 1.2 Audit Gate

Status: planned

Plan scope: Complete a separate TLS 1.2 external audit; retain explicit configuration and independent disablement.

Goal: complete the **TLS 1.2 Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- keep TLS 1.2 independently selectable and restricted to ECDHE plus AEAD with EMS, protocol-specific ticket types, and no retry fallback from TLS 1.3;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run TLS 1.2 vectors, transcript and nonce tests, admitted-suite interoperability, extension matrices, resumption tests, and explicit-disablement checks;
- prove rejection of static RSA, CBC, SHA-1 signatures, compression, renegotiation, weak groups, downgrade ambiguity, and cross-version state reuse;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the hardened TLS 1.2 profile is isolated, explicitly configured, independently disableable, and covered by its own audit evidence;
- `v0.58.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 3: QUIC TLS, DTLS, And Post-Quantum Work

QUIC, DTLS, and post-quantum integrations retain distinct transport, resource, transcript, and standards boundaries.

### v0.59.0 - QUIC Encryption Levels And Secrets

Status: planned

Plan scope: Define distinct QUIC encryption-level and secret-install/discard types; forbid TLS versions below 1.3 and TLS KeyUpdate.

Goal: complete the **QUIC Encryption Levels And Secrets** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- keep QUIC encryption levels, CRYPTO streams, transport parameters, secret events, and buffering limits distinct while excluding TLS records and retransmission;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC 9001 vectors, encryption-level ordering, CRYPTO offset, secret install/discard, transport-parameter, loss/reorder, and independent QUIC peer tests;
- test future- and late-level data, duplicated or conflicting ranges, forbidden TLS KeyUpdate and post-handshake authentication, 0-RTT rejection, and buffer exhaustion;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- QUIC consumes only bounded TLS handshake actions and secrets, with no record-layer ownership or cross-level state ambiguity;
- `v0.59.0 implementation stop reached. Run pentest for this exact commit.`

### v0.60.0 - QUIC Transport Parameters

Status: planned

Plan scope: Implement strict QUIC transport-parameter parsing, validation, and transcript binding.

Goal: complete the **QUIC Transport Parameters** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- keep QUIC encryption levels, CRYPTO streams, transport parameters, secret events, and buffering limits distinct while excluding TLS records and retransmission;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC 9001 vectors, encryption-level ordering, CRYPTO offset, secret install/discard, transport-parameter, loss/reorder, and independent QUIC peer tests;
- test future- and late-level data, duplicated or conflicting ranges, forbidden TLS KeyUpdate and post-handshake authentication, 0-RTT rejection, and buffer exhaustion;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- QUIC consumes only bounded TLS handshake actions and secrets, with no record-layer ownership or cross-level state ambiguity;
- `v0.60.0 implementation stop reached. Run pentest for this exact commit.`

### v0.61.0 - QUIC Sans-I/O Handshake

Status: planned

Plan scope: Implement QUIC Sans-I/O handshake actions, ordered CRYPTO offsets, bounded future-level buffering, and alert mapping.

Goal: complete the **QUIC Sans-I/O Handshake** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- keep QUIC encryption levels, CRYPTO streams, transport parameters, secret events, and buffering limits distinct while excluding TLS records and retransmission;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC 9001 vectors, encryption-level ordering, CRYPTO offset, secret install/discard, transport-parameter, loss/reorder, and independent QUIC peer tests;
- test future- and late-level data, duplicated or conflicting ranges, forbidden TLS KeyUpdate and post-handshake authentication, 0-RTT rejection, and buffer exhaustion;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- QUIC consumes only bounded TLS handshake actions and secrets, with no record-layer ownership or cross-level state ambiguity;
- `v0.61.0 implementation stop reached. Run pentest for this exact commit.`

### v0.62.0 - QUIC Conformance And Audit

Status: planned

Plan scope: Pass QUIC vectors plus loss, reorder, discard, 0-RTT, interoperability, and external review gates.

Goal: complete the **QUIC Conformance And Audit** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- keep QUIC encryption levels, CRYPTO streams, transport parameters, secret events, and buffering limits distinct while excluding TLS records and retransmission;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC 9001 vectors, encryption-level ordering, CRYPTO offset, secret install/discard, transport-parameter, loss/reorder, and independent QUIC peer tests;
- test future- and late-level data, duplicated or conflicting ranges, forbidden TLS KeyUpdate and post-handshake authentication, 0-RTT rejection, and buffer exhaustion;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- QUIC consumes only bounded TLS handshake actions and secrets, with no record-layer ownership or cross-level state ambiguity;
- `v0.62.0 implementation stop reached. Run pentest for this exact commit.`

### v0.63.0 - DTLS Epochs And Replay Windows

Status: planned

Plan scope: Implement DTLS epochs, compact headers, sequence reconstruction, AEAD nonces, and fixed authenticated replay windows.

Goal: complete the **DTLS Epochs And Replay Windows** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- make epochs, replay windows, reassembly, canonical transcripts, flights, timers, cookies, amplification, PMTU, and retransmission budgets explicit and caller-owned;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplication, overlap, conflicting-fragment, ACK, timer, retransmission, epoch-retention, and independent-peer matrices;
- exercise spoofed-address amplification, replay before and after authentication, sequence exhaustion, sparse-fragment pressure, stale timers, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- DTLS state remains bounded and deterministic under an adversarial datagram network and releases no unauthenticated protocol transition;
- `v0.63.0 implementation stop reached. Run pentest for this exact commit.`

### v0.64.0 - DTLS Fragmentation And Reassembly

Status: planned

Plan scope: Implement caller-owned bounded fragmentation/reassembly with overlap and conflicting-fragment rejection.

Goal: complete the **DTLS Fragmentation And Reassembly** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- make epochs, replay windows, reassembly, canonical transcripts, flights, timers, cookies, amplification, PMTU, and retransmission budgets explicit and caller-owned;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplication, overlap, conflicting-fragment, ACK, timer, retransmission, epoch-retention, and independent-peer matrices;
- exercise spoofed-address amplification, replay before and after authentication, sequence exhaustion, sparse-fragment pressure, stale timers, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- DTLS state remains bounded and deterministic under an adversarial datagram network and releases no unauthenticated protocol transition;
- `v0.64.0 implementation stop reached. Run pentest for this exact commit.`

### v0.65.0 - DTLS Flights ACKs And Timers

Status: planned

Plan scope: Implement deterministic flights, ACKs, typed timer actions, cached retransmission, backoff, and congestion limits.

Goal: complete the **DTLS Flights ACKs And Timers** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- make epochs, replay windows, reassembly, canonical transcripts, flights, timers, cookies, amplification, PMTU, and retransmission budgets explicit and caller-owned;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplication, overlap, conflicting-fragment, ACK, timer, retransmission, epoch-retention, and independent-peer matrices;
- exercise spoofed-address amplification, replay before and after authentication, sequence exhaustion, sparse-fragment pressure, stale timers, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- DTLS state remains bounded and deterministic under an adversarial datagram network and releases no unauthenticated protocol transition;
- `v0.65.0 implementation stop reached. Run pentest for this exact commit.`

### v0.66.0 - DTLS Address Validation And Amplification Defense

Status: planned

Plan scope: Implement cookies, address validation, amplification budgets, and deterministic PMTU/backoff policy.

Goal: complete the **DTLS Address Validation And Amplification Defense** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- make epochs, replay windows, reassembly, canonical transcripts, flights, timers, cookies, amplification, PMTU, and retransmission budgets explicit and caller-owned;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplication, overlap, conflicting-fragment, ACK, timer, retransmission, epoch-retention, and independent-peer matrices;
- exercise spoofed-address amplification, replay before and after authentication, sequence exhaustion, sparse-fragment pressure, stale timers, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- DTLS state remains bounded and deterministic under an adversarial datagram network and releases no unauthenticated protocol transition;
- `v0.66.0 implementation stop reached. Run pentest for this exact commit.`

### v0.67.0 - DTLS 1.3 State Machines

Status: planned

Plan scope: Complete DTLS 1.3 client/server states, epoch retention, exhaustion closure, and protocol-specific key updates.

Goal: complete the **DTLS 1.3 State Machines** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- make epochs, replay windows, reassembly, canonical transcripts, flights, timers, cookies, amplification, PMTU, and retransmission budgets explicit and caller-owned;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplication, overlap, conflicting-fragment, ACK, timer, retransmission, epoch-retention, and independent-peer matrices;
- exercise spoofed-address amplification, replay before and after authentication, sequence exhaustion, sparse-fragment pressure, stale timers, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- DTLS state remains bounded and deterministic under an adversarial datagram network and releases no unauthenticated protocol transition;
- `v0.67.0 implementation stop reached. Run pentest for this exact commit.`

### v0.68.0 - Hardened DTLS 1.2

Status: planned

Plan scope: Implement hardened DTLS 1.2 using only the admitted TLS 1.2 ECDHE+AEAD profile.

Goal: complete the **Hardened DTLS 1.2** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- make epochs, replay windows, reassembly, canonical transcripts, flights, timers, cookies, amplification, PMTU, and retransmission budgets explicit and caller-owned;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplication, overlap, conflicting-fragment, ACK, timer, retransmission, epoch-retention, and independent-peer matrices;
- exercise spoofed-address amplification, replay before and after authentication, sequence exhaustion, sparse-fragment pressure, stale timers, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- DTLS state remains bounded and deterministic under an adversarial datagram network and releases no unauthenticated protocol transition;
- `v0.68.0 implementation stop reached. Run pentest for this exact commit.`

### v0.69.0 - DTLS Conformance And Audit

Status: planned

Plan scope: Pass DTLS loss/reorder/duplicate, fuzz, interoperability, hostile-load, and external audit gates.

Goal: complete the **DTLS Conformance And Audit** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- make epochs, replay windows, reassembly, canonical transcripts, flights, timers, cookies, amplification, PMTU, and retransmission budgets explicit and caller-owned;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplication, overlap, conflicting-fragment, ACK, timer, retransmission, epoch-retention, and independent-peer matrices;
- exercise spoofed-address amplification, replay before and after authentication, sequence exhaustion, sparse-fragment pressure, stale timers, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- DTLS state remains bounded and deterministic under an adversarial datagram network and releases no unauthenticated protocol transition;
- `v0.69.0 implementation stop reached. Run pentest for this exact commit.`

### v0.70.0 - ML-KEM Arithmetic And Encoding

Status: planned

Plan scope: Implement ML-KEM polynomial, NTT, sampling, and canonical encoding/decoding foundations.

Goal: complete the **ML-KEM Arithmetic And Encoding** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- implement only standards-traced ML-KEM parameters and exact hybrid encodings with canonical lengths, component order, transcript binding, and explicit experimental boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run FIPS 203 vectors and errata, malformed key/ciphertext corpora, differential tests, stack/resource profiles, implicit-rejection tests, and supported-target evidence;
- run constant-time decapsulation, failure-path, downgrade, fragmentation, hybrid-combiner, code-point, and classical-only fallback tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- PQC scope has external review and either final standards admission or explicit exclusion from the stable compatibility and FIPS claims;
- `v0.70.0 implementation stop reached. Run pentest for this exact commit.`

### v0.71.0 - ML-KEM Key Generation And Encapsulation

Status: planned

Plan scope: Implement ML-KEM-512/768/1024 key generation and encapsulation with FIPS 203 and applicable SP 800-227 checks.

Goal: complete the **ML-KEM Key Generation And Encapsulation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- implement only standards-traced ML-KEM parameters and exact hybrid encodings with canonical lengths, component order, transcript binding, and explicit experimental boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run FIPS 203 vectors and errata, malformed key/ciphertext corpora, differential tests, stack/resource profiles, implicit-rejection tests, and supported-target evidence;
- run constant-time decapsulation, failure-path, downgrade, fragmentation, hybrid-combiner, code-point, and classical-only fallback tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- PQC scope has external review and either final standards admission or explicit exclusion from the stable compatibility and FIPS claims;
- `v0.71.0 implementation stop reached. Run pentest for this exact commit.`

### v0.72.0 - ML-KEM Decapsulation And Implicit Rejection

Status: planned

Plan scope: Implement constant-time ML-KEM decapsulation and implicit rejection with malformed-ciphertext and side-channel campaigns.

Goal: complete the **ML-KEM Decapsulation And Implicit Rejection** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- implement only standards-traced ML-KEM parameters and exact hybrid encodings with canonical lengths, component order, transcript binding, and explicit experimental boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run FIPS 203 vectors and errata, malformed key/ciphertext corpora, differential tests, stack/resource profiles, implicit-rejection tests, and supported-target evidence;
- run constant-time decapsulation, failure-path, downgrade, fragmentation, hybrid-combiner, code-point, and classical-only fallback tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- PQC scope has external review and either final standards admission or explicit exclusion from the stable compatibility and FIPS claims;
- `v0.72.0 implementation stop reached. Run pentest for this exact commit.`

### v0.73.0 - Standard Hybrid Groups

Status: planned

Plan scope: Implement only the exact predefined X25519MLKEM768, P256MLKEM768, and P384MLKEM1024 group encodings and combiner order.

Goal: complete the **Standard Hybrid Groups** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- implement only standards-traced ML-KEM parameters and exact hybrid encodings with canonical lengths, component order, transcript binding, and explicit experimental boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run FIPS 203 vectors and errata, malformed key/ciphertext corpora, differential tests, stack/resource profiles, implicit-rejection tests, and supported-target evidence;
- run constant-time decapsulation, failure-path, downgrade, fragmentation, hybrid-combiner, code-point, and classical-only fallback tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- PQC scope has external review and either final standards admission or explicit exclusion from the stable compatibility and FIPS claims;
- `v0.73.0 implementation stop reached. Run pentest for this exact commit.`

### v0.74.0 - Hybrid Protocol Integration

Status: planned

Plan scope: Complete hybrid TLS/DTLS/QUIC resource, fragmentation, downgrade, transcript-binding, and interoperability gates.

Goal: complete the **Hybrid Protocol Integration** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- implement only standards-traced ML-KEM parameters and exact hybrid encodings with canonical lengths, component order, transcript binding, and explicit experimental boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run FIPS 203 vectors and errata, malformed key/ciphertext corpora, differential tests, stack/resource profiles, implicit-rejection tests, and supported-target evidence;
- run constant-time decapsulation, failure-path, downgrade, fragmentation, hybrid-combiner, code-point, and classical-only fallback tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- PQC scope has external review and either final standards admission or explicit exclusion from the stable compatibility and FIPS claims;
- `v0.74.0 implementation stop reached. Run pentest for this exact commit.`

### v0.75.0 - PQ Standards And Audit Gate

Status: planned

Plan scope: Complete PQ external review and standards freeze; admit final RFC groups or keep draft work experimental and outside the GA compatibility promise.

Goal: complete the **PQ Standards And Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- implement only standards-traced ML-KEM parameters and exact hybrid encodings with canonical lengths, component order, transcript binding, and explicit experimental boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run FIPS 203 vectors and errata, malformed key/ciphertext corpora, differential tests, stack/resource profiles, implicit-rejection tests, and supported-target evidence;
- run constant-time decapsulation, failure-path, downgrade, fragmentation, hybrid-combiner, code-point, and classical-only fallback tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- PQC scope has external review and either final standards admission or explicit exclusion from the stable compatibility and FIPS claims;
- `v0.75.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 4: FIPS Artifact Boundary And Historical Isolation

FIPS is treated as an exact-build module and operational-environment claim, while historical protocol releases stay independent.

### v0.76.0 - FIPS Module Boundary

Status: planned

Plan scope: Freeze the FIPS module/artifact boundary, exact operational environments, ports, services, roles, SSP inventory, build inputs, and non-approved exclusions.

Goal: complete the **FIPS Module Boundary** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind the narrow cryptographic module to exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved/non-approved boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, failure injection, service-indicator, SSP lifecycle, entropy/DRBG, reproducible-artifact, and applicable ACVTS/CAVP evidence;
- prove the permanent failure latch, zeroization completion, non-approved service separation, no additive feature activation, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- claims match the accredited evidence exactly; algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.76.0 implementation stop reached. Run pentest for this exact commit.`

### v0.77.0 - Approved Provider And Service Indicator

Status: planned

Plan scope: Implement a sealed approved-only provider and unambiguous per-service approved indicator; do not expose an additive `fips` feature.

Goal: complete the **Approved Provider And Service Indicator** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind the narrow cryptographic module to exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved/non-approved boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, failure injection, service-indicator, SSP lifecycle, entropy/DRBG, reproducible-artifact, and applicable ACVTS/CAVP evidence;
- prove the permanent failure latch, zeroization completion, non-approved service separation, no additive feature activation, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- claims match the accredited evidence exactly; algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.77.0 implementation stop reached. Run pentest for this exact commit.`

### v0.78.0 - FIPS Self-Tests And Failure Latch

Status: planned

Plan scope: Implement integrity, CAST/KAT, pairwise-consistency, permanent failure latch, and deterministic fault-injection evidence.

Goal: complete the **FIPS Self-Tests And Failure Latch** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind the narrow cryptographic module to exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved/non-approved boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, failure injection, service-indicator, SSP lifecycle, entropy/DRBG, reproducible-artifact, and applicable ACVTS/CAVP evidence;
- prove the permanent failure latch, zeroization completion, non-approved service separation, no additive feature activation, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- claims match the accredited evidence exactly; algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.78.0 implementation stop reached. Run pentest for this exact commit.`

### v0.79.0 - SSP Lifecycle And Zeroization Services

Status: planned

Plan scope: Define SSP entry, output, storage, lifetime, and zeroization services with secret-free auditable status events.

Goal: complete the **SSP Lifecycle And Zeroization Services** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind the narrow cryptographic module to exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved/non-approved boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, failure injection, service-indicator, SSP lifecycle, entropy/DRBG, reproducible-artifact, and applicable ACVTS/CAVP evidence;
- prove the permanent failure latch, zeroization completion, non-approved service separation, no additive feature activation, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- claims match the accredited evidence exactly; algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.79.0 implementation stop reached. Run pentest for this exact commit.`

### v0.80.0 - Entropy And DRBG Boundary

Status: planned

Plan scope: Define the SP 800-90 entropy/DRBG boundary, health tests, reseed/failure behavior, and platform entropy evidence.

Goal: complete the **Entropy And DRBG Boundary** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind the narrow cryptographic module to exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved/non-approved boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, failure injection, service-indicator, SSP lifecycle, entropy/DRBG, reproducible-artifact, and applicable ACVTS/CAVP evidence;
- prove the permanent failure latch, zeroization completion, non-approved service separation, no additive feature activation, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- claims match the accredited evidence exactly; algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.80.0 implementation stop reached. Run pentest for this exact commit.`

### v0.81.0 - ACVTS And CAVP Evidence

Status: planned

Plan scope: Complete ACVTS/CAVP campaigns for every approved implementation and parameter set.

Goal: complete the **ACVTS And CAVP Evidence** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind the narrow cryptographic module to exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved/non-approved boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, failure injection, service-indicator, SSP lifecycle, entropy/DRBG, reproducible-artifact, and applicable ACVTS/CAVP evidence;
- prove the permanent failure latch, zeroization completion, non-approved service separation, no additive feature activation, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- claims match the accredited evidence exactly; algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.81.0 implementation stop reached. Run pentest for this exact commit.`

### v0.82.0 - CMVP Submission Artifacts

Status: planned

Plan scope: Produce the CMVP Security Policy, finite-state model, source-to-object trace, and reproducible module artifacts.

Goal: complete the **CMVP Submission Artifacts** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind the narrow cryptographic module to exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved/non-approved boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, failure injection, service-indicator, SSP lifecycle, entropy/DRBG, reproducible-artifact, and applicable ACVTS/CAVP evidence;
- prove the permanent failure latch, zeroization completion, non-approved service separation, no additive feature activation, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- claims match the accredited evidence exactly; algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.82.0 implementation stop reached. Run pentest for this exact commit.`

### v0.83.0 - Accredited FIPS Evaluation

Status: planned

Plan scope: Complete accredited-lab FIPS 140-3 evaluation, remediation, retest, and certificate/caveat recording; make no validation claim before issuance.

Goal: complete the **Accredited FIPS Evaluation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind the narrow cryptographic module to exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved/non-approved boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, failure injection, service-indicator, SSP lifecycle, entropy/DRBG, reproducible-artifact, and applicable ACVTS/CAVP evidence;
- prove the permanent failure latch, zeroization completion, non-approved service separation, no additive feature activation, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- claims match the accredited evidence exactly; algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.83.0 implementation stop reached. Run pentest for this exact commit.`

### v0.84.0 - Boundary And Package Audit

Status: planned

Plan scope: Complete the final modern/historical/FIPS dependency-boundary and package-content audit.

Goal: complete the **Boundary And Package Audit** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- bind the narrow cryptographic module to exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved/non-approved boundaries;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, failure injection, service-indicator, SSP lifecycle, entropy/DRBG, reproducible-artifact, and applicable ACVTS/CAVP evidence;
- prove the permanent failure latch, zeroization completion, non-approved service separation, no additive feature activation, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- claims match the accredited evidence exactly; algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.84.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 5: Stable Integration, Assurance, And General Availability

Stable integration follows boundary work; assurance, audit, remediation, rehearsal, and immutable promotion close the modern 1.0 line.

### v0.85.0 - Facade Configuration Typestates

Status: planned

Plan scope: Freeze facade typestates for exact modern versions, suites, trust, identity, resources, revocation, and 0-RTT policy; expose no raw crypto re-export.

Goal: complete the **Facade Configuration Typestates** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze application-facing typestates and Sans-I/O actions with explicit entropy, randomness, wall-time, monotonic-time, storage, accelerator, cancellation, and workspace contracts;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic action traces, adapter fault injection, zero-allocation accounting, stack ceilings, rotation tests, and every supported target;
- exercise unavailable clocks or entropy, partial providers, asynchronous cancellation, backpressure, stale handles, storage races, resource exhaustion, and forbidden fallback;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- integration is runtime-neutral, bounded, portable, and incapable of weakening a transcript or policy through adapter behavior;
- `v0.85.0 implementation stop reached. Run pentest for this exact commit.`

### v0.86.0 - Stable Sans-I/O API

Status: planned

Plan scope: Freeze the deterministic Sans-I/O client/server `Event -> Action` contract, backpressure, cancellation, pending crypto, and compile-fail misuse suite.

Goal: complete the **Stable Sans-I/O API** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze application-facing typestates and Sans-I/O actions with explicit entropy, randomness, wall-time, monotonic-time, storage, accelerator, cancellation, and workspace contracts;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic action traces, adapter fault injection, zero-allocation accounting, stack ceilings, rotation tests, and every supported target;
- exercise unavailable clocks or entropy, partial providers, asynchronous cancellation, backpressure, stale handles, storage races, resource exhaustion, and forbidden fallback;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- integration is runtime-neutral, bounded, portable, and incapable of weakening a transcript or policy through adapter behavior;
- `v0.86.0 implementation stop reached. Run pentest for this exact commit.`

### v0.87.0 - Host Platform Adapters

Status: planned

Plan scope: Add host adapters for OS entropy, secure randomness, separate wall/monotonic clocks, and transport/storage examples plus async guidance.

Goal: complete the **Host Platform Adapters** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze application-facing typestates and Sans-I/O actions with explicit entropy, randomness, wall-time, monotonic-time, storage, accelerator, cancellation, and workspace contracts;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic action traces, adapter fault injection, zero-allocation accounting, stack ceilings, rotation tests, and every supported target;
- exercise unavailable clocks or entropy, partial providers, asynchronous cancellation, backpressure, stale handles, storage races, resource exhaustion, and forbidden fallback;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- integration is runtime-neutral, bounded, portable, and incapable of weakening a transcript or policy through adapter behavior;
- `v0.87.0 implementation stop reached. Run pentest for this exact commit.`

### v0.88.0 - Zero-Allocation And Resource Proof

Status: planned

Plan scope: Prove the zero-allocation profile with caller-owned buffers, exact workspace sizes, stack ceilings, concurrency limits, and hostile-load budgets.

Goal: complete the **Zero-Allocation And Resource Proof** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze application-facing typestates and Sans-I/O actions with explicit entropy, randomness, wall-time, monotonic-time, storage, accelerator, cancellation, and workspace contracts;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic action traces, adapter fault injection, zero-allocation accounting, stack ceilings, rotation tests, and every supported target;
- exercise unavailable clocks or entropy, partial providers, asynchronous cancellation, backpressure, stale handles, storage races, resource exhaustion, and forbidden fallback;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- integration is runtime-neutral, bounded, portable, and incapable of weakening a transcript or policy through adapter behavior;
- `v0.88.0 implementation stop reached. Run pentest for this exact commit.`

### v0.89.0 - Aesynx Qualification

Status: planned

Plan scope: Qualify the Aesynx target and its entropy/time/transport/accelerator adapters with boot-to-handshake and lifecycle tests when the target is available.

Goal: complete the **Aesynx Qualification** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze application-facing typestates and Sans-I/O actions with explicit entropy, randomness, wall-time, monotonic-time, storage, accelerator, cancellation, and workspace contracts;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic action traces, adapter fault injection, zero-allocation accounting, stack ceilings, rotation tests, and every supported target;
- exercise unavailable clocks or entropy, partial providers, asynchronous cancellation, backpressure, stale handles, storage races, resource exhaustion, and forbidden fallback;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- integration is runtime-neutral, bounded, portable, and incapable of weakening a transcript or policy through adapter behavior;
- `v0.89.0 implementation stop reached. Run pentest for this exact commit.`

### v0.90.0 - Operational State Rotation

Status: planned

Plan scope: Complete session cache, ticket-key rotation, anti-replay storage, certificate rotation, and trust-anchor rotation contracts.

Goal: complete the **Operational State Rotation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze application-facing typestates and Sans-I/O actions with explicit entropy, randomness, wall-time, monotonic-time, storage, accelerator, cancellation, and workspace contracts;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic action traces, adapter fault injection, zero-allocation accounting, stack ceilings, rotation tests, and every supported target;
- exercise unavailable clocks or entropy, partial providers, asynchronous cancellation, backpressure, stale handles, storage races, resource exhaustion, and forbidden fallback;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- integration is runtime-neutral, bounded, portable, and incapable of weakening a transcript or policy through adapter behavior;
- `v0.90.0 implementation stop reached. Run pentest for this exact commit.`

### v0.91.0 - Core Optional Protocol Facilities

Status: planned

Plan scope: Complete ALPN, SNI, record-size-limit, raw public keys, exporters, and channel-binding behavior in bounded optional modules.

Goal: complete the **Core Optional Protocol Facilities** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze application-facing typestates and Sans-I/O actions with explicit entropy, randomness, wall-time, monotonic-time, storage, accelerator, cancellation, and workspace contracts;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic action traces, adapter fault injection, zero-allocation accounting, stack ceilings, rotation tests, and every supported target;
- exercise unavailable clocks or entropy, partial providers, asynchronous cancellation, backpressure, stale handles, storage races, resource exhaustion, and forbidden fallback;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- integration is runtime-neutral, bounded, portable, and incapable of weakening a transcript or policy through adapter behavior;
- `v0.91.0 implementation stop reached. Run pentest for this exact commit.`

### v0.92.0 - Bounded Modern Extensions

Status: planned

Plan scope: Complete ECH, delegated credentials, and certificate compression as independently bounded optional modules, admitting only finalized standards.

Goal: complete the **Bounded Modern Extensions** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze application-facing typestates and Sans-I/O actions with explicit entropy, randomness, wall-time, monotonic-time, storage, accelerator, cancellation, and workspace contracts;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic action traces, adapter fault injection, zero-allocation accounting, stack ceilings, rotation tests, and every supported target;
- exercise unavailable clocks or entropy, partial providers, asynchronous cancellation, backpressure, stale handles, storage races, resource exhaustion, and forbidden fallback;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- integration is runtime-neutral, bounded, portable, and incapable of weakening a transcript or policy through adapter behavior;
- `v0.92.0 implementation stop reached. Run pentest for this exact commit.`

### v0.93.0 - Formal Harnesses

Status: planned

Plan scope: Complete Kani proofs for cursors, lengths, state reachability, exhaustion, replay windows, and secret-release invariants.

Goal: complete the **Formal Harnesses** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, and operational evidence for the exact admitted scope;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named assurance campaign across every relevant compiler, target, provider, feature set, package archive, and independent implementation;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, and incident procedures;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the evidence set is complete for the exact commit, unresolved findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.93.0 implementation stop reached. Run pentest for this exact commit.`

### v0.94.0 - Fuzz And Differential Campaign

Status: planned

Plan scope: Complete isolated parser/state fuzzing, deterministic mutation, differential corpora, and crash minimization without adding shipped dependencies.

Goal: complete the **Fuzz And Differential Campaign** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, and operational evidence for the exact admitted scope;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named assurance campaign across every relevant compiler, target, provider, feature set, package archive, and independent implementation;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, and incident procedures;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the evidence set is complete for the exact commit, unresolved findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.94.0 implementation stop reached. Run pentest for this exact commit.`

### v0.95.0 - Memory And Side-Channel Evidence

Status: planned

Plan scope: Complete Miri/sanitizer/UB evidence and compiler/target constant-time assembly plus statistical side-channel matrices.

Goal: complete the **Memory And Side-Channel Evidence** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, and operational evidence for the exact admitted scope;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named assurance campaign across every relevant compiler, target, provider, feature set, package archive, and independent implementation;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, and incident procedures;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the evidence set is complete for the exact commit, unresolved findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.95.0 implementation stop reached. Run pentest for this exact commit.`

### v0.96.0 - Sustained Platform And Hostile-Load Qualification

Status: planned

Plan scope: Sustain Linux, Windows, macOS, BSD, mobile, bare-metal, and available Aesynx qualification under concurrency and hostile load.

Goal: complete the **Sustained Platform And Hostile-Load Qualification** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, and operational evidence for the exact admitted scope;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named assurance campaign across every relevant compiler, target, provider, feature set, package archive, and independent implementation;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, and incident procedures;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the evidence set is complete for the exact commit, unresolved findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.96.0 implementation stop reached. Run pentest for this exact commit.`

### v0.97.0 - Consolidated External Audits

Status: planned

Plan scope: Complete exact-commit external crypto, PKI, TLS, DTLS, QUIC, FIPS-boundary, and systems-integration audits.

Goal: complete the **Consolidated External Audits** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, and operational evidence for the exact admitted scope;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named assurance campaign across every relevant compiler, target, provider, feature set, package archive, and independent implementation;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, and incident procedures;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the evidence set is complete for the exact commit, unresolved findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.97.0 implementation stop reached. Run pentest for this exact commit.`

### v0.98.0 - Remediation And API Freeze

Status: planned

Plan scope: Remediate and cleanly retest every admitted finding; freeze public API, features, requirements, migration guidance, and incident procedures.

Goal: complete the **Remediation And API Freeze** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, and operational evidence for the exact admitted scope;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named assurance campaign across every relevant compiler, target, provider, feature set, package archive, and independent implementation;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, and incident procedures;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the evidence set is complete for the exact commit, unresolved findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.98.0 implementation stop reached. Run pentest for this exact commit.`

### v0.99.0 - Clean-Room Release Rehearsal

Status: planned

Plan scope: Pass a reproducible clean-room release rehearsal, installation, rollback, key-compromise, and disaster-recovery exercises.

Goal: complete the **Clean-Room Release Rehearsal** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, and operational evidence for the exact admitted scope;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named assurance campaign across every relevant compiler, target, provider, feature set, package archive, and independent implementation;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, and incident procedures;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the evidence set is complete for the exact commit, unresolved findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.99.0 implementation stop reached. Run pentest for this exact commit.`

### v1.0.0-rc.1 - Exact Production Candidate

Status: planned

Plan scope: Build final artifacts once and freeze source, compiler, flags, archives, SBOM, checksums, provenance, documentation, and the pentested exact commit.

Goal: complete the **Exact Production Candidate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze or promote only the approved modern artifacts, manifests, source, compiler, flags, archives, SBOM, checksums, provenance, documentation, and release metadata;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- reproduce artifacts in a clean environment, compare every byte and checksum, verify installation and rollback, and rerun all production-admission gates;
- exercise key-compromise and disaster procedures, registry/package inspection, downstream compatibility, and proof that historical or draft scope is absent;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the promoted stable artifacts are byte-identical to the approved candidate and every public claim maps to permanent exact-commit evidence;
- `v1.0.0-rc.1 implementation stop reached. Run pentest for this exact commit.`

### v1.0.0 - First Serious Production-Ready Brynja TLS Release

Status: planned

Plan scope: Promote only the byte-identical approved candidate without rebuild, source change, metadata drift, or expanded capability claim.

Goal: complete the **First Serious Production-Ready Brynja TLS Release** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, failure, and package boundaries;
- freeze or promote only the approved modern artifacts, manifests, source, compiler, flags, archives, SBOM, checksums, provenance, documentation, and release metadata;
- update the requirements ledger, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- reproduce artifacts in a clean environment, compare every byte and checksum, verify installation and rollback, and rerun all production-admission gates;
- exercise key-compromise and disaster procedures, registry/package inspection, downstream compatibility, and proof that historical or draft scope is absent;
- pass full repository checks, all promised Rust versions and targets, dependency
  policy, advisory scans, SBOM comparison, package inspection, documentation
  links, and modern/historical graph isolation.

Exit criteria:

- the promoted stable artifacts are byte-identical to the approved candidate and every public claim maps to permanent exact-commit evidence;
- `v1.0.0 implementation stop reached. Run pentest for this exact commit.`
