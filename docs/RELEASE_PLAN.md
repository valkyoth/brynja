# Brynja Release Plan To 1.0

Status: normative planning document

This plan is deliberately granular. Brynja processes hostile input and will
protect authentication material and application plaintext, so every milestone
must be independently reviewable, testable, pentestable, and safe to stop.

## Version-Plan Synchronization

[VERSION_PLAN.md](VERSION_PLAN.md) defines every modern release's title,
exclusive scope, and order. Each section below repeats the title in its heading
and the scope as `Plan scope:`. `scripts/check-release-plan.py` fails on a
missing, reordered, duplicated, renamed, or altered release.

Tags use `v0.N.0` for review milestones, `v1.0.0-rc.N` for immutable
production candidates, and `v1.0.0` for the first serious production-ready
modern TLS release. Split any growing scope; never merge adjacent work to
preserve a schedule or number.

## Release Principles

Every release requires mapped normative requirements, explicit resource and
work limits, secret-lifetime and effect boundaries, negative and adversarial
tests, documented limitations, release notes, no third-party crates in
repository Cargo manifests, `no_std` production evidence, source-file length
enforcement, SBOM comparison, clean local and CI gates, CodeQL Default review,
and a completed pentest for the exact implementation commit.

Pinned assurance tools may run externally but never become normal, optional,
development, test, build, fuzz, or tooling dependencies in repository Cargo
manifests without an explicit future policy change. Self-tests do not establish
cryptographic security. Official vectors, differential and interoperability
tests, resource analysis, compiler-output and side-channel evidence, formal
methods, external audit, and pentest are complementary.

The modern facade never depends on historical packages. FIPS is an exact-build
module and operational-environment claim, never an additive feature or a claim
inferred from vectors. Draft PQ groups remain experimental and outside stable
compatibility until their standards and code points are final.

## Required Milestone Contract

Every milestone contains, in order, Status, Plan scope, Goal, Deliverables,
Verification, and Exit criteria. Deliverables identify applicable input, state,
resource, secret, effect, failure, and package boundaries. Verification includes
positive, negative, boundary, deliberate-failure, and exact-target evidence.

Repository-wide checks are additive to milestone checks. Completing one stop
does not admit adjacent capability or broaden earlier claims.

## Pentest Before Every Tag

A tag is forbidden until `scripts/checks.sh`, `cargo deny check`,
`cargo audit --deny warnings`, latest-tool checks, SBOM comparison, release
notes, GitHub CI, CodeQL Default review, package checks, and the version gate
pass. The permanent pentest report names the exact 40-character
`git rev-parse HEAD`, date, tester, scope, and `Status: PASS`; the gate
compares that commit byte-for-byte with HEAD.

Implementation stops before pentest. Findings may live temporarily in ignored
root `PENTEST.md`, then must be fixed, documented, regression-tested, removed,
and cleanly retested. Tags and publishing happen only when explicitly requested.

## Historical Package Release Line

Historical packages use independent SemVer lines and never block or inherit the
modern facade's `1.0.0` claim. Repeat these stages separately for TLS 1.1, TLS
1.0, SSL 3, SSL 2, WTLS, PCT, and SNP. SSL 1 remains research-only and
unpublished.

| Stage | Required result |
| --- | --- |
| `H0.1.0` | Authenticate sources and rights, record errata, publish conspicuous insecurity warnings, and freeze the protocol threat model. |
| `H0.2.0` | Implement only the protocol-specific bounded wire codec. |
| `H0.3.0` | Implement an isolated state machine with no shared modern configuration, negotiation, credentials, caches, tickets, or fallback. |
| `H0.4.0` | Bind audited shared primitives and keep required weak primitives in a historical-only crypto package. |
| `H0.5.0` | Complete controlled client-only interoperability and containment evidence. |
| `H0.6.0` | Add server interoperability only when separately justified and reviewed for amplification and hostile load. |
| `H0.7.0` | Require separate listeners, policy, credentials, storage, diagnostics, and process-containment guidance. |
| `H0.8.0` | Complete a protocol-specific external audit and pentest and verify every warning and non-fallback property. |

## Phase 0: Repository, Effects, And Wire Foundations

Repository enforcement and bounded core types precede constant-time, entropy, clock, provider, FIPS-aware, and wire contracts.

### v0.1.0 - Workspace Foundation

Status: awaiting pentest

Plan scope: Preserve the existing workspace foundation with no cryptographic or protocol security claim.

Goal: complete the **Workspace Foundation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make policy executable through fail-closed scripts, broken fixtures, immutable evidence inputs, and documented ownership, approval, and release boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- exercise policy scripts with positive and deliberately broken dependency, feature, metadata, evidence, workflow, and release-state fixtures;
- inspect clean archives, source locks, CI permissions, branch and tag assumptions, tool pinning, and reproducibility inputs;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- repository evidence and enforcement agree and deliberate violations fail before artifacts, tags, or capability claims;
- `v0.1.0 implementation stop reached. Run pentest for this exact commit.`

### v0.2.0 - Release And Isolation Enforcement

Status: planned

Plan scope: Fix exact-HEAD pentest comparison, validate all-feature graphs and every package class, add negative modern/historical isolation fixtures, and document protected release controls.

Goal: complete the **Release And Isolation Enforcement** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make policy executable through fail-closed scripts, broken fixtures, immutable evidence inputs, and documented ownership, approval, and release boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- exercise policy scripts with positive and deliberately broken dependency, feature, metadata, evidence, workflow, and release-state fixtures;
- inspect clean archives, source locks, CI permissions, branch and tag assumptions, tool pinning, and reproducibility inputs;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- repository evidence and enforcement agree and deliberate violations fail before artifacts, tags, or capability claims;
- `v0.2.0 implementation stop reached. Run pentest for this exact commit.`

### v0.3.0 - Requirements And Standards Ledger

Status: planned

Plan scope: Build the requirements ledger for RFC 9846, RFC 5280, RFC 9001, RFC 9147, RFC 9180, applicable NIST standards and errata, and frozen IANA snapshots; map every normative requirement.

Goal: complete the **Requirements And Standards Ledger** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make policy executable through fail-closed scripts, broken fixtures, immutable evidence inputs, and documented ownership, approval, and release boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- exercise policy scripts with positive and deliberately broken dependency, feature, metadata, evidence, workflow, and release-state fixtures;
- inspect clean archives, source locks, CI permissions, branch and tag assumptions, tool pinning, and reproducibility inputs;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- repository evidence and enforcement agree and deliberate violations fail before artifacts, tags, or capability claims;
- `v0.3.0 implementation stop reached. Run pentest for this exact commit.`

### v0.4.0 - Assurance Harness And Bare-Metal Matrix

Status: planned

Plan scope: Establish mutation and differential harnesses, true bare-metal targets, and pinned external assurance-tool policy without adding any third-party crate to repository Cargo manifests.

Goal: complete the **Assurance Harness And Bare-Metal Matrix** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make policy executable through fail-closed scripts, broken fixtures, immutable evidence inputs, and documented ownership, approval, and release boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- exercise policy scripts with positive and deliberately broken dependency, feature, metadata, evidence, workflow, and release-state fixtures;
- inspect clean archives, source locks, CI permissions, branch and tag assumptions, tool pinning, and reproducibility inputs;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- repository evidence and enforcement agree and deliberate violations fail before artifacts, tags, or capability claims;
- `v0.4.0 implementation stop reached. Run pentest for this exact commit.`

### v0.5.0 - Error Alert And Exhaustion Domains

Status: planned

Plan scope: Freeze non-secret error, alert, close, provider-failure, and resource-exhaustion domains; prohibit secret-bearing formatting and ambiguous failure collapse.

Goal: complete the **Error Alert And Exhaustion Domains** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.5.0 implementation stop reached. Run pentest for this exact commit.`

### v0.6.0 - Bounded Numeric And Resource Domains

Status: planned

Plan scope: Introduce checked bounded integers, counts, lengths, sequence numbers, epochs, and immutable resource and work budgets.

Goal: complete the **Bounded Numeric And Resource Domains** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.6.0 implementation stop reached. Run pentest for this exact commit.`

### v0.7.0 - Borrowed Read Cursor

Status: planned

Plan scope: Implement a borrowed read cursor with exact consumption, truncation-at-every-byte coverage, and no indexing panics.

Goal: complete the **Borrowed Read Cursor** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.7.0 implementation stop reached. Run pentest for this exact commit.`

### v0.8.0 - Transactional Write Cursor

Status: planned

Plan scope: Implement caller-buffer write cursors with transactional encode-or-no-mutation behavior.

Goal: complete the **Transactional Write Cursor** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.8.0 implementation stop reached. Run pentest for this exact commit.`

### v0.9.0 - Caller-Owned Workspace And Arena Model

Status: planned

Plan scope: Define caller-owned workspaces and non-overlapping secret, plaintext, transcript, certificate, and output arenas with overlap rules, high-water tracking, and allocation counters.

Goal: complete the **Caller-Owned Workspace And Arena Model** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.9.0 implementation stop reached. Run pentest for this exact commit.`

### v0.10.0 - Secret Lifetime And Zeroization Contract

Status: planned

Plan scope: Define non-cloneable and non-serializable secret ownership, transition/error/cancellation/provider-failure/drop destruction, external secret-store duties, accelerator-handle destruction, and optimizer-resistant zeroization evidence or an explicit weaker claim.

Goal: complete the **Secret Lifetime And Zeroization Contract** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.10.0 implementation stop reached. Run pentest for this exact commit.`

### v0.11.0 - Constant-Time Foundation

Status: planned

Plan scope: Implement constant-time equality, choice and mask types, conditional select/swap, fixed-width secret operations, compiler-barrier strategy, and rules forbidding secret-dependent control flow, indexing, loop counts, and error timing.

Goal: complete the **Constant-Time Foundation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.11.0 implementation stop reached. Run pentest for this exact commit.`

### v0.12.0 - Provider Capabilities And Opaque Handles

Status: planned

Plan scope: Define crypto, signature, KEM, and AEAD capability traits with opaque key handles, frozen capabilities, transactional key installation, and no implicit software fallback.

Goal: complete the **Provider Capabilities And Opaque Handles** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.12.0 implementation stop reached. Run pentest for this exact commit.`

### v0.13.0 - Entropy And Secure-Random Contracts

Status: planned

Plan scope: Separate caller-provided raw entropy from initialized secure randomness; type security strength, purpose, retryable/permanent failure, fork/reseed rules, clone prohibition, and test-only providers that production configuration cannot construct.

Goal: complete the **Entropy And Secure-Random Contracts** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.13.0 implementation stop reached. Run pentest for this exact commit.`

### v0.14.0 - Wall And Monotonic Clock Contracts

Status: planned

Plan scope: Define non-interchangeable typed wall time for PKI and typed monotonic time for timers, freshness, tickets, and replay policy with checked arithmetic and explicit unavailable-time behavior.

Goal: complete the **Wall And Monotonic Clock Contracts** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.14.0 implementation stop reached. Run pentest for this exact commit.`

### v0.15.0 - Pending Operations And Accelerator Lifecycle

Status: planned

Plan scope: Define resumable provider tokens, certificate/signature/accelerator requests, cancellation, key-handle destruction, retry semantics, backpressure, and failure-atomic state transitions.

Goal: complete the **Pending Operations And Accelerator Lifecycle** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.15.0 implementation stop reached. Run pentest for this exact commit.`

### v0.16.0 - FIPS-Aware Provider Architecture

Status: planned

Plan scope: Freeze approved/non-approved service separation, self-test and permanent-failure hooks, dispatch, service indicators, SSP boundaries, deterministic module-build expectations, operational-environment assumptions, and sealed-provider exclusions without making a validation claim.

Goal: complete the **FIPS-Aware Provider Architecture** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.16.0 implementation stop reached. Run pentest for this exact commit.`

### v0.17.0 - TLS And DTLS Record Framing

Status: planned

Plan scope: Separate TLS and DTLS record framing codecs and make modern parsers reject unknown or legacy versions deterministically.

Goal: complete the **TLS And DTLS Record Framing** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.17.0 implementation stop reached. Run pentest for this exact commit.`

### v0.18.0 - Bounded DER Reader

Status: planned

Plan scope: Implement a non-recursive DER tag/length/value reader with definite, minimal, overflow-safe, depth-, node-, size-, and work-bounded parsing.

Goal: complete the **Bounded DER Reader** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.18.0 implementation stop reached. Run pentest for this exact commit.`

### v0.19.0 - Canonical ASN.1 Primitives

Status: planned

Plan scope: Add canonical ASN.1 integer, bit/octet string, OID, Boolean, string, sequence/set, and time primitives with malformed and non-canonical corpora.

Goal: complete the **Canonical ASN.1 Primitives** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public type invariants, caller-owned resource limits, effect boundaries, transactional mutation, provider failure, and secret-free error behavior before downstream use;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run unit, boundary, truncation-at-every-offset, overflow, exhaustion, compile-fail, no-mutation-on-error, no_std, and deterministic-provider tests;
- test minimum and maximum workspaces, arena overlap, malformed encodings, unavailable effects, pending cancellation, drop, and every documented terminal state;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the bounded foundation is deterministic and panic-free for hostile input and exposes no unfinished cryptographic or protocol capability;
- `v0.19.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 1: First-Party Cryptography, Identity Formats, And PKI

Cryptography is audited before bounded identity loading and split PKI validation enter their own audit gate.

### v0.20.0 - SHA-256

Status: planned

Plan scope: Implement streaming and fixed-message SHA-256 with official vectors, boundary lengths, and exhaustion handling.

Goal: complete the **SHA-256** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.20.0 implementation stop reached. Run pentest for this exact commit.`

### v0.21.0 - SHA-384 And SHA-512

Status: planned

Plan scope: Implement SHA-384 and SHA-512 with official vectors and checked length and exhaustion behavior.

Goal: complete the **SHA-384 And SHA-512** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.21.0 implementation stop reached. Run pentest for this exact commit.`

### v0.22.0 - Keccak SHA-3 And SHAKE

Status: planned

Plan scope: Implement Keccak-f[1600], SHA3-256/512, and SHAKE128/256 as the required ML-KEM foundation.

Goal: complete the **Keccak SHA-3 And SHAKE** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.22.0 implementation stop reached. Run pentest for this exact commit.`

### v0.23.0 - HMAC

Status: planned

Plan scope: Implement HMAC-SHA-256/384/512 with constant-time verification and misuse tests.

Goal: complete the **HMAC** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.23.0 implementation stop reached. Run pentest for this exact commit.`

### v0.24.0 - HKDF And TLS Labels

Status: planned

Plan scope: Implement HKDF extract/expand and TLS HKDF-Expand-Label with all input and output limits explicit.

Goal: complete the **HKDF And TLS Labels** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.24.0 implementation stop reached. Run pentest for this exact commit.`

### v0.25.0 - Portable AES

Status: planned

Plan scope: Implement portable constant-time AES-128/256 without secret-indexed tables; require layered emitted-code and statistical evidence for every admitted compiler and target.

Goal: complete the **Portable AES** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.25.0 implementation stop reached. Run pentest for this exact commit.`

### v0.26.0 - GHASH

Status: planned

Plan scope: Implement constant-time GHASH finite-field arithmetic and a bounded incremental interface.

Goal: complete the **GHASH** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.26.0 implementation stop reached. Run pentest for this exact commit.`

### v0.27.0 - AES-GCM

Status: planned

Plan scope: Implement AES-GCM seal/open with nonce and usage limits and no plaintext release before authentication.

Goal: complete the **AES-GCM** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.27.0 implementation stop reached. Run pentest for this exact commit.`

### v0.28.0 - ChaCha20

Status: planned

Plan scope: Implement ChaCha20 with checked counters and deterministic exhaustion closure.

Goal: complete the **ChaCha20** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.28.0 implementation stop reached. Run pentest for this exact commit.`

### v0.29.0 - Poly1305 And ChaCha20-Poly1305

Status: planned

Plan scope: Implement Poly1305 and ChaCha20-Poly1305 with constant-time tag verification and withheld unauthenticated plaintext.

Goal: complete the **Poly1305 And ChaCha20-Poly1305** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.29.0 implementation stop reached. Run pentest for this exact commit.`

### v0.30.0 - Fixed-Limb Arithmetic

Status: planned

Plan scope: Implement fixed-limb RSA and ECC arithmetic with no attacker-selected allocation, normalization schedule, or limb count.

Goal: complete the **Fixed-Limb Arithmetic** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.30.0 implementation stop reached. Run pentest for this exact commit.`

### v0.31.0 - X25519

Status: planned

Plan scope: Implement X25519 using a fixed ladder, low-order handling, and explicit non-FIPS classification.

Goal: complete the **X25519** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.31.0 implementation stop reached. Run pentest for this exact commit.`

### v0.32.0 - P-256

Status: planned

Plan scope: Implement P-256 ECDH and ECDSA, complete point validation, and explicit deterministic and randomized nonce policy using the secure-random contract.

Goal: complete the **P-256** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.32.0 implementation stop reached. Run pentest for this exact commit.`

### v0.33.0 - P-384

Status: planned

Plan scope: Implement P-384 ECDH and ECDSA with separate vectors, side-channel evidence, and review.

Goal: complete the **P-384** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.33.0 implementation stop reached. Run pentest for this exact commit.`

### v0.34.0 - RSA-PSS Verification

Status: planned

Plan scope: Implement strict RSA public-key decoding and RSA-PSS verification with unambiguous parameters and modulus and exponent policy.

Goal: complete the **RSA-PSS Verification** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.34.0 implementation stop reached. Run pentest for this exact commit.`

### v0.35.0 - RSA PKCS1 v1.5 Verification

Status: planned

Plan scope: Implement strict RSASSA-PKCS1-v1_5 certificate-signature verification for SHA-256/384/512 with complete padding, exact DigestInfo, no trailing bytes, and no SHA-1 or MD5 aliases; keep TLS CertificateVerify and signing excluded.

Goal: complete the **RSA PKCS1 v1.5 Verification** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.35.0 implementation stop reached. Run pentest for this exact commit.`

### v0.36.0 - RSA-PSS Private Operations

Status: planned

Plan scope: Implement blinded fixed-schedule RSA-PSS private operations and CRT consistency checks, or freeze an external-signer-only production scope.

Goal: complete the **RSA-PSS Private Operations** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.36.0 implementation stop reached. Run pentest for this exact commit.`

### v0.37.0 - Ed25519

Status: planned

Plan scope: Implement Ed25519 signing and verification with canonical encoding, small-order and malleability rejection, official vectors, and constant-time secret operations.

Goal: complete the **Ed25519** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.37.0 implementation stop reached. Run pentest for this exact commit.`

### v0.38.0 - Version-One Algorithm Decisions

Status: planned

Plan scope: Freeze explicit v1 admission or exclusion for P-521, Ed448, finite-field DHE, AES-CCM, SHA-1 certificate chains, PKCS1 v1.5 signing, encrypted private-key containers, and every unimplemented algorithm family.

Goal: complete the **Version-One Algorithm Decisions** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.38.0 implementation stop reached. Run pentest for this exact commit.`

### v0.39.0 - Cryptographic Substrate Audit Gate

Status: planned

Plan scope: Complete independent cryptographic-substrate review, per-target constant-time evidence, and remediation before PKI or TLS consumption.

Goal: complete the **Cryptographic Substrate Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- record parameters, key, nonce and randomness domains, usage ceilings, secret lifetimes, constant-time obligations, algorithm exclusions, and provider boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run official vectors, boundary and misuse cases, two independent differential implementations where available, supported-target no_std tests, and failure injection;
- review emitted MIR, LLVM and assembly and run primitive-appropriate timing, cache, branch, malformed-input, exhaustion, and zeroization-store tests for every admitted compiler and target;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- admitted algorithms have traceable functional, misuse, resource, and layered side-channel evidence and no downstream use before the crypto audit gate;
- `v0.39.0 implementation stop reached. Run pentest for this exact commit.`

### v0.40.0 - PEM Base64 And Chain Containers

Status: planned

Plan scope: Implement bounded strict Base64 and PEM armor plus certificate-chain containers with label, count, size, whitespace, trailing-data, and resource policies.

Goal: complete the **PEM Base64 And Chain Containers** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- bind parsers and validators to exact signed bytes, explicit normalization and algorithm policy, caller-supplied trust and time, secret arenas, and immutable size, depth, count, path, and work budgets;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER, armor, key and certificate corpora, truncation, path and policy matrices, differential validation, deterministic selection, and work-exhaustion tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, invalid key containers, cycles, cross-signing, constraint interactions, stale or unauthorized status data, and unavailable CT policy;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- identity and PKI processing is fail-closed, bounded, deterministic, and independently reviewed before a handshake authenticates a peer;
- `v0.40.0 implementation stop reached. Run pentest for this exact commit.`

### v0.41.0 - Private-Key Input Formats

Status: planned

Plan scope: Implement bounded unencrypted PKCS#8, SEC1 EC, and PKCS1 RSA private-key decoding with algorithm/key consistency and secret-arena ownership; keep encrypted PKCS#8 an explicit v1 non-goal unless separately versioned.

Goal: complete the **Private-Key Input Formats** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- bind parsers and validators to exact signed bytes, explicit normalization and algorithm policy, caller-supplied trust and time, secret arenas, and immutable size, depth, count, path, and work budgets;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER, armor, key and certificate corpora, truncation, path and policy matrices, differential validation, deterministic selection, and work-exhaustion tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, invalid key containers, cycles, cross-signing, constraint interactions, stale or unauthorized status data, and unavailable CT policy;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- identity and PKI processing is fail-closed, bounded, deterministic, and independently reviewed before a handshake authenticates a peer;
- `v0.41.0 implementation stop reached. Run pentest for this exact commit.`

### v0.42.0 - X.509 Decoder

Status: planned

Plan scope: Decode X.509 Certificate, TBSCertificate, and SPKI while preserving the exact original signed byte slice and rejecting ambiguous algorithms.

Goal: complete the **X.509 Decoder** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- bind parsers and validators to exact signed bytes, explicit normalization and algorithm policy, caller-supplied trust and time, secret arenas, and immutable size, depth, count, path, and work budgets;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER, armor, key and certificate corpora, truncation, path and policy matrices, differential validation, deterministic selection, and work-exhaustion tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, invalid key containers, cycles, cross-signing, constraint interactions, stale or unauthorized status data, and unavailable CT policy;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- identity and PKI processing is fail-closed, bounded, deterministic, and independently reviewed before a handshake authenticates a peer;
- `v0.42.0 implementation stop reached. Run pentest for this exact commit.`

### v0.43.0 - Service Identity And Extensions

Status: planned

Plan scope: Validate SAN/service identity, ASCII A-label DNS inputs, wildcards, IP, email and URI names, critical and duplicate extensions, and caller-owned international-name normalization policy.

Goal: complete the **Service Identity And Extensions** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- bind parsers and validators to exact signed bytes, explicit normalization and algorithm policy, caller-supplied trust and time, secret arenas, and immutable size, depth, count, path, and work budgets;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER, armor, key and certificate corpora, truncation, path and policy matrices, differential validation, deterministic selection, and work-exhaustion tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, invalid key containers, cycles, cross-signing, constraint interactions, stale or unauthorized status data, and unavailable CT policy;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- identity and PKI processing is fail-closed, bounded, deterministic, and independently reviewed before a handshake authenticates a peer;
- `v0.43.0 implementation stop reached. Run pentest for this exact commit.`

### v0.44.0 - Bounded Path Construction

Status: planned

Plan scope: Build bounded deterministic paths using caller-supplied pools, loop detection, and hard depth, candidate, comparison, and work limits with no automatic network fetch.

Goal: complete the **Bounded Path Construction** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- bind parsers and validators to exact signed bytes, explicit normalization and algorithm policy, caller-supplied trust and time, secret arenas, and immutable size, depth, count, path, and work budgets;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER, armor, key and certificate corpora, truncation, path and policy matrices, differential validation, deterministic selection, and work-exhaustion tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, invalid key containers, cycles, cross-signing, constraint interactions, stale or unauthorized status data, and unavailable CT policy;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- identity and PKI processing is fail-closed, bounded, deterministic, and independently reviewed before a handshake authenticates a peer;
- `v0.44.0 implementation stop reached. Run pentest for this exact commit.`

### v0.45.0 - Core Chain Validation

Status: planned

Plan scope: Validate chain signatures, validity, basic constraints, path length, key usage, and extended key usage.

Goal: complete the **Core Chain Validation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- bind parsers and validators to exact signed bytes, explicit normalization and algorithm policy, caller-supplied trust and time, secret arenas, and immutable size, depth, count, path, and work budgets;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER, armor, key and certificate corpora, truncation, path and policy matrices, differential validation, deterministic selection, and work-exhaustion tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, invalid key containers, cycles, cross-signing, constraint interactions, stale or unauthorized status data, and unavailable CT policy;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- identity and PKI processing is fail-closed, bounded, deterministic, and independently reviewed before a handshake authenticates a peer;
- `v0.45.0 implementation stop reached. Run pentest for this exact commit.`

### v0.46.0 - Name Constraints

Status: planned

Plan scope: Validate DNS, IP, email, URI, and directory-name constraints with explicit subtree, comparison, normalization, and work budgets.

Goal: complete the **Name Constraints** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- bind parsers and validators to exact signed bytes, explicit normalization and algorithm policy, caller-supplied trust and time, secret arenas, and immutable size, depth, count, path, and work budgets;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER, armor, key and certificate corpora, truncation, path and policy matrices, differential validation, deterministic selection, and work-exhaustion tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, invalid key containers, cycles, cross-signing, constraint interactions, stale or unauthorized status data, and unavailable CT policy;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- identity and PKI processing is fail-closed, bounded, deterministic, and independently reviewed before a handshake authenticates a peer;
- `v0.46.0 implementation stop reached. Run pentest for this exact commit.`

### v0.47.0 - Certificate Policy Processing

Status: planned

Plan scope: Implement certificate policies, mappings, anyPolicy, inhibition, policy constraints, and bounded policy-tree processing.

Goal: complete the **Certificate Policy Processing** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- bind parsers and validators to exact signed bytes, explicit normalization and algorithm policy, caller-supplied trust and time, secret arenas, and immutable size, depth, count, path, and work budgets;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER, armor, key and certificate corpora, truncation, path and policy matrices, differential validation, deterministic selection, and work-exhaustion tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, invalid key containers, cycles, cross-signing, constraint interactions, stale or unauthorized status data, and unavailable CT policy;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- identity and PKI processing is fail-closed, bounded, deterministic, and independently reviewed before a handshake authenticates a peer;
- `v0.47.0 implementation stop reached. Run pentest for this exact commit.`

### v0.48.0 - Trust Anchors Cross-Signing And Algorithms

Status: planned

Plan scope: Define trust-anchor inputs, cross-signing and alternate-path semantics, deterministic selection, distrust policy, and per-position algorithm constraints.

Goal: complete the **Trust Anchors Cross-Signing And Algorithms** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- bind parsers and validators to exact signed bytes, explicit normalization and algorithm policy, caller-supplied trust and time, secret arenas, and immutable size, depth, count, path, and work budgets;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER, armor, key and certificate corpora, truncation, path and policy matrices, differential validation, deterministic selection, and work-exhaustion tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, invalid key containers, cycles, cross-signing, constraint interactions, stale or unauthorized status data, and unavailable CT policy;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- identity and PKI processing is fail-closed, bounded, deterministic, and independently reviewed before a handshake authenticates a peer;
- `v0.48.0 implementation stop reached. Run pentest for this exact commit.`

### v0.49.0 - CRL Validation

Status: planned

Plan scope: Validate base, delta, and indirect CRLs with issuer authorization, freshness, distribution-point, reason, entry, and work ceilings.

Goal: complete the **CRL Validation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- bind parsers and validators to exact signed bytes, explicit normalization and algorithm policy, caller-supplied trust and time, secret arenas, and immutable size, depth, count, path, and work budgets;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER, armor, key and certificate corpora, truncation, path and policy matrices, differential validation, deterministic selection, and work-exhaustion tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, invalid key containers, cycles, cross-signing, constraint interactions, stale or unauthorized status data, and unavailable CT policy;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- identity and PKI processing is fail-closed, bounded, deterministic, and independently reviewed before a handshake authenticates a peer;
- `v0.49.0 implementation stop reached. Run pentest for this exact commit.`

### v0.50.0 - OCSP Validation

Status: planned

Plan scope: Validate stapled and offline OCSP responses, responder authorization, freshness, nonce, issuer and serial matching, and explicit hard/soft-fail policy.

Goal: complete the **OCSP Validation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- bind parsers and validators to exact signed bytes, explicit normalization and algorithm policy, caller-supplied trust and time, secret arenas, and immutable size, depth, count, path, and work budgets;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER, armor, key and certificate corpora, truncation, path and policy matrices, differential validation, deterministic selection, and work-exhaustion tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, invalid key containers, cycles, cross-signing, constraint interactions, stale or unauthorized status data, and unavailable CT policy;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- identity and PKI processing is fail-closed, bounded, deterministic, and independently reviewed before a handshake authenticates a peer;
- `v0.50.0 implementation stop reached. Run pentest for this exact commit.`

### v0.51.0 - SCT Parsing And Certificate Transparency Policy

Status: planned

Plan scope: Implement bounded SCT certificate-entry parsing and an explicit Certificate Transparency verification/provider policy; fail closed when CT is required and no admitted verifier exists.

Goal: complete the **SCT Parsing And Certificate Transparency Policy** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- bind parsers and validators to exact signed bytes, explicit normalization and algorithm policy, caller-supplied trust and time, secret arenas, and immutable size, depth, count, path, and work budgets;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER, armor, key and certificate corpora, truncation, path and policy matrices, differential validation, deterministic selection, and work-exhaustion tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, invalid key containers, cycles, cross-signing, constraint interactions, stale or unauthorized status data, and unavailable CT policy;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- identity and PKI processing is fail-closed, bounded, deterministic, and independently reviewed before a handshake authenticates a peer;
- `v0.51.0 implementation stop reached. Run pentest for this exact commit.`

### v0.52.0 - PKI Audit Gate

Status: planned

Plan scope: Complete PKI adversarial, differential, fuzz, path-complexity, revocation, and external audit campaigns with clean remediation.

Goal: complete the **PKI Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- bind parsers and validators to exact signed bytes, explicit normalization and algorithm policy, caller-supplied trust and time, secret arenas, and immutable size, depth, count, path, and work budgets;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run standards vectors, malformed DER, armor, key and certificate corpora, truncation, path and policy matrices, differential validation, deterministic selection, and work-exhaustion tests;
- test unknown critical and duplicate extensions, ambiguous algorithms, invalid key containers, cycles, cross-signing, constraint interactions, stale or unauthorized status data, and unavailable CT policy;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- identity and PKI processing is fail-closed, bounded, deterministic, and independently reviewed before a handshake authenticates a peer;
- `v0.52.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 2: Internal Sans-I/O, Modern TLS 1.3, And Explicit TLS 1.2

The internal effects model is exercised first; TLS 1.3 completes before an isolated, explicitly selected TLS 1.2 profile.

### v0.53.0 - Internal Sans-I/O Execution Contract

Status: planned

Plan scope: Define an explicitly unstable deterministic Event-to-Action driver for consumed input, output workspace, timers, entropy/time, certificate/signature/accelerator requests, application data, backpressure, resumable operations, cancellation, and terminal states.

Goal: complete the **Internal Sans-I/O Execution Contract** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze the internal input-consumption, output, timer, entropy, clock, certificate, signature, accelerator, application-data, pending-operation, cancellation, and terminal action vocabulary;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run deterministic action traces, partial-input/output, backpressure, re-entry prohibition, pending resume/cancel, provider fault, terminal-state, and workspace-exhaustion tests;
- prove no callback reentrancy, hidden I/O, global state, lost authenticated transition, half-installed key, secret output, or action replay after cancellation;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- protocol engines can be implemented as deterministic effects over caller-owned state without committing the later public facade API;
- `v0.53.0 implementation stop reached. Run pentest for this exact commit.`

### v0.54.0 - TLS Record Protection

Status: planned

Plan scope: Implement TLS record protection, checked sequence exhaustion, inner content-type and padding validation, transactional state changes, and fragmentation boundaries.

Goal: complete the **TLS Record Protection** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.54.0 implementation stop reached. Run pentest for this exact commit.`

### v0.55.0 - TLS 1.3 Handshake Codec

Status: planned

Plan scope: Implement the complete TLS 1.3 handshake codec with duplicate, ordering, extension-context, unknown/GREASE-extension, compatibility ChangeCipherSpec, and resource rules.

Goal: complete the **TLS 1.3 Handshake Codec** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.55.0 implementation stop reached. Run pentest for this exact commit.`

### v0.56.0 - Transcript And Key Schedule

Status: planned

Plan scope: Implement transcript and key-schedule states with immediate destruction of obsolete early, handshake, master, exporter, and resumption secrets.

Goal: complete the **Transcript And Key Schedule** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.56.0 implementation stop reached. Run pentest for this exact commit.`

### v0.57.0 - TLS 1.3 Opening Flight

Status: planned

Plan scope: Implement ClientHello, versions, groups, signatures, key shares, HelloRetryRequest, cookies, GREASE tolerance, and downgrade invariants.

Goal: complete the **TLS 1.3 Opening Flight** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.57.0 implementation stop reached. Run pentest for this exact commit.`

### v0.58.0 - TLS 1.3 Authenticated Server Flight

Status: planned

Plan scope: Implement ServerHello through the authenticated server flight, certificate presentation, and the sole ALPN and SNI negotiation implementation.

Goal: complete the **TLS 1.3 Authenticated Server Flight** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.58.0 implementation stop reached. Run pentest for this exact commit.`

### v0.59.0 - Certificate Negotiation And Selection

Status: planned

Plan scope: Implement signature_algorithms_cert, certificate_authorities, oid_filters, certificate/public-key compatibility, bounded identity selection, and deterministic external-signer requests.

Goal: complete the **Certificate Negotiation And Selection** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.59.0 implementation stop reached. Run pentest for this exact commit.`

### v0.60.0 - Stapled Status And SCT Transport

Status: planned

Plan scope: Implement status_request and stapled OCSP transport plus bounded SCT transport and handoff to the admitted PKI and CT policies.

Goal: complete the **Stapled Status And SCT Transport** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.60.0 implementation stop reached. Run pentest for this exact commit.`

### v0.61.0 - Client Authentication And Finished

Status: planned

Plan scope: Implement client authentication, CertificateVerify, Finished, authenticated application-data transition, and explicit rejection of post-handshake authentication for v1.

Goal: complete the **Client Authentication And Finished** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.61.0 implementation stop reached. Run pentest for this exact commit.`

### v0.62.0 - Alerts Closure And Cancellation

Status: planned

Plan scope: Complete alerts, close-notify, illegal-message handling, backpressure, cancellation, provider failure, terminal states, and terminal secret and handle destruction.

Goal: complete the **Alerts Closure And Cancellation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.62.0 implementation stop reached. Run pentest for this exact commit.`

### v0.63.0 - Tickets And Resumption PSKs

Status: planned

Plan scope: Implement session tickets and resumption PSK binders with protocol-specific ticket-key, cache, external-storage secrecy, rotation, and lifetime domains.

Goal: complete the **Tickets And Resumption PSKs** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.63.0 implementation stop reached. Run pentest for this exact commit.`

### v0.64.0 - External PSKs And PSK Modes

Status: planned

Plan scope: Separate external from resumption PSKs, require hardened psk_dhe_ke by default, type identity and binder policy, and prohibit silent psk_ke or cross-domain fallback.

Goal: complete the **External PSKs And PSK Modes** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.64.0 implementation stop reached. Run pentest for this exact commit.`

### v0.65.0 - Zero-RTT

Status: planned

Plan scope: Implement opt-in 0-RTT with anti-replay storage, freshness, deterministic rejection, secret lifetime, and application side-effect guidance.

Goal: complete the **Zero-RTT** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.65.0 implementation stop reached. Run pentest for this exact commit.`

### v0.66.0 - TLS KeyUpdate

Status: planned

Plan scope: Implement KeyUpdate with traffic-secret transition, immediate obsolete-key destruction, request coalescing policy, and long-lived key and record limits.

Goal: complete the **TLS KeyUpdate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.66.0 implementation stop reached. Run pentest for this exact commit.`

### v0.67.0 - Exporters And Channel Binding

Status: planned

Plan scope: Implement exporters and channel binding exactly once with context separation, transcript binding, authorization timing, and secret-output policy.

Goal: complete the **Exporters And Channel Binding** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.67.0 implementation stop reached. Run pentest for this exact commit.`

### v0.68.0 - TLS 1.3 Suite Completion

Status: planned

Plan scope: Admit only AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, and ChaCha20-Poly1305/SHA-256 for the initial TLS 1.3 profile.

Goal: complete the **TLS 1.3 Suite Completion** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.68.0 implementation stop reached. Run pentest for this exact commit.`

### v0.69.0 - TLS 1.3 Conformance And Interoperability

Status: planned

Plan scope: Pass official vectors, truncation and fragmentation matrices, independent peer implementations, state-model and fuzz gates, and provider fault injection.

Goal: complete the **TLS 1.3 Conformance And Interoperability** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.69.0 implementation stop reached. Run pentest for this exact commit.`

### v0.70.0 - TLS 1.3 Audit Gate

Status: planned

Plan scope: Complete an external TLS 1.3 audit and clean remediation retest.

Goal: complete the **TLS 1.3 Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- encode TLS 1.3 transcript, certificate, PSK, secret, record, effects, configuration, and failure invariants as closed types with caller-owned storage;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC vectors, truncation and fragmentation matrices, illegal-order, duplicate and GREASE tests, transcript and key-schedule checks, provider faults, and independent-peer interoperability;
- exercise downgrade, compatibility CCS, replay, binders, external and resumption PSKs, tickets, zero-RTT, key limits, backpressure, cancellation, alert, status, selection, and terminal cleanup;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the named TLS 1.3 boundary is interoperable and fail-closed without admitting unfinished states, unauthenticated output, or overlapping feature ownership;
- `v0.70.0 implementation stop reached. Run pentest for this exact commit.`

### v0.71.0 - TLS 1.2 Policy Boundary

Status: planned

Plan scope: Freeze an explicit TLS 1.2 ECDHE-plus-AEAD policy with EMS required and static RSA, CBC, SHA-1 signing, compression, renegotiation, and automatic fallback excluded.

Goal: complete the **TLS 1.2 Policy Boundary** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- keep TLS 1.2 independently selectable and restricted to ECDHE plus AEAD with EMS, protocol-specific tickets, and no retry fallback from TLS 1.3;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run TLS 1.2 vectors, transcript and nonce tests, admitted-suite interoperability, extension and resumption matrices, downgrade corpora, and explicit-disablement checks;
- prove rejection of static RSA, CBC, SHA-1 signing, compression, renegotiation, weak groups, downgrade ambiguity, and cross-version credential, cache, ticket, or state reuse;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the TLS 1.2 profile is isolated, explicitly configured, independently disableable, and covered by separate audit evidence;
- `v0.71.0 implementation stop reached. Run pentest for this exact commit.`

### v0.72.0 - TLS 1.2 PRF Records And Downgrade Defense

Status: planned

Plan scope: Implement the TLS 1.2 PRF, record nonces, EMS transcript binding, downgrade sentinel, and SCSV and renegotiation-info rejection rules.

Goal: complete the **TLS 1.2 PRF Records And Downgrade Defense** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- keep TLS 1.2 independently selectable and restricted to ECDHE plus AEAD with EMS, protocol-specific tickets, and no retry fallback from TLS 1.3;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run TLS 1.2 vectors, transcript and nonce tests, admitted-suite interoperability, extension and resumption matrices, downgrade corpora, and explicit-disablement checks;
- prove rejection of static RSA, CBC, SHA-1 signing, compression, renegotiation, weak groups, downgrade ambiguity, and cross-version credential, cache, ticket, or state reuse;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the TLS 1.2 profile is isolated, explicitly configured, independently disableable, and covered by separate audit evidence;
- `v0.72.0 implementation stop reached. Run pentest for this exact commit.`

### v0.73.0 - TLS 1.2 ECDHE State Machines

Status: planned

Plan scope: Implement isolated ECDHE_ECDSA and ECDHE_RSA TLS 1.2 client and server state machines.

Goal: complete the **TLS 1.2 ECDHE State Machines** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- keep TLS 1.2 independently selectable and restricted to ECDHE plus AEAD with EMS, protocol-specific tickets, and no retry fallback from TLS 1.3;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run TLS 1.2 vectors, transcript and nonce tests, admitted-suite interoperability, extension and resumption matrices, downgrade corpora, and explicit-disablement checks;
- prove rejection of static RSA, CBC, SHA-1 signing, compression, renegotiation, weak groups, downgrade ambiguity, and cross-version credential, cache, ticket, or state reuse;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the TLS 1.2 profile is isolated, explicitly configured, independently disableable, and covered by separate audit evidence;
- `v0.73.0 implementation stop reached. Run pentest for this exact commit.`

### v0.74.0 - TLS 1.2 Suite Completion

Status: planned

Plan scope: Admit only the six ECDSA/RSA combinations over AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.

Goal: complete the **TLS 1.2 Suite Completion** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- keep TLS 1.2 independently selectable and restricted to ECDHE plus AEAD with EMS, protocol-specific tickets, and no retry fallback from TLS 1.3;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run TLS 1.2 vectors, transcript and nonce tests, admitted-suite interoperability, extension and resumption matrices, downgrade corpora, and explicit-disablement checks;
- prove rejection of static RSA, CBC, SHA-1 signing, compression, renegotiation, weak groups, downgrade ambiguity, and cross-version credential, cache, ticket, or state reuse;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the TLS 1.2 profile is isolated, explicitly configured, independently disableable, and covered by separate audit evidence;
- `v0.74.0 implementation stop reached. Run pentest for this exact commit.`

### v0.75.0 - TLS 1.2 Resumption And Interoperability

Status: planned

Plan scope: Complete TLS 1.2 resumption, protocol-specific tickets, extension hardening, interop, and downgrade corpora.

Goal: complete the **TLS 1.2 Resumption And Interoperability** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- keep TLS 1.2 independently selectable and restricted to ECDHE plus AEAD with EMS, protocol-specific tickets, and no retry fallback from TLS 1.3;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run TLS 1.2 vectors, transcript and nonce tests, admitted-suite interoperability, extension and resumption matrices, downgrade corpora, and explicit-disablement checks;
- prove rejection of static RSA, CBC, SHA-1 signing, compression, renegotiation, weak groups, downgrade ambiguity, and cross-version credential, cache, ticket, or state reuse;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the TLS 1.2 profile is isolated, explicitly configured, independently disableable, and covered by separate audit evidence;
- `v0.75.0 implementation stop reached. Run pentest for this exact commit.`

### v0.76.0 - TLS 1.2 Audit Gate

Status: planned

Plan scope: Complete a separate TLS 1.2 external audit while retaining explicit configuration and independent disablement.

Goal: complete the **TLS 1.2 Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- keep TLS 1.2 independently selectable and restricted to ECDHE plus AEAD with EMS, protocol-specific tickets, and no retry fallback from TLS 1.3;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run TLS 1.2 vectors, transcript and nonce tests, admitted-suite interoperability, extension and resumption matrices, downgrade corpora, and explicit-disablement checks;
- prove rejection of static RSA, CBC, SHA-1 signing, compression, renegotiation, weak groups, downgrade ambiguity, and cross-version credential, cache, ticket, or state reuse;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the TLS 1.2 profile is isolated, explicitly configured, independently disableable, and covered by separate audit evidence;
- `v0.76.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 3: QUIC TLS, DTLS, And Post-Quantum Work

QUIC transport ownership, DTLS datagram state, and standardized post-quantum integrations remain separate boundaries.

### v0.77.0 - QUIC Ownership And Encryption Levels

Status: planned

Plan scope: Define distinct QUIC encryption levels and secret install/discard events; consume ordered bytes supplied by QUIC and exclude packet processing, offsets, retransmission, packet numbers, loss recovery, Retry, key phase, TLS records, and TLS KeyUpdate.

Goal: complete the **QUIC Ownership And Encryption Levels** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- keep QUIC encryption levels, ordered TLS bytes, transport-parameter syntax, secret events, optional helpers, and buffering limits distinct from QUIC transport ownership;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC 9001 vectors, level ordering, ordered-byte delivery, secret install and discard, transport-parameter syntax, helper conflict, loss and reorder simulation, and independent peer tests;
- test future and late data, conflicting helper ranges, forbidden TLS records, KeyUpdate and post-handshake authentication, semantic-boundary violations, 0-RTT rejection, and exhaustion;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- Brynja consumes and emits only bounded TLS effects and cannot become an implicit QUIC packet, recovery, offset, Retry, or key-phase implementation;
- `v0.77.0 implementation stop reached. Run pentest for this exact commit.`

### v0.78.0 - QUIC Transport Parameters

Status: planned

Plan scope: Implement bounded syntactic transport-parameter parsing and transcript binding while exposing typed values for QUIC-owned semantic enforcement.

Goal: complete the **QUIC Transport Parameters** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- keep QUIC encryption levels, ordered TLS bytes, transport-parameter syntax, secret events, optional helpers, and buffering limits distinct from QUIC transport ownership;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC 9001 vectors, level ordering, ordered-byte delivery, secret install and discard, transport-parameter syntax, helper conflict, loss and reorder simulation, and independent peer tests;
- test future and late data, conflicting helper ranges, forbidden TLS records, KeyUpdate and post-handshake authentication, semantic-boundary violations, 0-RTT rejection, and exhaustion;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- Brynja consumes and emits only bounded TLS effects and cannot become an implicit QUIC packet, recovery, offset, Retry, or key-phase implementation;
- `v0.78.0 implementation stop reached. Run pentest for this exact commit.`

### v0.79.0 - QUIC Sans-I/O Handshake

Status: planned

Plan scope: Implement per-level TLS handshake input/output, alerts, pending providers, bounded future-level data, secret events, and deterministic rejection of late data.

Goal: complete the **QUIC Sans-I/O Handshake** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- keep QUIC encryption levels, ordered TLS bytes, transport-parameter syntax, secret events, optional helpers, and buffering limits distinct from QUIC transport ownership;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC 9001 vectors, level ordering, ordered-byte delivery, secret install and discard, transport-parameter syntax, helper conflict, loss and reorder simulation, and independent peer tests;
- test future and late data, conflicting helper ranges, forbidden TLS records, KeyUpdate and post-handshake authentication, semantic-boundary violations, 0-RTT rejection, and exhaustion;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- Brynja consumes and emits only bounded TLS effects and cannot become an implicit QUIC packet, recovery, offset, Retry, or key-phase implementation;
- `v0.79.0 implementation stop reached. Run pentest for this exact commit.`

### v0.80.0 - Optional QUIC CRYPTO Reassembly Helper

Status: planned

Plan scope: Provide an explicitly optional bounded CRYPTO-offset reassembly helper with conflict and exhaustion handling that is not used implicitly and does not implement retransmission or loss recovery.

Goal: complete the **Optional QUIC CRYPTO Reassembly Helper** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- keep QUIC encryption levels, ordered TLS bytes, transport-parameter syntax, secret events, optional helpers, and buffering limits distinct from QUIC transport ownership;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC 9001 vectors, level ordering, ordered-byte delivery, secret install and discard, transport-parameter syntax, helper conflict, loss and reorder simulation, and independent peer tests;
- test future and late data, conflicting helper ranges, forbidden TLS records, KeyUpdate and post-handshake authentication, semantic-boundary violations, 0-RTT rejection, and exhaustion;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- Brynja consumes and emits only bounded TLS effects and cannot become an implicit QUIC packet, recovery, offset, Retry, or key-phase implementation;
- `v0.80.0 implementation stop reached. Run pentest for this exact commit.`

### v0.81.0 - QUIC Conformance And Audit

Status: planned

Plan scope: Pass RFC 9001 vectors plus loss, reorder, discard, 0-RTT, interoperability, ownership-boundary, and external review gates.

Goal: complete the **QUIC Conformance And Audit** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- keep QUIC encryption levels, ordered TLS bytes, transport-parameter syntax, secret events, optional helpers, and buffering limits distinct from QUIC transport ownership;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run RFC 9001 vectors, level ordering, ordered-byte delivery, secret install and discard, transport-parameter syntax, helper conflict, loss and reorder simulation, and independent peer tests;
- test future and late data, conflicting helper ranges, forbidden TLS records, KeyUpdate and post-handshake authentication, semantic-boundary violations, 0-RTT rejection, and exhaustion;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- Brynja consumes and emits only bounded TLS effects and cannot become an implicit QUIC packet, recovery, offset, Retry, or key-phase implementation;
- `v0.81.0 implementation stop reached. Run pentest for this exact commit.`

### v0.82.0 - DTLS Unified Headers And Epochs

Status: planned

Plan scope: Implement DTLS 1.3 unified headers, epochs, compact sequence reconstruction, AEAD nonce construction, and checked sequence exhaustion.

Goal: complete the **DTLS Unified Headers And Epochs** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make unified headers, record-number protection, epochs, replay, key retention, CIDs, reassembly, transcripts, flights, timers, cookies, amplification, and PMTU budgets explicit and caller-owned;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplicate, header, record-number, replay, CID, overlap, conflict, ACK, timer, retransmission, retention, and independent-peer matrices;
- exercise unauthenticated reconstruction failures, replay across transitions, spoofed amplification, sequence exhaustion, sparse fragments, stale timers, CID updates, provider failure, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- DTLS remains bounded and deterministic on an adversarial datagram network and releases no unauthenticated transition or stale secret;
- `v0.82.0 implementation stop reached. Run pentest for this exact commit.`

### v0.83.0 - DTLS Record-Number Encryption

Status: planned

Plan scope: Implement record-number encryption and authenticated reconstruction-failure handling with official vectors and no replay-window mutation before authentication.

Goal: complete the **DTLS Record-Number Encryption** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make unified headers, record-number protection, epochs, replay, key retention, CIDs, reassembly, transcripts, flights, timers, cookies, amplification, and PMTU budgets explicit and caller-owned;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplicate, header, record-number, replay, CID, overlap, conflict, ACK, timer, retransmission, retention, and independent-peer matrices;
- exercise unauthenticated reconstruction failures, replay across transitions, spoofed amplification, sequence exhaustion, sparse fragments, stale timers, CID updates, provider failure, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- DTLS remains bounded and deterministic on an adversarial datagram network and releases no unauthenticated transition or stale secret;
- `v0.83.0 implementation stop reached. Run pentest for this exact commit.`

### v0.84.0 - DTLS Replay And Epoch-Key Lifetimes

Status: planned

Plan scope: Implement fixed replay windows across epoch transitions, bounded previous/future retention, transactional key installation, and immediate obsolete-key destruction.

Goal: complete the **DTLS Replay And Epoch-Key Lifetimes** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make unified headers, record-number protection, epochs, replay, key retention, CIDs, reassembly, transcripts, flights, timers, cookies, amplification, and PMTU budgets explicit and caller-owned;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplicate, header, record-number, replay, CID, overlap, conflict, ACK, timer, retransmission, retention, and independent-peer matrices;
- exercise unauthenticated reconstruction failures, replay across transitions, spoofed amplification, sequence exhaustion, sparse fragments, stale timers, CID updates, provider failure, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- DTLS remains bounded and deterministic on an adversarial datagram network and releases no unauthenticated transition or stale secret;
- `v0.84.0 implementation stop reached. Run pentest for this exact commit.`

### v0.85.0 - DTLS Connection IDs

Status: planned

Plan scope: Implement bounded optional connection IDs and CID updates with routing/privacy policy, replay and migration invariants, or record their explicit exclusion if standards evidence cannot meet the gate.

Goal: complete the **DTLS Connection IDs** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make unified headers, record-number protection, epochs, replay, key retention, CIDs, reassembly, transcripts, flights, timers, cookies, amplification, and PMTU budgets explicit and caller-owned;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplicate, header, record-number, replay, CID, overlap, conflict, ACK, timer, retransmission, retention, and independent-peer matrices;
- exercise unauthenticated reconstruction failures, replay across transitions, spoofed amplification, sequence exhaustion, sparse fragments, stale timers, CID updates, provider failure, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- DTLS remains bounded and deterministic on an adversarial datagram network and releases no unauthenticated transition or stale secret;
- `v0.85.0 implementation stop reached. Run pentest for this exact commit.`

### v0.86.0 - DTLS Fragmentation And Reassembly

Status: planned

Plan scope: Implement caller-owned bounded handshake fragmentation and reassembly with canonical transcript messages and overlap and conflicting-fragment rejection.

Goal: complete the **DTLS Fragmentation And Reassembly** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make unified headers, record-number protection, epochs, replay, key retention, CIDs, reassembly, transcripts, flights, timers, cookies, amplification, and PMTU budgets explicit and caller-owned;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplicate, header, record-number, replay, CID, overlap, conflict, ACK, timer, retransmission, retention, and independent-peer matrices;
- exercise unauthenticated reconstruction failures, replay across transitions, spoofed amplification, sequence exhaustion, sparse fragments, stale timers, CID updates, provider failure, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- DTLS remains bounded and deterministic on an adversarial datagram network and releases no unauthenticated transition or stale secret;
- `v0.86.0 implementation stop reached. Run pentest for this exact commit.`

### v0.87.0 - DTLS Flights ACKs And Timers

Status: planned

Plan scope: Implement deterministic flights, ACK processing, typed timer actions, cached retransmission, checked backoff, and congestion limits.

Goal: complete the **DTLS Flights ACKs And Timers** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make unified headers, record-number protection, epochs, replay, key retention, CIDs, reassembly, transcripts, flights, timers, cookies, amplification, and PMTU budgets explicit and caller-owned;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplicate, header, record-number, replay, CID, overlap, conflict, ACK, timer, retransmission, retention, and independent-peer matrices;
- exercise unauthenticated reconstruction failures, replay across transitions, spoofed amplification, sequence exhaustion, sparse fragments, stale timers, CID updates, provider failure, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- DTLS remains bounded and deterministic on an adversarial datagram network and releases no unauthenticated transition or stale secret;
- `v0.87.0 implementation stop reached. Run pentest for this exact commit.`

### v0.88.0 - DTLS Address Validation And Amplification Defense

Status: planned

Plan scope: Implement cookies, address validation, amplification budgets, deterministic PMTU policy, and cheap rejection before expensive cryptography.

Goal: complete the **DTLS Address Validation And Amplification Defense** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make unified headers, record-number protection, epochs, replay, key retention, CIDs, reassembly, transcripts, flights, timers, cookies, amplification, and PMTU budgets explicit and caller-owned;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplicate, header, record-number, replay, CID, overlap, conflict, ACK, timer, retransmission, retention, and independent-peer matrices;
- exercise unauthenticated reconstruction failures, replay across transitions, spoofed amplification, sequence exhaustion, sparse fragments, stale timers, CID updates, provider failure, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- DTLS remains bounded and deterministic on an adversarial datagram network and releases no unauthenticated transition or stale secret;
- `v0.88.0 implementation stop reached. Run pentest for this exact commit.`

### v0.89.0 - DTLS 1.3 State Machines

Status: planned

Plan scope: Complete DTLS 1.3 client and server states, key updates, duplicate idempotence, terminal cleanup, and provider cancellation.

Goal: complete the **DTLS 1.3 State Machines** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make unified headers, record-number protection, epochs, replay, key retention, CIDs, reassembly, transcripts, flights, timers, cookies, amplification, and PMTU budgets explicit and caller-owned;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplicate, header, record-number, replay, CID, overlap, conflict, ACK, timer, retransmission, retention, and independent-peer matrices;
- exercise unauthenticated reconstruction failures, replay across transitions, spoofed amplification, sequence exhaustion, sparse fragments, stale timers, CID updates, provider failure, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- DTLS remains bounded and deterministic on an adversarial datagram network and releases no unauthenticated transition or stale secret;
- `v0.89.0 implementation stop reached. Run pentest for this exact commit.`

### v0.90.0 - Hardened DTLS 1.2

Status: planned

Plan scope: Implement DTLS 1.2 using only the admitted TLS 1.2 ECDHE-plus-AEAD profile and isolated epoch, replay, ticket, and downgrade state.

Goal: complete the **Hardened DTLS 1.2** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make unified headers, record-number protection, epochs, replay, key retention, CIDs, reassembly, transcripts, flights, timers, cookies, amplification, and PMTU budgets explicit and caller-owned;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplicate, header, record-number, replay, CID, overlap, conflict, ACK, timer, retransmission, retention, and independent-peer matrices;
- exercise unauthenticated reconstruction failures, replay across transitions, spoofed amplification, sequence exhaustion, sparse fragments, stale timers, CID updates, provider failure, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- DTLS remains bounded and deterministic on an adversarial datagram network and releases no unauthenticated transition or stale secret;
- `v0.90.0 implementation stop reached. Run pentest for this exact commit.`

### v0.91.0 - DTLS Conformance And Audit

Status: planned

Plan scope: Pass loss, reorder, duplicate, fragmentation, replay, CID, hostile-load, fuzz, interoperability, and external audit gates.

Goal: complete the **DTLS Conformance And Audit** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- make unified headers, record-number protection, epochs, replay, key retention, CIDs, reassembly, transcripts, flights, timers, cookies, amplification, and PMTU budgets explicit and caller-owned;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run DTLS vectors plus loss, reorder, duplicate, header, record-number, replay, CID, overlap, conflict, ACK, timer, retransmission, retention, and independent-peer matrices;
- exercise unauthenticated reconstruction failures, replay across transitions, spoofed amplification, sequence exhaustion, sparse fragments, stale timers, CID updates, provider failure, and hostile PMTU changes;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- DTLS remains bounded and deterministic on an adversarial datagram network and releases no unauthenticated transition or stale secret;
- `v0.91.0 implementation stop reached. Run pentest for this exact commit.`

### v0.92.0 - ML-KEM Arithmetic And Encoding

Status: planned

Plan scope: Implement ML-KEM polynomial, NTT, sampling, and canonical encoding and decoding foundations.

Goal: complete the **ML-KEM Arithmetic And Encoding** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- implement only standards-traced ML-KEM parameters and exact final hybrid encodings with canonical lengths, component order, transcript binding, randomness, and explicit experimental boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run FIPS 203 vectors and errata, malformed key and ciphertext corpora, differential tests, stack and resource profiles, implicit-rejection tests, and supported-target evidence;
- run constant-time decapsulation, failure-path, downgrade, fragmentation, combiner, code-point, required-policy, and classical-only fallback tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- PQC scope has external review and either final standards admission or explicit exclusion from stable compatibility and FIPS claims;
- `v0.92.0 implementation stop reached. Run pentest for this exact commit.`

### v0.93.0 - ML-KEM Key Generation And Encapsulation

Status: planned

Plan scope: Implement ML-KEM-512/768/1024 key generation and encapsulation with FIPS 203, errata, randomness, stack, and applicable SP 800-227 checks.

Goal: complete the **ML-KEM Key Generation And Encapsulation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- implement only standards-traced ML-KEM parameters and exact final hybrid encodings with canonical lengths, component order, transcript binding, randomness, and explicit experimental boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run FIPS 203 vectors and errata, malformed key and ciphertext corpora, differential tests, stack and resource profiles, implicit-rejection tests, and supported-target evidence;
- run constant-time decapsulation, failure-path, downgrade, fragmentation, combiner, code-point, required-policy, and classical-only fallback tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- PQC scope has external review and either final standards admission or explicit exclusion from stable compatibility and FIPS claims;
- `v0.93.0 implementation stop reached. Run pentest for this exact commit.`

### v0.94.0 - ML-KEM Decapsulation And Implicit Rejection

Status: planned

Plan scope: Implement constant-time ML-KEM decapsulation and implicit rejection with malformed-ciphertext, failure-path, and side-channel campaigns.

Goal: complete the **ML-KEM Decapsulation And Implicit Rejection** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- implement only standards-traced ML-KEM parameters and exact final hybrid encodings with canonical lengths, component order, transcript binding, randomness, and explicit experimental boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run FIPS 203 vectors and errata, malformed key and ciphertext corpora, differential tests, stack and resource profiles, implicit-rejection tests, and supported-target evidence;
- run constant-time decapsulation, failure-path, downgrade, fragmentation, combiner, code-point, required-policy, and classical-only fallback tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- PQC scope has external review and either final standards admission or explicit exclusion from stable compatibility and FIPS claims;
- `v0.94.0 implementation stop reached. Run pentest for this exact commit.`

### v0.95.0 - Standard Hybrid Groups

Status: planned

Plan scope: Implement only final standardized X25519MLKEM768, P256MLKEM768, and P384MLKEM1024 encodings, component order, lengths, identifiers, and combiner behavior.

Goal: complete the **Standard Hybrid Groups** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- implement only standards-traced ML-KEM parameters and exact final hybrid encodings with canonical lengths, component order, transcript binding, randomness, and explicit experimental boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run FIPS 203 vectors and errata, malformed key and ciphertext corpora, differential tests, stack and resource profiles, implicit-rejection tests, and supported-target evidence;
- run constant-time decapsulation, failure-path, downgrade, fragmentation, combiner, code-point, required-policy, and classical-only fallback tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- PQC scope has external review and either final standards admission or explicit exclusion from stable compatibility and FIPS claims;
- `v0.95.0 implementation stop reached. Run pentest for this exact commit.`

### v0.96.0 - Hybrid Protocol Integration

Status: planned

Plan scope: Complete hybrid TLS, DTLS, and QUIC transcript, resource, fragmentation, downgrade, required-policy, and interoperability gates with no classical-only fallback.

Goal: complete the **Hybrid Protocol Integration** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- implement only standards-traced ML-KEM parameters and exact final hybrid encodings with canonical lengths, component order, transcript binding, randomness, and explicit experimental boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run FIPS 203 vectors and errata, malformed key and ciphertext corpora, differential tests, stack and resource profiles, implicit-rejection tests, and supported-target evidence;
- run constant-time decapsulation, failure-path, downgrade, fragmentation, combiner, code-point, required-policy, and classical-only fallback tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- PQC scope has external review and either final standards admission or explicit exclusion from stable compatibility and FIPS claims;
- `v0.96.0 implementation stop reached. Run pentest for this exact commit.`

### v0.97.0 - PQ Standards And Audit Gate

Status: planned

Plan scope: Complete PQ external review and standards freeze; admit final RFC groups or keep draft work experimental and outside stable and FIPS claims.

Goal: complete the **PQ Standards And Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- implement only standards-traced ML-KEM parameters and exact final hybrid encodings with canonical lengths, component order, transcript binding, randomness, and explicit experimental boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run FIPS 203 vectors and errata, malformed key and ciphertext corpora, differential tests, stack and resource profiles, implicit-rejection tests, and supported-target evidence;
- run constant-time decapsulation, failure-path, downgrade, fragmentation, combiner, code-point, required-policy, and classical-only fallback tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- PQC scope has external review and either final standards admission or explicit exclusion from stable compatibility and FIPS claims;
- `v0.97.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 4: FIPS Module Instantiation And Validation

The FIPS-aware architecture frozen before crypto is instantiated, tested, documented, and submitted as an exact-build module.

### v0.98.0 - FIPS Module Boundary

Status: planned

Plan scope: Instantiate the exact binary and artifact boundary, operational environments, ports, services, roles, SSP inventory, compiler/linker/CPU inputs, and approved and non-approved exclusions.

Goal: complete the **FIPS Module Boundary** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- instantiate the predesigned narrow module using exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved and non-approved boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, fault injection, service indicators, SSP lifecycle, entropy and DRBG, reproducible artifacts, and applicable ACVTS and CAVP evidence;
- prove permanent failure latching, zeroization completion, dispatch separation, no additive feature activation, no untested environment claim, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- claims match accredited evidence exactly and algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.98.0 implementation stop reached. Run pentest for this exact commit.`

### v0.99.0 - Approved Provider And Service Indicator

Status: planned

Plan scope: Implement the sealed approved-only provider and unambiguous per-service approved indicator with no additive fips feature or construction before self-test success.

Goal: complete the **Approved Provider And Service Indicator** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- instantiate the predesigned narrow module using exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved and non-approved boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, fault injection, service indicators, SSP lifecycle, entropy and DRBG, reproducible artifacts, and applicable ACVTS and CAVP evidence;
- prove permanent failure latching, zeroization completion, dispatch separation, no additive feature activation, no untested environment claim, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- claims match accredited evidence exactly and algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.99.0 implementation stop reached. Run pentest for this exact commit.`

### v0.100.0 - FIPS Self-Tests And Failure Latch

Status: planned

Plan scope: Implement integrity, CAST/KAT, pairwise-consistency, required conditional tests, permanent failure latch, and deterministic fault-injection evidence.

Goal: complete the **FIPS Self-Tests And Failure Latch** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- instantiate the predesigned narrow module using exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved and non-approved boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, fault injection, service indicators, SSP lifecycle, entropy and DRBG, reproducible artifacts, and applicable ACVTS and CAVP evidence;
- prove permanent failure latching, zeroization completion, dispatch separation, no additive feature activation, no untested environment claim, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- claims match accredited evidence exactly and algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.100.0 implementation stop reached. Run pentest for this exact commit.`

### v0.101.0 - SSP Lifecycle And Zeroization Services

Status: planned

Plan scope: Define SSP entry, output, storage, high-water lifetime, external storage, accelerator handle, and zeroization services with completion indications and secret-free status events.

Goal: complete the **SSP Lifecycle And Zeroization Services** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- instantiate the predesigned narrow module using exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved and non-approved boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, fault injection, service indicators, SSP lifecycle, entropy and DRBG, reproducible artifacts, and applicable ACVTS and CAVP evidence;
- prove permanent failure latching, zeroization completion, dispatch separation, no additive feature activation, no untested environment claim, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- claims match accredited evidence exactly and algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.101.0 implementation stop reached. Run pentest for this exact commit.`

### v0.102.0 - Entropy And DRBG Boundary

Status: planned

Plan scope: Implement the SP 800-90 entropy and DRBG boundary, health tests, security-strength mapping, reseed and fork behavior, failure model, and platform entropy evidence.

Goal: complete the **Entropy And DRBG Boundary** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- instantiate the predesigned narrow module using exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved and non-approved boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, fault injection, service indicators, SSP lifecycle, entropy and DRBG, reproducible artifacts, and applicable ACVTS and CAVP evidence;
- prove permanent failure latching, zeroization completion, dispatch separation, no additive feature activation, no untested environment claim, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- claims match accredited evidence exactly and algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.102.0 implementation stop reached. Run pentest for this exact commit.`

### v0.103.0 - ACVTS And CAVP Evidence

Status: planned

Plan scope: Complete ACVTS and CAVP campaigns for every approved implementation, dispatch path, parameter set, and operational environment.

Goal: complete the **ACVTS And CAVP Evidence** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- instantiate the predesigned narrow module using exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved and non-approved boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, fault injection, service indicators, SSP lifecycle, entropy and DRBG, reproducible artifacts, and applicable ACVTS and CAVP evidence;
- prove permanent failure latching, zeroization completion, dispatch separation, no additive feature activation, no untested environment claim, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- claims match accredited evidence exactly and algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.103.0 implementation stop reached. Run pentest for this exact commit.`

### v0.104.0 - CMVP Submission Artifacts

Status: planned

Plan scope: Produce the CMVP Security Policy, finite-state model, service and SSP inventory, entropy assessment, source-to-object trace, and reproducible module artifacts.

Goal: complete the **CMVP Submission Artifacts** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- instantiate the predesigned narrow module using exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved and non-approved boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, fault injection, service indicators, SSP lifecycle, entropy and DRBG, reproducible artifacts, and applicable ACVTS and CAVP evidence;
- prove permanent failure latching, zeroization completion, dispatch separation, no additive feature activation, no untested environment claim, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- claims match accredited evidence exactly and algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.104.0 implementation stop reached. Run pentest for this exact commit.`

### v0.105.0 - Accredited FIPS Evaluation

Status: planned

Plan scope: Complete accredited-lab FIPS 140-3 evaluation, remediation, retest, and certificate and caveat recording; make no validation claim before issuance.

Goal: complete the **Accredited FIPS Evaluation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- instantiate the predesigned narrow module using exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved and non-approved boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, fault injection, service indicators, SSP lifecycle, entropy and DRBG, reproducible artifacts, and applicable ACVTS and CAVP evidence;
- prove permanent failure latching, zeroization completion, dispatch separation, no additive feature activation, no untested environment claim, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- claims match accredited evidence exactly and algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.105.0 implementation stop reached. Run pentest for this exact commit.`

### v0.106.0 - Boundary And Package Audit

Status: planned

Plan scope: Complete the final modern, historical, experimental, and FIPS dependency-boundary, symbol, dispatch, feature, and package-content audit.

Goal: complete the **Boundary And Package Audit** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- instantiate the predesigned narrow module using exact source, compiler, linker, flags, CPU features, operational environments, services, roles, SSPs, and approved and non-approved boundaries;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run integrity and algorithm self-tests, fault injection, service indicators, SSP lifecycle, entropy and DRBG, reproducible artifacts, and applicable ACVTS and CAVP evidence;
- prove permanent failure latching, zeroization completion, dispatch separation, no additive feature activation, no untested environment claim, and no output through failed self-tests;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- claims match accredited evidence exactly and algorithm testing alone is never represented as FIPS 140-3 validation;
- `v0.106.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 5: Stable Integration, Optional Modules, Assurance, And General Availability

Stable public integration and independent optional modules precede complete assurance, remediation, freeze, rehearsal, and immutable promotion.

### v0.107.0 - Facade Configuration Typestates

Status: planned

Plan scope: Freeze facade typestates for exact modern versions, suites, trust, identity, resources, revocation, PSK, 0-RTT, CT, and provider policy; expose no raw crypto re-export or legacy-version range.

Goal: complete the **Facade Configuration Typestates** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.107.0 implementation stop reached. Run pentest for this exact commit.`

### v0.108.0 - Stable Sans-I/O API

Status: planned

Plan scope: Promote the exercised internal effects model into the stable deterministic client and server Event-to-Action API with consumed/produced counts, backpressure, pending operations, cancellation, and compile-fail misuse tests.

Goal: complete the **Stable Sans-I/O API** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.108.0 implementation stop reached. Run pentest for this exact commit.`

### v0.109.0 - Host Platform Adapters

Status: planned

Plan scope: Add host adapters for raw entropy, secure randomness, separate wall and monotonic clocks, opaque-key accelerators, and transport and storage examples plus async integration guidance.

Goal: complete the **Host Platform Adapters** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.109.0 implementation stop reached. Run pentest for this exact commit.`

### v0.110.0 - Zero-Allocation And Resource Proof

Status: planned

Plan scope: Prove the caller-owned zero-allocation profile with exact workspace sizes, non-overlapping arenas, stack ceilings, concurrency limits, and hostile-load budgets.

Goal: complete the **Zero-Allocation And Resource Proof** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.110.0 implementation stop reached. Run pentest for this exact commit.`

### v0.111.0 - Aesynx Qualification

Status: planned

Plan scope: Qualify the Aesynx target and entropy, randomness, time, transport, storage, and accelerator adapters with boot-to-handshake and lifecycle tests when the target is available.

Goal: complete the **Aesynx Qualification** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.111.0 implementation stop reached. Run pentest for this exact commit.`

### v0.112.0 - Operational State Rotation

Status: planned

Plan scope: Complete session cache, ticket-key and resumption-PSK rotation, anti-replay storage, certificate and private-key rotation, trust-anchor rotation, and transactional failure recovery.

Goal: complete the **Operational State Rotation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.112.0 implementation stop reached. Run pentest for this exact commit.`

### v0.113.0 - Record Size Limit

Status: planned

Plan scope: Implement Record Size Limit negotiation and enforcement with directional limits, fragmentation, buffering, peer-violation, and interoperability tests.

Goal: complete the **Record Size Limit** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.113.0 implementation stop reached. Run pentest for this exact commit.`

### v0.114.0 - Raw Public Keys

Status: planned

Plan scope: Implement Raw Public Keys with a dedicated pinning and trust-provider contract, identity and rotation policy, negotiation, and proof that RPK never silently bypasses X.509 requirements.

Goal: complete the **Raw Public Keys** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.114.0 implementation stop reached. Run pentest for this exact commit.`

### v0.115.0 - HPKE KEM And Context Foundation

Status: planned

Plan scope: Implement HPKE DHKEM X25519 and P-256 context derivation, labeled HKDF operations, public-key validation, domain separation, and bounded context state.

Goal: complete the **HPKE KEM And Context Foundation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.115.0 implementation stop reached. Run pentest for this exact commit.`

### v0.116.0 - HPKE Base Mode

Status: planned

Plan scope: Implement RFC 9180 HPKE base mode with admitted AEADs, sequence and nonce exhaustion, seal/open failure atomicity, official vectors, and independent differential tests.

Goal: complete the **HPKE Base Mode** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.116.0 implementation stop reached. Run pentest for this exact commit.`

### v0.117.0 - ECH Configuration And Suite Selection

Status: planned

Plan scope: Implement bounded ECHConfig parsing, version and suite selection, public-name policy, key configuration, GREASE inputs, and resource limits.

Goal: complete the **ECH Configuration And Suite Selection** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.117.0 implementation stop reached. Run pentest for this exact commit.`

### v0.118.0 - ECH Protocol Integration

Status: planned

Plan scope: Implement inner and outer ClientHello construction, outer-extension references, AAD, acceptance confirmation, retry configurations, HRR interaction, GREASE, padding, transcript binding, and downgrade/resource tests.

Goal: complete the **ECH Protocol Integration** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.118.0 implementation stop reached. Run pentest for this exact commit.`

### v0.119.0 - Delegated Credentials

Status: planned

Plan scope: Implement delegated credentials as an independent optional module with authorization, lifetime, signature, selection, revocation interaction, and downgrade policy.

Goal: complete the **Delegated Credentials** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.119.0 implementation stop reached. Run pentest for this exact commit.`

### v0.120.0 - Certificate Compression Provider

Status: planned

Plan scope: Implement certificate compression through a bounded caller-provided decompression provider with transcript preservation, exact output length, ratio, CPU-work, workspace, algorithm-selection, and no-peer-admission-before-authentication rules; first-party zlib, Brotli, and Zstandard remain separate future work.

Goal: complete the **Certificate Compression Provider** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze public typestates and effects with explicit trust, identity, entropy, clocks, storage, compression, accelerator, cancellation, workspace, extension, and downgrade contracts;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run compile-fail misuse tests, deterministic traces, adapter and provider fault injection, zero-allocation accounting, stack ceilings, rotation, extension vectors, and every supported target;
- exercise unavailable effects, partial providers, cancellation, stale handles, storage races, decompression bombs, trust-model confusion, resource exhaustion, and forbidden policy fallback;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- public integration and each optional module is runtime-neutral, bounded, independently disableable, and incapable of weakening authentication or transcript policy;
- `v0.120.0 implementation stop reached. Run pentest for this exact commit.`

### v0.121.0 - Formal Harnesses

Status: planned

Plan scope: Complete Kani or equivalent harnesses for cursors, lengths, state reachability, exhaustion, replay, transactional transitions, and secret-release invariants using pinned external tools.

Goal: complete the **Formal Harnesses** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, API-freeze, and operational evidence for exact admitted scope;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named campaign across every relevant compiler, target, provider, feature set, package archive, independent peer, and clean environment;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, key-compromise, and incident procedures;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the exact-commit evidence set is complete, findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.121.0 implementation stop reached. Run pentest for this exact commit.`

### v0.122.0 - Fuzz And Differential Campaign

Status: planned

Plan scope: Complete parser and state fuzzing, deterministic mutation, differential corpora, and crash minimization without adding third-party crates to repository Cargo manifests or shipped graphs.

Goal: complete the **Fuzz And Differential Campaign** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, API-freeze, and operational evidence for exact admitted scope;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named campaign across every relevant compiler, target, provider, feature set, package archive, independent peer, and clean environment;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, key-compromise, and incident procedures;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the exact-commit evidence set is complete, findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.122.0 implementation stop reached. Run pentest for this exact commit.`

### v0.123.0 - Memory And Side-Channel Evidence

Status: planned

Plan scope: Complete Miri and sanitizer evidence plus compiler/target constant-time assembly, zeroization-store survival, cache/branch, and statistical side-channel matrices.

Goal: complete the **Memory And Side-Channel Evidence** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, API-freeze, and operational evidence for exact admitted scope;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named campaign across every relevant compiler, target, provider, feature set, package archive, independent peer, and clean environment;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, key-compromise, and incident procedures;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the exact-commit evidence set is complete, findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.123.0 implementation stop reached. Run pentest for this exact commit.`

### v0.124.0 - Sustained Platform And Hostile-Load Qualification

Status: planned

Plan scope: Sustain Linux, Windows, macOS, BSD, Android, iOS, bare-metal, and available Aesynx qualification under concurrency, provider failure, resource exhaustion, and hostile load.

Goal: complete the **Sustained Platform And Hostile-Load Qualification** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, API-freeze, and operational evidence for exact admitted scope;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named campaign across every relevant compiler, target, provider, feature set, package archive, independent peer, and clean environment;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, key-compromise, and incident procedures;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the exact-commit evidence set is complete, findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.124.0 implementation stop reached. Run pentest for this exact commit.`

### v0.125.0 - Consolidated External Audits

Status: planned

Plan scope: Complete exact-commit external crypto, PKI, TLS, DTLS, QUIC, PQ, FIPS-boundary, optional-module, and systems-integration audits.

Goal: complete the **Consolidated External Audits** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, API-freeze, and operational evidence for exact admitted scope;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named campaign across every relevant compiler, target, provider, feature set, package archive, independent peer, and clean environment;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, key-compromise, and incident procedures;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the exact-commit evidence set is complete, findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.125.0 implementation stop reached. Run pentest for this exact commit.`

### v0.126.0 - Audit Remediation And Clean Retest

Status: planned

Plan scope: Remediate every admitted finding, add permanent regressions, and obtain clean independent retests with no unresolved critical or high findings.

Goal: complete the **Audit Remediation And Clean Retest** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, API-freeze, and operational evidence for exact admitted scope;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named campaign across every relevant compiler, target, provider, feature set, package archive, independent peer, and clean environment;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, key-compromise, and incident procedures;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the exact-commit evidence set is complete, findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.126.0 implementation stop reached. Run pentest for this exact commit.`

### v0.127.0 - Public API Requirements And Documentation Freeze

Status: planned

Plan scope: Freeze public APIs, features, package inventory, requirements ledger, admitted algorithms and extensions, migration guidance, deployment profiles, incident procedures, limitations, and non-goals.

Goal: complete the **Public API Requirements And Documentation Freeze** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, API-freeze, and operational evidence for exact admitted scope;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named campaign across every relevant compiler, target, provider, feature set, package archive, independent peer, and clean environment;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, key-compromise, and incident procedures;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the exact-commit evidence set is complete, findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.127.0 implementation stop reached. Run pentest for this exact commit.`

### v0.128.0 - Clean-Room Release Rehearsal

Status: planned

Plan scope: Pass reproducible clean-room builds, package installation, artifact comparison, rollback, key-compromise, incident, and disaster-recovery exercises.

Goal: complete the **Clean-Room Release Rehearsal** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- capture reproducible proof, fuzz, sanitizer, side-channel, platform, hostile-load, external-review, remediation, API-freeze, and operational evidence for exact admitted scope;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- run the named campaign across every relevant compiler, target, provider, feature set, package archive, independent peer, and clean environment;
- retain minimized regressions for every finding and prove clean retests, requirements traceability, artifact identity, rollback, key-compromise, and incident procedures;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- the exact-commit evidence set is complete, findings are dispositioned, and frozen claims do not exceed tested behavior;
- `v0.128.0 implementation stop reached. Run pentest for this exact commit.`

### v1.0.0-rc.1 - Exact Production Candidate

Status: planned

Plan scope: Build final artifacts once and freeze source, compiler, flags, archives, SBOM, checksums, provenance, documentation, and the pentested exact commit.

Goal: complete the **Exact Production Candidate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze or promote only approved modern artifacts, manifests, source, compiler, flags, archives, SBOM, checksums, provenance, documentation, and metadata;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- reproduce artifacts cleanly, compare every byte and checksum, verify installation and rollback, and rerun every production-admission gate;
- exercise key-compromise and disaster procedures, registry and package inspection, downstream compatibility, and absence of historical, draft, or excluded scope;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- stable artifacts are byte-identical to the approved candidate and every public claim maps to permanent exact-commit evidence;
- `v1.0.0-rc.1 implementation stop reached. Run pentest for this exact commit.`

### v1.0.0 - First Serious Production-Ready Brynja TLS Release

Status: planned

Plan scope: Promote only the byte-identical approved candidate without rebuild, source change, metadata drift, or expanded capability claim.

Goal: complete the **First Serious Production-Ready Brynja TLS Release** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, failure, and package boundaries;
- freeze or promote only approved modern artifacts, manifests, source, compiler, flags, archives, SBOM, checksums, provenance, documentation, and metadata;
- update requirement mappings, threat-model delta, security controls, current
  status, known limitations, release notes, and permanent evidence index for
  this exact implementation.

Verification:

- reproduce artifacts cleanly, compare every byte and checksum, verify installation and rollback, and rerun every production-admission gate;
- exercise key-compromise and disaster procedures, registry and package inspection, downstream compatibility, and absence of historical, draft, or excluded scope;
- pass full repository checks, all promised Rust versions and targets,
  dependency policy, advisory scans, SBOM comparison, package inspection,
  documentation links, and modern/historical graph isolation.

Exit criteria:

- stable artifacts are byte-identical to the approved candidate and every public claim maps to permanent exact-commit evidence;
- `v1.0.0 implementation stop reached. Run pentest for this exact commit.`
