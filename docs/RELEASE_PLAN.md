# Brynja Release Plan To 1.0

Status: normative planning document

Every Brynja milestone is independently reviewable, testable, pentestable, and
safe to stop. [VERSION_PLAN.md](VERSION_PLAN.md) defines exact titles, scopes,
and ordering; this document repeats them and automated checks reject drift.

## Release Principles

Every release requires generated normative traceability, explicit resource,
secret, storage, effect, dependency and failure boundaries, adversarial tests,
documented limitations, no third-party crates in repository Cargo manifests,
`no_std` evidence, SBOM comparison, clean CI and CodeQL Default, and an
exact-commit pentest.

Early negotiation policy is separate from final routing. Optional modules remain
downstream of validated provider ports and pass a composition gate before public
API freeze. FIPS catastrophic module failure is distinct from terminating a
connection or configuration that violates approved-only policy.

Every arithmetic and cryptographic implementation stop introduces its applicable
proof harness beside the production code. Claims must identify whether evidence
is a symbolic full-width proof, a sound limb-count-parameterized proof, a
reduced-width exhaustive model that validates algorithm and harness structure,
or production-width vector and differential evidence. Reduced-width evidence
never establishes production-width equivalence, and every residual proof gap is
published through the final v0.155.0 coverage gate.

## Required Milestone Contract

Every section contains Status, Plan scope, Goal, Deliverables, Verification, and
Exit criteria. Repository checks are additive and one stop never admits adjacent
capability.

## Historical Package Release Line

Historical packages use independent SemVer and separately pass source, codec,
state, primitive, client, optional server, containment, and audit/pentest stages.
SSL 1 remains research-only and unpublished.

| Historical stage | Required result |
| --- | --- |
| `H0.1.0` | Authenticate sources and rights, record errata, publish conspicuous insecurity warnings, and freeze the protocol threat model. |
| `H0.2.0` | Implement only the protocol-specific bounded wire codec. |
| `H0.3.0` | Implement isolated state with no shared modern configuration, negotiation, credentials, caches, tickets, paths, or fallback. |
| `H0.4.0` | Bind audited shared primitives and keep required weak primitives in a historical-only crypto package. |
| `H0.5.0` | Complete controlled client-only interoperability and containment evidence. |
| `H0.6.0` | Add server interoperability only when separately justified and reviewed for amplification and hostile load. |
| `H0.7.0` | Require separate listeners, paths, policy, credentials, storage, diagnostics, and process containment. |
| `H0.8.0` | Complete a protocol-specific external audit and pentest and verify every warning and non-fallback property. |

## Phase 0: Repository, Effects, Memory, And Wire Foundations

Generated requirements and upstream interfaces precede implementation.

### v0.1.0 - Workspace Foundation

Status: awaiting pentest

Plan scope: Preserve the existing workspace foundation with no cryptographic or protocol security claim.

Goal: complete the **Workspace Foundation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- make policy executable through generated traceability, fail-closed scripts, broken fixtures, immutable evidence, ownership, and release boundaries;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exercise positive and broken dependency, metadata, standards-ledger, workflow, isolation, evidence, and release-state fixtures;
- inspect source locks, clean archives, permissions, tag assumptions, tool pinning, ledger completeness, and reproducibility;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- repository evidence and enforcement agree and every deliberate violation fails before release;
- `v0.1.0 implementation stop reached. Run pentest for this exact commit.`

### v0.2.0 - Release And Isolation Enforcement

Status: planned

Plan scope: Fix exact-HEAD pentest comparison, validate all-feature graphs and every package class, add negative modern and historical isolation fixtures, and document protected release controls.

Goal: complete the **Release And Isolation Enforcement** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- make policy executable through generated traceability, fail-closed scripts, broken fixtures, immutable evidence, ownership, and release boundaries;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exercise positive and broken dependency, metadata, standards-ledger, workflow, isolation, evidence, and release-state fixtures;
- inspect source locks, clean archives, permissions, tag assumptions, tool pinning, ledger completeness, and reproducibility;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- repository evidence and enforcement agree and every deliberate violation fails before release;
- `v0.2.0 implementation stop reached. Run pentest for this exact commit.`

### v0.3.0 - Requirements And Standards Ledger

Status: planned

Plan scope: Generate the requirements and source ledger from every admitted algorithm, encoding, extension, and protocol milestone; include RFC 5077, RFC 5705, RFC 5746, RFC 6962 or RFC 9162, RFC 7468, RFC 8410, RFC 5958 or the chosen PKCS#8 authority, RFC 9146 when DTLS 1.2 CID is admitted, RFC 9258, RFC 9266, applicable NIST standards and errata, frozen IANA snapshots, and the final ECDHE-ML-KEM RFC and code points before admission.

Goal: complete the **Requirements And Standards Ledger** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- make policy executable through generated traceability, fail-closed scripts, broken fixtures, immutable evidence, ownership, and release boundaries;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exercise positive and broken dependency, metadata, standards-ledger, workflow, isolation, evidence, and release-state fixtures;
- inspect source locks, clean archives, permissions, tag assumptions, tool pinning, ledger completeness, and reproducibility;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- repository evidence and enforcement agree and every deliberate violation fails before release;
- `v0.3.0 implementation stop reached. Run pentest for this exact commit.`

### v0.4.0 - Assurance Harness And Bare-Metal Matrix

Status: planned

Plan scope: Establish first-party mutation and differential harnesses, true bare-metal targets, and pinned external assurance-tool policy without adding third-party crates to repository Cargo manifests.

Goal: complete the **Assurance Harness And Bare-Metal Matrix** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- make policy executable through generated traceability, fail-closed scripts, broken fixtures, immutable evidence, ownership, and release boundaries;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exercise positive and broken dependency, metadata, standards-ledger, workflow, isolation, evidence, and release-state fixtures;
- inspect source locks, clean archives, permissions, tag assumptions, tool pinning, ledger completeness, and reproducibility;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- repository evidence and enforcement agree and every deliberate violation fails before release;
- `v0.4.0 implementation stop reached. Run pentest for this exact commit.`

### v0.5.0 - Error Alert And Exhaustion Domains

Status: planned

Plan scope: Freeze non-secret error, alert, close, provider-failure, and resource-exhaustion domains; prohibit secret-bearing formatting and ambiguous failure collapse.

Goal: complete the **Error Alert And Exhaustion Domains** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.5.0 implementation stop reached. Run pentest for this exact commit.`

### v0.6.0 - Bounded Numeric And Resource Domains

Status: planned

Plan scope: Introduce checked bounded integers, counts, lengths, sequence numbers, epochs, and immutable resource and work budgets.

Goal: complete the **Bounded Numeric And Resource Domains** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.6.0 implementation stop reached. Run pentest for this exact commit.`

### v0.7.0 - Borrowed Read Cursor

Status: planned

Plan scope: Implement a borrowed read cursor with exact consumption, truncation-at-every-byte coverage, and no indexing panics.

Goal: complete the **Borrowed Read Cursor** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.7.0 implementation stop reached. Run pentest for this exact commit.`

### v0.8.0 - Transactional Write Cursor

Status: planned

Plan scope: Implement caller-buffer write cursors with transactional encode-or-no-mutation behavior.

Goal: complete the **Transactional Write Cursor** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.8.0 implementation stop reached. Run pentest for this exact commit.`

### v0.9.0 - Caller-Owned Workspace And Arena Model

Status: planned

Plan scope: Define caller-owned workspaces and non-overlapping secret, plaintext, transcript, certificate, and output arenas with overlap rules, high-water tracking, and allocation counters.

Goal: complete the **Caller-Owned Workspace And Arena Model** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.9.0 implementation stop reached. Run pentest for this exact commit.`

### v0.10.0 - Secret Lifetime And Destruction Contract

Status: planned

Plan scope: Define non-cloneable and non-serializable secret ownership, transition, error, cancellation, provider-failure and drop destruction, immediate obsolete-secret cleanup, external-store and accelerator duties, and a mandatory production guarantee for the complete owned memory region.

Goal: complete the **Secret Lifetime And Destruction Contract** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.10.0 implementation stop reached. Run pentest for this exact commit.`

### v0.11.0 - Owned-Memory Zeroization Primitive

Status: planned

Plan scope: After explicit unsafe-policy approval, implement the smallest isolated first-party primitive needed to preserve zeroization stores through optimization; define proof obligations, cache and DMA completion duties, MIR, LLVM and assembly evidence for every supported compiler and target, and precise exclusions for registers, copies, dumps, and physical memory.

Goal: complete the **Owned-Memory Zeroization Primitive** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.11.0 implementation stop reached. Run pentest for this exact commit.`

### v0.12.0 - Constant-Time Foundation

Status: planned

Plan scope: Implement constant-time equality, choice and mask types, conditional select and swap, fixed-width secret operations, compiler barriers, and rules forbidding secret-dependent control flow, indexing, loop counts, and error timing.

Goal: complete the **Constant-Time Foundation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.12.0 implementation stop reached. Run pentest for this exact commit.`

### v0.13.0 - Provider Capabilities And Opaque Handles

Status: planned

Plan scope: Define all protocol-facing crypto, signature, KEM, AEAD, entropy, clock, path, storage, and pending-operation contracts in upstream no_std interface modules such as brynja-core, with opaque handles, frozen capabilities, transactional installation, exact-operation token binding, and no implicit fallback; brynja-platform only implements downstream contracts.

Goal: complete the **Provider Capabilities And Opaque Handles** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.13.0 implementation stop reached. Run pentest for this exact commit.`

### v0.14.0 - Entropy And Secure-Random Contracts

Status: planned

Plan scope: Separate caller-provided raw entropy from initialized secure randomness; type security strength, purpose, retryable and permanent failure, fork and reseed rules, clone prohibition, and test-only providers that production configuration cannot construct.

Goal: complete the **Entropy And Secure-Random Contracts** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.14.0 implementation stop reached. Run pentest for this exact commit.`

### v0.15.0 - Wall And Monotonic Clock Contracts

Status: planned

Plan scope: Define non-interchangeable typed wall time for PKI and typed monotonic time for timers, freshness, tickets, and replay policy with checked arithmetic and explicit unavailable-time behavior.

Goal: complete the **Wall And Monotonic Clock Contracts** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.15.0 implementation stop reached. Run pentest for this exact commit.`

### v0.16.0 - Pending Operations And Accelerator Lifecycle

Status: planned

Plan scope: Define resumable provider tokens, certificate, signature and accelerator requests, cancellation, retry semantics, backpressure, and failure-atomic state transitions; external-key and accelerator-handle destruction completes only through a mandatory single-consumption token transition, never through an informational event.

Goal: complete the **Pending Operations And Accelerator Lifecycle** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, terminal states, and exact single consumption of every external-key or accelerator-handle destruction token;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.16.0 implementation stop reached. Run pentest for this exact commit.`

### v0.17.0 - FIPS-Aware Provider Architecture

Status: planned

Plan scope: Freeze approved and non-approved service separation, self-test and permanent-failure hooks, dispatch, service indicators, SSP boundaries, deterministic module-build expectations, operational-environment assumptions, and sealed-provider exclusions without making a validation claim.

Goal: complete the **FIPS-Aware Provider Architecture** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.17.0 implementation stop reached. Run pentest for this exact commit.`

### v0.18.0 - Bounded Observational Security Event Contract

Status: planned

Plan scope: Define an upstream no_std, Sans-I/O SecurityEvent audit schema that only duplicates authoritative state and mandatory results for self-tests, service approval, protocol and profile selection, authentication, tickets, resumption, PSKs, early data, replay, amplification, exhaustion, provider failure, key lifecycle, ECH, and terminal transitions; FIPS approval is returned by a mandatory typed service result or ActionV1, external-key destruction by a mandatory completion-token transition, and authentication, ECH, early-data, anti-replay, and policy decisions by engine state plus mandatory results, so dropped or ignored events cannot make a rejected or non-approved connection appear accepted or approved; events remain caller-drained, allocation-free, bounded, secret-free, format-safe, alert-independent, optionally caller-timestamped or explicitly untimestamped for later enrichment, use saturating drop counters with visible saturation, contain no secret or stable correlating identifier, never reenter, and cannot block or alter cryptographic state.

Goal: complete the **Bounded Observational Security Event Contract** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze bounded discriminants and payloads, caller-drain and optional timestamp
  enrichment actions, deterministic ordering, identifier redaction, saturating
  dropped-event accounting with a visible saturation state, and the separation
  between operational evidence and peer-visible alerts;
- define authoritative mandatory results and state transitions for service
  approval, external-key destruction, authentication, ECH, early data,
  anti-replay, and policy decisions; events only duplicate those outcomes for
  audit and never complete or authorize them;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exhaustively construct and format every event variant and prove no key handle,
  identity, plaintext, transcript, PSK identity, ticket, ECH inner name, or
  stable cross-connection correlation value can appear;
- test timestamp-free boot and self-tests, later caller enrichment, full queues,
  delayed and absent drains, saturating counters and saturation reporting,
  unavailable time, cancellation, provider failure, terminal transitions, and
  attempted reentrancy without cryptographic-state or peer-alert differences;
- discard every SecurityEvent in accepted, rejected, approved, non-approved,
  destruction, authentication, ECH, early-data, anti-replay, and policy paths
  and prove mandatory results and engine state remain complete and unambiguous;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- security events are bounded, pull-based, secret-free, deterministic audit
  duplicates, while every security decision and completion remains mandatory
  and unambiguous when all events are ignored or dropped;
- `v0.18.0 implementation stop reached. Run pentest for this exact commit.`

### v0.19.0 - TLS And DTLS Record Framing

Status: planned

Plan scope: Keep record framing independent of protocol selection and fallback; ignore TLSPlaintext legacy_record_version where required, validate TLSCiphertext constants where applicable, preserve bytes, and leave version choice exclusively to typed handshake policy.

Goal: complete the **TLS And DTLS Record Framing** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.19.0 implementation stop reached. Run pentest for this exact commit.`

### v0.20.0 - Bounded DER Reader

Status: planned

Plan scope: Implement a non-recursive DER tag, length and value reader with definite, minimal, overflow-safe, depth-, node-, size-, and work-bounded parsing.

Goal: complete the **Bounded DER Reader** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.20.0 implementation stop reached. Run pentest for this exact commit.`

### v0.21.0 - Canonical ASN.1 Primitives

Status: planned

Plan scope: Add canonical ASN.1 integer, bit and octet string, OID, Boolean, string, sequence and set, and time primitives with malformed and non-canonical corpora.

Goal: complete the **Canonical ASN.1 Primitives** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects, mandatory zeroization, version-neutral framing, provider failure, and secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, and terminal states;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- `v0.21.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 1: First-Party Cryptography, Identity Formats, And PKI

Import-only RSA and exact AEAD caller-buffer behavior precede audit gates.

### v0.22.0 - SHA-256

Status: planned

Plan scope: Implement streaming and fixed-message SHA-256 with official vectors, boundary lengths, and exhaustion handling.

Goal: complete the **SHA-256** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.22.0 implementation stop reached. Run pentest for this exact commit.`

### v0.23.0 - SHA-384 And SHA-512

Status: planned

Plan scope: Implement SHA-384 and SHA-512 with official vectors and checked length and exhaustion behavior.

Goal: complete the **SHA-384 And SHA-512** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.23.0 implementation stop reached. Run pentest for this exact commit.`

### v0.24.0 - Keccak SHA-3 And SHAKE

Status: planned

Plan scope: Implement Keccak-f[1600], SHA3-256 and SHA3-512, and SHAKE128 and SHAKE256 as the required ML-KEM foundation.

Goal: complete the **Keccak SHA-3 And SHAKE** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.24.0 implementation stop reached. Run pentest for this exact commit.`

### v0.25.0 - HMAC

Status: planned

Plan scope: Implement HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with constant-time verification and misuse tests.

Goal: complete the **HMAC** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.25.0 implementation stop reached. Run pentest for this exact commit.`

### v0.26.0 - HKDF And TLS Labels

Status: planned

Plan scope: Implement HKDF extract and expand and TLS HKDF-Expand-Label with all input and output limits explicit, introducing symbolic or bounded proof harnesses for output-length and counter exhaustion beside the implementation.

Goal: complete the **HKDF And TLS Labels** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.26.0 implementation stop reached. Run pentest for this exact commit.`

### v0.27.0 - Portable AES

Status: planned

Plan scope: Implement portable constant-time AES-128 and AES-256 without secret-indexed tables; require layered emitted-code and statistical evidence for every admitted compiler and target.

Goal: complete the **Portable AES** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.27.0 implementation stop reached. Run pentest for this exact commit.`

### v0.28.0 - GHASH

Status: planned

Plan scope: Implement constant-time GHASH finite-field arithmetic and a bounded incremental interface.

Goal: complete the **GHASH** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.28.0 implementation stop reached. Run pentest for this exact commit.`

### v0.29.0 - AES-GCM

Status: planned

Plan scope: Implement AES-GCM seal and open with nonce and usage limits, authenticate ciphertext before caller-visible decryption, permit only exact in-place or disjoint buffers, reject partial overlap, leave the complete destination unchanged on authentication failure, and introduce its failure-atomicity proof harness beside the implementation.

Goal: complete the **AES-GCM** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.29.0 implementation stop reached. Run pentest for this exact commit.`

### v0.30.0 - ChaCha20

Status: planned

Plan scope: Implement ChaCha20 with checked counters and deterministic exhaustion closure.

Goal: complete the **ChaCha20** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.30.0 implementation stop reached. Run pentest for this exact commit.`

### v0.31.0 - Poly1305 And ChaCha20-Poly1305

Status: planned

Plan scope: Implement Poly1305 and ChaCha20-Poly1305 with constant-time tag verification, authenticate ciphertext before caller-visible decryption, permit only exact in-place or disjoint buffers, reject partial overlap, leave the complete destination unchanged on failure, and introduce its failure-atomicity proof harness beside the implementation.

Goal: complete the **Poly1305 And ChaCha20-Poly1305** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.31.0 implementation stop reached. Run pentest for this exact commit.`

### v0.32.0 - Fixed-Limb RSA Arithmetic

Status: planned

Plan scope: Implement fixed-limb unsigned arithmetic, Montgomery operations, modular exponentiation, and RSA-size policies with no attacker-selected allocation, normalization schedule, or limb count; introduce carry, borrow, reduction, conversion, and multiplication harnesses, preferring limb-count-generic or full-width proofs and recording reduced-width limits.

Goal: complete the **Fixed-Limb RSA Arithmetic** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.32.0 implementation stop reached. Run pentest for this exact commit.`

### v0.33.0 - Prime-Field And ECC Arithmetic

Status: planned

Plan scope: Implement fixed-width prime-field arithmetic, inversion, square roots, scalar primitives, and complete-formula foundations needed by admitted curves, separate from RSA limbs; introduce field canonicalization, scalar-range, and exceptional-case proof harnesses beside the implementation.

Goal: complete the **Prime-Field And ECC Arithmetic** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.33.0 implementation stop reached. Run pentest for this exact commit.`

### v0.34.0 - X25519 Field And Ladder

Status: planned

Plan scope: Implement X25519 field encoding, canonical decoding policy, clamping, fixed Montgomery ladder, and low-order input handling, with full-width or explicitly reduced-width ladder and exceptional-input proof harnesses introduced beside the implementation.

Goal: complete the **X25519 Field And Ladder** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.34.0 implementation stop reached. Run pentest for this exact commit.`

### v0.35.0 - X25519 ECDH Lifecycle

Status: planned

Plan scope: Implement unbiased ephemeral input generation, no private-key reuse, imported public and private consistency policy, all-zero shared-secret rejection, immediate scalar destruction, and provider-token binding to group, connection, and transcript.

Goal: complete the **X25519 ECDH Lifecycle** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.35.0 implementation stop reached. Run pentest for this exact commit.`

### v0.36.0 - P-256 Group Operations

Status: planned

Plan scope: Implement P-256 point decoding, on-curve and subgroup validation, complete group operations, fixed-schedule scalar multiplication, and official group vectors; introduce point-rejection, scalar-range, group-exception, and canonicalization proof harnesses beside the implementation.

Goal: complete the **P-256 Group Operations** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.36.0 implementation stop reached. Run pentest for this exact commit.`

### v0.37.0 - P-256 ECDH Lifecycle

Status: planned

Plan scope: Implement unbiased P-256 private-scalar generation, no ephemeral reuse, imported key consistency, invalid shared-secret handling, immediate scalar destruction, and exact group, connection, and transcript provider-token binding.

Goal: complete the **P-256 ECDH Lifecycle** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.37.0 implementation stop reached. Run pentest for this exact commit.`

### v0.38.0 - P-256 ECDSA

Status: planned

Plan scope: Implement P-256 ECDSA signing and verification, strict encoding, low-S policy decision, and deterministic and randomized nonce policy using the secure-random contract.

Goal: complete the **P-256 ECDSA** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.38.0 implementation stop reached. Run pentest for this exact commit.`

### v0.39.0 - P-384 Group Operations

Status: planned

Plan scope: Implement P-384 point decoding, on-curve and subgroup validation, complete group operations, fixed-schedule scalar multiplication, and official group vectors; introduce point-rejection, scalar-range, group-exception, and canonicalization proof harnesses beside the implementation.

Goal: complete the **P-384 Group Operations** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.39.0 implementation stop reached. Run pentest for this exact commit.`

### v0.40.0 - P-384 ECDH Lifecycle

Status: planned

Plan scope: Implement unbiased P-384 private-scalar generation, no ephemeral reuse, imported key consistency, invalid shared-secret handling, immediate scalar destruction, and exact group, connection, and transcript provider-token binding.

Goal: complete the **P-384 ECDH Lifecycle** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.40.0 implementation stop reached. Run pentest for this exact commit.`

### v0.41.0 - P-384 ECDSA

Status: planned

Plan scope: Implement P-384 ECDSA signing and verification with strict encoding, nonce policy, vectors, per-target side-channel evidence, and independent review.

Goal: complete the **P-384 ECDSA** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.41.0 implementation stop reached. Run pentest for this exact commit.`

### v0.42.0 - RSA-PSS Verification

Status: planned

Plan scope: Implement strict RSA public-key decoding and RSA-PSS verification with unambiguous parameters and modulus and exponent policy.

Goal: complete the **RSA-PSS Verification** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.42.0 implementation stop reached. Run pentest for this exact commit.`

### v0.43.0 - RSA PKCS1 v1.5 Verification

Status: planned

Plan scope: Implement strict RSASSA-PKCS1-v1_5 certificate-signature verification for SHA-256, SHA-384 and SHA-512 with complete padding, exact DigestInfo, no trailing bytes, and no SHA-1 or MD5 aliases; keep TLS CertificateVerify and signing excluded.

Goal: complete the **RSA PKCS1 v1.5 Verification** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.43.0 implementation stop reached. Run pentest for this exact commit.`

### v0.44.0 - RSA-PSS Private Operations

Status: planned

Plan scope: Implement blinded fixed-schedule first-party RSA-PSS private operations for strictly validated imported keys, with CRT consistency, fault detection, immediate blinding and intermediate destruction, and external-signer support; v1 does not generate RSA keys.

Goal: complete the **RSA-PSS Private Operations** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.44.0 implementation stop reached. Run pentest for this exact commit.`

### v0.45.0 - Ed25519

Status: planned

Plan scope: Implement Ed25519 signing and verification with canonical encoding, small-order and malleability rejection, official vectors, and constant-time secret operations.

Goal: complete the **Ed25519** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.45.0 implementation stop reached. Run pentest for this exact commit.`

### v0.46.0 - Version-One Algorithm Decisions

Status: planned

Plan scope: Freeze explicit v1 admission or exclusion for P-521, Ed448, finite-field DHE, AES-CCM, SHA-1 certificate chains, PKCS1 v1.5 signing, encrypted private-key containers, first-party RSA key generation, ML-DSA, SLH-DSA, and every unimplemented algorithm family.

Goal: complete the **Version-One Algorithm Decisions** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.46.0 implementation stop reached. Run pentest for this exact commit.`

### v0.47.0 - Cryptographic Substrate Audit Gate

Status: planned

Plan scope: Complete independent cryptographic-substrate review, per-target constant-time and zeroization evidence, and remediation before PKI or TLS consumption.

Goal: complete the **Cryptographic Substrate Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- record arithmetic, group, buffer, key, nonce, randomness, use-limit, import-only RSA, ephemeral-lifecycle, constant-time, exclusion, and provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed inputs, invalid secrets, exhaustion, reuse, fault attacks, and zeroization;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted algorithms have functional, caller-buffer, lifecycle, resource, and side-channel evidence before downstream use;
- `v0.47.0 implementation stop reached. Run pentest for this exact commit.`

### v0.48.0 - PEM Base64 And Chain Containers

Status: planned

Plan scope: Implement bounded strict Base64 and PEM armor plus certificate-chain containers with label, count, size, whitespace, trailing-data, and resource policies.

Goal: complete the **PEM Base64 And Chain Containers** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind parsing to exact bytes and explicit normalization, CT, algorithm, trust, time, secret-arena, size, depth, count, path, and work policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run standards vectors, malformed key and certificate corpora, truncation, path, constraint, policy, revocation, CT, differential, selection, and exhaustion tests;
- test ambiguity, cycles, cross-signing, stale status, disqualified logs, duplicate SCTs, operator diversity, log updates, and unavailable verifier state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity, PKI, revocation, and CT are fail-closed, bounded, deterministic, and independently audited;
- `v0.48.0 implementation stop reached. Run pentest for this exact commit.`

### v0.49.0 - Private-Key Input Formats

Status: planned

Plan scope: Implement bounded unencrypted PKCS#8, SEC1 EC, and PKCS1 RSA private-key decoding with algorithm and key consistency and secret-arena ownership; keep encrypted PKCS#8 an explicit v1 non-goal unless separately versioned.

Goal: complete the **Private-Key Input Formats** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind parsing to exact bytes and explicit normalization, CT, algorithm, trust, time, secret-arena, size, depth, count, path, and work policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run standards vectors, malformed key and certificate corpora, truncation, path, constraint, policy, revocation, CT, differential, selection, and exhaustion tests;
- test ambiguity, cycles, cross-signing, stale status, disqualified logs, duplicate SCTs, operator diversity, log updates, and unavailable verifier state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity, PKI, revocation, and CT are fail-closed, bounded, deterministic, and independently audited;
- `v0.49.0 implementation stop reached. Run pentest for this exact commit.`

### v0.50.0 - X.509 Decoder

Status: planned

Plan scope: Decode X.509 Certificate, TBSCertificate, and SPKI while preserving the exact original signed byte slice and rejecting ambiguous algorithms.

Goal: complete the **X.509 Decoder** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind parsing to exact bytes and explicit normalization, CT, algorithm, trust, time, secret-arena, size, depth, count, path, and work policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run standards vectors, malformed key and certificate corpora, truncation, path, constraint, policy, revocation, CT, differential, selection, and exhaustion tests;
- test ambiguity, cycles, cross-signing, stale status, disqualified logs, duplicate SCTs, operator diversity, log updates, and unavailable verifier state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity, PKI, revocation, and CT are fail-closed, bounded, deterministic, and independently audited;
- `v0.50.0 implementation stop reached. Run pentest for this exact commit.`

### v0.51.0 - Service Identity And Extensions

Status: planned

Plan scope: Validate SAN and service identity, ASCII A-label DNS inputs, wildcards, IP, email and URI names, critical and duplicate extensions, and caller-owned international-name normalization policy.

Goal: complete the **Service Identity And Extensions** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind parsing to exact bytes and explicit normalization, CT, algorithm, trust, time, secret-arena, size, depth, count, path, and work policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run standards vectors, malformed key and certificate corpora, truncation, path, constraint, policy, revocation, CT, differential, selection, and exhaustion tests;
- test ambiguity, cycles, cross-signing, stale status, disqualified logs, duplicate SCTs, operator diversity, log updates, and unavailable verifier state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity, PKI, revocation, and CT are fail-closed, bounded, deterministic, and independently audited;
- `v0.51.0 implementation stop reached. Run pentest for this exact commit.`

### v0.52.0 - Bounded Path Construction

Status: planned

Plan scope: Build bounded deterministic paths using caller-supplied pools, loop detection, and hard depth, candidate, comparison, and work limits with no automatic network fetch.

Goal: complete the **Bounded Path Construction** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind parsing to exact bytes and explicit normalization, CT, algorithm, trust, time, secret-arena, size, depth, count, path, and work policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run standards vectors, malformed key and certificate corpora, truncation, path, constraint, policy, revocation, CT, differential, selection, and exhaustion tests;
- test ambiguity, cycles, cross-signing, stale status, disqualified logs, duplicate SCTs, operator diversity, log updates, and unavailable verifier state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity, PKI, revocation, and CT are fail-closed, bounded, deterministic, and independently audited;
- `v0.52.0 implementation stop reached. Run pentest for this exact commit.`

### v0.53.0 - Core Chain Validation

Status: planned

Plan scope: Validate chain signatures, validity, basic constraints, path length, key usage, and extended key usage.

Goal: complete the **Core Chain Validation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind parsing to exact bytes and explicit normalization, CT, algorithm, trust, time, secret-arena, size, depth, count, path, and work policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run standards vectors, malformed key and certificate corpora, truncation, path, constraint, policy, revocation, CT, differential, selection, and exhaustion tests;
- test ambiguity, cycles, cross-signing, stale status, disqualified logs, duplicate SCTs, operator diversity, log updates, and unavailable verifier state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity, PKI, revocation, and CT are fail-closed, bounded, deterministic, and independently audited;
- `v0.53.0 implementation stop reached. Run pentest for this exact commit.`

### v0.54.0 - Name Constraints

Status: planned

Plan scope: Validate DNS, IP, email, URI, and directory-name constraints with explicit subtree, comparison, normalization, and work budgets.

Goal: complete the **Name Constraints** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind parsing to exact bytes and explicit normalization, CT, algorithm, trust, time, secret-arena, size, depth, count, path, and work policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run standards vectors, malformed key and certificate corpora, truncation, path, constraint, policy, revocation, CT, differential, selection, and exhaustion tests;
- test ambiguity, cycles, cross-signing, stale status, disqualified logs, duplicate SCTs, operator diversity, log updates, and unavailable verifier state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity, PKI, revocation, and CT are fail-closed, bounded, deterministic, and independently audited;
- `v0.54.0 implementation stop reached. Run pentest for this exact commit.`

### v0.55.0 - Certificate Policy Processing

Status: planned

Plan scope: Implement certificate policies, mappings, anyPolicy, inhibition, policy constraints, and bounded policy-tree processing.

Goal: complete the **Certificate Policy Processing** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind parsing to exact bytes and explicit normalization, CT, algorithm, trust, time, secret-arena, size, depth, count, path, and work policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run standards vectors, malformed key and certificate corpora, truncation, path, constraint, policy, revocation, CT, differential, selection, and exhaustion tests;
- test ambiguity, cycles, cross-signing, stale status, disqualified logs, duplicate SCTs, operator diversity, log updates, and unavailable verifier state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity, PKI, revocation, and CT are fail-closed, bounded, deterministic, and independently audited;
- `v0.55.0 implementation stop reached. Run pentest for this exact commit.`

### v0.56.0 - Trust Anchors Cross-Signing And Algorithms

Status: planned

Plan scope: Define trust-anchor inputs, cross-signing and alternate-path semantics, deterministic selection, distrust policy, and per-position algorithm constraints.

Goal: complete the **Trust Anchors Cross-Signing And Algorithms** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind parsing to exact bytes and explicit normalization, CT, algorithm, trust, time, secret-arena, size, depth, count, path, and work policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run standards vectors, malformed key and certificate corpora, truncation, path, constraint, policy, revocation, CT, differential, selection, and exhaustion tests;
- test ambiguity, cycles, cross-signing, stale status, disqualified logs, duplicate SCTs, operator diversity, log updates, and unavailable verifier state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity, PKI, revocation, and CT are fail-closed, bounded, deterministic, and independently audited;
- `v0.56.0 implementation stop reached. Run pentest for this exact commit.`

### v0.57.0 - CRL Validation

Status: planned

Plan scope: Validate base, delta, and indirect CRLs with issuer authorization, freshness, distribution-point, reason, entry, and work ceilings.

Goal: complete the **CRL Validation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind parsing to exact bytes and explicit normalization, CT, algorithm, trust, time, secret-arena, size, depth, count, path, and work policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run standards vectors, malformed key and certificate corpora, truncation, path, constraint, policy, revocation, CT, differential, selection, and exhaustion tests;
- test ambiguity, cycles, cross-signing, stale status, disqualified logs, duplicate SCTs, operator diversity, log updates, and unavailable verifier state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity, PKI, revocation, and CT are fail-closed, bounded, deterministic, and independently audited;
- `v0.57.0 implementation stop reached. Run pentest for this exact commit.`

### v0.58.0 - OCSP Validation

Status: planned

Plan scope: Validate stapled and offline OCSP responses, responder authorization, freshness, nonce, issuer and serial matching, and explicit hard and soft-fail policy.

Goal: complete the **OCSP Validation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind parsing to exact bytes and explicit normalization, CT, algorithm, trust, time, secret-arena, size, depth, count, path, and work policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run standards vectors, malformed key and certificate corpora, truncation, path, constraint, policy, revocation, CT, differential, selection, and exhaustion tests;
- test ambiguity, cycles, cross-signing, stale status, disqualified logs, duplicate SCTs, operator diversity, log updates, and unavailable verifier state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity, PKI, revocation, and CT are fail-closed, bounded, deterministic, and independently audited;
- `v0.58.0 implementation stop reached. Run pentest for this exact commit.`

### v0.59.0 - Certificate Transparency Contract

Status: planned

Plan scope: Implement bounded SCT parsing and define verifier ownership, log identities and list updates, signed-entry reconstruction, timestamp validity, log disqualification, duplicate handling, and distinct-log and operator policy; fail closed when CT is required and no admitted verifier exists.

Goal: complete the **Certificate Transparency Contract** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind parsing to exact bytes and explicit normalization, CT, algorithm, trust, time, secret-arena, size, depth, count, path, and work policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run standards vectors, malformed key and certificate corpora, truncation, path, constraint, policy, revocation, CT, differential, selection, and exhaustion tests;
- test ambiguity, cycles, cross-signing, stale status, disqualified logs, duplicate SCTs, operator diversity, log updates, and unavailable verifier state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity, PKI, revocation, and CT are fail-closed, bounded, deterministic, and independently audited;
- `v0.59.0 implementation stop reached. Run pentest for this exact commit.`

### v0.60.0 - PKI Audit Gate

Status: planned

Plan scope: Complete PKI adversarial, differential, fuzz, path-complexity, revocation, Certificate Transparency, and external audit campaigns with clean remediation.

Goal: complete the **PKI Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind parsing to exact bytes and explicit normalization, CT, algorithm, trust, time, secret-arena, size, depth, count, path, and work policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run standards vectors, malformed key and certificate corpora, truncation, path, constraint, policy, revocation, CT, differential, selection, and exhaustion tests;
- test ambiguity, cycles, cross-signing, stale status, disqualified logs, duplicate SCTs, operator diversity, log updates, and unavailable verifier state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity, PKI, revocation, and CT are fail-closed, bounded, deterministic, and independently audited;
- `v0.60.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 2: Shared Handshake, Internal Sans-I/O, And Modern TLS

Shared handshake, separate policy, audited engines, and final routing remain ordered.

### v0.61.0 - Shared Recordless TLS Handshake Boundary

Status: planned

Plan scope: Create an upstream no_std brynja-tls-handshake crate containing the single record-independent TLS 1.3 handshake state machine consumed by brynja-tls and brynja-quic-tls; stream TLS owns records, QUIC owns transport, and DTLS may reuse codecs, transcript, certificate and key-schedule components but retains its own state machine, epochs, fragmentation, and retransmission.

Goal: complete the **Shared Recordless TLS Handshake Boundary** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze shared handshake ownership and unstable internal input, output, timer, entropy, clock, path, trust, compression, signature, accelerator, pending, cancellation, and terminal effects;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run graph, single-handshake, deterministic trace, partial I/O, path, backpressure, pending resume and cancel, fault, terminal, and exhaustion tests;
- prove QUIC cannot duplicate TLS, DTLS cannot reuse stream state, and no hidden I/O, global state, half key, cross-path budget, secret output, or cancelled action survives;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- stream TLS and QUIC share one handshake, DTLS retains independent state, and internal effects remain unstable until optional composition completes;
- `v0.61.0 implementation stop reached. Run pentest for this exact commit.`

### v0.62.0 - Internal Sans-I/O Execution Contract

Status: planned

Plan scope: Define an explicitly unstable deterministic Event-to-Action driver for consumed input, output workspace, timers, entropy and time, certificate, signature and accelerator requests, application data, backpressure, resumable operations, path tokens, cancellation, and terminal states.

Goal: complete the **Internal Sans-I/O Execution Contract** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze shared handshake ownership and unstable internal input, output, timer, entropy, clock, path, trust, compression, signature, accelerator, pending, cancellation, and terminal effects;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run graph, single-handshake, deterministic trace, partial I/O, path, backpressure, pending resume and cancel, fault, terminal, and exhaustion tests;
- prove QUIC cannot duplicate TLS, DTLS cannot reuse stream state, and no hidden I/O, global state, half key, cross-path budget, secret output, or cancelled action survives;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- stream TLS and QUIC share one handshake, DTLS retains independent state, and internal effects remain unstable until optional composition completes;
- `v0.62.0 implementation stop reached. Run pentest for this exact commit.`

### v0.63.0 - TLS Record Protection

Status: planned

Plan scope: Implement TLS record protection, checked sequence exhaustion, inner content-type and padding validation, transactional state changes, and fragmentation boundaries without performing protocol selection.

Goal: complete the **TLS Record Protection** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.63.0 implementation stop reached. Run pentest for this exact commit.`

### v0.64.0 - TLS 1.3 Handshake Codec

Status: planned

Plan scope: Implement the complete TLS 1.3 handshake codec with duplicate, ordering, extension-context, unknown and GREASE extension, compatibility ChangeCipherSpec, and resource rules.

Goal: complete the **TLS 1.3 Handshake Codec** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.64.0 implementation stop reached. Run pentest for this exact commit.`

### v0.65.0 - Transcript And Key Schedule

Status: planned

Plan scope: Implement transcript and key-schedule states with immediate destruction of obsolete early, handshake, master, exporter, and resumption secrets.

Goal: complete the **Transcript And Key Schedule** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.65.0 implementation stop reached. Run pentest for this exact commit.`

### v0.66.0 - ClientHello Construction And Offers

Status: planned

Plan scope: Implement bounded ClientHello construction and parsing for supported versions, groups, signature schemes, key shares, GREASE, SNI, ALPN, extension ordering, and exact original-byte preservation.

Goal: complete the **ClientHello Construction And Offers** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.66.0 implementation stop reached. Run pentest for this exact commit.`

### v0.67.0 - HelloRetryRequest And Cookies

Status: planned

Plan scope: Implement HelloRetryRequest validation, transcript message_hash transformation, selected-group rules, cookies, second-ClientHello invariants, and retry resource ceilings.

Goal: complete the **HelloRetryRequest And Cookies** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.67.0 implementation stop reached. Run pentest for this exact commit.`

### v0.68.0 - TLS Version Negotiation Codec And Policy

Status: planned

Plan scope: Implement shared offer and selection parsing and policy without routing into an engine: servers evaluate one ClientHello, clients evaluate one ServerHello, unknown future offered versions are skipped safely, recognized legacy versions are rejected by policy, highest-version and downgrade-sentinel rules are typed, and exact transcript bytes are preserved.

Goal: complete the **TLS Version Negotiation Codec And Policy** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.68.0 implementation stop reached. Run pentest for this exact commit.`

### v0.69.0 - TLS 1.3 Authenticated Server Flight

Status: planned

Plan scope: Implement ServerHello through the authenticated server flight, certificate presentation, and the sole ALPN and SNI negotiation implementation.

Goal: complete the **TLS 1.3 Authenticated Server Flight** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.69.0 implementation stop reached. Run pentest for this exact commit.`

### v0.70.0 - Certificate Negotiation And Selection

Status: planned

Plan scope: Implement signature_algorithms_cert, certificate_authorities, oid_filters, certificate and public-key compatibility, bounded identity selection, and deterministic external-signer requests.

Goal: complete the **Certificate Negotiation And Selection** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.70.0 implementation stop reached. Run pentest for this exact commit.`

### v0.71.0 - Stapled Status And SCT Transport

Status: planned

Plan scope: Implement status_request and stapled OCSP transport plus bounded SCT transport and handoff to admitted PKI and Certificate Transparency policies.

Goal: complete the **Stapled Status And SCT Transport** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.71.0 implementation stop reached. Run pentest for this exact commit.`

### v0.72.0 - Client Authentication And Finished

Status: planned

Plan scope: Implement client authentication, CertificateVerify, Finished, authenticated application-data transition, and explicit rejection of post-handshake authentication for v1.

Goal: complete the **Client Authentication And Finished** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.72.0 implementation stop reached. Run pentest for this exact commit.`

### v0.73.0 - Alerts Closure And Cancellation

Status: planned

Plan scope: Complete alerts, close-notify, illegal-message handling, backpressure, cancellation, provider failure, terminal states, and terminal secret and handle destruction.

Goal: complete the **Alerts Closure And Cancellation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.73.0 implementation stop reached. Run pentest for this exact commit.`

### v0.74.0 - Stateful Tickets And Resumption PSKs

Status: planned

Plan scope: Implement stateful cache tickets and resumption PSK binders with protocol-specific cache and identity domains, constant-work unknown-identity handling where possible, single-use pending operations, concurrency and crash-consistency contracts, external-storage secrecy, rotation, and lifetime policy.

Goal: complete the **Stateful Tickets And Resumption PSKs** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.74.0 implementation stop reached. Run pentest for this exact commit.`

### v0.75.0 - Stateless Ticket Protection

Status: planned

Plan scope: Implement an optional versioned AEAD ticket envelope binding protocol version, suite, SNI, ALPN, client-authentication state, PSK and early-data policy, issue and expiry time, key identifier, rotation generation, and deployment domain with nonce uniqueness and uniform failures.

Goal: complete the **Stateless Ticket Protection** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.75.0 implementation stop reached. Run pentest for this exact commit.`

### v0.76.0 - TLS 1.3-Profile External PSKs And PSK Importer

Status: planned

Plan scope: Separate external from resumption PSKs; apply RFC 9258 only to admitted TLS 1.3-derived profiles—TLS 1.3, DTLS 1.3, and QUIC—and never enable external-PSK or PSK cipher suites in hardened TLS 1.2 or DTLS 1.2; implement imported identities and derived imported PSKs with protocol, KDF, context, application, ALPN, and deployment-domain separation; require the importer whenever one provisioned key could cross admitted protocol or deployment domains; allow raw external PSKs only with unique per-profile and deployment provisioning; require psk_dhe_ke, constant-work identity and binder handling, single-use pending lookups, and no silent psk_ke, cross-domain, binder-failure, or certificate-authentication fallback.

Goal: complete the **TLS 1.3-Profile External PSKs And PSK Importer** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise imported-identity derivation across TLS 1.3, DTLS 1.3 and QUIC, protocol, KDF, context, application, ALPN and deployment separation, raw-key uniqueness attestation, and negative TLS 1.2 and DTLS 1.2 PSK-suite construction and negotiation tests alongside replay, binder failure, zero-RTT races, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- RFC 9258 and raw external PSKs are confined to TLS 1.3-derived profiles, and hardened TLS 1.2 and DTLS 1.2 cannot construct or negotiate a PSK suite;
- `v0.76.0 implementation stop reached. Run pentest for this exact commit.`

### v0.77.0 - Zero-RTT

Status: planned

Plan scope: Implement opt-in zero-RTT with an atomic anti-replay check-and-insert contract, concurrency and crash consistency, single-use pending storage operations, freshness, deterministic rejection, secret lifetime, and application side-effect guidance.

Goal: complete the **Zero-RTT** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.77.0 implementation stop reached. Run pentest for this exact commit.`

### v0.78.0 - TLS KeyUpdate

Status: planned

Plan scope: Implement KeyUpdate with traffic-secret transition, immediate obsolete-key destruction, request coalescing policy, and long-lived key and record limits.

Goal: complete the **TLS KeyUpdate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.78.0 implementation stop reached. Run pentest for this exact commit.`

### v0.79.0 - Exporters And TLS-Exporter Channel Binding

Status: planned

Plan scope: Implement the RFC 5705 exporter for TLS 1.2 and the RFC 9846 exporter for TLS 1.3, then admit only the RFC 9266 tls-exporter channel binding with exact label, context, transcript, and protocol-version rules; exclude tls-unique for TLS 1.3 and tls-server-end-point for v1; release outputs only after protocol-specific authorization as typed, non-formatting secrets with explicit ownership, use, and zeroization policy.

Goal: complete the **Exporters And TLS-Exporter Channel Binding** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC 5705, RFC 9266 and RFC 9846 exporter vectors, label and context boundaries, TLS 1.2 and 1.3 transcript and authorization timing, excluded binding types, secret ownership and zeroization, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.79.0 implementation stop reached. Run pentest for this exact commit.`

### v0.80.0 - TLS 1.3 Suite Completion

Status: planned

Plan scope: Admit only AES-128-GCM/SHA-256, AES-256-GCM/SHA-384, and ChaCha20-Poly1305/SHA-256 for the initial TLS 1.3 profile.

Goal: complete the **TLS 1.3 Suite Completion** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.80.0 implementation stop reached. Run pentest for this exact commit.`

### v0.81.0 - TLS 1.3 Conformance And Interoperability

Status: planned

Plan scope: Pass official vectors, truncation and fragmentation matrices, independent peer implementations, state-model and fuzz gates, and provider fault injection.

Goal: complete the **TLS 1.3 Conformance And Interoperability** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.81.0 implementation stop reached. Run pentest for this exact commit.`

### v0.82.0 - TLS 1.3 Audit Gate

Status: planned

Plan scope: Complete an external TLS 1.3 audit and clean remediation retest.

Goal: complete the **TLS 1.3 Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.82.0 implementation stop reached. Run pentest for this exact commit.`

### v0.83.0 - TLS 1.2 Policy Boundary

Status: planned

Plan scope: Freeze an explicit TLS 1.2 ECDHE-plus-AEAD policy with EMS required and static RSA, CBC, SHA-1 signing, compression, renegotiation, and automatic fallback excluded.

Goal: complete the **TLS 1.2 Policy Boundary** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- keep TLS 1.2 independently implemented with ECDHE, AEAD, EMS, exact initial signaling, isolated tickets, and no fallback;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run PRF, records, EMS, SCSV, renegotiation-info, FALLBACK_SCSV, downgrade, resumption, suite, interop, and disablement matrices;
- reject actual renegotiation, static RSA, CBC, SHA-1 signing, compression, weak groups, cross-version state, and retry while accepting required initial signals;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.2 is compliant, isolated, explicitly configured, disableable, and audited before integrated routing;
- `v0.83.0 implementation stop reached. Run pentest for this exact commit.`

### v0.84.0 - TLS 1.2 PRF And Key Block

Status: planned

Plan scope: Implement the TLS 1.2 PRF, master secret, EMS master-secret input, key-block expansion, label separation, and length limits.

Goal: complete the **TLS 1.2 PRF And Key Block** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- keep TLS 1.2 independently implemented with ECDHE, AEAD, EMS, exact initial signaling, isolated tickets, and no fallback;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run PRF, records, EMS, SCSV, renegotiation-info, FALLBACK_SCSV, downgrade, resumption, suite, interop, and disablement matrices;
- reject actual renegotiation, static RSA, CBC, SHA-1 signing, compression, weak groups, cross-version state, and retry while accepting required initial signals;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.2 is compliant, isolated, explicitly configured, disableable, and audited before integrated routing;
- `v0.84.0 implementation stop reached. Run pentest for this exact commit.`

### v0.85.0 - TLS 1.2 Record Nonces And Protection

Status: planned

Plan scope: Implement admitted TLS 1.2 AEAD record nonces, additional data, sequence exhaustion, limits, fragmentation, and failure-atomic open.

Goal: complete the **TLS 1.2 Record Nonces And Protection** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- keep TLS 1.2 independently implemented with ECDHE, AEAD, EMS, exact initial signaling, isolated tickets, and no fallback;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run PRF, records, EMS, SCSV, renegotiation-info, FALLBACK_SCSV, downgrade, resumption, suite, interop, and disablement matrices;
- reject actual renegotiation, static RSA, CBC, SHA-1 signing, compression, weak groups, cross-version state, and retry while accepting required initial signals;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.2 is compliant, isolated, explicitly configured, disableable, and audited before integrated routing;
- `v0.85.0 implementation stop reached. Run pentest for this exact commit.`

### v0.86.0 - TLS 1.2 EMS Transcript Binding

Status: planned

Plan scope: Implement Extended Master Secret transcript selection, session-hash rules, resumption consistency, and mandatory EMS failure behavior.

Goal: complete the **TLS 1.2 EMS Transcript Binding** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- keep TLS 1.2 independently implemented with ECDHE, AEAD, EMS, exact initial signaling, isolated tickets, and no fallback;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run PRF, records, EMS, SCSV, renegotiation-info, FALLBACK_SCSV, downgrade, resumption, suite, interop, and disablement matrices;
- reject actual renegotiation, static RSA, CBC, SHA-1 signing, compression, weak groups, cross-version state, and retry while accepting required initial signals;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.2 is compliant, isolated, explicitly configured, disableable, and audited before integrated routing;
- `v0.86.0 implementation stop reached. Run pentest for this exact commit.`

### v0.87.0 - TLS 1.2 Signaling And Renegotiation Semantics

Status: planned

Plan scope: Accept TLS_EMPTY_RENEGOTIATION_INFO_SCSV only as initial secure-renegotiation signaling, accept empty renegotiation_info where required, emit inappropriate_fallback for TLS_FALLBACK_SCSV only when a higher enabled version exists, apply downgrade sentinels, and reject every subsequent renegotiation attempt.

Goal: complete the **TLS 1.2 Signaling And Renegotiation Semantics** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- keep TLS 1.2 independently implemented with ECDHE, AEAD, EMS, exact initial signaling, isolated tickets, and no fallback;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run PRF, records, EMS, SCSV, renegotiation-info, FALLBACK_SCSV, downgrade, resumption, suite, interop, and disablement matrices;
- reject actual renegotiation, static RSA, CBC, SHA-1 signing, compression, weak groups, cross-version state, and retry while accepting required initial signals;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.2 is compliant, isolated, explicitly configured, disableable, and audited before integrated routing;
- `v0.87.0 implementation stop reached. Run pentest for this exact commit.`

### v0.88.0 - TLS 1.2 ECDHE State Machines

Status: planned

Plan scope: Implement isolated ECDHE_ECDSA and ECDHE_RSA TLS 1.2 client and server state machines entered only by the one-pass modern selector.

Goal: complete the **TLS 1.2 ECDHE State Machines** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- keep TLS 1.2 independently implemented with ECDHE, AEAD, EMS, exact initial signaling, isolated tickets, and no fallback;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run PRF, records, EMS, SCSV, renegotiation-info, FALLBACK_SCSV, downgrade, resumption, suite, interop, and disablement matrices;
- reject actual renegotiation, static RSA, CBC, SHA-1 signing, compression, weak groups, cross-version state, and retry while accepting required initial signals;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.2 is compliant, isolated, explicitly configured, disableable, and audited before integrated routing;
- `v0.88.0 implementation stop reached. Run pentest for this exact commit.`

### v0.89.0 - TLS 1.2 Suite Completion

Status: planned

Plan scope: Admit only the six ECDSA and RSA combinations over AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.

Goal: complete the **TLS 1.2 Suite Completion** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- keep TLS 1.2 independently implemented with ECDHE, AEAD, EMS, exact initial signaling, isolated tickets, and no fallback;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run PRF, records, EMS, SCSV, renegotiation-info, FALLBACK_SCSV, downgrade, resumption, suite, interop, and disablement matrices;
- reject actual renegotiation, static RSA, CBC, SHA-1 signing, compression, weak groups, cross-version state, and retry while accepting required initial signals;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.2 is compliant, isolated, explicitly configured, disableable, and audited before integrated routing;
- `v0.89.0 implementation stop reached. Run pentest for this exact commit.`

### v0.90.0 - TLS 1.2 Resumption And Interoperability

Status: planned

Plan scope: Complete TLS 1.2 stateful and stateless resumption, protocol-specific tickets, extension hardening, interop, and downgrade corpora.

Goal: complete the **TLS 1.2 Resumption And Interoperability** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- keep TLS 1.2 independently implemented with ECDHE, AEAD, EMS, exact initial signaling, isolated tickets, and no fallback;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run PRF, records, EMS, SCSV, renegotiation-info, FALLBACK_SCSV, downgrade, resumption, suite, interop, and disablement matrices;
- reject actual renegotiation, static RSA, CBC, SHA-1 signing, compression, weak groups, cross-version state, and retry while accepting required initial signals;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.2 is compliant, isolated, explicitly configured, disableable, and audited before integrated routing;
- `v0.90.0 implementation stop reached. Run pentest for this exact commit.`

### v0.91.0 - TLS 1.2 Audit Gate

Status: planned

Plan scope: Complete a separate TLS 1.2 external audit while retaining explicit configuration and independent disablement.

Goal: complete the **TLS 1.2 Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- keep TLS 1.2 independently implemented with ECDHE, AEAD, EMS, exact initial signaling, isolated tickets, and no fallback;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run PRF, records, EMS, SCSV, renegotiation-info, FALLBACK_SCSV, downgrade, resumption, suite, interop, and disablement matrices;
- reject actual renegotiation, static RSA, CBC, SHA-1 signing, compression, weak groups, cross-version state, and retry while accepting required initial signals;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.2 is compliant, isolated, explicitly configured, disableable, and audited before integrated routing;
- `v0.91.0 implementation stop reached. Run pentest for this exact commit.`

### v0.92.0 - Integrated One-Pass Modern TLS Router

Status: planned

Plan scope: After both TLS 1.3 and hardened TLS 1.2 engines exist, integrate symmetric one-pass routing: one server ClientHello or one client ServerHello selects exactly one highest acceptable offered engine, validates downgrade sentinels, transfers original transcript bytes and version-domain state once, and never retries another engine or crosses credentials, tickets, PSKs, caches, or secrets after failure.

Goal: complete the **Integrated One-Pass Modern TLS Router** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.92.0 implementation stop reached. Run pentest for this exact commit.`

### v0.93.0 - Modern Multi-Version Routing Audit Gate

Status: planned

Plan scope: Complete client and server cross-version, downgrade, unknown-version, transcript-preservation, domain-separation, no-retry, interoperability, differential, fuzz, and external audit campaigns for the integrated TLS router.

Goal: complete the **Modern Multi-Version Routing Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.93.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 3: QUIC TLS, DTLS, And Post-Quantum Work

QUIC resumption, version-specific DTLS CIDs, v1 early-data exclusion, and hybrid policies are explicit.

### v0.94.0 - QUIC Ownership And Encryption Levels

Status: planned

Plan scope: Define distinct QUIC encryption levels and secret install and discard events; consume ordered bytes supplied by QUIC and exclude packet processing, offsets, retransmission, packet numbers, loss recovery, Retry, key phase, TLS records, and TLS KeyUpdate.

Goal: complete the **QUIC Ownership And Encryption Levels** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- enforce recordless QUIC TLS plus resumption and zero-RTT semantics while separating TLS traffic secrets and optional expansion from QUIC transport ownership;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC 9001, forbidden-message, level, CRYPTO_ERROR, ALPN, completion and confirmation, key-discard, ticket sentinel and binding, zero-RTT decision, secret, expansion, parameter, and peer matrices;
- test CCS, EndOfEarlyData, KeyUpdate, records, invalid early size, ticket reuse, missing ALPN, late data, conflicting ranges, derivation confusion, and exhaustion;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- QUIC uses the shared handshake with explicit completion, confirmation, resumption, zero-RTT, and transport-owned quantity and packet state;
- `v0.94.0 implementation stop reached. Run pentest for this exact commit.`

### v0.95.0 - QUIC-Specific TLS Profile

Status: planned

Plan scope: Implement the recordless QUIC TLS profile with no ChangeCipherSpec, EndOfEarlyData, TLS KeyUpdate, or record compatibility mode; enforce handshake-message legality per encryption level, TLS alert to QUIC CRYPTO_ERROR mapping, required ALPN negotiation and failure, and typed handshake and application secret events.

Goal: complete the **QUIC-Specific TLS Profile** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- enforce recordless QUIC TLS plus resumption and zero-RTT semantics while separating TLS traffic secrets and optional expansion from QUIC transport ownership;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC 9001, forbidden-message, level, CRYPTO_ERROR, ALPN, completion and confirmation, key-discard, ticket sentinel and binding, zero-RTT decision, secret, expansion, parameter, and peer matrices;
- test CCS, EndOfEarlyData, KeyUpdate, records, invalid early size, ticket reuse, missing ALPN, late data, conflicting ranges, derivation confusion, and exhaustion;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- QUIC uses the shared handshake with explicit completion, confirmation, resumption, zero-RTT, and transport-owned quantity and packet state;
- `v0.95.0 implementation stop reached. Run pentest for this exact commit.`

### v0.96.0 - QUIC Key-Derivation Boundary

Status: planned

Plan scope: Have TLS emit typed handshake and application traffic secrets; optionally derive quic key, quic iv and quic hp in brynja-quic-tls; keep version-specific Initial salts and secrets, packet protection, Retry integrity, key phase, and quic ku in the QUIC transport; verify all admitted derivations with RFC 9001 vectors.

Goal: complete the **QUIC Key-Derivation Boundary** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- enforce recordless QUIC TLS plus resumption and zero-RTT semantics while separating TLS traffic secrets and optional expansion from QUIC transport ownership;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC 9001, forbidden-message, level, CRYPTO_ERROR, ALPN, completion and confirmation, key-discard, ticket sentinel and binding, zero-RTT decision, secret, expansion, parameter, and peer matrices;
- test CCS, EndOfEarlyData, KeyUpdate, records, invalid early size, ticket reuse, missing ALPN, late data, conflicting ranges, derivation confusion, and exhaustion;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- QUIC uses the shared handshake with explicit completion, confirmation, resumption, zero-RTT, and transport-owned quantity and packet state;
- `v0.96.0 implementation stop reached. Run pentest for this exact commit.`

### v0.97.0 - QUIC Transport Parameters

Status: planned

Plan scope: Implement bounded syntactic transport-parameter parsing and transcript binding while exposing typed values for QUIC-owned semantic enforcement.

Goal: complete the **QUIC Transport Parameters** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- enforce recordless QUIC TLS plus resumption and zero-RTT semantics while separating TLS traffic secrets and optional expansion from QUIC transport ownership;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC 9001, forbidden-message, level, CRYPTO_ERROR, ALPN, completion and confirmation, key-discard, ticket sentinel and binding, zero-RTT decision, secret, expansion, parameter, and peer matrices;
- test CCS, EndOfEarlyData, KeyUpdate, records, invalid early size, ticket reuse, missing ALPN, late data, conflicting ranges, derivation confusion, and exhaustion;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- QUIC uses the shared handshake with explicit completion, confirmation, resumption, zero-RTT, and transport-owned quantity and packet state;
- `v0.97.0 implementation stop reached. Run pentest for this exact commit.`

### v0.98.0 - QUIC Sans-I/O Handshake

Status: planned

Plan scope: Implement per-level TLS handshake input and output, alerts, pending providers, bounded future-level data, traffic-secret events, and deterministic rejection of late data.

Goal: complete the **QUIC Sans-I/O Handshake** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- enforce recordless QUIC TLS plus resumption and zero-RTT semantics while separating TLS traffic secrets and optional expansion from QUIC transport ownership;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC 9001, forbidden-message, level, CRYPTO_ERROR, ALPN, completion and confirmation, key-discard, ticket sentinel and binding, zero-RTT decision, secret, expansion, parameter, and peer matrices;
- test CCS, EndOfEarlyData, KeyUpdate, records, invalid early size, ticket reuse, missing ALPN, late data, conflicting ranges, derivation confusion, and exhaustion;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- QUIC uses the shared handshake with explicit completion, confirmation, resumption, zero-RTT, and transport-owned quantity and packet state;
- `v0.98.0 implementation stop reached. Run pentest for this exact commit.`

### v0.99.0 - QUIC Resumption And Zero-RTT Profile

Status: planned

Plan scope: Distinguish TLS handshake completion from QUIC handshake confirmation; emit typed completion, confirmation and key-discard events; deliver NewSessionTicket only after handshake completion; require max_early_data_size 0xffffffff; bind remembered QUIC transport parameters, ALPN and application state to tickets; map invalid early-data values to the correct QUIC error; expose deterministic acceptance and rejection; enforce ticket privacy and non-reuse policy; and leave the transport in control of zero-RTT byte quantity.

Goal: complete the **QUIC Resumption And Zero-RTT Profile** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- enforce recordless QUIC TLS plus resumption and zero-RTT semantics while separating TLS traffic secrets and optional expansion from QUIC transport ownership;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC 9001, forbidden-message, level, CRYPTO_ERROR, ALPN, completion and confirmation, key-discard, ticket sentinel and binding, zero-RTT decision, secret, expansion, parameter, and peer matrices;
- test CCS, EndOfEarlyData, KeyUpdate, records, invalid early size, ticket reuse, missing ALPN, late data, conflicting ranges, derivation confusion, and exhaustion;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- QUIC uses the shared handshake with explicit completion, confirmation, resumption, zero-RTT, and transport-owned quantity and packet state;
- `v0.99.0 implementation stop reached. Run pentest for this exact commit.`

### v0.100.0 - Optional QUIC CRYPTO Reassembly Helper

Status: planned

Plan scope: Provide an explicitly optional bounded CRYPTO-offset reassembly helper with conflict and exhaustion handling that is not used implicitly and does not implement retransmission or loss recovery.

Goal: complete the **Optional QUIC CRYPTO Reassembly Helper** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- enforce recordless QUIC TLS plus resumption and zero-RTT semantics while separating TLS traffic secrets and optional expansion from QUIC transport ownership;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC 9001, forbidden-message, level, CRYPTO_ERROR, ALPN, completion and confirmation, key-discard, ticket sentinel and binding, zero-RTT decision, secret, expansion, parameter, and peer matrices;
- test CCS, EndOfEarlyData, KeyUpdate, records, invalid early size, ticket reuse, missing ALPN, late data, conflicting ranges, derivation confusion, and exhaustion;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- QUIC uses the shared handshake with explicit completion, confirmation, resumption, zero-RTT, and transport-owned quantity and packet state;
- `v0.100.0 implementation stop reached. Run pentest for this exact commit.`

### v0.101.0 - QUIC Conformance And Audit

Status: planned

Plan scope: Pass RFC 9001 vectors plus loss, reorder, discard, 0-RTT, key-derivation, interoperability, ownership-boundary, and external review gates.

Goal: complete the **QUIC Conformance And Audit** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- enforce recordless QUIC TLS plus resumption and zero-RTT semantics while separating TLS traffic secrets and optional expansion from QUIC transport ownership;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC 9001, forbidden-message, level, CRYPTO_ERROR, ALPN, completion and confirmation, key-discard, ticket sentinel and binding, zero-RTT decision, secret, expansion, parameter, and peer matrices;
- test CCS, EndOfEarlyData, KeyUpdate, records, invalid early size, ticket reuse, missing ALPN, late data, conflicting ranges, derivation confusion, and exhaustion;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- QUIC uses the shared handshake with explicit completion, confirmation, resumption, zero-RTT, and transport-owned quantity and packet state;
- `v0.101.0 implementation stop reached. Run pentest for this exact commit.`

### v0.102.0 - DTLS Path Identity Contract

Status: planned

Plan scope: Introduce an opaque caller-provided path token binding cookie state, amplification accounting, CID routing, migration, PMTU, timers, and datagram metadata so packets cannot transfer validation or budgets between paths.

Goal: complete the **DTLS Path Identity Contract** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.102.0 implementation stop reached. Run pentest for this exact commit.`

### v0.103.0 - DTLS Version Negotiation Codec And Policy

Status: planned

Plan scope: Implement shared DTLS offer and selection parsing and policy without routing into an engine: one ClientHello or ServerHello is evaluated, unknown future versions are skipped, recognized legacy versions are rejected, the highest configured version and downgrade policy are typed, and transcript plus opaque path identity are preserved.

Goal: complete the **DTLS Version Negotiation Codec And Policy** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.103.0 implementation stop reached. Run pentest for this exact commit.`

### v0.104.0 - DTLS Unified Headers And Epochs

Status: planned

Plan scope: Implement DTLS 1.3 unified headers, epochs, compact sequence reconstruction, AEAD nonce construction, and checked sequence exhaustion.

Goal: complete the **DTLS Unified Headers And Epochs** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.104.0 implementation stop reached. Run pentest for this exact commit.`

### v0.105.0 - DTLS Record-Number Encryption

Status: planned

Plan scope: Implement record-number encryption and authenticated reconstruction-failure handling with official vectors and no replay-window mutation before authentication.

Goal: complete the **DTLS Record-Number Encryption** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.105.0 implementation stop reached. Run pentest for this exact commit.`

### v0.106.0 - DTLS Replay And Epoch-Key Lifetimes

Status: planned

Plan scope: Implement fixed replay windows across epoch transitions, bounded previous and future retention, transactional key installation, and immediate obsolete-key destruction.

Goal: complete the **DTLS Replay And Epoch-Key Lifetimes** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.106.0 implementation stop reached. Run pentest for this exact commit.`

### v0.107.0 - DTLS 1.2 Connection IDs

Status: planned

Plan scope: Implement RFC 9146 DTLS 1.2 connection-ID negotiation and its version-specific record construction with opaque path-token routing, privacy, replay, rebinding, migration, PMTU, and amplification invariants; do not accept DTLS 1.3 CID-update messages.

Goal: complete the **DTLS 1.2 Connection IDs** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.107.0 implementation stop reached. Run pentest for this exact commit.`

### v0.108.0 - DTLS 1.3 Connection-ID Updates

Status: planned

Plan scope: Implement DTLS 1.3 connection IDs, NewConnectionId and RequestConnectionId post-handshake updates with bounded active and retired IDs, opaque path-token routing, collision, privacy, replay, migration, rotation, PMTU, and amplification invariants.

Goal: complete the **DTLS 1.3 Connection-ID Updates** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.108.0 implementation stop reached. Run pentest for this exact commit.`

### v0.109.0 - DTLS Fragmentation And Reassembly

Status: planned

Plan scope: Implement caller-owned bounded handshake fragmentation and reassembly with canonical transcript messages and overlap and conflicting-fragment rejection.

Goal: complete the **DTLS Fragmentation And Reassembly** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.109.0 implementation stop reached. Run pentest for this exact commit.`

### v0.110.0 - DTLS Flights ACKs And Timers

Status: planned

Plan scope: Implement deterministic flights, ACK processing, typed timer actions, cached retransmission, checked backoff, congestion limits, and path-token ownership.

Goal: complete the **DTLS Flights ACKs And Timers** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.110.0 implementation stop reached. Run pentest for this exact commit.`

### v0.111.0 - DTLS Address Validation And Amplification Defense

Status: planned

Plan scope: Implement path-bound cookies, address validation, amplification budgets, deterministic PMTU policy, and cheap rejection before expensive cryptography.

Goal: complete the **DTLS Address Validation And Amplification Defense** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.111.0 implementation stop reached. Run pentest for this exact commit.`

### v0.112.0 - DTLS 1.3 State Machines

Status: planned

Plan scope: Complete DTLS 1.3 client and server states, key updates, duplicate idempotence, terminal cleanup, and provider cancellation.

Goal: complete the **DTLS 1.3 State Machines** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.112.0 implementation stop reached. Run pentest for this exact commit.`

### v0.113.0 - DTLS 1.3 Early-Data Exclusion

Status: planned

Plan scope: Reject DTLS 1.3 early data for v1: never offer or accept it, never derive or retain epoch 1 application-data keys, reject EndOfEarlyData on wire and in transcript, and test reordered or duplicated early records, address validation, amplification accounting, ticket policy, and deterministic peer failure independently from record replay.

Goal: complete the **DTLS 1.3 Early-Data Exclusion** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.113.0 implementation stop reached. Run pentest for this exact commit.`

### v0.114.0 - Hardened DTLS 1.2

Status: planned

Plan scope: Implement DTLS 1.2 using only the admitted TLS 1.2 ECDHE-plus-AEAD profile and isolated epoch, replay, ticket, path, and downgrade state.

Goal: complete the **Hardened DTLS 1.2** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.114.0 implementation stop reached. Run pentest for this exact commit.`

### v0.115.0 - Integrated One-Pass DTLS Router

Status: planned

Plan scope: After both DTLS engines exist, integrate symmetric one-pass routing: one server ClientHello or one client ServerHello enters exactly one highest acceptable offered engine, preserves transcript and opaque path state, validates downgrade policy, and never retries or crosses credentials, tickets, epochs, replay windows, CIDs, or secrets after failure.

Goal: complete the **Integrated One-Pass DTLS Router** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.115.0 implementation stop reached. Run pentest for this exact commit.`

### v0.116.0 - DTLS Conformance And Audit

Status: planned

Plan scope: Pass loss, reorder, duplicate, fragmentation, replay, path-token, CID, version-selection, hostile-load, fuzz, interoperability, and external audit gates.

Goal: complete the **DTLS Conformance And Audit** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from final routing and bind headers, record numbers, epochs, replay, version-specific CIDs, reassembly, flights, timers, cookies, early-data exclusion, PMTU, migration, and engines to paths;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run path, version, loss, reorder, duplicate, header, record-number, replay, DTLS 1.2 CID, DTLS 1.3 CID update, early-record rejection, timer, selector, and peer matrices;
- exercise cross-path packets, wrong-version CID messages, EndOfEarlyData, epoch 1, replay transitions, spoofed amplification, sparse fragments, stale timers, and cross-version state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- both engines exist before one-pass routing, DTLS early data is absent in v1, and CID behavior remains version-specific;
- `v0.116.0 implementation stop reached. Run pentest for this exact commit.`

### v0.117.0 - ML-KEM Arithmetic And Encoding

Status: planned

Plan scope: Implement ML-KEM polynomial, NTT, sampling, and canonical encoding and decoding foundations while introducing array-bound, index, reduction, and encoding round-trip proof harnesses beside the implementation.

Goal: complete the **ML-KEM Arithmetic And Encoding** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- implement standards-traced ML-KEM and hybrids with explicit HybridRequired and HybridPreferred policies, canonical components, transcript binding, and exclusions;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run FIPS 203, errata, malformed keys and ciphertexts, differentials, stack profiles, implicit rejection, hybrid policy, transcript, and target evidence;
- test partial hybrid failure, downgrade, fragmentation, combiner, code point, required and preferred selection, classical fallback rules, and excluded signatures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every selected hybrid completes both components and only Preferred may select a separately offered classical group when hybrids are unavailable;
- `v0.117.0 implementation stop reached. Run pentest for this exact commit.`

### v0.118.0 - ML-KEM Key Generation And Encapsulation

Status: planned

Plan scope: Implement ML-KEM-512, ML-KEM-768 and ML-KEM-1024 key generation and encapsulation with FIPS 203, errata, randomness, stack, and applicable SP 800-227 checks.

Goal: complete the **ML-KEM Key Generation And Encapsulation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- implement standards-traced ML-KEM and hybrids with explicit HybridRequired and HybridPreferred policies, canonical components, transcript binding, and exclusions;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run FIPS 203, errata, malformed keys and ciphertexts, differentials, stack profiles, implicit rejection, hybrid policy, transcript, and target evidence;
- test partial hybrid failure, downgrade, fragmentation, combiner, code point, required and preferred selection, classical fallback rules, and excluded signatures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every selected hybrid completes both components and only Preferred may select a separately offered classical group when hybrids are unavailable;
- `v0.118.0 implementation stop reached. Run pentest for this exact commit.`

### v0.119.0 - ML-KEM Decapsulation And Implicit Rejection

Status: planned

Plan scope: Implement constant-time ML-KEM decapsulation and implicit rejection with malformed-ciphertext, failure-path, and side-channel campaigns.

Goal: complete the **ML-KEM Decapsulation And Implicit Rejection** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- implement standards-traced ML-KEM and hybrids with explicit HybridRequired and HybridPreferred policies, canonical components, transcript binding, and exclusions;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run FIPS 203, errata, malformed keys and ciphertexts, differentials, stack profiles, implicit rejection, hybrid policy, transcript, and target evidence;
- test partial hybrid failure, downgrade, fragmentation, combiner, code point, required and preferred selection, classical fallback rules, and excluded signatures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every selected hybrid completes both components and only Preferred may select a separately offered classical group when hybrids are unavailable;
- `v0.119.0 implementation stop reached. Run pentest for this exact commit.`

### v0.120.0 - Standard Hybrid Groups

Status: planned

Plan scope: Implement only final standardized X25519MLKEM768, P256MLKEM768, and P384MLKEM1024 encodings, component order, lengths, identifiers, and combiner behavior.

Goal: complete the **Standard Hybrid Groups** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- implement standards-traced ML-KEM and hybrids with explicit HybridRequired and HybridPreferred policies, canonical components, transcript binding, and exclusions;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run FIPS 203, errata, malformed keys and ciphertexts, differentials, stack profiles, implicit rejection, hybrid policy, transcript, and target evidence;
- test partial hybrid failure, downgrade, fragmentation, combiner, code point, required and preferred selection, classical fallback rules, and excluded signatures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every selected hybrid completes both components and only Preferred may select a separately offered classical group when hybrids are unavailable;
- `v0.120.0 implementation stop reached. Run pentest for this exact commit.`

### v0.121.0 - Hybrid Protocol Integration

Status: planned

Plan scope: Implement explicit HybridRequired and HybridPreferred policies: Required fails if no admitted hybrid is negotiated; Preferred may select an offered admitted classical group through ordinary one-pass negotiation when the peer lacks hybrids; every selected hybrid must complete both components and partial failure never degrades to its classical component.

Goal: complete the **Hybrid Protocol Integration** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- implement standards-traced ML-KEM and hybrids with explicit HybridRequired and HybridPreferred policies, canonical components, transcript binding, and exclusions;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run FIPS 203, errata, malformed keys and ciphertexts, differentials, stack profiles, implicit rejection, hybrid policy, transcript, and target evidence;
- test partial hybrid failure, downgrade, fragmentation, combiner, code point, required and preferred selection, classical fallback rules, and excluded signatures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every selected hybrid completes both components and only Preferred may select a separately offered classical group when hybrids are unavailable;
- `v0.121.0 implementation stop reached. Run pentest for this exact commit.`

### v0.122.0 - PQ Standards And Audit Gate

Status: planned

Plan scope: Complete PQ external review and standards freeze; keep ML-DSA and SLH-DSA excluded from v1 authentication unless a separately reviewed final standard, TLS mapping, and interoperability milestone is added.

Goal: complete the **PQ Standards And Audit Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- implement standards-traced ML-KEM and hybrids with explicit HybridRequired and HybridPreferred policies, canonical components, transcript binding, and exclusions;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run FIPS 203, errata, malformed keys and ciphertexts, differentials, stack profiles, implicit rejection, hybrid policy, transcript, and target evidence;
- test partial hybrid failure, downgrade, fragmentation, combiner, code point, required and preferred selection, classical fallback rules, and excluded signatures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every selected hybrid completes both components and only Preferred may select a separately offered classical group when hybrids are unavailable;
- `v0.122.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 4: FIPS Module Instantiation, Validation, And TLS Profile

Architecture is frozen before implementation; exact artifact identity is frozen only after all module components and self-tests exist. Correct module-versus-connection failure semantics are enforced throughout.

### v0.123.0 - FIPS Module Architecture Freeze

Status: planned

Plan scope: Freeze the architectural boundary, dependency allowlist, approved and non-approved services, ports, roles, SSP inventory, operational-environment design, build-reproducibility contract, and downstream optional-module constraints without claiming or freezing an exact binary, source identity, dispatch table, dependency closure, or validation artifact.

Goal: complete the **FIPS Module Architecture Freeze** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze only architecture and allowlists at this stop, preserving exact binary, source identity, dispatch, and dependency-closure instantiation until every module component and self-test is final;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run SP 800-90A/B/C, provider and SSP, final integrity and KAT, conditional, fault latch, profile, closure, reproducibility, and ACVTS/CAVP tests;
- prove optional modules cannot alter symbols, dependencies, features, dispatch or inputs; test excluded-service connection termination separately from module latching;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the architecture is frozen without a premature artifact claim, and connection policy failures never misuse the module catastrophic-failure latch;
- `v0.123.0 implementation stop reached. Run pentest for this exact commit.`

### v0.124.0 - SP 800-90 Entropy And DRBG Boundary

Status: planned

Plan scope: Select SP 800-90A DRBGs; validate SP 800-90B entropy sources and health tests; satisfy SP 800-90C construction rules; and define prediction resistance, personalization, fork, reseed, security-strength, and catastrophic-failure semantics.

Goal: complete the **SP 800-90 Entropy And DRBG Boundary** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- preserve the architectural freeze, implement final DRBG, provider, SSP and linked tests, instantiate the exact closure only after every component is final, and distinguish connection-profile termination from module catastrophic failure;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run SP 800-90A/B/C, provider and SSP, final integrity and KAT, conditional, fault latch, profile, closure, reproducibility, and ACVTS/CAVP tests;
- prove optional modules cannot alter symbols, dependencies, features, dispatch or inputs; test excluded-service connection termination separately from module latching;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- architectural boundaries and, after v0.129.0, exact artifact identity are preserved while connection policy failures never misuse the module catastrophic-failure latch;
- `v0.124.0 implementation stop reached. Run pentest for this exact commit.`

### v0.125.0 - Approved Provider And Mandatory Service Indicator

Status: planned

Plan scope: Implement the sealed approved-only provider and return an unambiguous per-service approval indicator through each mandatory typed service result or ActionV1, with SecurityEvent only duplicating that status for audit; permit no additive fips feature or construction before self-test success.

Goal: complete the **Approved Provider And Mandatory Service Indicator** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- preserve the architectural freeze, implement final DRBG, provider, SSP and linked tests, instantiate the exact closure only after every component is final, and distinguish connection-profile termination from module catastrophic failure;
- return the approval or non-approval status from every service invocation in a
  mandatory typed result or ActionV1 and emit only a redundant, non-authoritative
  SecurityEvent audit copy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run SP 800-90A/B/C, provider and SSP, final integrity and KAT, conditional, fault latch, profile, closure, reproducibility, and ACVTS/CAVP tests;
- prove optional modules cannot alter symbols, dependencies, features, dispatch or inputs; test excluded-service connection termination separately from module latching;
- drop every audit event and prove callers must still consume an unambiguous
  mandatory approval indicator before treating service output as approved;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every service result carries mandatory approval status independently of audit
  delivery, while architectural boundaries and catastrophic-latch semantics are preserved;
- `v0.125.0 implementation stop reached. Run pentest for this exact commit.`

### v0.126.0 - SSP Lifecycle And Zeroization Services

Status: planned

Plan scope: Define SSP entry, output, storage, high-water lifetime, external storage, accelerator handle, cache and DMA completion, and zeroization services with mandatory single-consumption completion indications; SecurityEvent may only duplicate secret-free status for audit.

Goal: complete the **SSP Lifecycle And Zeroization Services** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- preserve the architectural freeze, implement final DRBG, provider, SSP and linked tests, instantiate the exact closure only after every component is final, and distinguish connection-profile termination from module catastrophic failure;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run SP 800-90A/B/C, provider and SSP, final integrity and KAT, conditional, fault latch, profile, closure, reproducibility, and ACVTS/CAVP tests;
- prove optional modules cannot alter symbols, dependencies, features, dispatch or inputs; test excluded-service connection termination separately from module latching;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- architectural boundaries and, after v0.129.0, exact artifact identity are preserved while connection policy failures never misuse the module catastrophic-failure latch;
- `v0.126.0 implementation stop reached. Run pentest for this exact commit.`

### v0.127.0 - FIPS Self-Tests And Failure Latch

Status: planned

Plan scope: After the final DRBG, provider, SSP and algorithm implementations are linked, implement module integrity, algorithm and DRBG KATs, pairwise-consistency and conditional tests, permanent failure latching, and deterministic fault-injection evidence over the complete module contents.

Goal: complete the **FIPS Self-Tests And Failure Latch** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- preserve the architectural freeze, implement final DRBG, provider, SSP and linked tests, instantiate the exact closure only after every component is final, and distinguish connection-profile termination from module catastrophic failure;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run SP 800-90A/B/C, provider and SSP, final integrity and KAT, conditional, fault latch, profile, closure, reproducibility, and ACVTS/CAVP tests;
- prove optional modules cannot alter symbols, dependencies, features, dispatch or inputs; test excluded-service connection termination separately from module latching;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- architectural boundaries and, after v0.129.0, exact artifact identity are preserved while connection policy failures never misuse the module catastrophic-failure latch;
- `v0.127.0 implementation stop reached. Run pentest for this exact commit.`

### v0.128.0 - FIPS Observational Security Event Integration

Status: planned

Plan scope: Duplicate mandatory service indicators, module-state results, SSP lifecycle token completions, and catastrophic failures into the frozen audit schema without making SecurityEvent authoritative; keep payloads and identifiers secret-free, format-safe, and non-correlating, permit optional caller timestamps and later enrichment, preserve ordering and saturating drop accounting, and prove missing or ignored events cannot alter or obscure approval, service results, latching, zeroization, destruction completion, or cryptographic state.

Goal: complete the **FIPS Observational Security Event Integration** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- bind each module transition, service indicator, SSP lifecycle completion, and
  catastrophic condition to a deterministic redacted event while preserving
  caller-drained delivery, optional later timestamp enrichment, saturating drop
  totals and visible saturation, non-correlating identifiers, and non-reentrancy;
- retain service approval, module state, SSP zeroization and destruction
  completion as mandatory typed results, state, and single-consumption token
  transitions; events are checked only as audit duplicates;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- fault-inject every self-test, provider, SSP, zeroization, indicator, and latch
  path and compare each event duplicate with its authoritative result or module
  state and with the documented event order and category;
- fill, neglect, and repeatedly drain event capacity through timestamp-free
  boot, later enrichment, counter saturation, concurrent services, and terminal
  failure, proving no identifier correlation and identical service output,
  latching, destruction completion, and cryptographic state;
- suppress all SecurityEvents and prove approval, non-approval, permanent
  failure, zeroization, and destruction completion remain mandatory and
  unambiguous to the caller;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- module events are non-authoritative audit duplicates that may be absent without
  obscuring any mandatory service, state, latch, zeroization, or destruction outcome;
- `v0.128.0 implementation stop reached. Run pentest for this exact commit.`

### v0.129.0 - Exact FIPS Module Artifact Freeze

Status: planned

Plan scope: After the DRBG, approved provider, service indicators, SSP services, algorithms, self-tests, and module security-event integration are final and linked, instantiate and freeze the exact binary, source identity, build inputs, compiler and linker configuration, symbols, dispatch tables, dependency closure, operational-environment mappings, and reproducible artifact hashes; all ACVTS, CAVP, CMVP, and later closure evidence must name this exact artifact.

Goal: complete the **Exact FIPS Module Artifact Freeze** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- emit a reviewed identity manifest covering every source, tool, flag, build
  input, symbol, dispatch path, dependency, operational environment, binary,
  and self-test input that determines the module artifact;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- reproduce the artifact from clean inputs and byte-compare binaries, hashes,
  symbols, dispatch tables, dependencies, build metadata, and source identity;
- prove the complete linked self-test and failure-latch implementation belongs
  to that artifact and make ACVTS, CAVP, CMVP, and closure tooling reject every
  mismatched identity or post-freeze module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- one final artifact identity is reproducible and every later validation datum is mechanically bound to it;
- `v0.129.0 implementation stop reached. Run pentest for this exact commit.`

### v0.130.0 - ACVTS And CAVP Evidence

Status: planned

Plan scope: Complete ACVTS and CAVP campaigns for every approved implementation, dispatch path, parameter set, and operational environment.

Goal: complete the **ACVTS And CAVP Evidence** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- preserve the architectural freeze, implement final DRBG, provider, SSP and linked tests, instantiate the exact closure only after every component is final, and distinguish connection-profile termination from module catastrophic failure;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run SP 800-90A/B/C, provider and SSP, final integrity and KAT, conditional, fault latch, profile, closure, reproducibility, and ACVTS/CAVP tests;
- prove optional modules cannot alter symbols, dependencies, features, dispatch or inputs; test excluded-service connection termination separately from module latching;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- architectural boundaries and, after v0.129.0, exact artifact identity are preserved while connection policy failures never misuse the module catastrophic-failure latch;
- `v0.130.0 implementation stop reached. Run pentest for this exact commit.`

### v0.131.0 - CMVP Submission Artifacts

Status: planned

Plan scope: Produce the CMVP Security Policy, finite-state model, service and SSP inventory, entropy assessment, source-to-object trace, and reproducible module artifacts.

Goal: complete the **CMVP Submission Artifacts** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- preserve the architectural freeze, implement final DRBG, provider, SSP and linked tests, instantiate the exact closure only after every component is final, and distinguish connection-profile termination from module catastrophic failure;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run SP 800-90A/B/C, provider and SSP, final integrity and KAT, conditional, fault latch, profile, closure, reproducibility, and ACVTS/CAVP tests;
- prove optional modules cannot alter symbols, dependencies, features, dispatch or inputs; test excluded-service connection termination separately from module latching;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- architectural boundaries and, after v0.129.0, exact artifact identity are preserved while connection policy failures never misuse the module catastrophic-failure latch;
- `v0.131.0 implementation stop reached. Run pentest for this exact commit.`

### v0.132.0 - Accredited FIPS Evaluation

Status: planned

Plan scope: Complete accredited-lab FIPS 140-3 evaluation, remediation, retest, and certificate and caveat recording; make no validation claim before issuance.

Goal: complete the **Accredited FIPS Evaluation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- preserve the architectural freeze, implement final DRBG, provider, SSP and linked tests, instantiate the exact closure only after every component is final, and distinguish connection-profile termination from module catastrophic failure;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run SP 800-90A/B/C, provider and SSP, final integrity and KAT, conditional, fault latch, profile, closure, reproducibility, and ACVTS/CAVP tests;
- prove optional modules cannot alter symbols, dependencies, features, dispatch or inputs; test excluded-service connection termination separately from module latching;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- architectural boundaries and, after v0.129.0, exact artifact identity are preserved while connection policy failures never misuse the module catastrophic-failure latch;
- `v0.132.0 implementation stop reached. Run pentest for this exact commit.`

### v0.133.0 - Boundary And Package Audit

Status: planned

Plan scope: Complete the final modern, historical, experimental, and FIPS dependency-boundary, symbol, dispatch, feature, and package-content audit.

Goal: complete the **Boundary And Package Audit** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- preserve the architectural freeze, implement final DRBG, provider, SSP and linked tests, instantiate the exact closure only after every component is final, and distinguish connection-profile termination from module catastrophic failure;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run SP 800-90A/B/C, provider and SSP, final integrity and KAT, conditional, fault latch, profile, closure, reproducibility, and ACVTS/CAVP tests;
- prove optional modules cannot alter symbols, dependencies, features, dispatch or inputs; test excluded-service connection termination separately from module latching;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- architectural boundaries and, after v0.129.0, exact artifact identity are preserved while connection policy failures never misuse the module catastrophic-failure latch;
- `v0.133.0 implementation stop reached. Run pentest for this exact commit.`

### v0.134.0 - Approved-Only TLS Operating Profile

Status: planned

Plan scope: Implement a facade approved-only connection profile enforcing minimum key and security strengths, admitted suite, group, signature and certificate combinations, approved entropy and key-generation provenance, resumption, external PSK and zero-RTT policy, and aggregated per-service indicators; invoking a non-approved service terminates the connection and invalidates its approved configuration claim, while the module permanent latch remains reserved for FIPS-defined integrity, self-test, and catastrophic failures.

Goal: complete the **Approved-Only TLS Operating Profile** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- preserve the architectural freeze, implement final DRBG, provider, SSP and linked tests, instantiate the exact closure only after every component is final, and distinguish connection-profile termination from module catastrophic failure;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run SP 800-90A/B/C, provider and SSP, final integrity and KAT, conditional, fault latch, profile, closure, reproducibility, and ACVTS/CAVP tests;
- prove optional modules cannot alter symbols, dependencies, features, dispatch or inputs; test excluded-service connection termination separately from module latching;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- architectural boundaries and, after v0.129.0, exact artifact identity are preserved while connection policy failures never misuse the module catastrophic-failure latch;
- `v0.134.0 implementation stop reached. Run pentest for this exact commit.`

## Phase 5: Optional Modules, Composition, Stable Integration, Assurance, And General Availability

Optional send/receive paths, FIPS closure, and composition precede public freeze.

### v0.135.0 - Operational State Rotation

Status: planned

Plan scope: Complete session cache, stateless ticket-key and resumption-PSK rotation, anti-replay storage, certificate and private-key rotation, trust-anchor and CT log-list updates, and transactional failure recovery.

Goal: complete the **Operational State Rotation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.135.0 implementation stop reached. Run pentest for this exact commit.`

### v0.136.0 - Record Size Limit

Status: planned

Plan scope: Implement Record Size Limit negotiation and enforcement with directional limits, fragmentation, buffering, peer-violation, and interoperability tests.

Goal: complete the **Record Size Limit** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.136.0 implementation stop reached. Run pentest for this exact commit.`

### v0.137.0 - Raw Public Keys

Status: planned

Plan scope: Implement Raw Public Keys with a dedicated pinning and trust-provider contract, identity and rotation policy, negotiation, and proof that RPK never silently bypasses X.509 requirements.

Goal: complete the **Raw Public Keys** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.137.0 implementation stop reached. Run pentest for this exact commit.`

### v0.138.0 - HPKE KEM And Context Foundation

Status: planned

Plan scope: Implement HPKE DHKEM X25519 and P-256 context derivation, labeled HKDF, public-key validation, domain separation, and bounded contexts strictly downstream of validated provider ports, with no symbol, dependency, feature, dispatch, build-input, or source change to a validated FIPS module.

Goal: complete the **HPKE KEM And Context Foundation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.138.0 implementation stop reached. Run pentest for this exact commit.`

### v0.139.0 - HPKE Base Mode

Status: planned

Plan scope: Implement RFC 9180 HPKE base mode with admitted AEADs, sequence and nonce exhaustion, seal and open failure atomicity, official vectors, and independent differential tests.

Goal: complete the **HPKE Base Mode** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.139.0 implementation stop reached. Run pentest for this exact commit.`

### v0.140.0 - ECH Origin Policy And Configuration Bootstrap

Status: planned

Plan scope: Keep DNS, SVCB, HTTPS resolution, network access, and caching caller-owned; accept bounded hostile ECHConfigList bytes with separately typed intended origin, caller-asserted provenance and trust status, configuration generation, and lifetime; implement bounded parsing, version and suite selection, public-name and key configuration, GREASE inputs, origin binding, retry precedence, stale replacement, and explicit EchRequired, EchPreferred, and GreaseOnly policies; missing, stale, malformed, stripped, or unusable configuration fails closed under EchRequired and can never silently establish a public-SNI connection.

Goal: complete the **ECH Origin Policy And Configuration Bootstrap** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- treat every ECHConfigList as hostile while testing intended-origin mismatch, each caller-asserted provenance status, generation and lifetime, EchRequired, EchPreferred and GreaseOnly, missing, stale, malformed, stripped and unusable inputs, retry precedence, cache replacement, and hidden-I/O prohibition;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.140.0 implementation stop reached. Run pentest for this exact commit.`

### v0.141.0 - ECH Client Construction

Status: planned

Plan scope: Implement client inner and outer ClientHello construction, outer-extension references, AAD inputs, GREASE, padding, transcript preservation, and configuration and resource policy.

Goal: complete the **ECH Client Construction** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.141.0 implementation stop reached. Run pentest for this exact commit.`

### v0.142.0 - ECH Server Opening And Acceptance

Status: planned

Plan scope: Implement server configuration lookup, HPKE opening, inner and outer consistency checks, acceptance confirmation, identity selection, uniform rejection, and no fallback to attacker-modified state.

Goal: complete the **ECH Server Opening And Acceptance** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.142.0 implementation stop reached. Run pentest for this exact commit.`

### v0.143.0 - ECH HRR Retry And Rotation

Status: planned

Plan scope: Implement ECH HelloRetryRequest interaction, retry configurations, configuration rotation, second-ClientHello invariants, downgrade detection, and client and server interoperability.

Goal: complete the **ECH HRR Retry And Rotation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.143.0 implementation stop reached. Run pentest for this exact commit.`

### v0.144.0 - Delegated Credentials

Status: planned

Plan scope: Implement delegated credentials as an independent optional module with authorization, lifetime, signature, selection, revocation interaction, and downgrade policy.

Goal: complete the **Delegated Credentials** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.144.0 implementation stop reached. Run pentest for this exact commit.`

### v0.145.0 - Certificate Compression Receive Provider

Status: planned

Plan scope: Treat decompression as strictly bounded hostile pre-authentication work; retain wire CompressedCertificate bytes for the transcript, pass decompressed Certificate bytes to PKI, release no identity or application data before decompression, X.509, CertificateVerify and Finished succeed, and terminate on provider error, overrun, short output, trailing compressed data, or algorithm mismatch.

Goal: complete the **Certificate Compression Receive Provider** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.145.0 implementation stop reached. Run pentest for this exact commit.`

### v0.146.0 - Certificate Compression Send Artifacts

Status: planned

Plan scope: Support sending compressed server and client-authentication certificates through caller-supplied precompressed artifacts verified at configuration by decompressing and byte-comparing with the complete canonical Certificate message, including certificate_request_context and every per-certificate extension; regenerate or invalidate every artifact whenever any encoded input changes, including OCSP staples, SCT lists, delegated credentials, request context, per-certificate extensions, or selected RPK versus X.509 representation; advertise only usable and peer-advertised algorithms, preserve transcript bytes, and enforce exact algorithm, input, output, identity, and rotation binding.

Goal: complete the **Certificate Compression Send Artifacts** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run complete canonical Certificate byte-comparison and invalidation tests across changing OCSP staples, SCT lists, delegated credentials, certificate_request_context, per-certificate extensions, RPK versus X.509 selection, server and client authentication, malformed and stale artifacts, rotation, and targets;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.146.0 implementation stop reached. Run pentest for this exact commit.`

### v0.147.0 - Validated FIPS Closure Preservation Gate

Status: planned

Plan scope: After HPKE, ECH and every optional module exists, prove they remain downstream of validated provider ports and cannot add module symbols, dependencies, features, dispatch entries, build inputs, non-approved algorithms, or source changes; any module change invalidates prior artifact identity and validation claims and requires a new validation line.

Goal: complete the **Validated FIPS Closure Preservation Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.147.0 implementation stop reached. Run pentest for this exact commit.`

### v0.148.0 - Generated Optional-Feature Composition Gate

Status: planned

Plan scope: Generate a compatibility matrix for every pair of admitted optional features and their explicit stream TLS, DTLS, and QUIC applicability, plus targeted higher-order combinations across ECH, X.509 and RPK authentication, delegated credentials, tickets, resumption, imported and raw PSKs, zero-RTT, HybridRequired and HybridPreferred groups, approved-only FIPS policy, certificate compression, rotating OCSP and SCT extensions, Record Size Limit, and DTLS fragmentation; bind ECH tickets to inner identity, policy, and configuration generation; test ClientHello size, HRR, padding, transcript, downgrade, rotation, cancellation, storage, and exhaustion; make forbidden combinations unrepresentable or reject them during configuration before any handshake.

Goal: complete the **Generated Optional-Feature Composition Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- generate and execute every pairwise feature and protocol-applicability case plus targeted ECH, authentication, resumption, hybrid, FIPS and compression higher-order combinations;
- exercise ECH with hybrid ClientHello size, HRR, padding, transcript and downgrade, ECH with RPK, hybrid tickets, PSKs, resumption and zero-RTT, hybrid approved-only policy, rotating OCSP and SCT compression inputs, and configuration-time rejection of every forbidden combination;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.148.0 implementation stop reached. Run pentest for this exact commit.`

### v0.149.0 - Facade Configuration Typestates

Status: planned

Plan scope: After every planned v1 optional module has exercised the internal effects model, freeze facade typestates for exact versions, integrated one-pass routing, suites, trust, RPK, ECH, delegated credentials, compression, resources, revocation, PSK, zero-RTT, Certificate Transparency, FIPS profile, and providers with no raw crypto re-export or legacy range.

Goal: complete the **Facade Configuration Typestates** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.149.0 implementation stop reached. Run pentest for this exact commit.`

### v0.150.0 - Versioned Stable Sans-I/O V1 API

Status: planned

Plan scope: Freeze EngineV1, EventV1, and ActionV1 with exhaustive mandatory entropy, signing, storage, timer, decompression, trust, provider, transport, service-approval, external-destruction, authentication, ECH, early-data, anti-replay, and policy results; applications cannot wildcard-ignore mandatory effects, and unhandled or mismatched effects fail closed; new mandatory effects require V2 interfaces and a major SemVer release; only bounded secret-free observational SecurityEvent values are non-exhaustive, and ignoring every such event still leaves accepted, rejected, approved, non-approved, and destruction-complete states unambiguous through mandatory state and results.

Goal: complete the **Versioned Stable Sans-I/O V1 API** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- freeze authoritative mandatory result and state paths for approval,
  destruction, authentication, ECH, early data, anti-replay, and policy outcomes
  separately from the non-exhaustive observational SecurityEvent schema;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- compile-test exhaustive EngineV1, EventV1 and ActionV1 handling with no wildcard ignore path; inject unknown, mismatched and unhandled mandatory effects and require fail-closed termination; prove mandatory additions require V2 and a major release while unknown informational SecurityEvent values remain bounded, secret-free and observational;
- ignore or drop every SecurityEvent across accepted, rejected, approved,
  non-approved, and destruction-complete paths and prove exhaustive mandatory
  results and engine state cannot be mistaken for the opposite outcome;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every V1 security outcome is authoritative in exhaustive mandatory state or
  results, every unhandled mandatory action fails closed, and only bounded
  observational SecurityEvent audit values are non-exhaustive;
- `v0.150.0 implementation stop reached. Run pentest for this exact commit.`

### v0.151.0 - Caller-Provided Host Capability Integration

Status: planned

Plan scope: Keep protocol-facing contracts upstream and require caller-provided entropy and OS integration for v1; provide no built-in OS entropy FFI. Supply reviewed examples for safe std clocks, transport and storage and for caller or kernel entropy, while documenting that any future Windows, macOS, BSD, mobile, or bare-metal unsafe adapter requires its own crate, versioned unsafe and FFI milestone, audit, and platform evidence.

Goal: complete the **Caller-Provided Host Capability Integration** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.151.0 implementation stop reached. Run pentest for this exact commit.`

### v0.152.0 - Zero-Allocation And Resource Proof

Status: planned

Plan scope: Prove the caller-owned zero-allocation profile with exact workspace sizes, non-overlapping arenas, stack ceilings, concurrency limits, and hostile-load budgets.

Goal: complete the **Zero-Allocation And Resource Proof** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.152.0 implementation stop reached. Run pentest for this exact commit.`

### v0.153.0 - Aesynx ABI And Emulator Qualification

Status: planned

Plan scope: Make the stable Aesynx adapter contract a v1 requirement and pass an executable target-ABI or emulator harness for entropy, randomness, time, transport, storage, acceleration, boot-to-handshake, and lifecycle behavior; allow real-hardware qualification after v1 without weakening the contract.

Goal: complete the **Aesynx ABI And Emulator Qualification** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run extension, precompressed-artifact, composition, incompatible typestate, FIPS-closure, ECH, RPK, delegation, compression, trace, zero-allocation, Aesynx, rotation, and target tests;
- exercise cross-feature cancellation, rotation, transcript, storage, exhaustion, decompression, trust confusion, unavailable entropy, and prohibited validated-module mutation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.153.0 implementation stop reached. Run pentest for this exact commit.`

### v0.154.0 - Protocol State And Resource Formal Harnesses

Status: planned

Plan scope: Complete Kani or equivalent harnesses for cursors, lengths, state reachability, exhaustion, replay, transactional transitions, one-pass selectors, secret-release invariants, zeroization and obsolete-key transitions, X.509 path-work and policy-tree ceilings, and single-consumption pending-operation tokens using pinned external tools.

Goal: complete the **Protocol State And Resource Formal Harnesses** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- capture formal, external-process fuzz, differential, sanitizer, side-channel, platform, hostile-load, review, remediation, freeze, and operational evidence;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- prove cursor, length, transition, replay, selector, zeroization, obsolete-key, X.509 budget, policy-tree, pending-token single-consumption, and secret-release properties across bounded models and supported configurations;
- retain regressions and prove replay, clean retest, traceability, artifact identity, rollback, compromise, and incident procedures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- protocol, resource, zeroization, X.509-budget, and pending-token proof claims name exact harnesses, bounds, assumptions, and implementations;
- `v0.154.0 implementation stop reached. Run pentest for this exact commit.`

### v0.155.0 - Cryptographic Formal Coverage And Residual-Gap Gate

Status: planned

Plan scope: Complete and audit the proof harnesses introduced with every arithmetic and cryptographic milestone: use symbolic full-width proofs where tractable, limb-count-parameterized proofs where sound, and reduced-width exhaustive models only to validate algorithms and harness structure; treat production-width official vectors and at least two independent external differential processes as evidence rather than proof; publish a machine-readable claim register mapping every primitive, implementation symbol, proven property, supported width or parameter, verification method, and residual gap without claiming reduced-to-production-width equivalence.

Goal: complete the **Cryptographic Formal Coverage And Residual-Gap Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- maintain proof harnesses beside small arithmetic and cryptographic modules,
  classify every harness as symbolic full-width, sound limb-count-parameterized,
  or reduced-width exhaustive, record every abstraction and assumption, map it
  to exact production code and supported widths, and inventory residual gaps;
- define and generate a versioned, deterministic machine-readable cryptographic
  claim register whose entries name the primitive, exact implementation symbol,
  claimed property, supported widths or parameters, verification method,
  evidence identifiers, assumptions, and residual gaps;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run pinned Kani or equivalent full-width, limb-count-parameterized, or
  explicitly reduced-width harnesses for limb, Montgomery, field, scalar,
  point, ladder, group, ML-KEM, HKDF, AEAD failure-atomicity, bounds, exhaustion,
  canonicalization, rejection, and round-trip invariants;
- exercise production widths with official vectors, boundary corpora, and at
  least two independent external reference processes as differential evidence,
  never as proof of equivalence; reject unsupported claims and publish every
  remaining width, path, tool, or abstraction gap;
- schema-validate and deterministically regenerate the claim register; reject
  duplicate or orphan entries, missing symbols, unclassified verification
  methods, unsupported widths or parameters, stale evidence references, and
  omitted residual gaps;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every cryptographic claim names its exact implementation, proof class,
  assumptions, widths, production evidence, and residual gaps, with no
  reduced-to-production-width equivalence claim, and the machine-readable
  register completely represents the reviewed claim set;
- `v0.155.0 implementation stop reached. Run pentest for this exact commit.`

### v0.156.0 - External-Process Fuzz And Differential Campaign

Status: planned

Plan scope: Do not use cargo-fuzz or libfuzzer-sys; drive first-party corpus and stdin harness binaries with pinned external process-level mutation and instrumentation, deterministic replay, differential corpora, and crash minimization without third-party repository crates.

Goal: complete the **External-Process Fuzz And Differential Campaign** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- capture formal, external-process fuzz, differential, sanitizer, side-channel, platform, hostile-load, review, remediation, freeze, and operational evidence;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run campaigns across compiler, target, provider, feature combination, package, harness, peer, path, selector, adapter, and clean environment;
- retain regressions and prove replay, clean retest, traceability, artifact identity, rollback, compromise, and incident procedures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the exact-commit evidence is complete, findings are dispositioned, and claims do not exceed tested behavior;
- `v0.156.0 implementation stop reached. Run pentest for this exact commit.`

### v0.157.0 - Memory And Side-Channel Evidence

Status: planned

Plan scope: Complete Miri and sanitizer evidence plus compiler and target constant-time assembly, owned-region zeroization-store survival, cache and branch, and statistical side-channel matrices.

Goal: complete the **Memory And Side-Channel Evidence** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- capture formal, external-process fuzz, differential, sanitizer, side-channel, platform, hostile-load, review, remediation, freeze, and operational evidence;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run campaigns across compiler, target, provider, feature combination, package, harness, peer, path, selector, adapter, and clean environment;
- retain regressions and prove replay, clean retest, traceability, artifact identity, rollback, compromise, and incident procedures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the exact-commit evidence is complete, findings are dispositioned, and claims do not exceed tested behavior;
- `v0.157.0 implementation stop reached. Run pentest for this exact commit.`

### v0.158.0 - Sustained Platform And Hostile-Load Qualification

Status: planned

Plan scope: Sustain Linux, Windows, macOS, BSD, Android, iOS, bare-metal, and Aesynx ABI or emulator qualification under concurrency, provider failure, resource exhaustion, and hostile load.

Goal: complete the **Sustained Platform And Hostile-Load Qualification** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- capture formal, external-process fuzz, differential, sanitizer, side-channel, platform, hostile-load, review, remediation, freeze, and operational evidence;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run campaigns across compiler, target, provider, feature combination, package, harness, peer, path, selector, adapter, and clean environment;
- retain regressions and prove replay, clean retest, traceability, artifact identity, rollback, compromise, and incident procedures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the exact-commit evidence is complete, findings are dispositioned, and claims do not exceed tested behavior;
- `v0.158.0 implementation stop reached. Run pentest for this exact commit.`

### v0.159.0 - Consolidated External Audits

Status: planned

Plan scope: Complete exact-commit external crypto, PKI, TLS, DTLS, QUIC, PQ, FIPS-boundary and profile, optional-module, zeroization, and systems-integration audits.

Goal: complete the **Consolidated External Audits** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- capture formal, external-process fuzz, differential, sanitizer, side-channel, platform, hostile-load, review, remediation, freeze, and operational evidence;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run campaigns across compiler, target, provider, feature combination, package, harness, peer, path, selector, adapter, and clean environment;
- retain regressions and prove replay, clean retest, traceability, artifact identity, rollback, compromise, and incident procedures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the exact-commit evidence is complete, findings are dispositioned, and claims do not exceed tested behavior;
- `v0.159.0 implementation stop reached. Run pentest for this exact commit.`

### v0.160.0 - Audit Remediation And Clean Retest

Status: planned

Plan scope: Remediate every admitted finding, add permanent regressions, and obtain clean independent retests with no unresolved critical or high findings.

Goal: complete the **Audit Remediation And Clean Retest** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- capture formal, external-process fuzz, differential, sanitizer, side-channel, platform, hostile-load, review, remediation, freeze, and operational evidence;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run campaigns across compiler, target, provider, feature combination, package, harness, peer, path, selector, adapter, and clean environment;
- retain regressions and prove replay, clean retest, traceability, artifact identity, rollback, compromise, and incident procedures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the exact-commit evidence is complete, findings are dispositioned, and claims do not exceed tested behavior;
- `v0.160.0 implementation stop reached. Run pentest for this exact commit.`

### v0.161.0 - Public API Requirements And Documentation Freeze

Status: planned

Plan scope: Freeze public APIs, features, package inventory, requirements ledger, admitted algorithms and extensions, migration guidance, deployment profiles, incident procedures, limitations, and non-goals.

Goal: complete the **Public API Requirements And Documentation Freeze** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- capture formal, external-process fuzz, differential, sanitizer, side-channel, platform, hostile-load, review, remediation, freeze, and operational evidence;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run campaigns across compiler, target, provider, feature combination, package, harness, peer, path, selector, adapter, and clean environment;
- retain regressions and prove replay, clean retest, traceability, artifact identity, rollback, compromise, and incident procedures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the exact-commit evidence is complete, findings are dispositioned, and claims do not exceed tested behavior;
- `v0.161.0 implementation stop reached. Run pentest for this exact commit.`

### v0.162.0 - Clean-Room Release Rehearsal

Status: planned

Plan scope: Pass reproducible clean-room builds, package installation, artifact comparison, rollback, key-compromise, incident, and disaster-recovery exercises.

Goal: complete the **Clean-Room Release Rehearsal** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- capture formal, external-process fuzz, differential, sanitizer, side-channel, platform, hostile-load, review, remediation, freeze, and operational evidence;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run campaigns across compiler, target, provider, feature combination, package, harness, peer, path, selector, adapter, and clean environment;
- retain regressions and prove replay, clean retest, traceability, artifact identity, rollback, compromise, and incident procedures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the exact-commit evidence is complete, findings are dispositioned, and claims do not exceed tested behavior;
- `v0.162.0 implementation stop reached. Run pentest for this exact commit.`

### v1.0.0-rc.1 - Exact Production Candidate

Status: planned

Plan scope: Build final artifacts once and freeze source, compiler, flags, archives, SBOM, checksums, provenance, documentation, and the pentested exact commit.

Goal: complete the **Exact Production Candidate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze or promote only approved modern artifacts, source, toolchain, archives, SBOM, checksums, provenance, documentation, and metadata;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- reproduce artifacts, compare every byte, verify installation and rollback, and rerun every production gate;
- exercise compromise, disaster, package inspection, downstream compatibility, and absence of historical, draft, or excluded scope;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- stable artifacts are byte-identical to the approved candidate and every claim maps to exact-commit evidence;
- `v1.0.0-rc.1 implementation stop reached. Run pentest for this exact commit.`

### v1.0.0 - First Serious Production-Ready Brynja TLS Release

Status: planned

Plan scope: Promote only the byte-identical approved candidate without rebuild, source change, metadata drift, or expanded capability claim.

Goal: complete the **First Serious Production-Ready Brynja TLS Release** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze or promote only approved modern artifacts, source, toolchain, archives, SBOM, checksums, provenance, documentation, and metadata;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- reproduce artifacts, compare every byte, verify installation and rollback, and rerun every production gate;
- exercise compromise, disaster, package inspection, downstream compatibility, and absence of historical, draft, or excluded scope;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- stable artifacts are byte-identical to the approved candidate and every claim maps to exact-commit evidence;
- `v1.0.0 implementation stop reached. Run pentest for this exact commit.`
