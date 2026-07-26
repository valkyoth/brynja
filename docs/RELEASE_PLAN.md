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
up-to-date committed pentest report.

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

## Simple Pentest, CI, And Tag Flow

Each version uses one report at `security/pentest/vX.Y.Z[-rc.N].md`:

1. Complete the version scope and local verification, then stop and ask the
   user for pentest.
2. Keep the report current while findings are fixed and retested. If no finding
   exists, record that explicitly.
3. Commit the implementation and PASS report together. The report must state
   `Open-Findings: 0` and `Retest: PASS`.
4. Push and wait for GitHub CI and CodeQL Default to become green.
5. If GitHub exposes a problem, fix it, update the same report, commit both,
   push, and wait for green again.
6. Create the tag only after the user explicitly confirms that GitHub is green.

The report does not contain a self-referential commit hash. The gate instead
proves that the versioned report is committed at `HEAD`, matches the worktree,
has a final PASS state, and was updated in any later commit that changed the
candidate. The pre-tag gate rejects an existing tag. The guarded publisher
accepts the tag only when it points to that exact green candidate commit.

## Crate Versioning And Publication

The workspace follows the same independent-crate release model as `eth`, with
additional fail-closed rules for repository-only packages.
`release-crates.toml` records every package's previous version, planned
version, change class, publication decision, and reason.

- every official modern release tag publishes the `brynja` facade at exactly
  the tag version, even when the release only advances its dependency pins or
  release-facing metadata;
- the initial public release publishes every modern package required by the
  facade, including optional normal dependencies, before the facade;
- supporting crates publish only for an explicit initial release, code or API
  work, an API-compatible bug fix, a required internal dependency-pin change,
  or immutable crates.io metadata correction;
- unchanged supporting crates retain their previous independent versions and
  are not republished;
- changed dependencies publish and become available first, and `brynja`
  publishes last;
- repository-only test, interop, task, proof, and SSL 1 research packages can
  never be selected for crates.io publication; and
- legacy packages require their independent legacy admission line and remain
  unreachable from the modern facade.

`scripts/release_crates.py --check` enforces the complete inventory, exact
internal pins, manifest publishability, independent SemVer transitions,
dependency availability and ordering, repository-only exclusions, and the
mandatory facade release. `--package-check` validates the Cargo file set for
every selected crate and builds every dependency-root `.crate` archive that is
packageable before new internal dependencies reach crates.io. The interactive
publisher then packages and publishes downstream crates in dependency order,
waiting for each new dependency to be indexed. Actual publication additionally
requires a clean worktree, the matching tag at `HEAD`, the versioned release
gate, Cargo deny and audit checks, Cargo package verification, and typed
version confirmation.
There is no production bypass for a dirty or untagged tree, skipped checks, or
`cargo publish --no-verify`.

## TLS Package And Retirement Rule

`brynja-tls` remains the evergreen public facade and one-pass router.
`brynja-tls12`, `brynja-tls13`, and each later admitted TLS generation own
separate version-specific engines; record-independent TLS 1.3 state is isolated
in `brynja-tls13-handshake` for stream TLS and QUIC. Adding a TLS generation
requires a new package, requirements closure, implementation sequence, engine
audit, and router integration and audit milestones.

A successor does not automatically make an older TLS generation legacy.
Retirement requires a newly added numbered security-boundary milestone backed
by current standards and cryptographic evidence. It removes the engine from all
modern graphs and negotiation before any controlled-interoperability package is
created. Any continuation starts a separate
`brynja-legacy-tls1N` SemVer, warning, audit, and pentest line; the former
modern package is explicitly deprecated and never forwards to legacy code.

## Legacy Package Release Line

Legacy packages use independent SemVer and separately pass source, codec,
state, primitive, client, optional server, containment, and audit/pentest stages.
SSL 1 remains research-only and unpublished.

| Legacy stage | Required result |
| --- | --- |
| `H0.1.0` | Authenticate sources and rights, record errata, publish conspicuous insecurity warnings, and freeze the protocol threat model. |
| `H0.1.1` | Freeze the exact per-protocol cipher-suite, compression, extension, message, certificate, key-format, and primitive admission register before codec or weak-primitive work. |
| `H0.2.0` | Implement only the protocol-specific bounded wire codec. |
| `H0.3.0` | Implement isolated state with no shared modern configuration, negotiation, credentials, caches, tickets, paths, or fallback. |
| `H0.4.0` | Bind audited shared primitives and keep required weak primitives in a legacy-only crypto package. |
| `H0.5.0` | Complete controlled client-only interoperability and containment evidence. |
| `H0.6.0` | Add server interoperability only when separately justified and reviewed for amplification and hostile load. |
| `H0.7.0` | Require separate listeners, paths, policy, credentials, storage, diagnostics, and process containment. |
| `H0.8.0` | Complete a protocol-specific external audit and pentest and verify every warning and non-fallback property. |

## Phase 0: Repository, Effects, Memory, And Wire Foundations

Generated requirements and upstream interfaces precede implementation.

### v0.1.0 - Workspace Foundation

Status: awaiting green CI

Plan scope: Preserve the explicit `brynja-legacy-*` naming boundary, evergreen `brynja-tls` router facade, version-specific `brynja-tls12`, `brynja-tls13`, and `brynja-tls13-handshake` package graph, and the remaining workspace foundation with no cryptographic or protocol security claim.

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
- `v0.1.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.2.0 - Release And Isolation Enforcement

Status: planned

Plan scope: Harden committed-report and exact-tag comparison, validate all-feature graphs and every package class, add negative modern and legacy isolation fixtures, and document protected release controls.

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
- `v0.2.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.3.0 - Requirements And Standards Source Ledger

Status: planned

Plan scope: Generate the normative source ledger from every algorithm, encoding, extension, protocol, validation, and operational milestone; close current RFC updated-by and obsoleted-by chains, record errata decisions and IANA snapshots, distinguish current authorities from compatibility baselines, and require the final ECDHE-ML-KEM group RFC and code points before admission.

Goal: complete the **Requirements And Standards Source Ledger** implementation stop without admitting or
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
- `v0.3.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.3.1 - Machine-Readable Protocol Surface Decision Register

Status: planned

Plan scope: Generate a machine-readable register covering every current TLS, DTLS, QUIC-TLS, PKIX, HPKE, ECH, legacy-protocol, algorithm, extension, content and handshake message, alert, cipher suite, signature scheme, named group, certificate and key format, and relevant IANA entry; classify each as implemented, intentionally rejected, safely ignored, caller-owned, legacy-only, or future work with normative source, owning milestone, code and test targets, including explicit decisions for Heartbeat, status_request_v2, SSLKEYLOGFILE, TLS 1.3 post-handshake authentication, certificate-with-external-PSK, legacy PKCS1 client signatures, ML-KEM PKIX credentials, HPKE non-base modes, unsigned X.509 certificates, QUIC version-specific transport cryptography, and compression algorithms; fail when a source, registry snapshot, status, erratum, or classification drifts.

Goal: complete the **Machine-Readable Protocol Surface Decision Register** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- define a versioned deterministic schema for protocol surfaces, normative
  sources, ownership, milestone, code, test, and status classification;
- generate human-readable coverage from the machine register and preserve
  current RFC Editor, IANA, NIST, CMVP, errata, and transition snapshots;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- regenerate twice and byte-compare the register and rendered coverage;
- inject missing, duplicate, unknown, obsolete, status-drifted, unowned, and
  untested entries and require repository failure;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every relevant protocol and cryptographic surface has one explicit,
  reviewable disposition and drift cannot remain silent;
- `v0.3.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.3.2 - Normative Requirement Matrix Foundation

Status: planned

Plan scope: Define stable requirement identifiers bound to exact source hashes, sections, status and errata; model planned, implemented, tested, evidenced, rejected, caller-owned, legacy and blocked lifecycles; generate bidirectional source, decision, milestone, target-symbol-or-boundary, test and evidence mappings; and prove extraction and drift failures on the normative-language and registry authorities.

Goal: complete the **Normative Requirement Matrix Foundation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- define deterministic schema, identifiers, lifecycle transitions, target
  references, and machine-to-human projections that survive rendering changes;
- implement source hash, section, status, errata, strength, applicability,
  decision, milestone, planned or actual symbol, test, evidence, and residual
  fields without pretending future code already exists;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- regenerate twice and byte-compare schema, pilot records, and rendered reports;
- inject changed source hashes, invalid sections, illegal lifecycle transitions,
  obsolete authority, duplicate ID, absent owner, premature evidence, weakened
  SHOULD decision, and missing target records and require repository failure;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the matrix can truthfully represent requirements before and after code exists,
  and the normative-language and registry pilot proves deterministic drift;
- `v0.3.2 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.3.3 - Cryptography Encoding And PKIX Normative Coverage

Status: planned

Plan scope: Populate and review every applicable normative statement and invariant for admitted primitives, arithmetic, DER, key and certificate formats, service identity, path processing, revocation, OCSP and Certificate Transparency; record explicit algorithm exclusions, current-versus-compatibility authority, positive and negative target tests, work bounds, and unresolved evidence.

Goal: complete the **Cryptography Encoding And PKIX Normative Coverage** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- populate the complete crypto, encoding, key-container, certificate, name,
  path, policy, revocation, OCSP, TLS Feature, and CT requirement domains;
- bind every rule to an owner, explicit disposition, resource or side-channel
  invariant, planned target, positive and negative target tests, and evidence
  lifecycle without accepting an unreviewed algorithm identifier;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- compare source-to-plan and plan-to-source coverage for every owning milestone
  and regenerate all projections byte-identically;
- remove, duplicate, weaken, misclassify, obsolete, or orphan requirements from
  each domain and require failure, including cross-domain AlgorithmIdentifier,
  name, policy, revocation, CT-version, and work-bound cases;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every locked cryptographic, encoding, and PKIX rule has a reviewable lifecycle
  and no admitted or rejected algorithm or validation surface remains implicit;
- `v0.3.3 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.3.4 - TLS DTLS And QUIC Normative Coverage

Status: planned

Plan scope: Populate and review every applicable normative statement and invariant for current and compatibility TLS, hardened TLS 1.2, QUIC-TLS, DTLS 1.2 and DTLS 1.3; map every message, extension, alert, registry value, state transition, transport boundary, intentional rejection and caller-owned responsibility to its milestone and target tests.

Goal: complete the **TLS DTLS And QUIC Normative Coverage** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- populate base, update, compatibility, deprecation, feature-freeze, record,
  handshake, PSK, exporter, ticket, QUIC, datagram, CID, path, and routing rules;
- map every wire surface and state transition to exact ownership, disposition,
  alert or transport failure, resource bounds, planned target, target tests, and
  evidence lifecycle while preserving version separation;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- compare every TLS, DTLS, and QUIC-TLS source, registry, and planned milestone
  in both directions and regenerate projections byte-identically;
- inject missing messages, illegal contexts, registry drift, wrong-version
  reuse, obsolete authority, caller/protocol ownership swaps, ignored alerts,
  and weakened security requirements and require failure;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every transport-protocol requirement and boundary is explicitly versioned,
  owned, test-targeted, and unable to hide behind generic TLS reuse;
- `v0.3.4 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.3.5 - Optional Legacy And Residual Normative Closure

Status: planned

Plan scope: Populate HPKE, ECH, ML-KEM and hybrid, optional TLS facilities, legacy protocol, operational and presently pinned non-RFC requirements; represent unavailable future or mutable authorities as fail-closed blockers owned by their dependent milestone; and reject every orphan, duplicate, stale, obsolete-as-current, silently weakened or uncovered planned surface before cryptographic or protocol implementation begins.

Goal: complete the **Optional Legacy And Residual Normative Closure** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- populate every remaining optional, PQ, legacy, operational, source-rights,
  test-only, caller-owned, rejected, blocked, and presently pinned non-RFC rule;
- generate complete source-to-plan, plan-to-source, surface-to-requirement, and
  requirement-to-owner reports with explicit dependent-milestone refresh rules
  for mutable guidance and unavailable future standards;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- require complete bidirectional coverage across all locked sources, roadmap
  rows, surface decisions, non-RFC ledgers, legacy packages, and blockers;
- inject draft identifiers, future-source claims, rights gaps, stale mutable
  guidance, missing exclusions, orphan plans, premature implementation status,
  and uncovered surfaces and require repository failure;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the complete current planning baseline is closed without claiming unavailable
  standards, future code, mutable evidence, or legacy rights as complete;
- `v0.3.5 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.4.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.5.0 - Error Alert And Exhaustion Domains

Status: planned

Plan scope: Freeze non-secret error, alert, close, provider-failure, and resource-exhaustion domains; prohibit secret-bearing formatting and ambiguous failure collapse.

Goal: complete the **Error Alert And Exhaustion Domains** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- freeze upstream capability types, caller limits, transactional effects,
  mandatory zeroization, version-neutral framing, provider failure,
  secret-free errors, and a one-way production-to-test-support boundary;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run boundary, truncation, overflow, exhaustion, compile-fail, no-mutation, no_std, direction, zeroization, and deterministic-provider tests;
- test arena overlap, malformed framing, unavailable effects, dependency
  inversion, cancellation, optimization, cache and DMA duties, terminal states,
  and broken production graphs containing RFC 9850 labels or hooks;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe,
  platform-independent, reviewably destroys owned secrets, and cannot log
  production traffic secrets;
- `v0.5.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.6.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.7.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.8.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.9.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.10.0 - Secret Lifetime And Destruction Contract

Status: planned

Plan scope: Define non-cloneable and non-serializable secret ownership, transition, error, cancellation, provider-failure and drop destruction, immediate obsolete-secret cleanup, external-store and accelerator duties, a mandatory production guarantee for the complete owned memory region, and RFC 9850 key logging only in a separately compiled test-support artifact that cannot enter production packages or features.

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
- `v0.10.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.11.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.11.1 - Sanitization Adapter Admission Review

Status: planned

Plan scope: Audit the latest stable first-party `sanitization` crate against Brynja's MSRV, `no_std`, license, unsafe, target, complete-owned-region destruction, feature, dependency, advisory, optimization-evidence, and FIPS-boundary policies; compare one protocol-neutral adapter with a legacy-specific split, require an activated graph with no `zeroize` or other third-party crate, and record a fail-closed admit-or-reject decision without changing any Brynja production dependency graph.

Goal: decide whether `sanitization` can support a separately selected Brynja
adapter without weakening the mandatory first-party core destruction contract,
modern/legacy isolation, dependency policy, or FIPS boundary.

Deliverables:

- record the exact audited `sanitization` release, source and package hashes,
  MSRV, license, enabled and disabled features, unsafe inventory, dependency
  closure, target guarantees, evidence, advisories, and residual gaps;
- freeze a downstream adapter boundary using adapter-owned wrapper types, with
  no orphan-rule workaround, protocol-engine dependency, facade feature,
  default activation, implicit conversion, or ownership ambiguity;
- decide whether one protocol-neutral `brynja-sanitization` can serve modern
  and legacy consumers with identical guarantees; reject a separate
  `brynja-legacy-sanitization` unless irreducible legacy-only semantics make a
  later independently versioned package necessary;
- specify that Brynja's v0.11.0 primitive remains mandatory and authoritative,
  while the optional adapter may only add reviewed storage and lifecycle
  ergonomics and cannot downgrade complete-owned-region destruction;
- record an explicit admission or rejection decision, including the reason,
  required remediation, update policy, and conditions that force re-review.

Verification:

- build and test the candidate boundary from Rust `1.90.0` through the pinned
  stable toolchain across the promised `no_std`, desktop, mobile, BSD, and
  bare-metal target matrix;
- inspect Cargo metadata, the lockfile, package archive, activated features,
  and feature-unification fixtures to prove that `zeroize`, derive, serde,
  subtle, and every other third-party crate remain outside the activated graph;
- compare destruction behavior and emitted MIR, LLVM IR, and assembly with
  Brynja's v0.11.0 obligations, including drop, explicit clear, replacement,
  error, cancellation, panic-unwind, optimization, and complete-capacity cases;
- exercise negative dependency-direction, modern/legacy isolation, orphan
  wrapper, FIPS-boundary, version-drift, advisory, and unsupported-target
  fixtures, then pass repository policy, SBOM, documentation, and pentest gates.

Exit criteria:

- a committed, evidence-backed admit-or-reject decision preserves every Brynja
  destruction and isolation invariant without adding a production dependency;
- `v0.11.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.11.2 - Optional Brynja Sanitization Adapter

Status: planned

Plan scope: Conditional on the v0.11.1 admission decision, implement and independently publish a `no_std` `brynja-sanitization` downstream adapter using exact-pinned `sanitization` with default features disabled, adapter-owned wrapper types, and identical modern and legacy destruction semantics; keep it out of every facade, engine, default feature, and FIPS validated-module closure, or close the milestone with documented non-admission if any invariant cannot be preserved.

Goal: provide an explicitly selected first-party sanitization integration
without making Brynja depend on it or creating a weaker legacy destruction
domain.

Deliverables:

- if admitted, add the separately versioned and separately published
  `brynja-sanitization` package with adapter-owned secret wrappers and narrow
  conversions over frozen `brynja-core` contracts;
- exact-pin the admitted `sanitization` release with default features disabled,
  expose no feature that activates `zeroize` or another third-party crate, and
  require a new admission review before any version or feature change;
- make applications select the adapter through an explicit dependency; do not
  add it to `brynja`, `brynja-tls`, any version-specific engine, any legacy
  engine or facade, `brynja-platform`, or a default/all-features shortcut;
- share the protocol-neutral adapter between modern and legacy applications
  while preserving separate engine state and credentials; do not create
  `brynja-legacy-sanitization` unless a later numbered review proves it is
  necessary and safe;
- exclude the adapter from `brynja-fips-module` and all validation claims;
  application use outside the module boundary cannot satisfy or imply FIPS SSP
  destruction, service approval, or certificate coverage;
- if admission fails or later evidence invalidates it, publish no adapter and
  close the milestone with the rejection evidence and migration guidance.

Verification:

- run adapter API, redaction, non-Clone, destruction, replacement, cancellation,
  error, unwind, capacity, compile-fail, Miri, emitted-code, and differential
  tests against the exact admitted release;
- prove `no_std` and Rust `1.90.0` through pinned-stable compatibility across
  every promised target, with explicit compile-only versus runtime evidence;
- test modern and legacy downstream examples against the same adapter contract
  and reject dependency paths from any facade or engine back to the adapter;
- inspect Cargo metadata, feature resolution, lockfile, SBOM, package contents,
  crates.io order, and negative fixtures for version drift, default-feature
  activation, `zeroize`, third-party crates, and FIPS-boundary contamination;
- pass the full repository, documentation, advisory, isolation, release, and
  pentest gates with the independent-crate publication policy enforced.

Exit criteria:

- either the optional adapter is independently usable with identical modern and
  legacy guarantees and no core or FIPS dependency, or a documented
  fail-closed non-admission leaves the production graph unchanged;
- `v0.11.2 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.12.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.13.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.14.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.15.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.16.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.17.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.18.0 - Mandatory Security Outcome Authority Contract

Status: planned

Plan scope: Define authoritative engine state and exhaustive mandatory typed results for self-tests, service approval, protocol and profile selection, authentication, tickets, resumption, PSKs, early data, anti-replay, amplification, exhaustion, provider failure, key lifecycle, ECH, policy, and terminal transitions; external-key destruction completes only through a mandatory token transition, and ignoring every informational output cannot make rejected, non-approved, incomplete, or failed work appear accepted, approved, complete, or successful.

Goal: complete the **Mandatory Security Outcome Authority Contract** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- define authoritative mandatory results and state transitions for service
  approval, external-key destruction, authentication, ECH, early data,
  anti-replay, and policy decisions, with exact success, rejection, pending,
  cancellation, failure, and terminal semantics;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exhaustively exercise accepted, rejected, approved, non-approved, pending,
  destruction, authentication, ECH, early-data, anti-replay, and policy paths
  and prove mandatory results and engine state are complete and unambiguous;
- discard every informational output, inject cancellation and provider failure,
  and prove no incomplete or failed operation can be observed as successful;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every security decision and completion is authoritative, mandatory, and
  unambiguous without relying on an audit or informational path;
- `v0.18.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.18.1 - Bounded Observational Security Event Schema

Status: planned

Plan scope: Define an upstream no_std Sans-I/O SecurityEvent audit schema that only duplicates the authoritative outcomes frozen at v0.18.0; events are caller-drained, allocation-free, bounded, secret-free, format-safe, alert-independent, optionally caller-timestamped or explicitly untimestamped for later enrichment, use saturating drop counters with visible saturation, contain no secret or stable correlating identifier, never reenter, and cannot block, authorize, complete, or alter cryptographic or protocol state.

Goal: complete the **Bounded Observational Security Event Schema** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- freeze bounded event discriminants and payloads, deterministic ordering,
  caller-drain and optional timestamp enrichment, redaction, drop accounting,
  visible saturation, and separation from peer-visible alerts;
- map each event to an already-authoritative v0.18.0 state or mandatory result
  and prohibit event-only decisions, completion, authorization, or latching;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exhaustively construct and format every variant and prove no key handle,
  identity, plaintext, transcript, PSK identity, ticket, ECH inner name, or
  stable cross-connection correlation value can appear;
- test timestamp-free boot, later enrichment, full queues, absent drains,
  counter saturation, provider failure, terminal transitions, and attempted
  reentrancy with identical authoritative state and peer-alert behavior;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- events are bounded audit duplicates whose absence or loss cannot change or
  obscure any security outcome;
- `v0.18.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.19.0 - TLS And DTLS Record Framing

Status: planned

Plan scope: Keep record framing independent of protocol selection and fallback; ignore TLSPlaintext legacy_record_version where required, validate TLSCiphertext constants where applicable, preserve bytes, reject RFC 6520 Heartbeat content and negotiation in every modern profile, and leave version choice exclusively to typed handshake policy.

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
- `v0.19.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.20.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.21.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- record arithmetic, group, buffer, key, nonce, randomness, use-limit,
  import-only RSA, ephemeral-lifecycle, constant-time, exclusion, registry, and
  provider-token invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official vectors, in-place and disjoint buffers, partial-overlap rejection, unchanged failure destinations, differentials, imported-key consistency, no_std, and provider faults;
- review MIR, LLVM and assembly and test timing, cache, branch, malformed
  inputs, invalid secrets, exhaustion, reuse, fault attacks, zeroization, and
  negative RFC 9935 and RFC 9963 code-point reachability;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- admitted and rejected algorithms have complete registry decisions, and every
  admitted algorithm has functional, caller-buffer, lifecycle, resource, and
  side-channel evidence before downstream use;
- `v0.22.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.23.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.24.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.25.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.26.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.27.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.28.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.29.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.30.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.31.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.32.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.33.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.34.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.35.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.36.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.37.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.38.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.39.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.40.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.41.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.42.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.43.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.44.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.45.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.46.0 - Version-One Algorithm Decisions

Status: planned

Plan scope: Freeze explicit v1 admission or exclusion for P-521, Ed448, finite-field DHE, AES-CCM, SHA-1 certificate chains, PKCS1 v1.5 signing including RFC 9963 legacy client CertificateVerify code points, encrypted private-key containers, first-party RSA key generation, RFC 9935 ML-KEM PKIX credentials, ML-DSA, SLH-DSA, and every unimplemented algorithm family.

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
- `v0.46.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.47.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.48.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.49.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.50.0 - X.509 Decoder

Status: planned

Plan scope: Decode X.509 Certificate, TBSCertificate, and SPKI under the current RFC 5280 update closure while preserving the exact original signed byte slice, enforcing current RSA, EC, X25519, and Ed25519 AlgorithmIdentifier rules, and rejecting ambiguous algorithms and id-alg-unsigned in every signature-verification context.

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
- `v0.50.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.51.0 - Service Identity And Extensions

Status: planned

Plan scope: Validate SAN and service identity, ASCII IDNA2008 A-label DNS inputs, wildcards, IP, internationalized and ASCII email, and URI names under RFC 9525 and the current RFC 5280 internationalization updates; enforce critical and duplicate extensions while keeping Unicode mapping and presentation caller-owned.

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
- `v0.51.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.52.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.53.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.54.0 - Name Constraints

Status: planned

Plan scope: Validate DNS, IP, rfc822Name and SmtpUTF8Mailbox email, URI, and directory-name constraints under the current RFC 5280 internationalization updates with explicit subtree, comparison, normalization, and work budgets.

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
- `v0.54.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.55.0 - Certificate Policy Processing

Status: planned

Plan scope: Implement certificate policies, mappings, anyPolicy, inhibition, policy constraints, and RFC 9618 bounded policy-graph processing with signature-first validation, hard depth, node, edge, output, and work ceilings, and no exponential policy-tree construction.

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
- `v0.55.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.56.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.57.0 - CRL Validation

Status: planned

Plan scope: Validate base, delta, and indirect CRLs with issuer authorization, freshness, distribution-point, reason, entry, and work ceilings; for every v3 CRL-issuer certificate require a present keyUsage extension with cRLSign asserted as clarified by RFC 10007.

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
- `v0.57.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.57.1 - No-Revocation-Available Certificate Policy

Status: planned

Plan scope: Implement RFC 9608 noRevAvail parsing and path semantics; reject the extension on CA certificates and every contradictory CRL, Freshest CRL, OCSP AIA, or basicConstraints combination, and skip revocation only for a valid end-entity assertion under explicit caller policy.

Goal: complete the **No-Revocation-Available Certificate Policy** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the noRevAvail extension, certificate-profile validation, path
  result, and explicit relying-party policy without inferring availability;
- preserve the distinction between valid noRevAvail, absent revocation data,
  unavailable status, stale evidence, and ordinary soft-fail policy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- test end-entity and CA placement, criticality, basicConstraints, CRL and
  Freshest CRL extensions, OCSP AIA, mixed paths, unknown extensions, and
  caller policies at every certificate position;
- prove contradictory or malformed assertions fail validation and that only a
  valid explicitly admitted assertion can suppress revocation processing;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- revocation is skipped only under the exact RFC 9608 certificate profile and
  an explicit relying-party decision;
- `v0.57.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.58.0 - OCSP Validation

Status: planned

Plan scope: Validate stapled and offline OCSP responses, responder authorization, freshness, issuer and serial matching, and RFC 9654 nonce generation, encoding, bounds, echo, mismatch, omission, and malformed-request behavior under explicit hard and soft-fail policy.

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
- `v0.58.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.58.1 - TLS Feature Must-Staple Enforcement

Status: planned

Plan scope: Implement RFC 7633 TLS Feature extension parsing and policy, require a valid applicable stapled OCSP response when status_request is asserted, reject unknown required feature values or unsatisfied declarations, and keep connection validity authoritative and independent of audit-event delivery.

Goal: complete the **TLS Feature Must-Staple Enforcement** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- parse and validate bounded TLS Feature values and bind status_request
  requirements to the exact end-entity certificate and handshake;
- expose an authoritative mandatory validation result for satisfied, absent,
  unknown, malformed, and unsatisfied declarations;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- test critical and non-critical encodings, empty, duplicate, unknown, and
  malformed values, missing and stale staples, wrong issuer or serial, revoked
  status, responder failure, resumption, and certificate rotation;
- drop all observational events and prove an unsatisfied declaration still
  rejects the connection with no identity or application-data release;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every admitted TLS Feature declaration is either satisfied by applicable
  validated evidence or terminates authentication unambiguously;
- `v0.58.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.58.2 - Lightweight OCSP Message Profile

Status: planned

Plan scope: Implement the RFC 9919 message profile with one SHA-256 CertID request, request extension and signature policy, BasicOCSPResponse and responder-ID handling, mandatory nextUpdate freshness, nonce-to-time fallback, and signed-data-before-request ordering.

Goal: complete the **Lightweight OCSP Message Profile** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the bounded one-certificate request and response profile, current
  SHA-256 identifiers, responder authorization, byKey and byName handling,
  exact time and freshness rules, and nonce policy;
- order certificate-signature validation before request release and keep
  ordinary RFC 6960 validation distinct from the explicitly selected profile;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exercise every request field, CertID hash, responder ID, status, extension,
  signature, producedAt, thisUpdate, nextUpdate, nonce, clock, DER encoding,
  and response-count boundary;
- prove certificate signatures are validated before any request action and
  stale, unsigned, mismatched, or unauthorized responses cannot become good
  status;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the optional high-volume message profile cannot emit SHA-1 requests, process
  stale status, or bypass ordinary OCSP authentication;
- `v0.58.2 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.58.3 - Lightweight OCSP Sans-I/O Transport And Cache Profile

Status: planned

Plan scope: Implement RFC 9919 AIA discovery, exact GET-at-or-below-255 and POST-above-255 selection, Base64 and URI construction, response media and length checks, cache metadata, freshness, retry, and invalidation as typed effects while keeping network and cache implementation caller-owned and signed OCSP data authoritative.

Goal: complete the **Lightweight OCSP Sans-I/O Transport And Cache Profile** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- expose typed AIA, GET, POST, URI, request-body, response-metadata, time, retry,
  cache-read, cache-write, and invalidation effects with exact size limits;
- validate Base64 and percent encoding, media type, content length, cache
  controls, and freshness hints without performing I/O or treating unsigned
  transport data as certificate status;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- test the 255-byte boundary, URI joins, every Base64 and percent character,
  malformed AIA, GET and POST bodies, content metadata, retries, clock skew,
  cache hit, expiry, replacement, rollback, and hostile caller results;
- forge or omit every HTTP field and prove only the signed OCSP thisUpdate,
  nextUpdate, producedAt, status, and signature can authorize acceptance;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the caller can implement RFC 9919 transport and caching through deterministic
  typed effects, while Brynja performs no network access and unsigned metadata
  never overrides signed revocation evidence;
- `v0.58.3 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.59.0 - Versioned Certificate Transparency Contract

Status: planned

Plan scope: Implement strictly version-separated RFC 6962 CT v1 and RFC 9162 CT v2 SCT, log, signed-entry, timestamp, extension, and proof formats; define verifier ownership, log-list and operator updates, disqualification and duplicate handling, and fail closed without a verifier for every required version while never interpreting one version as the other.

Goal: complete the **Versioned Certificate Transparency Contract** implementation stop without admitting or
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
- `v0.59.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.60.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

## Phase 2: Shared Handshake, Internal Sans-I/O, And Modern TLS

Shared handshake, separate policy, audited engines, and final routing remain ordered.

### v0.61.0 - Shared Recordless TLS 1.3 Handshake Boundary

Status: planned

Plan scope: Implement and freeze the upstream no_std brynja-tls13-handshake crate containing the single record-independent TLS 1.3 handshake state machine consumed by brynja-tls13 and brynja-quic-tls; brynja-tls13 owns stream records, QUIC owns transport, brynja-tls reaches it only through the version-specific engine, and DTLS may reuse codecs, transcript, certificate and key-schedule components but retains its own state machine, epochs, fragmentation, and retransmission.

Goal: complete the **Shared Recordless TLS 1.3 Handshake Boundary** implementation stop without admitting or
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
- `v0.61.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.62.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.63.0 - TLS 1.3 Record Protection

Status: planned

Plan scope: Implement TLS 1.3 record protection in brynja-tls13, including checked sequence exhaustion, inner content-type and padding validation, transactional state changes, and fragmentation boundaries, without performing protocol selection or exposing the evergreen router.

Goal: complete the **TLS 1.3 Record Protection** implementation stop without admitting or
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
- `v0.63.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.64.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.65.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.66.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.67.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.68.0 - TLS Version Negotiation Codec And Policy

Status: planned

Plan scope: Implement shared offer and selection parsing and policy without routing into an engine: servers evaluate one ClientHello, clients evaluate one ServerHello, unknown future offered versions are skipped safely, recognized legacy versions are rejected by policy, highest-version and downgrade-sentinel rules are typed, exact transcript bytes are preserved, and application profiles can require TLS 1.3 so new protocols satisfy RFC 9852 without silently enabling TLS 1.2.

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
- `v0.68.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.69.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.70.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.71.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.72.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.73.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.74.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.75.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.76.0 - TLS 1.3-Profile External PSK Policy

Status: planned

Plan scope: Separate external from resumption PSKs; admit external PSKs only for TLS 1.3, DTLS 1.3, and QUIC, never for hardened TLS 1.2 or DTLS 1.2; require psk_dhe_ke, constant-work identity and binder handling, single-use pending lookups, unique per-profile and deployment provisioning for any raw PSK, and no silent psk_ke, cross-domain, binder-failure, or certificate-authentication fallback.

Goal: complete the **TLS 1.3-Profile External PSK Policy** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise external-versus-resumption separation, raw-key uniqueness
  attestation, constant-work selection and binder handling, and negative TLS
  1.2 and DTLS 1.2 PSK-suite construction and negotiation tests;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- external PSKs are confined to TLS 1.3-derived profiles, require DHE, and
  cannot silently fall back or enter hardened TLS 1.2 or DTLS 1.2;
- `v0.76.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.76.1 - External PSK Importer And Domain Separation

Status: planned

Plan scope: Implement RFC 9258 imported identities and derived imported PSKs with protocol, KDF, context, application, ALPN, and deployment-domain separation; require the importer whenever provisioned key material could cross an admitted protocol or deployment domain, bind importer metadata into tickets and pending operations, and reject missing, ambiguous, mismatched, or reused import contexts.

Goal: complete the **External PSK Importer And Domain Separation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement imported identities and derived PSKs with exact RFC 9258 labels,
  contexts, KDF binding, input validation, and secret destruction;
- type importer provenance and bind it to profile, application, ALPN,
  deployment, tickets, storage, and single-use pending operations;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run official and generated importer vectors, context-boundary, collision,
  malformed identity, wrong-KDF, cross-protocol, and cross-deployment tests;
- prove missing, ambiguous, mismatched, replayed, or reused contexts fail
  without raw-PSK, certificate-authentication, or other-profile fallback;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- provisioned PSK material cannot cross an admitted domain without explicit,
  importer-enforced separation;
- `v0.76.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.76.2 - External PSK Provisioning And Role Security

Status: planned

Plan scope: Apply RFC 9257 with a mandatory 128-bit minimum key length, typed entropy provenance, client/server role and logical-node binding, pairwise-or-imported group policy, opaque identity comparison and collision domains, peer-identifier confirmation, privacy warnings, rotation and main-key destruction; reject low-entropy PSKs and RFC 9973 certificate-with-external-PSK mode for v1.

Goal: complete the **External PSK Provisioning And Role Security** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- define typed provisioning for key length, claimed entropy provenance, client
  and server roles, logical nodes, intended peer identifiers, identity domains,
  reuse, rotation, and deletion obligations;
- enforce pairwise PSKs or RFC 9258 imported contexts that bind both endpoint
  identities, separate external and resumption identities, and make linkability
  and group-membership limitations explicit;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- test short, low-entropy, reused, shared, same-role, reflected, misbound,
  colliding, cross-profile, stale, undeleted, and privacy-bearing PSK cases;
- prove psk_dhe_ke remains mandatory, raw or imported keys cannot switch roles
  or peers, parent material is destroyed when promised, and RFC 9973 cannot be
  negotiated or smuggled through unknown-extension handling;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every admitted external PSK has reviewable strength, provenance, role, peer,
  domain, lifetime, and destruction policy with no silent group or combined-
  certificate mode;
- `v0.76.2 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.77.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.78.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.79.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.80.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.81.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.82.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.83.0 - TLS 1.2 Engine And Policy Boundary

Status: planned

Plan scope: Freeze brynja-tls12 as an engine independent from TLS 1.3 and define its explicit ECDHE-plus-AEAD policy with Extended Main Secret required and static RSA, finite-field DH, static ECDH, CBC, MD5 and SHA-1 signing, compression, renegotiation, and automatic fallback excluded.

Goal: complete the **TLS 1.2 Engine And Policy Boundary** implementation stop without admitting or
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
- `v0.83.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.83.1 - Current TLS And DTLS 1.2 Deprecation Closure

Status: planned

Plan scope: Apply RFC 9155 and RFC 10015 to TLS 1.2 and the later DTLS 1.2 profile: never offer or select MD5/SHA-1 signatures, static RSA, finite-field DH, or static DH/ECDH certificate types; generate exact alerts for forbidden peer selections and prove IANA discouraged entries cannot enter configuration, negotiation, resumption, or imported state.

Goal: complete the **Current TLS And DTLS 1.2 Deprecation Closure** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- generate deny sets from the current signature, cipher-suite, certificate-type,
  and named-group registry decisions and bind them to both 1.2 profiles;
- reject forbidden values at configuration, offer construction, peer
  selection, certificate selection, state import, and resumption boundaries;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exercise every RFC 9155 and RFC 10015 affected signature, key exchange,
  certificate type, cipher suite, alias, malformed value, and registry status;
- prove TLS 1.2 and DTLS 1.2 allow only ECDHE with admitted AEAD suites and
  current signatures, emit exact alerts, and cannot revive rejected state via
  tickets, caches, providers, or serialized configuration;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- obsolete 1.2 key exchange and signature mechanisms are unreachable across
  configuration, negotiation, authentication, resumption, and import;
- `v0.83.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.83.2 - TLS 1.2 Feature-Freeze Enforcement

Status: planned

Plan scope: Apply RFC 9851 to TLS 1.2 only: reject post-freeze protocol, cipher, group, signature, extension, alert, and other registry additions unless they are an authenticated urgent-security correction or the RFC-permitted ALPN and exporter-label exceptions; keep DTLS decisions separate and prohibit PQC backports to TLS 1.2.

Goal: complete the **TLS 1.2 Feature-Freeze Enforcement** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- bind the RFC 9851 publication cutoff and current IANA registration metadata to
  the TLS 1.2 surface register and typed configuration;
- implement separate authenticated decisions for urgent security corrections,
  ALPN identifiers, exporter labels, DTLS entries, and TLS 1.3-or-later entries
  without broadening the frozen TLS 1.2 profile;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- inject post-freeze cipher, group, signature, extension, alert, certificate,
  compression, PSK, and content entries plus valid and invalid exceptions;
- prove no PQC or other new TLS 1.2 mechanism is constructible, ALPN and exporter
  label additions do not expand cryptography, and DTLS registry decisions remain
  independently classified;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.2 remains a closed hardened compatibility profile whose only post-freeze
  changes are authenticated RFC 9851 exceptions;
- `v0.83.2 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.84.0 - TLS 1.2 PRF And Key Block

Status: planned

Plan scope: Implement the TLS 1.2 PRF, main secret, Extended Main Secret input, key-block expansion, label compatibility, separation, and length limits.

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
- `v0.84.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.85.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.86.0 - TLS 1.2 Extended Main Secret Transcript Binding

Status: planned

Plan scope: Implement the RFC 9846-renamed Extended Main Secret transcript selection, wire-compatible label, session-hash rules, resumption consistency, API indication for TLS 1.3, and mandatory failure behavior.

Goal: complete the **TLS 1.2 Extended Main Secret Transcript Binding** implementation stop without admitting or
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
- `v0.86.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.87.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.88.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.89.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.90.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.91.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.92.0 - Integrated Evergreen One-Pass TLS Router

Status: planned

Plan scope: In brynja-tls, after brynja-tls13 and brynja-tls12 exist and pass independent audits, integrate symmetric one-pass routing: one server ClientHello or one client ServerHello selects exactly one highest acceptable offered engine, validates downgrade sentinels, transfers original transcript bytes and version-domain state once, and never retries another engine or crosses credentials, tickets, PSKs, caches, or secrets after failure; preserve an engine-registration boundary for a separately versioned future TLS generation.

Goal: complete the **Integrated Evergreen One-Pass TLS Router** implementation stop without admitting or
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
- `v0.92.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.93.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.94.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.95.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.96.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.97.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.98.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.99.0 - QUIC Resumption Lifecycle

Status: planned

Plan scope: Distinguish TLS handshake completion from QUIC handshake confirmation; emit typed completion, confirmation and key-discard outcomes; deliver NewSessionTicket only after handshake completion; bind negotiated QUIC version, remembered transport parameters, ALPN, application state, and deployment domain to tickets; and enforce ticket confidentiality, lifetime, privacy, rotation, and non-reuse policy.

Goal: complete the **QUIC Resumption Lifecycle** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- enforce recordless QUIC TLS resumption while separating TLS completion,
  confirmation, ticket, traffic-secret, and key-discard ownership;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC 9001 completion, confirmation, key-discard, NewSessionTicket,
  transport-parameter, version, ALPN, application, deployment, and peer matrices;
- test premature ticket delivery, version and parameter mismatch, ticket reuse,
  missing ALPN, late data, rotation, derivation confusion, and exhaustion;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- QUIC resumption preserves explicit completion and confirmation, exact ticket
  binding, non-reuse, and transport-owned packet state;
- `v0.99.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.99.1 - QUIC Zero-RTT Profile

Status: planned

Plan scope: Require max_early_data_size 0xffffffff for QUIC, validate remembered transport parameters and application policy before offering or accepting early data, map invalid values to the correct QUIC error, expose deterministic authoritative acceptance and rejection, preserve anti-replay and ticket single-use rules, and leave the QUIC transport in control of zero-RTT byte quantity and packet processing.

Goal: complete the **QUIC Zero-RTT Profile** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement QUIC-specific early-data offer, acceptance, rejection, and error
  mapping over the shared TLS 1.3 zero-RTT policy;
- bind remembered transport parameters, version, ALPN, application state,
  deployment domain, anti-replay, and single-use ticket state;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- test exact max_early_data_size handling, changed transport parameters,
  cross-version tickets, replay, reordered levels, rejection, and confirmation;
- prove TLS never meters QUIC early-data bytes or processes packets and that
  ignored audit events cannot obscure authoritative acceptance or rejection;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- QUIC zero-RTT is explicitly accepted or rejected with anti-replay and
  transport ownership preserved;
- `v0.99.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.100.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.101.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.102.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.103.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.104.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.105.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.106.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.107.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.108.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.109.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.110.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.111.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.111.1 - DTLS Return Routability Check

Status: planned

Plan scope: Implement RFC 9853 negotiation and authenticated basic and enhanced return-routability checks for CID-enabled DTLS 1.2 and DTLS 1.3, including path challenge, response and drop messages, unpredictable cookies, timers, pacing, anti-amplification, PMTU probes, rebinding and voluntary migration, buffered-data suspension, nested-rebinding behavior, unknown-message handling, and exact old/new path binding.

Goal: complete the **DTLS Return Routability Check** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement rrc negotiation, all three message types, basic and enhanced state
  machines, opaque path-token binding, caller timer and pacing actions, and
  explicit application-data suspension or anti-amplification results;
- keep DTLS 1.2 and 1.3 authentication, padding, CID, record, epoch, replay,
  PMTU, rebinding, migration, and failure behavior version-specific;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- test negotiation dependencies, unknown message types, challenge randomness,
  response and drop routing, timeout, loss, duplication, reordering, nested
  rebinding, voluntary migration, old-path failure, spoofing, and PMTU probes;
- prove buffered data cannot escape to an unvalidated path, every response is
  sent to the challenge source, invalid responses are silent, and
  anti-amplification limits hold across both protocol versions;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every CID path change is either validated by the selected RFC 9853 procedure
  or remains bound to the prior path without application-data leakage;
- `v0.111.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.112.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.113.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.114.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.115.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.116.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.117.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.118.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.119.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.120.0 - Standard Hybrid Groups

Status: planned

Plan scope: Implement only final standardized X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024 encodings, component order, lengths, identifiers, and concatenated shared-secret construction under RFC 9954 plus the final Standards Track ECDHE-ML-KEM group RFC; provisional drafts and private code points never enter release artifacts.

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
- `v0.120.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.121.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.122.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

## Phase 4: FIPS Module Instantiation, Validation, And TLS Profile

Architecture is frozen before implementation; exact artifact identity is frozen only after all module components and self-tests exist. Correct module-versus-connection failure semantics are enforced throughout.

### v0.123.0 - FIPS 140-3 Level-One Requirements Baseline

Status: planned

Plan scope: Target an overall Security Level 1 software cryptographic module and map every applicable FIPS 140-3 and ISO/IEC 19790 security area and ISO/IEC 24759 test assertion to FIPS 140-3, SP 800-140 and 140A through 140F, the current CMVP Management Manual, current Implementation Guidance, RFG and CMVP resolutions, algorithm transitions, caveats, and lab evidence; record justified non-applicability, pin dated submission baselines, and require review of later guidance without claiming validation.

Goal: complete the **FIPS 140-3 Level-One Requirements Baseline** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- produce a dated requirement and test-assertion matrix for all eleven FIPS
  security areas, applicable supplemental publications, guidance, transitions,
  caveats, evidence owners, and justified non-applicability;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- compare the matrix with current CMVP publications, Management Manual,
  Implementation Guidance, RFG resolutions, transition tables, and lab input;
- inject stale guidance, missing assertions, unowned evidence, unsupported
  levels, and unjustified non-applicability and require repository failure;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the Level 1 target and every applicable requirement have dated, owned,
  testable evidence obligations without a validation claim;
- `v0.123.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.123.1 - FIPS Module Architecture Freeze

Status: planned

Plan scope: Freeze the separately publishable brynja-fips-module boundary, dependency allowlist, approved and non-approved services, ports, roles, authentication applicability, SSP inventory, operational environments, build-reproducibility contract, and downstream brynja-fips facade and optional-module constraints without claiming or freezing an exact binary, certificate, source identity, dispatch table, dependency closure, or validation artifact.

Goal: complete the **FIPS Module Architecture Freeze** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- freeze the module diagram, logical interfaces, roles, services, SSP flows,
  operational environments, dependency allowlist, and downstream ports;
- keep exact source, binary, dispatch, dependency closure, certificate, and
  validation identity unfrozen until every component and self-test is final;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- prove ordinary brynja, brynja-fips, optional modules, platform adapters, and
  legacy packages cannot enter or mutate the module boundary;
- test approved/non-approved service separation, port direction, role and
  authentication applicability, SSP flows, environment mapping, and build inputs;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- a separately publishable Level 1 module architecture is frozen without a
  premature artifact or validation claim;
- `v0.123.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.124.0 - SP 800-90B Entropy Source And Health Tests

Status: planned

Plan scope: Select each in-boundary, bound-module, or caller-supplied validated entropy-source construction and operational environment; define noise source, conditioning, IID or non-IID assessment, minimum entropy, startup and continuous health tests, failure handling, restart and virtualization assumptions, and complete SP 800-90B and ESV documentation without treating an arbitrary caller RNG as validated entropy.

Goal: complete the **SP 800-90B Entropy Source And Health Tests** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- define each entropy source, conditioning chain, assessed entropy rate,
  operational environment, restart model, and health-test state machine;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run IID or non-IID assessment, startup, repetition-count, adaptive-proportion,
  restart, failure-injection, conditioning, virtualization, and environment tests;
- prove arbitrary caller randomness cannot satisfy a validated entropy-source
  contract and every health failure is authoritative and fail closed;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every admitted entropy source has bounded behavior and complete SP 800-90B
  evidence tied to its operational environment;
- `v0.124.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.124.1 - SP 800-90A DRBG Implementation

Status: planned

Plan scope: Select and implement the final approved DRBG mechanisms with exact instantiate, generate, reseed, uninstantiate, security-strength, personalization, additional-input, prediction-resistance, request, fork, rollback, concurrency, state-protection, zeroization, and catastrophic-error behavior plus algorithm and state-machine test harnesses.

Goal: complete the **SP 800-90A DRBG Implementation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement only the selected SP 800-90A mechanisms and complete request,
  reseed, state, concurrency, fork, rollback, and zeroization contracts;
- add official algorithm vectors, deterministic providers, fault hooks, and
  state-machine and proof harnesses beside the implementation;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run instantiate, generate, reseed, prediction-resistance, personalization,
  additional-input, limit, exhaustion, rollback, fork, and concurrency matrices;
- fault-inject entropy, state, request, reseed, and zeroization paths and prove
  no output or reusable state escapes a catastrophic error;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the final DRBG implementation is bounded, testable, zeroizing, and ready for
  an exact SP 800-90C construction;
- `v0.124.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.124.2 - SP 800-90C RBG Construction

Status: planned

Plan scope: Bind only admitted SP 800-90B entropy sources to the final SP 800-90A DRBGs through selected SP 800-90C RBG constructions; define primary and subordinate DRBG topology, entropy and nonce inputs, reseed chains, health and catastrophic propagation, operational-environment identity, and the exact RBG service boundary for later ESV testing.

Goal: complete the **SP 800-90C RBG Construction** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the selected RBG construction and explicit primary, subordinate,
  entropy, nonce, reseed, and security-strength topology;
- bind every source, DRBG, service, state, and failure to the exact module and
  operational-environment identity required by later ESV evidence;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run SP 800-90C construction, source substitution, reseed chain, subordinate
  state, strength, prediction-resistance, fork, health, and catastrophic tests;
- prove unvalidated source, DRBG, topology, environment, and state substitutions
  fail closed and cannot inherit an approved indicator;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- one exact RBG construction connects validated entropy assumptions to the
  module random service without ambiguous substitutions;
- `v0.124.2 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.125.0 - Approved Provider And Mandatory Service Indicator

Status: planned

Plan scope: Implement the sealed approved-only provider and return an unambiguous per-service approval indicator through each mandatory typed service result or ActionV1, with SecurityEvent only duplicating that status for audit; permit no additive fips feature or construction before self-test success.

Goal: complete the **Approved Provider And Mandatory Service Indicator** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- generate an approved-only policy from the exact validated service and
  parameter manifest while keeping connection failure distinct from module error;
- return the approval or non-approval status from every service invocation in a
  mandatory typed result or ActionV1 and emit only a redundant, non-authoritative
  SecurityEvent audit copy;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- test every admitted and excluded suite, group, signature, certificate,
  entropy, key provenance, resumption, PSK, and early-data combination;
- inject non-approved services and prove immediate connection termination,
  mandatory non-approval results, no application data, and no module latch;
- drop every audit event and prove callers must still consume an unambiguous
  mandatory approval indicator before treating service output as approved;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every service result carries mandatory approval status independently of audit
  delivery, while architectural boundaries and catastrophic-latch semantics are preserved;
- `v0.125.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.126.0 - SSP Lifecycle And Zeroization Services

Status: planned

Plan scope: Define SSP entry, output, storage, high-water lifetime, external storage, accelerator handle, cache and DMA completion, and zeroization services with mandatory single-consumption completion indications; SecurityEvent may only duplicate secret-free status for audit.

Goal: complete the **SSP Lifecycle And Zeroization Services** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- define the complete service table for SSP generation, establishment, entry,
  output, use, storage, replacement, and destruction, including roles,
  inputs, outputs, state transitions, and mandatory completion indications;
- implement bounded lifetimes and zeroization for stack, heap, static,
  external-storage, accelerator-handle, cache, high-water, and DMA-backed SSPs,
  with single-consumption completion tokens and no secret-bearing audit data;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exercise every SSP transition, abnormal return, cancellation, reset, panic,
  retry, ownership transfer, external-storage failure, accelerator timeout,
  cache path, and DMA completion ordering;
- prove zeroization before reuse or release, prove completion indications cannot
  be forged, replayed, dropped, or consumed twice, and scan all errors, traces,
  events, dumps, and test artifacts for SSP material;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every SSP has a reviewed, testable lifetime and destruction path, and callers
  receive a mandatory secret-free completion result independently of auditing;
- `v0.126.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.127.0 - Module Integrity And Pre-Operational Self-Tests

Status: planned

Plan scope: After the final DRBG, provider, SSP, and algorithm implementations are linked, implement module-integrity verification and every required algorithm, DRBG, and component pre-operational self-test over the complete final image; no cryptographic service or output is available before success, and deterministic fault injection covers every test and integrity path.

Goal: complete the **Module Integrity And Pre-Operational Self-Tests** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- implement final-image integrity and required algorithm, DRBG, component, and
  dependency pre-operational tests with deterministic fault hooks;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- corrupt every covered image region and every self-test expected result and
  require failure before any cryptographic service or output;
- test concurrent first use, repeated status queries, interrupted startup,
  unavailable dependencies, exact test coverage, and secret-free errors;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- complete-image integrity and pre-operational tests block every service until
  success and fail deterministically under every injected fault;
- `v0.127.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.127.1 - Conditional Self-Tests And Permanent Failure State

Status: planned

Plan scope: Implement required pairwise-consistency, conditional, on-demand, firmware or software load, and continuous health-test coordination; serialize concurrent test requests, destroy affected SSPs, block prohibited services, and enter an irreversible module error state exactly for FIPS-defined integrity, self-test, and catastrophic failures.

Goal: complete the **Conditional Self-Tests And Permanent Failure State** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement every applicable conditional, pairwise-consistency, on-demand,
  load, and health-test transition with explicit concurrency semantics;
- freeze irreversible error-state entry, SSP destruction, allowed status and
  zeroization services, recovery requirements, and connection/module separation;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- fault-inject each test before, during, and after concurrent services and prove
  affected outputs and SSPs never escape and prohibited services stay blocked;
- distinguish ordinary invalid inputs and approved-profile connection failures
  from integrity, self-test, entropy, and catastrophic module failures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- conditional testing and the permanent module error state are complete,
  irreversible where required, and never misused for connection policy;
- `v0.127.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.128.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.129.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.130.0 - ACVTS And CAVP Evidence

Status: planned

Plan scope: Complete ACVTS and CAVP campaigns for every approved implementation, dispatch path, parameter set, and operational environment.

Goal: complete the **ACVTS And CAVP Evidence** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- enumerate every claimed algorithm, parameter set, implementation symbol, CPU
  dispatch path, dependency, and operational environment in an evidence matrix
  bound to the exact v0.129.0 artifact;
- complete production ACVTS/CAVP vector campaigns, retain request and response
  identifiers plus lab-consumable results, and clearly label development or
  demonstration vectors as non-validation evidence;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- reconcile every vector result with the implementation symbol, dispatch path,
  parameters, operational environment, source identity, and frozen artifact
  hash, rejecting omissions, substitutions, and post-freeze changes;
- replay locally reproducible portions, test malformed and rejected vectors,
  compare production evidence with independent known-answer tests, and require
  every claimed approved service to have applicable evidence;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every claimed approved implementation and dispatch path has traceable
  production validation evidence bound to the exact frozen module artifact;
- `v0.130.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.130.1 - ESV Entropy And RBG Validation Evidence

Status: planned

Plan scope: Complete production ESVTS evidence for every claimed SP 800-90B entropy source and SP 800-90C RBG construction in each operational environment, bind validation identifiers and caveats to the exact module artifact, and reject unvalidated entropy substitutions or environment drift.

Goal: complete the **ESV Entropy And RBG Validation Evidence** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- complete production ESVTS submissions and documentation for each entropy
  source, RBG construction, conditioning chain, and operational environment;
- bind returned identifiers, assessed entropy, evidence, environment,
  construction, dependencies, and caveats to the exact frozen artifact;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- replay ESV evidence generation and compare source, sample, assessment,
  documentation, environment, RBG topology, and returned identifiers;
- reject demo-only results, stale evidence, source substitution, environment
  drift, changed conditioning, caveat omission, and mismatched artifacts;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every entropy and RBG claim has production validation evidence tied to the
  exact module and operational environment;
- `v0.130.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.131.0 - CMVP Security Policy And Public Documentation

Status: planned

Plan scope: Produce the SP 800-140B Rev. 1 security policy, module specification, ports and interfaces, roles, services, approved-service indicators, SSP inventory and lifecycle, finite-state model, self-tests, installation, initialization, secure-operation, zeroization, operational-environment, mitigation, and guidance documents with exact certificate-ready tables and no unsupported claim.

Goal: complete the **CMVP Security Policy And Public Documentation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- generate the security policy and public guidance tables from the frozen
  service, SSP, state, self-test, environment, and evidence inventories;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- schema-check every required SP 800-140B Rev. 1 section and cross-reference
  every service, indicator, SSP, state, algorithm, certificate, and caveat;
- compare generated documentation with public APIs, module identity, exact
  artifact, operational environments, tests, and secure-operation procedures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the complete public security policy is certificate-ready, exact-artifact
  bound, internally consistent, and free of unsupported claims;
- `v0.131.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.131.1 - CMVP Test Evidence And Lab Submission Package

Status: planned

Plan scope: Produce the SP 800-140A and Derived Test Requirements evidence package, source-to-object and requirements trace, algorithm and entropy certificates, test environment, reproducible artifacts, vendor evidence, responses, and lab handoff package, with every datum mechanically bound to the exact frozen artifact.

Goal: complete the **CMVP Test Evidence And Lab Submission Package** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- assemble the derived-test, vendor, algorithm, entropy, source-to-object,
  environment, reproducibility, and artifact evidence required by the lab;
- generate traceability from each applicable assertion and security-policy
  statement to exact source, symbol, binary, test, result, owner, and response;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- schema and cross-reference the complete handoff package against the current
  baseline, exact artifact, security policy, certificates, and lab checklist;
- inject missing assertions, mismatched hashes, stale results, changed tools,
  incomplete responses, and unowned evidence and require rejection;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the accredited lab receives one complete, reproducible, internally consistent
  evidence package for the exact module artifact;
- `v0.131.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.132.0 - Accredited FIPS Lab Evaluation And Findings

Status: planned

Plan scope: Submit the exact artifact and evidence to an NVLAP-accredited CST laboratory, complete applicable FIPS 140-3 and ISO/IEC 24759 testing, preserve question and evidence provenance, and record every finding without changing or claiming validation for the submitted artifact.

Goal: complete the **Accredited FIPS Lab Evaluation And Findings** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- preserve a tamper-evident lab exchange and finding ledger naming exact
  artifacts, questions, evidence, responses, decisions, owners, and deadlines;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- reproduce every lab test and response locally where possible and compare the
  exact artifact, environment, input, output, and interpretation;
- prove no lab exchange silently changes source, binaries, evidence, scope,
  security policy, or validation claim and every finding remains visible;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- evaluation is complete for the submitted identity, every finding is recorded,
  and no validation claim has been made;
- `v0.132.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.132.1 - FIPS Evaluation Remediation And Clean Retest

Status: planned

Plan scope: Classify every lab or CMVP finding, remediate through a new exact artifact identity when code or build inputs change, repeat affected algorithm, entropy, regression, and module tests, update all evidence, and obtain a clean accredited-lab retest with no unresolved finding.

Goal: complete the **FIPS Evaluation Remediation And Clean Retest** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- trace each finding to root cause, affected requirements, artifacts, evidence,
  remediation, regressions, revalidation impact, and independent retest;
- create a new artifact identity for every source, build, dependency, dispatch,
  self-test, or other identity-changing correction and regenerate all evidence;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- replay every finding against old and remediated artifacts and retain a
  permanent failing regression plus affected algorithm and module retests;
- compare lab retest scope with the change-impact analysis and require no
  unresolved, waived-without-authority, stale, or identity-mismatched finding;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the final submitted identity has a clean accredited-lab retest and complete
  remediation evidence with no unresolved finding;
- `v0.132.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.132.2 - FIPS Certificate Issuance Caveat And Claim Gate

Status: planned

Plan scope: Make no FIPS 140-3 validated or Inside claim until CMVP issuance; then record the exact certificate number, module version, overall and per-area levels, tested operational environments, approved services, dependencies, caveats, status, sunset, security-policy hash, and permitted wording, and mechanically prevent claims from mismatched, unissued, revoked, or unsupported artifacts.

Goal: complete the **FIPS Certificate Issuance Caveat And Claim Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- capture the issued certificate, security policy, caveats, levels, services,
  dependencies, environments, dates, status, hashes, and permitted claim text;
- generate package and documentation claims only from exact certificate and
  artifact identity, with ordinary brynja remaining explicitly non-validated;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- test pre-issuance, pending, active, interim, legacy, revoked, sunset,
  wrong-environment, wrong-artifact, wrong-version, and changed-policy states;
- scan packages, metadata, docs, examples, banners, and release notes for
  unsupported FIPS wording, logo use, missing certificate number, or caveat loss;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- only the exact issued module can carry the exact permitted certificate-bound
  claim, and all other builds fail closed to a non-validated status;
- `v0.132.2 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.133.0 - Boundary And Package Audit

Status: planned

Plan scope: Complete the final modern, legacy, experimental, and FIPS dependency-boundary, symbol, dispatch, feature, and package-content audit.

Goal: complete the **Boundary And Package Audit** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- audit ordinary `brynja`, `brynja-fips`, `brynja-fips-module`, legacy, and
  experimental packages independently, recording source, dependency, feature,
  symbol, dispatch, build-script, generated-file, and archive membership;
- add automated allowlists and negative scans proving ordinary and optional
  packages cannot import, re-export, select, mutate, or claim the validated
  module except through the certificate-bound FIPS facade;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- compare package archives, dependency graphs, features, public APIs, symbols,
  dispatch tables, build outputs, SBOMs, and reproducible hashes with their
  allowlists on every supported configuration;
- inject forbidden cross-boundary imports, re-exports, feature activation,
  provider substitution, optional dispatch, and FIPS wording and require the
  corresponding build, package, or claim gate to fail;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every shipped package has an exact reviewed closure, and no optional,
  legacy, experimental, or ordinary path can contaminate or impersonate
  the validated module;
- `v0.133.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.134.0 - Approved-Only TLS Operating Profile

Status: planned

Plan scope: Implement an internal approved-only connection profile derived from the exact validated-module service manifest and current final NIST TLS, key-strength, algorithm-transition, key-generation, and key-establishment guidance; enforce admitted version, suite, group, signature, certificate, entropy, key provenance, resumption, external PSK, and zero-RTT combinations plus aggregated mandatory per-service indicators; invoking a non-approved service terminates the connection and invalidates its approved configuration claim, while the permanent module error state remains reserved for FIPS-defined integrity, self-test, and catastrophic failures.

Goal: complete the **Approved-Only TLS Operating Profile** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- generate the admitted TLS combination matrix from the exact validated-module
  service manifest and a dated snapshot of current final NIST TLS, strength,
  transition, key-generation, and key-establishment guidance;
- implement a typed approved-only connection builder and mandatory aggregate
  service result that rejects excluded entropy, keys, certificates, PSKs,
  resumption state, zero-RTT, algorithms, and parameter combinations before use;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exhaustively test admitted and pairwise/exhaustively relevant excluded
  combinations, guideline snapshot changes, service-indicator aggregation,
  resumed sessions, imported state, and downgrade or fallback attempts;
- prove excluded-service use terminates only the affected connection, while
  FIPS-defined integrity, self-test, or catastrophic failure alone enters the
  permanent module error state;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the TLS profile admits only certificate-bound approved services and reports
  every service outcome without confusing connection and module failure;
- `v0.134.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.134.1 - Validated Module Manifest And Operational-Environment Selection

Status: planned

Plan scope: Generate a machine-readable immutable manifest for each validated brynja-fips-module artifact containing hashes, certificate identity and status snapshot, caveats, sunset, security-policy hash, approved services and parameter sets, self-test identity, CPU dispatch, build inputs, and tested operational environments; require exact target and runtime module-identity matching and fail closed without an applicable validated artifact.

Goal: complete the **Validated Module Manifest And Operational-Environment Selection** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- define and generate the certificate-bound validated-module manifest and a
  typed module identity and readiness query;
- map compile target, runtime environment, CPU dispatch, module hashes,
  certificate caveats, services, parameters, and self-test identity exactly;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- deterministically regenerate and schema-check manifests against the issued
  certificate, security policy, artifact identity, and environment evidence;
- reject wrong targets, CPU paths, environments, hashes, versions, policies,
  certificates, caveats, status snapshots, services, and self-test identities;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- module selection succeeds only for one exact validated artifact in an
  explicitly listed operational environment;
- `v0.134.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.134.2 - Ergonomic Brynja FIPS Facade And Misconfiguration Gate

Status: planned

Plan scope: Publish a separate no_std brynja-fips facade with obvious client and server constructors that require a validated-module handle and select the approved-only TLS profile, exact provider, DRBG, algorithms, strengths, certificate policy, resumption, PSK, and early-data rules from the manifest; expose only permitted choices, provide authoritative readiness and per-service results, prohibit a boolean Cargo fips feature, generic-provider injection, silent fallback, and any FIPS claim from ordinary brynja configuration, and compile-fail every mixed or incomplete configuration.

Goal: complete the **Ergonomic Brynja FIPS Facade And Misconfiguration Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- publish the separate brynja-fips facade and minimal typed client and server
  builders that require a validated module and approved identity and trust inputs;
- derive closed algorithm and policy choices from the certificate-bound
  manifest while keeping ordinary brynja and optional modules outside the claim;
- update requirements, threat model, controls, status, limitations, release
  notes, examples, and permanent evidence index.

Verification:

- compile-pass documented minimal client and server configurations for every
  validated environment and compile-fail missing or mixed security inputs;
- test Cargo feature unification, generic provider injection, ordinary-facade
  construction, non-approved overrides, fallback, stale manifests, and ignored
  audit events while preserving mandatory readiness and service results;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- users select FIPS through one obvious separate facade that is easy to use
  correctly and impossible to use for an unsupported validation claim;
- `v0.134.2 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.134.3 - FIPS Deployment Claim Update And Revalidation Lifecycle

Status: planned

Plan scope: Publish install, initialize, self-test, secure-operation, zeroization, troubleshooting, certificate and caveat verification, approved-mode, indicator, and integration guidance; monitor current CMVP guidance, RFG resolutions, algorithm transitions, certificate status, sunset, CVEs, patches, and operational environments; separate immutable validated artifacts from patched unvalidated lines and require documented change impact, regression testing, revalidation scenario, incident response, rollback, and claim withdrawal.

Goal: complete the **FIPS Deployment Claim Update And Revalidation Lifecycle** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- publish operator and integrator procedures for exact installation,
  initialization, identity, self-tests, approved services, zeroization, and status;
- automate dated monitoring and triage for CMVP guidance, transitions,
  certificate status, CVEs, environments, sunsets, patches, and claim wording;
- define immutable validated and separate patched-unvalidated release lines,
  revalidation decisions, incident response, rollback, and claim withdrawal.

Verification:

- rehearse supported and unsupported installation, initialization, startup,
  service indicator, zeroization, update, rollback, compromise, and recovery;
- inject guidance, transition, certificate, CVE, patch, environment, sunset,
  and revocation changes and require correct hold, withdrawal, or revalidation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- operators can keep the exact validation claim true over deployment and
  lifecycle changes, or automatically lose the claim safely when it is not;
- `v0.134.3 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

## Phase 5: Optional Modules, Composition, Stable Integration, Assurance, And General Availability

Optional send/receive paths, FIPS closure, and composition precede public freeze.

### v0.135.0 - Resumption And Anti-Replay State Rotation

Status: planned

Plan scope: Complete stateful cache, stateless ticket-key, resumption-PSK, and anti-replay generation rotation with overlap windows, bounded retention, concurrency, crash consistency, rollback detection, compromise response, transactional failure recovery, and protocol, identity, ALPN, FIPS-profile, ECH, and deployment-domain separation.

Goal: complete the **Resumption And Anti-Replay State Rotation** implementation stop without admitting or
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
- `v0.135.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.135.1 - Identity Trust And Transparency Rotation

Status: planned

Plan scope: Complete certificate and private-key rotation, external signer and handle rollover, trust-anchor and distrust updates, noRevAvail, Must-Staple and revocation state, versioned CT log-list and operator-policy updates, ECH identity binding, atomic configuration generations, in-flight connection semantics, rollback and compromise response, and transactional failure recovery.

Goal: complete the **Identity Trust And Transparency Rotation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement atomic identity, signer, trust, distrust, revocation, CT, and ECH
  configuration generations with bounded overlap and in-flight semantics;
- bind external handles, caches, tickets, precompressed artifacts, delegated
  credentials, and ECH state to exact generations and compromise response;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- test concurrent handshakes across every rotation boundary, rollback,
  cancellation, partial storage failure, stale handles, and compromise;
- prove old trust, identity, CT, revocation, ECH, and artifact state cannot
  leak into a new generation or silently reappear after rollback;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- identity and trust state rotates atomically with explicit in-flight,
  rollback, and compromise behavior;
- `v0.135.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.136.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.137.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.138.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.139.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.139.1 - HPKE Secret Export And Context Lifecycle

Status: planned

Plan scope: Implement RFC 9180 Context.Export with exact exporter-context and 255*Nh output bounds, role separation, export-only AEAD policy, single-shot API decisions, ordered-open requirements, loss and cancellation invalidation, sequence-exhaustion closure, replay ownership, and immediate destruction of key, base nonce, exporter secret, and failed or discarded contexts; reject PSK, Auth, and AuthPSK modes unless separately admitted.

Goal: complete the **HPKE Secret Export And Context Lifecycle** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement typed sender, recipient, export, and optional single-shot
  operations with exact suite, role, context, length, and ownership binding;
- define mandatory context invalidation and destruction for loss, out-of-order
  input, authentication failure, cancellation, provider failure, exhaustion,
  and explicit discard, with unsupported modes unconstructible;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run every applicable RFC 9180 vector for Export, export-only, sender and
  recipient contexts, bounds, roles, ordering, single-shot decisions, and
  admitted suites;
- inject replay, loss, reordering, wrong role or suite, oversized output,
  sequence exhaustion, failed open, cancellation, and unsupported modes and
  prove failure atomicity plus complete secret destruction;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the complete admitted HPKE base-mode context interface includes bounded
  export and deterministic destruction, and no unsupported mode is reachable;
- `v0.139.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.140.0 - ECH Origin And Downgrade Policy

Status: planned

Plan scope: Keep DNS, SVCB, HTTPS resolution, network access, and cache ownership outside protocol crates; type the intended origin, caller-asserted source and trust status, EchRequired, EchPreferred, and GreaseOnly intent, public-name exposure, retry authority, and fallback result so missing, stripped, rejected, or unusable ECH can never silently violate caller policy or establish the wrong public-SNI identity.

Goal: complete the **ECH Origin And Downgrade Policy** implementation stop without admitting or
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
- `v0.140.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.140.1 - ECH Configuration Bootstrap And Cache Lifecycle

Status: planned

Plan scope: Accept bounded hostile ECHConfigList bytes from RFC 9848 bootstrap with typed provenance, origin, generation, receipt and expiry; implement RFC 9849 bounded parsing, mandatory-extension handling, version and HPKE-suite selection, public-name and key validation, GREASE inputs, stale replacement, retry-configuration precedence, cache partitioning and invalidation, and deterministic behavior for malformed, unknown, expired, or rotated configurations.

Goal: complete the **ECH Configuration Bootstrap And Cache Lifecycle** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement bounded ECHConfigList parsing, mandatory-extension behavior,
  version, suite, public-name, key, length, and duplicate validation;
- bind provenance, origin, receipt, lifetime, generation, retry authority,
  cache partition, replacement, invalidation, and GREASE state;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC 9848 and RFC 9849 vectors plus truncation, duplicate, mandatory
  extension, unknown version, malformed key, suite, expiry, rotation, and retry;
- test cross-origin and cross-generation cache confusion, stale replacement,
  poisoned provenance, unavailable time, rollback, and deterministic GREASE;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- ECH configuration state is bounded, origin-bound, freshness-aware, and
  deterministically selected without protocol-owned network access;
- `v0.140.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.141.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.142.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.143.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.144.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.145.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.146.0 - Precompressed Certificate Artifact Validation

Status: planned

Plan scope: Validate each caller-supplied compressed server or client-authentication artifact at configuration by bounded decompression and byte comparison with the complete canonical Certificate message, including certificate_request_context and every per-certificate extension; bind exact algorithm, compressed and uncompressed lengths, identity, configuration generation, and all encoded inputs, and invalidate on any OCSP, SCT, delegated-credential, request-context, extension, chain, or RPK-versus-X.509 change.

Goal: complete the **Precompressed Certificate Artifact Validation** implementation stop without admitting or
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
- `v0.146.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.146.1 - Certificate Compression Send Negotiation And Transcript Integration

Status: planned

Plan scope: Advertise only locally validated compression algorithms and select only a peer-advertised algorithm with a current validated artifact; integrate server and client-authentication sends, preserve the exact CompressedCertificate wire bytes in the transcript, enforce direction and message-context legality, rotation and cancellation behavior, deterministic uncompressed fallback only when policy permits, and fail closed on missing, stale, mismatched, or over-budget artifacts.

Goal: complete the **Certificate Compression Send Negotiation And Transcript Integration** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement algorithm advertisement and selection over current validated
  artifacts for server and client-authentication directions;
- bind transcript bytes, direction, request context, identity generation,
  rotation, cancellation, fallback policy, and resource budgets;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- test peer preference, unsupported and duplicate algorithms, both directions,
  transcript bytes, request context, rotation, cancellation, and fallback;
- reject stale, missing, mismatched, over-budget, wrong-direction, wrong-context,
  and post-validation-mutated artifacts without partial output;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- send compression uses only current validated artifacts with exact transcript,
  direction, identity, and policy binding;
- `v0.146.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.147.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.148.0 - Generated Optional-Feature Composition Gate

Status: planned

Plan scope: Generate a compatibility matrix for every pair of admitted optional features and their explicit stream TLS, DTLS, and QUIC applicability, plus targeted higher-order combinations across ECH, X.509 and RPK authentication, delegated credentials, tickets, resumption, imported and raw PSKs, pairwise external-PSK roles, zero-RTT, HybridRequired and HybridPreferred groups, the validated-module manifest and brynja-fips approved-only profile, noRevAvail, Must-Staple, ordinary and lightweight OCSP, versioned CT, HPKE export, certificate compression, rotating OCSP and SCT extensions, Record Size Limit, DTLS fragmentation, and return routability; bind ECH tickets to inner identity, policy, and configuration generation; test ClientHello size, HRR, padding, transcript, downgrade, rotation, migration, cancellation, storage, and exhaustion; make forbidden combinations unrepresentable or reject them during configuration before any handshake.

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
- `v0.148.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.149.0 - Facade Configuration Typestates

Status: planned

Plan scope: After every planned v1 optional module has exercised the internal effects model, freeze ordinary brynja typestates for exact versions, integrated one-pass routing, suites, trust, RPK, ECH, delegated credentials, compression, resources, revocation, PSK, zero-RTT, Certificate Transparency, and providers, and separately freeze brynja-fips typestates around the certificate-bound validated-module handle and closed approved-only profile; neither facade re-exports raw cryptography or admits a legacy range.

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
- `v0.149.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.150.0 - Versioned Stable Sans-I/O V1 API

Status: planned

Plan scope: Freeze EngineV1, EventV1, and ActionV1 with exhaustive mandatory entropy, signing, storage, timer, path-validation, OCSP transport and cache, decompression, trust, revocation-feature, external-PSK provisioning, CT-version, HPKE-context, provider, transport, service-approval, external-destruction, authentication, ECH, early-data, anti-replay, and policy results; applications cannot wildcard-ignore mandatory effects, and unhandled or mismatched effects fail closed; new mandatory effects require V2 interfaces and a major SemVer release; only bounded secret-free observational SecurityEvent values are non-exhaustive, and ignoring every such event still leaves accepted, rejected, approved, non-approved, and destruction-complete states unambiguous through mandatory state and results.

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
- `v0.150.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.151.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.152.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.153.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.154.0 - Protocol State And Resource Formal Harnesses

Status: planned

Plan scope: Complete Kani or equivalent harnesses for cursors, lengths, state reachability, exhaustion, replay, transactional transitions, one-pass selectors, secret-release invariants, zeroization and obsolete-key transitions, X.509 path-work and policy-graph ceilings, DTLS return-routability path binding, HPKE context invalidation, and single-consumption pending-operation tokens using pinned external tools.

Goal: complete the **Protocol State And Resource Formal Harnesses** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- capture formal, external-process fuzz, differential, sanitizer, side-channel, platform, hostile-load, review, remediation, freeze, and operational evidence;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- prove cursor, length, transition, replay, selector, zeroization, obsolete-key,
  X.509 budget, policy-graph, DTLS path-binding, HPKE invalidation,
  pending-token single-consumption, and secret-release properties across bounded
  models and supported configurations;
- retain regressions and prove replay, clean retest, traceability, artifact identity, rollback, compromise, and incident procedures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- protocol, resource, zeroization, X.509-budget, and pending-token proof claims name exact harnesses, bounds, assumptions, and implementations;
- `v0.154.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.155.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.156.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.157.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.158.0 - Sustained Platform And Hostile-Load Qualification

Status: planned

Plan scope: Sustain Linux, Windows, macOS, BSD, Android, iOS, bare-metal, and Aesynx ABI or emulator qualification under concurrency, provider failure, resource exhaustion, and hostile load; separately qualify every claimed FIPS artifact only on its certificate-listed operational environments and dispatch paths.

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
- `v0.158.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.159.0 - Consolidated External Audits

Status: planned

Plan scope: Complete exact-commit external standards-closure and normative-traceability, crypto, PKI, TLS, DTLS, QUIC, PQ, FIPS boundary, entropy, self-test, manifest, facade, profile, deployment and claim lifecycle, optional-module, zeroization, and systems-integration audits.

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
- `v0.159.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.160.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.161.0 - Public API Requirements And Documentation Freeze

Status: planned

Plan scope: Freeze public APIs, features, package inventory, current and compatibility source closure, normative-requirement and protocol-surface ledgers, admitted algorithms and extensions, migration guidance, deployment profiles, incident procedures, limitations, non-goals, and exact FIPS certificate, manifest, operational-environment, caveat, claim, update, and revalidation documentation.

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
- `v0.161.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- `v0.162.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v1.0.0-rc.1 - Exact Production Candidate

Status: planned

Plan scope: Build final artifacts once and freeze source, compiler, flags, archives, SBOM, checksums, provenance, documentation, and the pentested candidate state with its committed report.

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
- exercise compromise, disaster, package inspection, downstream compatibility, and absence of legacy, draft, or excluded scope;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- stable artifacts are byte-identical to the approved candidate and every claim maps to exact-commit evidence;
- `v1.0.0-rc.1 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

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
- exercise compromise, disaster, package inspection, downstream compatibility, and absence of legacy, draft, or excluded scope;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- stable artifacts are byte-identical to the approved candidate and every claim maps to exact-commit evidence;
- `v1.0.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`
