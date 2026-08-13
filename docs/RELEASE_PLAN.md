# Brynja Release Plan To 1.0

Status: normative planning document

Every Brynja milestone is independently reviewable, testable, and safe to
stop. Milestones through `v0.10.0` retain the original one-version release
cadence. After the signed `v0.10.0` tag, every ordered milestone still advances
the `brynja` version and receives an immutable signed `vX.Y.Z` tag after the
complete automated gate and green GitHub and CodeQL. Scheduled pentesting and
crates.io publication occur at five-minor integration checkpoints instead of
at every tag. [VERSION_PLAN.md](VERSION_PLAN.md) defines exact titles, scopes,
and ordering; this document repeats them and automated checks reject drift.

## Release Principles

Every tag requires generated normative traceability,
explicit resource, secret, storage, effect, dependency and failure boundaries,
adversarial tests, documented limitations, no unreviewed external crate in the
core workspace or any facade, engine, crypto, default, legacy, bare-metal or
FIPS graph, `no_std` evidence, SBOM comparison, clean CI and CodeQL Default, and
explicit user authorization. Scheduled or exceptional public
checkpoints additionally require an up-to-date committed pentest report and
crates.io release preparation. Development milestones create a signed tag but
no scheduled report, GitHub Release, or crates.io publication.

Every cryptographic and FIPS service follows the permanent first-party Rust
golden rule. No release may substitute a C or foreign/native cryptographic
module, wrapper, vendor library, external assembly file, prebuilt object, or
delegated software provider. Separately reviewed first-party Rust intrinsics or
inline assembly remain exact Brynja implementation symbols. Future rustls and
Tokio companion adapters may own narrowly admitted pure-Rust framework API
dependencies only in separately locked downstream graphs; they never become a
dependency or feature of the core workspace or a FIPS-module implementation.

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

Portable scalar cryptography precedes acceleration. CPU candidates live only
in the optional first-party `no_std` backend package; standard-library runtime
detection lives in a separate opt-in adapter. Exact feature evidence, direct
KATs, health and quarantine, scalar differentials, native AMD, Intel, Apple
and AWS Arm measurements, qualifying RISC-V evidence, per-compiler emitted
code and side-channel results, and explicit FIPS disposition precede
activation. QEMU and cross-builds are supplemental. An unavailable or slower
path remains visibly candidate, rejected or scalar-only.

## Required Milestone Contract

Every section contains Status, Plan scope, Goal, Deliverables, Verification, and
Exit criteria. Repository checks are additive and one stop never admits adjacent
capability.

## Five-Minor Release Trains

Milestone classification is mechanical and fail-closed:

- `v0.1.0` through `v0.10.0`, including their historical patch milestones,
  retain the original per-milestone release process;
- after `v0.10.0`, `v0.N.0` is a scheduled public release checkpoint when
  `N` is divisible by five: `v0.15.0`, `v0.20.0`, and so on through
  `v0.160.0`;
- every other `v0` milestone after `v0.10.0`, including patch-numbered roadmap
  rows such as `v0.11.1`, is a tagged development milestone; and
- `v1.0.0-rc.1` and `v1.0.0` are always public release checkpoints.

A development milestone completes its exact scope, tests, evidence,
documentation delta, security-delta review, and complete automated tag gate in
a signed commit. After GitHub and CodeQL are green and the user authorizes it,
the exact commit receives an immutable signed `vX.Y.Z` tag. The `brynja`
manifest version equals that tag, but the milestone creates no scheduled
pentest report, GitHub Release, or crates.io publication. Supporting crates
retain their independent published versions until a public checkpoint selects
their cumulative change.

A scheduled checkpoint pentests backwards over the complete change delta from
the previous public tag through the new candidate. Thus `v0.15.0` compares and
reviews the changes after `v0.10.0` through `v0.15.0`, including tagged
milestones `v0.11.0`, `v0.11.1`, `v0.11.2`, `v0.12.0`, `v0.13.0`,
`v0.13.1`, `v0.13.2`, `v0.13.3`, and `v0.14.0`. The next checkpoint reviews
changes after `v0.15.0` through
`v0.20.0`, and so on. The public `brynja` crate may therefore jump directly
from `0.10.0` to `0.15.0`; intervening tags identify tested source milestones,
not crates.io releases.

Repository tooling mechanically classifies the current milestone, requires the
facade version to equal every tag, rejects non-empty publication selections for
a development milestone, permits ordinary CI without a scheduled pentest
report, and requires the complete cumulative public gate at a scheduled or
exceptional release checkpoint.

## Exceptional Pentest Trigger

The five-minor cadence is a maximum planned interval, not permission to defer a
material security concern. An exceptional pentest is mandatory when requested
by the repository owner, when a material finding or incident remains open, when
an early public release is proposed, or when the milestone security review
documents that waiting for the scheduled checkpoint would make the cumulative
scope unsafe or unreviewable. That decision must explicitly consider:

- unsafe code, FFI, assembly, secret destruction, entropy, constant-time code,
  cryptographic arithmetic or primitives;
- attacker-controlled nested parsing, allocation or resource accounting,
  certificate/path validation, record protection, protocol state, key
  schedules, authentication, resumption, early data, or anti-replay;
- FIPS module identity or claims, validated artifacts, legacy protocols, or a
  new externally exposed package/API boundary;
- unresolved assurance gaps and interactions spanning more than one of those
  boundaries; and
- any proposed prerelease, crates.io upload, public tag, or externally usable
  validation claim before the next scheduled checkpoint.

An exceptional pentest of a development milestone does not automatically
authorize crates.io publication. Its findings and regressions remain in the
cumulative train, and the next scheduled checkpoint still pentests the
integrated delta.
An emergency public patch or deliberately early public release must instead
run the complete release flow below and becomes the new public baseline.

## Simple Pentest, CI, Tag, And Publication Flow

Each scheduled or exceptional public release uses one report at
`security/pentest/vX.Y.Z[-rc.N].md`:

1. Complete the cumulative checkpoint scope and local verification, then stop
   and ask the user for a backwards-looking pentest of all changes after the
   report's `Baseline` public tag through the current candidate.
2. Keep the report current while findings are fixed and retested. If no finding
   exists, record that explicitly.
3. Commit the implementation and PASS report together. The report must state
   `Open-Findings: 0` and `Retest: PASS`.
4. Push and wait for GitHub CI and CodeQL Default to become green.
5. If GitHub exposes a problem, fix it, update the same report, commit both,
   push, and wait for green again.
6. Create the tag only after the user explicitly confirms that GitHub and
   CodeQL are green.
7. Publish only the release manifest's selected crates in dependency order,
   with the `brynja` facade mandatory and last.

The report records the previous public tag in `Baseline` and names both ends of
the reviewed range in `Scope`; the gate rejects an incomplete cumulative
range. The report does not contain a self-referential commit hash. The gate instead
proves that the versioned report is committed at `HEAD`, matches the worktree,
has a final PASS state, and was updated in any later commit that changed the
candidate. The pre-tag gate rejects an existing tag. The guarded publisher
accepts the tag only when it points to that exact green candidate commit.

## Crate Versioning And Publication

The workspace follows the same independent-crate release model as `eth`, with
additional fail-closed rules for repository-only packages.
`release-crates.toml` records every package's previous version, planned
version, change class, publication decision, and reason.

- every signed modern tag advances the `brynja` facade manifest to exactly the
  tag version;
- every scheduled or exceptional public checkpoint publishes that facade,
  even when the release only advances dependency pins or release-facing
  metadata;
- development milestones publish no crate and cannot select a facade or
  supporting package in `release-crates.toml`;
- the initial public release publishes every modern package required by the
  facade, including optional normal dependencies, before the facade;
- at a public checkpoint, supporting crates publish only when their cumulative
  delta since the last public tag contains an explicit initial release, code or
  API work, an API-compatible bug fix, a required internal dependency-pin
  change, or immutable crates.io metadata correction;
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
dependency availability and ordering, repository-only exclusions, cumulative
package-tree changes since the previous public tag, and the mandatory facade
release at checkpoints. `--package-check` validates the Cargo file set for
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

Status: released

Plan scope: Preserve the explicit `brynja-legacy-*` naming boundary, evergreen `brynja-tls` router facade, version-specific `brynja-tls12`, `brynja-tls13`, and `brynja-tls13-handshake` package graph, and the remaining workspace foundation with no cryptographic or protocol security claim.

Goal: complete the **Workspace Foundation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- make policy executable through generated traceability, fail-closed scripts, broken fixtures, immutable evidence, ownership, and release boundaries;
- record that no normative protocol requirement advances, and update the threat
  model, controls, status, limitations, release notes, and permanent evidence
  index.

Verification:

- exercise positive and broken dependency, metadata, standards-ledger, workflow, isolation, evidence, and release-state fixtures;
- inspect source locks, clean archives, permissions, tag assumptions, tool pinning, ledger completeness, and reproducibility;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- repository evidence and enforcement agree and every deliberate violation fails before release;
- `v0.1.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.2.0 - Release And Isolation Enforcement

Status: released

Plan scope: Harden committed-report and exact-tag comparison, validate all-feature graphs and every package class, add negative modern and legacy isolation fixtures, and document protected release controls.

Goal: complete the **Release And Isolation Enforcement** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- classify every workspace package and freeze its exact direct dependencies,
  optional feature edges, publication status, library target, edition, MSRV,
  license, and source boundary in one committed policy;
- validate both no-default and all-feature resolved graphs, including the
  modern facade, evergreen TLS router, QUIC adapter, legacy facade, all legacy
  engines, research boundary, platform adapter, and repository-only packages;
- require a regular committed pentest report synchronized against every parent
  that already carried the report, and accept publication only from an exact
  directly targeted signed annotated tag with the canonical subject;
- install and live-check the protected main-branch ruleset used by `eth`,
  including signed linear history, review, CODEOWNER, CodeQL, force-push and
  deletion protections, and explicit accountable bypass identities;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exercise positive graphs plus broken package inventory, publication class,
  target, edition, exact-pin, optionality, feature-smuggling, modern/legacy,
  QUIC/stream, repository, report-file, signed-tag, review, CodeQL, ruleset,
  and bypass fixtures;
- inspect clean archives, package versions, live GitHub protection, exact tag
  identity and signature, committed report mode and history, permissions,
  action pins, tool pins, SBOM, and reproducibility;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- repository evidence and enforcement agree and every deliberate violation fails before release;
- `v0.2.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.3.0 - Requirements And Standards Source Ledger

Status: released

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

Status: released

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

Status: released

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

Status: released

Plan scope: Populate and review every applicable normative statement and invariant for admitted primitives, arithmetic, DER, key and certificate formats, service identity, path processing, revocation, OCSP and Certificate Transparency; record explicit algorithm exclusions, current-versus-compatibility authority, positive and negative target tests, work bounds, and unresolved evidence.

Goal: complete the **Cryptography Encoding And PKIX Normative Coverage** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- populate the complete crypto, encoding, key-container, certificate, name,
  path, policy, revocation, OCSP, TLS Feature, and CT requirement domains;
- pin the missing FIPS 202 and in-force ITU-T X.690 plus erratum authorities,
  classify SHA-3/SHAKE, GHASH, and ChaCha20 explicitly, and correct stale
  primitive milestone ownership before coverage is accepted;
- bind every rule to an owner, explicit disposition, resource or side-channel
  invariant, planned target, positive and negative target tests, and evidence
  lifecycle without accepting an unreviewed algorithm identifier;
- generate an exact authority, normative-section, surface-assignment, and
  deferral artifact bound to the source ledger and surface register;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- compare source-to-plan and plan-to-source coverage for every owning milestone
  and regenerate all projections byte-identically;
- require all 53 assigned authorities and all 3,322 selected surfaces to be
  covered, with only the two explicitly named v0.3.5 ML-KEM deferrals;
- remove, duplicate, weaken, misclassify, obsolete, or orphan requirements from
  each domain and require failure, including cross-domain AlgorithmIdentifier,
  name, policy, revocation, CT-version, and work-bound cases;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every locked cryptographic, encoding, and PKIX rule has a reviewable lifecycle
  and no admitted or rejected algorithm or validation surface remains implicit;
- every record carries a substantive work bound, unresolved-evidence statement,
  residual risk, and both positive and negative planned test targets;
- `v0.3.3 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.3.4 - TLS DTLS And QUIC Normative Coverage

Status: released

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
- require an explicit requirement binding or reviewed disposition for every
  normative RFC section, preserving its unique extraction anchor and exact
  section hash;
- inject missing messages, illegal contexts, registry drift, wrong-version
  reuse, obsolete authority, caller/protocol ownership swaps, ignored alerts,
  unrelated multi-surface links, missing section bindings, and weakened
  security requirements and require failure;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every transport-protocol requirement and boundary is explicitly versioned,
  owned, test-targeted, and unable to hide behind generic TLS reuse;
- `v0.3.4 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.3.5 - Optional Legacy And Residual Normative Closure

Status: released

Plan scope: Populate HPKE, ECH, ML-KEM and hybrid, optional TLS facilities, legacy protocol, operational and presently pinned non-RFC requirements; represent unavailable future or mutable authorities as fail-closed blockers owned by their dependent milestone; reconcile exact cross-bundle section ownership, confine every RFC 9853 RRC surface to DTLS, separate RFC 6066 wire-ignore behavior from configuration rejection, cover RFC 6066 independently in TLS 1.2, and reject every orphan, duplicate, stale, obsolete-as-current, silently weakened or uncovered planned surface before cryptographic or protocol implementation begins.

Goal: complete the **Optional Legacy And Residual Normative Closure** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- populate every remaining optional, PQ, legacy, operational, source-rights,
  test-only, caller-owned, rejected, blocked, and presently pinned non-RFC rule;
- reconcile section mappings and exclusions globally across every requirement
  bundle, require every cross-bundle delegation to resolve to an exact owner,
  keep every DTLS RRC state, extension, content type, and registry surface
  inside the DTLS boundary, and bind source-blocked legacy surfaces to exact
  blocker requirements;
- assign RFC 6066 sections only to exact TLS 1.2, TLS 1.3, SNI,
  certificate-status, status-transport, alert, terminology, or excluded
  facility decisions; safely ignore bounded unsupported peer ClientHello
  bodies while rejecting configuration, offers, unsolicited responses,
  echoes, negotiation, tickets, and imported-state admission;
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
  cross-policy section contradictions, wrong protocol ownership, actionable
  source-blocked requirements, orphaned section delegations, RFC 6066 semantic
  laundering, missing TLS 1.2 ownership, wire/configuration conflation,
  stream-TLS RRC admission, and uncovered surfaces and require repository
  failure;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the complete current planning baseline is closed without claiming unavailable
  standards, future code, mutable evidence, or legacy rights as complete;
- RFC 9853 runtime and registry ownership is reachable through
  `brynja-dtls-core`, ContentType 27 is rejected outside negotiated DTLS RRC,
  RFC 6066 cannot launder unrelated facilities through OCSP or TLS 1.3, its
  bounded peer ClientHello ignore path cannot enable local admission, RFC 7568
  cannot authorize unrelated legacy protocols, and every unavailable legacy
  source fails closed through its exact blocker;
- `v0.3.5 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.4.0 - Assurance Harness And Bare-Metal Matrix

Status: released

Plan scope: Establish first-party mutation and differential harnesses, true bare-metal targets, and pinned external assurance-tool policy without adding third-party crates to repository Cargo manifests.

Goal: complete the **Assurance Harness And Bare-Metal Matrix** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- freeze a raw-stdin, canonical-JSON adapter protocol with deterministic
  mutation order, exact replay indexes, bounded input, output, case count, and
  timeout, descriptor-bound no-follow limit-plus-one file reads, one-case
  corpus and mutation streaming, no shell execution, no automatic
  failure-input persistence, and an explicit external
  network/filesystem/process sandbox duty;
- require two distinct independently maintained process adapters for
  differential evidence and fail on timeout, crash, excess output,
  noncanonical result, unsupported class, or semantic mismatch; place Windows
  adapters in a suspended kill-on-close Job Object before execution, use
  POSIX sessions only as cooperative cleanup, and fail closed for hostile
  POSIX execution unless its launcher declares enforced cgroup v2, PID
  namespace, container/VM, or fork-and-`setsid`-denied containment;
- compile the complete all-feature workspace on
  `thumbv7em-none-eabi`, `riscv32imac-unknown-none-elf`, and
  `x86_64-unknown-none` without implying runtime, entropy, platform, or Aesynx
  support;
- pin Kani, Miri, sanitizers, AFL++, and honggfuzz by exact version and
  upstream revision without adding them to any Cargo manifest; keep stable
  release Rust separate from the documented Rust 1.90.0 Kani verifier pairing,
  and bound local tool and remote source probes with explicit timeouts;
- generate deterministic evidence binding the policy, workflows, harness
  scripts, and every Cargo manifest and reject policy, pin, workflow, target,
  dependency, or generated-evidence drift with broken fixtures;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exercise deterministic mutation, replay, canonical result, independent
  adapter, mismatch, crash, timeout, output-exhaustion, weak-bound, duplicate
  target, wrong Kani pairing, unpinned tool, workflow, dependency, evidence,
  release-state, local target-probe timeout, and remote tag-probe timeout
  fixtures, plus parent-exit pipe retention, descendant timeout, descendant
  output flood, cooperative descendant survival, detached POSIX escape,
  absent external-containment rejection, Windows suspended-start constant,
  native Linux/macOS/Windows execution, limit-plus-one and oversized input,
  symlink or reparse input, corpus-count, one-case streaming, and exact
  streamed-mutation equivalence regressions;
- inspect source locks, clean archives, permissions, tag assumptions, stable
  versus verifier toolchains, external tool pins, OS-less target availability,
  ledger completeness, and reproducibility;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- repository evidence and enforcement agree, every deliberate violation fails,
  Windows descendants remain Job-owned, hostile POSIX execution is rejected
  without an external containment contract, the cooperative POSIX limitation
  is tested and disclosed, input allocation and corpus residency remain
  bounded before parsing, the three OS-less targets compile, ordinary Cargo
  graphs remain first-party only, and policy-only Kani status cannot be
  mistaken for a completed proof;
- `v0.4.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.5.0 - Error Alert And Exhaustion Domains

Status: released

Plan scope: Freeze non-secret error, alert, close, provider-failure, and resource-exhaustion domains; prohibit secret-bearing formatting and ambiguous failure collapse.

Goal: freeze the shared allocation-free outcome taxonomy consumed by later
TLS and DTLS engines without implementing framing, state transitions,
cryptography, providers, or numeric budget policy early.

Deliverables:

- classify all 256 TLS AlertDescription bytes as assigned, reserved, or
  unassigned from the pinned IANA registry without ambiguous coercion;
- define concrete TLS 1.2, TLS 1.3, DTLS 1.2, and DTLS 1.3 identities and
  fail-closed admission for version-specific assigned alerts;
- keep orderly close, explicit cancellation, alert failure, local failure,
  provider failure, and resource exhaustion as distinct types;
- prevent failure envelopes from carrying arbitrary strings, byte payloads,
  provider-native codes, numeric limits, or `Debug`/`Display` formatting;
- retain numeric bounds, wire encoding, terminal protocol state, provider
  capabilities, and zeroization mechanics for their owning later milestones;
- transition `BRY-REQ-TLS-0005` through immutable `implemented` and `tested`
  revisions and mark only the alert registry surface implemented;
- publish `brynja-core 0.2.0`, dependency-only patch releases for its changed
  exact-pinned modern closure, and the mandatory `brynja 0.5.0` facade.

Verification:

- exhaustively classify the 256-byte registry and verify every assigned and
  reserved value, semantic class, fixed severity, and version exception;
- run positive and negative typed-outcome, close/cancellation separation,
  provider-category, exhaustion, representation-bound, and compile-fail
  formatting/payload tests;
- verify `no_std`, no allocation, no unsafe code, no external dependency,
  fixed work, all promised Rust versions and targets, package ordering,
  documentation, SBOM, advisory policy, and protocol isolation;
- run the full first-party assurance and repository gates, then obtain the
  required external release pentest.

Exit criteria:

- all v0.5 domains are deterministic, fixed-work, platform-independent,
  secret-free by construction, and cannot collapse close or cancellation into
  a failure;
- the requirement and registry artifacts identify the implementation and its
  linked tests without claiming independent review, interoperability, TLS
  operation, cryptographic verification, or FIPS validation;
- `v0.5.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.6.0 - Bounded Numeric And Resource Domains

Status: released

Plan scope: Add private-field compile-time bounded `u64`/`usize` values with checked arithmetic, distinct count and byte-length types with fail-closed pointer-width conversion, non-wrapping protocol-neutral sequence and epoch values, and explicit immutable resource/work budgets whose typed exhaustion errors reveal no limit values; retain parsing, mutable accounting, wire widths, direction-specific state, and protocol behavior for later owners.

Goal: freeze the allocation-free numeric and limit-policy vocabulary consumed
by later codecs and engines without implementing framing, state machines,
mutable accounting, allocation, cryptography, or provider behavior early.

Deliverables:

- provide private-field `BoundedU64<MAX>` and `BoundedUsize<MAX>` types with
  fallible construction and checked addition, subtraction, and multiplication;
- keep bounded item counts and byte lengths as distinct types, including
  fail-closed conversion from platform-independent `u64` values to `usize`;
- provide protocol-neutral sequence-number and 16-bit epoch values that
  advance monotonically and return typed exhaustion instead of wrapping;
- define explicit immutable resource and work budgets through named
  single-assignment construction without positional transposition, duplicate
  overwrite, defaults, mutable setters, allocation, mutable counters, or
  numeric values in exhaustion errors;
- retain direction-specific state, record limits, wire widths, parsing,
  accounting, arena ownership, zeroization, and protocol transitions for their
  owning later milestones;
- preserve every later protocol requirement and surface as future work: v0.6
  is a source-free foundation boundary and does not claim TLS/DTLS sequence or
  epoch behavior;
- publish `brynja-core 0.3.0`, dependency-only patch releases for its changed
  exact-pinned modern closure, and the mandatory `brynja 0.6.0` facade;
- update the threat model, controls, status, limitations, release notes, and
  permanent evidence index.

Verification:

- exhaustively compare small-domain checked arithmetic, sequence advances, and
  epoch advances with primitive checked operations;
- test zero, exact maximum, above-maximum, primitive overflow, underflow,
  pointer-width conversion, zero budgets, every resource dimension, every
  duplicate and missing named-builder field, positional-constructor rejection,
  immutable no-mutation behavior, storage bounds, and sequence/epoch
  exhaustion;
- run compile-fail tests for count/length confusion and accidental formatting
  of bounded values or budgets;
- verify `no_std`, no allocation, no unsafe code, no external dependencies,
  every promised Rust version and OS-less target, exact package ordering,
  documentation, SBOM, advisory policy, and modern/legacy isolation;
- run the full first-party assurance and repository gates, then obtain the
  required external release pentest.

Exit criteria:

- all v0.6 numeric operations fail closed without wraparound, budgets are
  explicit and immutable, errors remain limit-value-free, and source and test
  files stay below 500 lines;
- documentation and generated closure evidence do not claim a parser,
  protocol state, secret ownership, formal proof, independent review,
  interoperability, production readiness, or FIPS validation;
- `v0.6.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.7.0 - Borrowed Read Cursor

Status: released

Plan scope: Implement a borrowed read cursor with exact consumption, truncation-at-every-byte coverage, and no indexing panics.

Goal: freeze the allocation-free, protocol-neutral borrowed input primitive
used by later codecs without implementing integer decoding, nested framing,
protocol parsing, write-side mutation, arenas, secret ownership, or state
machines early.

Deliverables:

- provide a private-field `ReadCursor<'input>` that borrows immutable
  caller-owned bytes and stores only the input slice and current position;
- borrow and consume exact dynamic lengths, typed `Length<MAX>` values, and
  fixed-size arrays without allocation, unsafe code, or indexing;
- compute end offsets with checked arithmetic and leave position and remaining
  input unchanged after every overflow, truncation, or conversion failure;
- expose position, remaining length, remaining borrowed suffix, and explicit
  consuming `finish()` semantics that reject trailing data;
- keep the cursor non-`Clone`, non-`Copy`, non-formattable, and `must_use` so
  parser forks, accidental byte diagnostics, and ignored cursor state remain
  review-visible;
- return only closed value-free `Truncated`, `LengthOverflow`, and
  `TrailingData` categories without input bytes, offsets, requested lengths,
  available lengths, strings, allocation, or provider details;
- retain integer decoding, canonical encoding, nested framing, transactional
  writes, caller arenas, mutable resource accounting, zeroization ownership,
  protocol parsing, and state transitions for their owning later milestones;
- publish `brynja-core 0.4.0`, dependency-only `0.1.3` patches for its changed
  exact-pinned modern closure, and the mandatory `brynja 0.7.0` facade;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- test a composite exact read at every truncation byte and reject every
  trailing suffix through explicit completion;
- exhaust every input position and requested length around a bounded fixture,
  proving exact advancement on success and unchanged position/suffix on
  truncation;
- test `usize` end-offset overflow, zero-length reads at every boundary, typed
  lengths, fixed arrays, empty input, borrow identity, and compact storage;
- run compile-fail doctests for cursor cloning, byte formatting, and returned
  borrows escaping the caller-owned input lifetime;
- enforce the no-indexing, no-panic, no-unsafe, no-allocation, no-external-
  dependency, `no_std`, 500-line, and valueless-error boundaries with workspace
  lints, resolved-graph policy, representation checks, and OS-less builds;
- verify every promised Rust version, host/target matrix, documentation,
  package order, SBOM, standards drift, advisory policy, modern/legacy
  isolation, and the complete first-party assurance gate;
- obtain the required external release pentest.

Exit criteria:

- every admitted cursor operation is deterministic, borrowed, exact, and
  failure-transactional across hostile lengths and truncated input;
- the cursor owns no secret and makes no zeroization claim; later owners remain
  responsible for copied/decoded secret material and caller-buffer erasure;
- no documentation, requirement, or protocol surface claims framing, parsing,
  interoperability, independent review, formal proof, production readiness, or
  FIPS validation;
- `v0.7.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.8.0 - Transactional Write Cursor

Status: released

Plan scope: Implement caller-buffer write cursors with transactional encode-or-no-mutation behavior.

Goal: freeze the allocation-free, protocol-neutral caller-buffer output
primitive used by later codecs, with complete-operation preflight and no
partial mutation on failure, without implementing integer encoding, framing,
arenas, secret ownership, or protocol state early.

Deliverables:

- provide a private-field `WriteCursor<'output>` that exclusively borrows a
  caller-owned mutable byte slice and stores only that slice and its position;
- preflight every complete single-slice, multi-part, and repeated-byte write
  before changing output, then advance only after the whole operation succeeds;
- treat all slices supplied to one multi-part call as one transaction, checking
  their aggregate length with overflow-safe arithmetic before the first copy;
- expose position, remaining capacity, immutable written-prefix inspection,
  finished state, and a consuming exact-capacity completion check;
- keep the cursor non-`Clone`, non-`Copy`, non-formattable, and `must_use`, and
  prevent safe caller access to the exclusively borrowed output while active;
- return only closed value-free `InsufficientCapacity`, `LengthOverflow`, and
  `TrailingCapacity` categories without bytes, offsets, lengths, strings,
  allocation, or provider detail;
- state explicitly that separate successful calls are separate transactions
  and that the cursor neither owns nor destroys secrets;
- retain integer encoding, canonical formats, nested framing, patching,
  caller-owned arenas, overlap policy, mutable accounting, secret destruction,
  protocol parsing, and state transitions for their later milestones;
- publish `brynja-core 0.5.0`, dependency-only `0.1.4` patches for its changed
  exact-pinned modern closure, and the mandatory `brynja 0.8.0` facade;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exhaust every start position and requested length around bounded output,
  proving exact success and byte-for-byte buffer plus position preservation on
  insufficient capacity;
- test multi-part ordering, empty parts, complete preflight, repeated bytes,
  `usize` end-offset overflow, zero-length writes at every boundary, empty
  output, exact completion, output identity, and compact storage;
- run compile-fail doctests for cursor cloning, formatting, and accessing the
  caller's mutably borrowed output while the cursor remains live;
- enforce the no-indexing, no-panic, no-unsafe, no-allocation, no-external-
  dependency, `no_std`, 500-line, and valueless-error boundaries through
  workspace lints, resolved-graph policy, representation checks, and OS-less
  builds;
- prove no protocol surface or normative protocol requirement advances because
  this is a source-free buffer foundation, and retain all adjacent capabilities
  under their existing owners;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, protocol isolation, and the
  complete first-party assurance gate;
- obtain the required external release pentest.

Exit criteria:

- every admitted output operation is deterministic and failure-transactional:
  a rejected operation changes neither any output byte nor cursor position;
- cursor construction performs no write, successful operations affect only
  their exact destination, and safe Rust preserves the exclusive caller-buffer
  borrow for the cursor lifetime;
- no documentation, requirement, or protocol surface claims integer encoding,
  framing, parsing, arenas, secret destruction, interoperability, independent
  review, formal proof, production readiness, or FIPS validation;
- `v0.8.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.9.0 - Caller-Owned Workspace And Arena Model

Status: released

Plan scope: Define caller-owned workspaces and non-overlapping secret, plaintext, transcript, certificate, and output arenas with overlap rules, high-water tracking, and allocation counters.

Goal: freeze one exact allocation-free partition and monotonic allocation
contract for protocol-neutral caller storage without implementing erasure,
reuse, encoding, parsing, cryptography, or protocol state early.

Deliverables:

- provide a named single-assignment `WorkspaceLayoutBuilder` requiring explicit
  byte capacities for secret, plaintext, transcript, certificate, and output
  domains, rejecting every duplicate, omission, and aggregate `usize` overflow;
- require one caller-owned mutable backing slice whose length exactly equals
  the checked layout total, reject both short and oversized slices before
  mutation, and partition every byte once in fixed named order;
- use only safe slice splitting so distinct domains are structurally
  non-overlapping; permit equal boundaries only for empty ranges, which contain
  no byte and therefore cannot overlap;
- provide private-field, non-clonable, non-formattable `Arena` values with
  named individual access and simultaneous named borrows of all five disjoint
  domains, using sealed zero-sized compile-time domain markers so named arena
  handles have different Rust types and cannot be accidentally swapped;
- admit only monotonic complete-range allocation: successful non-empty
  allocations consume disjoint ranges and advance once, empty allocations do
  not affect accounting, and arithmetic overflow or capacity failure changes
  neither bytes nor accounting;
- expose fixed capacity, used and remaining bytes, monotonic high-water mark,
  and successful non-empty allocation count per arena without including those
  values in errors or automatic diagnostics;
- state explicitly that returned ranges retain caller bytes, that callers must
  initialize them before use, and that this milestone provides no release,
  rewind, ownership, erasure, destruction, or secret-lifecycle guarantee;
- retain integer encoding, framing, mutable reclamation, secret lifetime and
  destruction, providers, protocol parsing, cryptography, and state machines
  for their separately versioned owners;
- publish `brynja-core 0.6.0`, dependency-only `0.1.5` patches for its changed
  exact-pinned modern closure, and the mandatory `brynja 0.9.0` facade;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exhaust every small five-domain layout and every arena position/request pair,
  including zero-length domains and allocations, exact exhaustion, one-byte
  overrun, and `usize::MAX` end and aggregate overflow;
- prove every duplicate and omitted domain fails with a typed arena identity,
  both backing-length mismatch directions preserve sentinel bytes, and every
  failed allocation preserves used, remaining, high-water, count, and storage;
- verify exact backing and allocation pointer identity, fixed partition order,
  simultaneous named disjoint use, compile-time domain-swap rejection, retained
  caller contents, zero marker overhead, and byte-for-byte domain isolation
  after distinct sentinel writes;
- run compile-fail doctests for formatting and outside mutation during the
  exclusive workspace borrow, and enforce no indexing, panic, unsafe,
  allocation, external dependency, secret-value diagnostics, or source file
  above 500 lines;
- prove no protocol surface or normative protocol requirement advances because
  the arena model is a source-free foundation, with zeroization and destruction
  remaining explicitly deferred to v0.10.0 and v0.11.0;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every workspace byte belongs to exactly one named arena, every successful
  non-empty allocation belongs to exactly one disjoint monotonic range, and
  every rejection is byte- and accounting-transactional;
- no API or documentation claims release, reuse, zeroization, secret ownership,
  integer framing, protocol behavior, interoperability, independent review,
  production readiness, or FIPS validation;
- `v0.9.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.10.0 - Secret Lifetime And Destruction Contract

Status: released

Plan scope: Define non-cloneable and non-serializable secret ownership, transition, error, cancellation, provider-failure and drop destruction, immediate obsolete-secret cleanup, external-store and accelerator duties, a mandatory production guarantee for the complete owned memory region, and RFC 9850 key logging only in a separately compiled test-support artifact that cannot enter production packages or features.

Goal: complete the **Secret Lifetime And Destruction Contract** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- define private non-cloneable, non-serializable, and non-formattable secret
  owner states separately from the v0.9 raw `SecretDomain` storage marker;
- make retained caller bytes enter a write-only initialization state and permit
  transition to a readable secret owner only after the complete owned region is
  explicitly initialized, with no partial-initialization escape on error,
  cancellation, exhaustion, or provider failure;
- define immediate obsolete-secret and drop-destruction effects, terminal
  failure behavior, and single-consumption completion duties for local memory,
  external stores, accelerators, caches, and DMA-visible regions;
- prohibit any concrete production secret backing from using the raw v0.9
  arena as an ownership or erasure mechanism until the v0.11.0 primitive has
  approved unsafe policy, store-survival evidence, and exact target coverage;
- keep RFC 9850 key logging only in a separately compiled test-support artifact
  that no production package, feature, or resolved graph can reach;
- preserve secret-free errors and deterministic transition outcomes without
  bytes, keys, offsets, lengths, native provider detail, or arbitrary strings;
- make the post-`v0.10.0` development/checkpoint classifier, signed tag path,
  empty development publication plan, exceptional trigger, cumulative pentest
  scope, and facade/tag equality mechanically enforceable before `v0.11.0`
  completes;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exhaust every initialization boundary and early-return path, proving no read,
  formatting, serialization, clone, output, or owner transition exists before
  the complete region is initialized;
- test obsolete-key, replacement, error, cancellation, provider failure, drop,
  external-store, accelerator, cache, and DMA destruction duties with exact
  single-consumption completion tokens and terminal failure states;
- prove debug canaries and ordinary safe fills are test aids rather than
  production zeroization evidence, and reject any concrete production backing
  that lacks the v0.11.0 primitive and emitted-code evidence;
- reject a development milestone that creates a scheduled release report,
  GitHub Release, crates.io selection, or facade publication; require its
  signed tag only after green GitHub and CodeQL; and reject a scheduled
  checkpoint that omits any cumulative milestone, PASS report, selected-crate
  delta, or facade-last publication rule;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the secret lifecycle and initialization contract is deterministic and
  fail-closed, while no concrete production secret owner can be constructed
  before reviewed complete-region destruction exists;
- `v0.10.0 implementation stop reached. Run pentest for this release candidate and commit the updated report.`

### v0.11.0 - Owned-Memory Zeroization Primitive

Status: released

Plan scope: After explicit unsafe-policy approval, implement the smallest isolated first-party primitive needed to preserve zeroization stores through optimization; define proof obligations, cache and DMA completion duties, MIR, LLVM and assembly evidence for every supported compiler and target, and precise exclusions for registers, copies, dumps, and physical memory.

Goal: complete the **Owned-Memory Zeroization Primitive** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- isolate one per-byte volatile zero store behind a safe exclusive-slice API,
  retain the final compiler barrier, and mechanically reject unsafe code,
  assembly, or FFI outside that private module;
- add affine write-only initialization and readable owned-region states that
  clear old bytes at admission, reject incomplete read transition, preserve
  failed-write state, and clear the complete allocation on every explicit and
  `Drop` exit;
- define the exact local-allocation claim, separate cache and DMA completion
  duties, and exclusions for registers, copies, caches, DMA-visible copies,
  dumps, suspend images, physical memory, concurrency, forgotten owners, and
  termination;
- update requirements, threat model, controls, status, limitations, release
  notes, exceptional-pentest policy, and permanent evidence index.

Verification:

- exhaust direct-clear lengths, every complete and incomplete initialization
  split, overflow, capacity failure, old-byte admission, partial Drop, owner
  Drop, explicit clear, compile-fail clone/format, `no_std`, and no-mutation
  behavior;
- require the volatile call in MIR, volatile zero store in LLVM IR, and byte
  store in assembly across Rust 1.90.0 through 1.97.1 and all nine promised
  targets, plus pinned Miri and AddressSanitizer execution;
- reject any second unsafe allowance/block/item, unproved pointer derivation,
  assembly, FFI, weakened claim, missing exclusion, skipped exceptional report,
  or accidental crate publication;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe,
  platform-independent, and reviewably clears the complete exclusively borrowed
  allocation without extending that claim to platform-owned copies or effects;
- the exceptional trigger is active: commit a PASS report for the exact
  candidate before green GitHub and CodeQL may authorize its signed tag;
- `v0.11.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.11.1 - Sanitization Adapter Admission Review

Status: released

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
  fixtures, then pass repository policy, SBOM, documentation, development-tag,
  and exceptional-trigger gates.

Exit criteria:

- a committed, evidence-backed admit-or-reject decision preserves every Brynja
  destruction and isolation invariant without adding a production dependency;
- the exceptional assessment is complete: its one Medium error-payload
  remanence finding is closed by signed remediation, the repository-owner
  retest is PASS with zero open findings, and the permanent report is committed
  for the exact candidate before tagging;
- `v0.11.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.11.2 - Optional Brynja Sanitization Adapter

Status: released

Plan scope: Conditional on the v0.11.1 admission decision, implement and prepare for separate publication at the next scheduled or exceptional release checkpoint a `no_std` `brynja-sanitization` downstream adapter using exact-pinned `sanitization` with default features disabled, adapter-owned wrapper types, and identical modern and legacy destruction semantics; keep it out of every facade, engine, default feature, and FIPS validated-module closure, or close the milestone with documented non-admission if any invariant cannot be preserved.

Goal: provide an explicitly selected first-party sanitization integration
without making Brynja depend on it or creating a weaker legacy destruction
domain.

Deliverables:

- if admitted, add the separately versioned `brynja-sanitization` package with
  adapter-owned secret wrappers and narrow conversions over frozen
  `brynja-core` contracts, but defer crates.io publication to the next
  scheduled or exceptional release checkpoint;
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
- pass the full repository, documentation, advisory, isolation, development-tag,
  and exceptional-trigger gates; validate the future independent-crate
  publication plan without uploading it.

Exit criteria:

- either the optional adapter is independently usable with identical modern and
  legacy guarantees and no core or FIPS dependency, or a documented
  fail-closed non-admission leaves the production graph unchanged;
- the exceptional repository-owner assessment records PASS/PASS with zero open
  findings in `security/pentest/v0.11.2.md`;
- `v0.11.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.12.0 - Constant-Time Foundation

Status: released

Plan scope: Implement constant-time equality, choice and mask types, conditional select and swap, fixed-width secret operations, compiler barriers, and rules forbidding secret-dependent control flow, indexing, loop counts, and error timing.

Goal: complete the **Constant-Time Foundation** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement opaque normalized `Choice` and full-width `CtMask` values without
  ordinary equality, formatting, hashing, ordering, or raw-mask exposure;
- implement infallible constant-time equality, conditional selection, and
  conditional swap for every unsigned word width and compile-time byte array,
  with one explicit final-decision declassification API;
- provide an explicit compiler/optimization barrier while documenting that it
  does not itself prove downstream code generation, timing, synchronization,
  or destruction;
- confine fixed-array passes, reject value-dependent control flow, dynamic
  byte slices, indexed access, variable error surfaces, representation drift,
  and barrier weakening through reviewed source hashes and broken fixtures;
- update threat model, controls, status, limitations, release notes, and
  permanent evidence index without claiming a cryptographic algorithm.

Verification:

- exhaust all 65,536 byte-equality and byte-selection pairs, both choices for
  every unsigned width, zero-length and fixed-array equality, every mismatch
  position, selection and swap, representation size, and barrier identity;
- compile-fail ordinary decision equality, formatting, and mask construction;
  run twelve source-policy regressions and five evidence-matrix regressions;
- inspect fixed-work 32-byte and word roots in optimized LLVM IR and assembly
  across Rust 1.90.0 through 1.97.1 and every promised target, permitting only
  a public-width-32 loop where a target does not unroll an array pass;
- inspect each concrete assembly function body with target-specific branch
  rules, canonicalize RV32 numeric argument-register aliases, classify all
  eighteen base, pseudo, and compressed conditional forms, reject direct
  Choice-register branches and memory addressing, and retain negative fixtures
  for secret branches, secret-indexed loads, aliases, and public-loop classification;
- preserve `no_std`, no-allocation, no-new-unsafe, dependency, modern/legacy,
  zeroization, and source-file-size boundaries;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the fixed-width foundation is deterministic, infallible, allocation-free,
  platform-independent, and carries exact source and emitted-code evidence
  without extending that evidence into a proof or independent verification;
- the exceptional trigger is active: commit a PASS report for the exact
  candidate before green GitHub and CodeQL may authorize its signed tag;
- any assessment finding keeps the tag blocked until remediation passes the
  complete compiler/target matrix and the repository owner reports a green
  retest;
- `v0.12.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.13.0 - Provider Capabilities And Opaque Handles

Status: released

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
- test arena overlap, malformed framing, unavailable effects, dependency inversion, cancellation, optimization, cache and DMA duties, exact provider retention, provider-owned work charging, and absence of request-side terminal claims;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe, platform-independent, and reviewably destroys owned secrets;
- the voluntary assessment activated an exceptional trigger; the exact signed
  remediation candidate passed repository-owner retest with zero open findings;
- `v0.13.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.13.1 - CPU Backend Capability And Dispatch Contract

Status: released

Plan scope: Before any cryptographic primitive exists, freeze first-party scalar, opportunistic-accelerated, required-accelerated, and validated-module backend policies; separate candidate detection from admitted activation; define exact feature-bundle evidence, non-forgeable thread-bound capability tokens, backend identity, per-operation dispatch, startup known-answer tests, health generations, quarantine, fail-closed required mode, and secret-free reporting so safe code cannot execute an unsupported instruction or silently change service approval.

Goal: freeze the CPU-backend security contract before an ISA-specific implementation can constrain cryptographic APIs or provider ownership.

Deliverables:

- define sealed backend identifiers, exact operation and feature bundles, candidate and active states, scalar, opportunistic, required and validated policies, and value-free unavailable, unhealthy and quarantined results;
- define safe compiler-proven construction, a separately reviewed platform-evidence boundary, thread and CPU-migration rules, KAT generations, permanent quarantine, explicit initialization, and non-recursive scalar fallback;
- bind backend and service-approval reporting to mandatory provider results while keeping reports secret-free, observational, allocation-free and incapable of authorizing work.

Verification:

- compile-fail forged tokens, cross-thread movement, feature-bundle mismatch, unsupported operations, generic-provider injection and validated-policy substitution;
- model concurrent first use, recursion, panic, cancellation, fork or runtime cloning, KAT failure, quarantine generation changes, required-mode failure and opportunistic scalar fallback;
- pass no_std, no-atomics, supported Rust matrix, package-isolation, documentation, threat-model and FIPS-boundary checks with no ISA code admitted.

Exit criteria:

- safe callers cannot reach an unsupported instruction and every fallback or required-mode refusal is explicit in authoritative state;
- record PASS/PASS with zero open findings after the repository-owner retest closed the exceptional assessment's cross-instance KAT replay, CPU-migration, and guarded-entry callback/closure TOCTOU findings on exact signed remediation candidate `738d21227d9681299d7464d9df360cf49cac8cca`;
- `v0.13.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.13.2 - CPU Acceleration Package And Unsafe Boundary

Status: released

Plan scope: Freeze future `brynja-crypto-cpu` as an optional zero-dependency `no_std` package for isolated ISA kernels and static selection, and future `brynja-crypto-cpu-std` as a separate opt-in `std` runtime-detection adapter; keep scalar `brynja-crypto`, every protocol engine, default feature, bare-metal graph, and ordinary facade independent of both, keep the std adapter outside `brynja-fips-module`, and require a separately hashed, versioned, under-500-line unsafe-intrinsic or assembly boundary for every admitted backend without authorizing any implementation yet.

Goal: make ISA code and host runtime detection independently selectable and auditable without weakening the scalar, no_std, dependency or FIPS closures.

Deliverables:

- reserve and classify the two packages, dependency directions, empty default features, publication roles, ordinary-facade exclusion, scalar ownership and exact FIPS inclusion and exclusion rules;
- specify per-backend source modules, exact hash inventory, local unsafe allowances, instruction and ABI preconditions, safe wrapper invariants, maximum file size and amendment process;
- prohibit third-party detection crates, build-time source inclusion, implicit std, OS entropy or other platform services, and feature unification that changes a validated artifact.

Verification:

- use broken manifests and package graphs to test default, no-default, all-feature, bare-metal, ordinary facade, legacy, std-adapter and future FIPS isolation;
- reject unclassified intrinsics, assembly, FFI, local lint escapes, unhashed source, oversized modules, dependency cycles, std leakage and an activated backend without its contract;
- package and docs-test both reserved boundaries across the Rust and target matrix while proving the current production graph and unsafe inventory remain unchanged.

Exit criteria:

- package and unsafe-policy enforcement can admit one exact future backend without granting authority to any sibling backend or std adapter;
- record the exceptional assessment's High source-admission and Medium policy-integrity findings, their exact remediation, and repository-owner PASS/PASS retest before the signed tag; and
- `v0.13.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.13.3 - Native CPU Evidence And Performance Admission Harness

Status: released

Plan scope: Establish reproducible backend evidence manifests, forced-backend and unsupported-feature processes, KAT and quarantine fault injection, scalar differential corpora, emitted-code and side-channel capture, code-size and latency budgets, and benchmark admission thresholds across local AMD x86_64, an observed-feature AWS Intel x86_64 instance, Apple M2, AWS AArch64, and the available RISC-V cloud host; record CPU, microcode, OS, compiler, flags, frequency policy, and feature evidence, treat emulation as supplemental only, and leave an unavailable or unmeasured backend unadmitted rather than blocking portable scalar support.

Goal: make correctness, security and useful performance—not architecture labels—the admission criteria for every optimized backend.

Deliverables:

- define a machine-readable evidence schema for CPU identity, observed features, microcode or firmware, OS, compiler, flags, runner ownership, clock and frequency policy, operation, size distribution and raw result hashes;
- implement first-party forced-backend, required-no-fallback, negative unsupported-instruction, KAT fault, quarantine, scalar differential, concurrency-isolation, emitted-code, code-size, cold-start, latency, throughput and side-channel harness contracts;
- register the local AMD and M2 lanes, AWS Intel and Arm lanes selected by observed features rather than product name, the slow RISC-V lane, and QEMU only as supplemental instruction coverage.

Verification:

- validate schema regeneration, provenance, stale-run rejection, missing feature evidence, fabricated native labels, mixed CPUs, noisy or non-finite measurements and benchmark-order bias;
- run scalar and mock-backend positive, mismatch, unsupported, quarantine, concurrency and required-mode fixtures under host tests and a dependency-free no_std/no-atomics model across OS-less targets; exercise emulated-label and QEMU-promotion refusal as supplemental fixtures because no ISA kernel yet exists to execute;
- prove an unavailable Intel instance, non-qualifying RISC-V ISA or unreachable runner produces an explicit unadmitted result without creating a false support claim or blocking scalar builds.

Exit criteria:

- every future backend has a reproducible route to native admission and emulation cannot satisfy native performance or side-channel evidence;
- record PASS/PASS with zero open findings after repository-owner retest confirmed both High findings resolved on exact signed first remediation candidate `7de753a57e942c28dac8406d8f93d62c4767de3a` and the follow-up Low parser finding resolved on exact signed second remediation candidate `1f08ca0fd9be6bf1995a22a9ca806addc17641e0`; and
- `v0.13.3 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.14.0 - Entropy And Secure-Random Contracts

Status: released

Plan scope: Separate affine caller-provided raw entropy from non-cloneable initialized secure randomness; bind exact purpose, strength capacity, bytes, runtime generation, fork and bounded reseed rules, transactional caller-owned output, retryable versus permanently quarantined failure, synchronous destruction, and a deterministic/fault provider confined to unpublished test support; add no algorithm, OS RNG, FFI, source-quality, independent-verification, or FIPS claim.

Goal: complete the **Entropy And Secure-Random Contracts** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement affine raw-entropy requests with exact instantiation/reseed purpose,
  declared 128/192/256-bit strength capacity, exact byte length, bounded input,
  and complete-region clearing without claiming source quality;
- implement a non-cloneable initialized secure-random wrapper with exact engine
  strength, successful-request reseed accounting, runtime-generation and fork
  invalidation, retryable/permanent failure separation, terminal quarantine,
  and synchronous explicit/Drop destruction duties;
- expose output only after exact complete transactional initialization; clear
  pre-existing bytes and every partial, mismatched, retryable, permanent,
  underfilled, exhausted, forked, or rollback result;
- add deterministic and fault-injecting test support only to permanently
  unpublished `brynja-test-support`, with no production dependency path;
- freeze upstream capability types, caller limits, transactional effects,
  mandatory zeroization, version-neutral framing, provider failure, and
  secret-free errors;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run exact bound, strength, purpose, interval, output-size, compile-fail,
  no-mutation, no_std, zeroization, runtime-generation, fork, reseed,
  retry/permanent-fault, underfill, teardown, and deterministic-provider tests;
- enforce reviewed hashes, the 500-line ceiling, no std/alloc/unsafe/FFI/OS
  randomness, secret-state trait exclusions, and repository-only provider
  isolation with positive and nine broken policy fixtures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- the upstream foundation is deterministic, hostile-input safe,
  platform-independent, reviewably destroys owned secrets, and makes no
  entropy-quality, DRBG, OS-source, FIPS, or independent-verification claim;
- record PASS/PASS with zero open findings after repository-owner retest
  confirmed the Medium explicit-teardown terminal-handler omission resolved on
  exact signed remediation candidate
  `854c301de56ba432bd0544e2acc525b34a7b28c8`; and
- `v0.14.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.15.0 - Wall And Monotonic Clock Contracts

Status: released

Plan scope: Define non-interchangeable typed wall time for PKI and typed monotonic time for timers, freshness, tickets, and replay policy with checked arithmetic and explicit unavailable-time behavior.

Goal: complete the **Wall And Monotonic Clock Contracts** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement canonical nonnegative durations and signed Unix wall time with
  checked carry, borrow, range, direction, and representability behavior;
- define inclusive PKI-oriented wall-time ranges and a value-free unavailable
  result, while leaving every OS clock read to a downstream capability;
- define opaque monotonic instants bound to one explicit nonzero runtime/boot
  generation, with no raw-tick accessor, redacted formatting, checked elapsed
  time, and permanent rollback failure;
- bind monotonic deadlines to exact timer, freshness, ticket, or replay purpose
  and their originating generation, rejecting cross-purpose and cross-generation
  use without substitution;
- add deterministic scripted wall and monotonic sources only to permanently
  unpublished test support, with no production dependency path;
- prepare the cumulative public package set after v0.10.0 in dependency order,
  but keep publication blocked until the scheduled cumulative pentest report,
  hosted checks, explicit tag authorization, and exact tag are complete;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run canonical subsecond, signed epoch, carry, borrow, overflow, underflow,
  reversed-range, inclusive-boundary, generation-exhaustion, equal-tick,
  rollback, unavailable, purpose, deadline, and deterministic-source tests;
- compile-fail wall/monotonic interchange and raw-instant construction; enforce
  reviewed hashes, private raw state, redacted monotonic formatting, the
  500-line ceiling, no std/alloc/unsafe/FFI/OS-clock access, and repository-only
  fixture isolation with nine broken policy fixtures;
- verify every selected package, exact internal pin, publication order, package
  archive, SBOM, cumulative delta after v0.10.0, and committed-report
  fail-closed behavior without uploading or creating the tag;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- wall and monotonic values cannot be interchanged, all time arithmetic is
  checked, unavailable time is explicit, clock rollback fails permanently, and
  no OS clock, protocol timer engine, PKI validation, ticket service, replay
  store, cryptographic algorithm, independent verification, or FIPS claim is
  implied;
- `v0.15.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

### v0.16.0 - Pending Operations And Accelerator Lifecycle

Status: released

Plan scope: Define resumable provider tokens, certificate, signature and accelerator requests, cancellation, retry semantics, backpressure, and failure-atomic state transitions; external-key and accelerator-handle destruction completes only through a mandatory single-consumption token transition, never through an informational event.

Goal: complete the **Pending Operations And Accelerator Lifecycle** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- admit only exact certificate-path, external-signature, and accelerator-
  eligible provider requests whose chosen provider also declares poll, cancel,
  and applicable external-store or accelerator destruction duties;
- bind each affine request to immutable nonzero effect-attempt and
  backpressure-response limits, preserving the same request on no-state begin
  retry or backpressure and failing closed at every checked counter boundary;
- define a downstream `PendingProvider` effect whose begin result creates
  either no state or exactly one opaque state; bind that effect to the exact
  installed-provider handle that authorized the request and reject substitution
  before begin or any later provider effect;
- require bounded, effect-free provider cost derivation before begin, resume,
  or cancellation; debit the authoritative monotonic meter and issue one
  non-forgeable, nonzero work permit before the corresponding effect;
- split bounded effect-free inert state preparation from effectful activation;
  construct `PendingOperation` with prepared state before activation can create
  an external resource; recheck exact provider identity after guarded
  preparation immediately before activation; and make activation, resume, cancellation, and
  destruction borrow that state so recoverable unwinding leaves partial state
  available to mandatory `Drop` cleanup;
- make completion, cancellation, provider failure, exhaustion, and `Drop`
  synchronously consume provider state through one non-cloneable destruction
  token covering frozen local, external-store, accelerator, cache, and DMA
  duties; completion or cancellation is authoritative only after that token is
  consumed into a complete result;
- return only closed secret-free retry, backpressure, provider, exhaustion,
  and destruction outcomes; route failed destruction reached through `Drop`
  to the mandatory durable/fail-stop provider hook;
- add deterministic scripted provider tests and reviewed source policy without
  adding an implementation, registry, thread, allocator, OS, FFI, unsafe, or
  cryptographic dependency;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run exact-kind, wrong-direction, missing-capability, missing-duty, zero-limit,
  provider-substitution, preparation-time identity change, provider-derived charge, zero-charge, work-exhaustion,
  pre-resource, post-resource, and partial-mutation begin unwind, begin-unwind
  destruction failure, resume/cancel unwind, no-state begin, retry,
  backpressure, active, complete, cancel, provider-fail,
  attempt-exhaustion, backpressure-exhaustion, destruction-fail, `Drop`, and
  input-preservation tests with a deterministic provider;
- compile-fail affine request, operation, destruction-token duplication, and
  work-permit forgery; enforce checked counters, exact provider identity,
  borrowed callback state, lifecycle-only work charging, exact single-
  consumption methods, terminal `Drop` handling, reviewed hashes, private
  state, the 500-line ceiling, and no std/alloc/unsafe/FFI/platform access with
  twenty-one broken policy fixtures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- certificate, signature, and accelerator requests cannot cross kinds; retry
  and backpressure cannot duplicate state or bypass caller bounds; an
  authorizing provider cannot be substituted; effect work cannot run without a
  provider-derived accepted charge; no effectful activation runs before state
  is lifecycle-owned or without a post-preparation identity check; recoverable
  callback panic cannot evade cleanup; every
  state-owning terminal path attempts authoritative destruction;
  and no provider implementation, certificate validation,
  signature, accelerator, platform effect, protocol engine, independent
  verification, or FIPS claim is implied;
- the exceptional repository-owner retests report all five findings (three
  High and two Medium) closed with zero open findings on exact signed final
  remediation candidate `f0557b8419b77129d1763e9469ae4e7deeffc2e7` before the
  report-bearing candidate may proceed through green GitHub and CodeQL to
  explicit signed-tag authorization; no crates.io publication is selected.
- `v0.16.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.17.0 - FIPS-Aware Provider Architecture

Status: released

Plan scope: Freeze broad operation classification with every current capability explicitly non-approved and every nonempty approved set rejected until exact service identities span execution; add self-test and permanent-failure hooks, exact scalar and CPU-backend dispatch ownership, non-authorizing service indicators, provider-derived SSP destruction duties, deterministic module-build expectations, CPU-feature and operational-environment assumptions, and sealed-provider exclusions; ordinary opportunistic or std-adapter selection can never enter or alter the future module, and no validation claim is made.

Goal: complete the **FIPS-Aware Provider Architecture** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- add broad operation-category service sets, require every current
  installed-provider capability to be explicitly non-approved, and reject
  every nonempty approved set until exact algorithm, parameter, backend and
  usage identities span provider manifests, requests, effects and results;
  reject overlap, omission, and unsupported work;
- bind one nonzero operational-environment identity to an exact module-owned
  scalar or accelerated backend and its complete required feature bundle;
  explicitly reject the ordinary validated-module placeholder and expose no
  `BackendPolicy`, opportunistic dispatch, std detection, or std adapter;
- freeze nonzero deterministic source, toolchain, flags, and dependency digest
  expectations without claiming the final validated binary identity;
- freeze internal/import/export SSP-flow intent and derive mandatory nonempty
  complete-copy destruction targets directly from the installed provider,
  without a caller-configurable second source or an implemented port or erasure;
- require exact integrity and algorithm-known-answer self-tests through an
  explicitly trusted runner; keep the completion guard private and permanently
  latch failure on rejection, reentry, interruption, unwind, impossible state,
  generation exhaustion, or a later catastrophic event;
- issue only non-cloneable, non-formattable, thread-bound informational service
  indicators tied to one broad operation category, disposition, provider and
  health generation; give them no provider-execution authority and invalidate
  all outstanding indicators after terminal failure;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run service-set, duplicate, empty-side, overlap, omission, unsupported,
  nonempty-approved rejection, environment identity, backend owner, feature
  bundle, build digest, provider-derived SSP duty, pre-test indication,
  successful test, failed test, interrupted test,
  reentry, catastrophic failure, generation invalidation and unsupported-service
  tests;
- compile-fail raw service-set construction, ordinary backend-policy injection,
  and service-indicator cloning; enforce reviewed hashes, private state,
  permanent-failure transitions, exact provider classification, the 500-line
  ceiling, and no std/alloc/unsafe/FFI/runtime-detection/ordinary-dispatch/global
  state with twenty-four broken policy fixtures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every provider capability is explicitly non-approved until an exact service
  identity exists; an operation-only indicator cannot authorize execution;
  indication is impossible before the exact self-test plan passes; failure is
  permanent and invalidates earlier indicators; provider-derived destruction
  duties cannot be weakened; module backend identity and feature
  assumptions are exact; ordinary dispatch cannot alter the boundary; and no
  module, algorithm, self-test implementation, service execution, build
  reproduction, SSP effect, provider effect, independent verification,
  certificate, CMVP submission, or FIPS validation is implied; current
  permanent failure remains caller-session-scoped, and v0.127.1 must make it
  module-wide and sibling-proof before any executable or approved FIPS service;
  the application-implementable self-test runner is trusted but non-authorizing,
  and v0.125.0/v0.127.0 must require and internally issue an opaque module-owned
  attestation before execution or approved status can become reachable;
- the exceptional assessment's two High findings are remediated, the exact
  signed remediation candidate receives a green repository-owner retest, and
  the permanent report records `PASS`/`PASS` with zero open findings;
- `v0.17.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.18.0 - Mandatory Security Outcome Authority Contract

Status: released

Plan scope: Define authoritative engine state and exhaustive mandatory typed results for self-tests, service approval, protocol and profile selection, authentication, tickets, resumption, PSKs, early data, anti-replay, amplification, exhaustion, provider failure, key lifecycle, ECH, policy, and terminal transitions; public inputs cannot forge accepted or approved authority without sealed exact-subject evidence, each validated disposition has an opaque non-interchangeable result with private reasons and an exact authority-retained commit match, self-test failure is permanently terminal, every resolved non-terminal result requires an affine commit whose abandonment fails closed, pending abandonment fails closed, external-key destruction completes only through an exact mandatory token transition, and ignoring every informational output cannot make rejected, non-approved, incomplete, or failed work appear accepted, approved, complete, or successful.

Goal: complete the **Mandatory Security Outcome Authority Contract** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- add sealed type-level domains for every named decision and an allocation-free
  caller-owned authority whose checked generation permits only one incomplete
  decision and permanently latches exact terminal reasons;
- define authoritative mandatory results and state transitions for service
  approval, external-key destruction, authentication, ECH, early data,
  anti-replay, and policy decisions, with exact success, rejection, pending,
  cancellation, failure, and terminal semantics;
- prevent public resolution values from establishing accepted or approved
  authority; require every future positive path to consume sealed evidence
  bound to its exact subject, operation, provider, authority, and generation;
- give each accepted, approved, non-approved, rejected, canceled, and failed
  disposition an opaque non-interchangeable result, keep validated reasons
  private and read-only, and retain the exact disposition in authority state
  for commit-time comparison;
- hold resolved non-terminal work in an authoritative `AwaitingCommit` state
  behind an affine completion, permanently fail on pending or completion
  abandonment, and permanently latch mandatory self-test failure as integrity
  failure;
- require external-key success to consume a non-cloneable, thread-bound token
  for the exact external-store target and reject duplicate, cross-authority,
  cross-generation, failed, or abandoned completion;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- exhaustively exercise inaccessible caller-forged acceptance/approval plus
  rejected, non-approved, pending,
  destruction, authentication, ECH, early-data, anti-replay, and policy paths
  and prove mandatory results and engine state are complete and unambiguous;
- discard pending and resolved authoritative values, inject self-test,
  cancellation and provider failure, and prove abandonment terminalizes rather
  than unlocking or permanently busying the authority;
- compile-fail rejection-to-acceptance, non-approval-to-approval, reason
  substitution, cross-disposition conversion, pending-decision and external-key
  token cloning, and pending cross-thread movement; enforce reviewed hashes, private state, the
  500-line ceiling, and
  no std/alloc/unsafe/FFI/provider-effect/audit-event boundary with eighteen
  or more broken policy fixtures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every security decision and completion is authoritative, mandatory, and
  unambiguous without relying on an audit or informational path; no public
  resolution can forge positive authority, every future positive path requires
  sealed exact-subject evidence, no validated disposition or reason can be
  relabeled before commit, commit matches exact authority-retained disposition,
  uncommitted resolution and pending abandonment fail terminally, mandatory self-test failure cannot recover, rejection and
  failure reasons cannot cross their typed domains, terminal transitions cannot
  claim non-terminal success, and external-key
  destruction cannot complete without its exact consumed token;
- `v0.18.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.18.1 - Bounded Observational Security Event Schema

Status: released

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

Implementation evidence:

- four hash-locked source modules keep the event, timestamp record, and queue
  contracts independently reviewable and below 500 lines;
- ten integration tests and two internal boundary tests cover all seventeen
  decision domains, every closed event class, exact negative and accepted
  outcomes, terminal snapshots, timestamp-free and later-enriched records,
  deterministic FIFO ordering, zero/full capacity, absent drains, visible
  saturation, and generation-free equality;
- three compile-fail examples and twenty-two broken policy fixtures reject
  event forging, authorization, reentrant mutable access, dynamic or secret
  payloads, identifiers, callbacks, alert/provider/authority crossings,
  wrapping counters, public state, oversized files, and reviewed-source drift.
- the exceptional repository-owner assessment of exact signed implementation
  candidate `9ff9a459d8caae7e7f5c18b6576647487ba5b251` passed with zero
  findings and is permanently recorded in `security/pentest/v0.18.1.md`;

Exit criteria:

- events are bounded audit duplicates whose absence or loss cannot change or
  obscure any security outcome;
- `v0.18.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.19.0 - TLS And DTLS Record Framing

Status: awaiting pentest

Plan scope: Keep record framing independent of protocol selection and fallback; ignore TLSPlaintext legacy_record_version where required, validate TLSCiphertext constants where applicable, preserve bytes, reject RFC 6520 Heartbeat content and negotiation in every modern profile, and leave version choice exclusively to typed handshake policy.

Goal: establish one bounded, allocation-free record-envelope boundary shared
by the modern TLS and DTLS engines, without permitting wire bytes to choose a
protocol version or claiming a record-protection or handshake engine.

Deliverables:

- add unpublished `brynja-protocol 0.1.0`, directly exposed by the development
  facade and consumed by the TLS 1.2, TLS 1.3, and DTLS engine boundaries;
- add typed `WirePolicy` profiles supplied only after external protocol
  selection; keep their fields private and never infer, negotiate, downgrade,
  or fall back from record bytes;
- parse and encode borrowed TLS 1.2/TLS 1.3 plaintext and ciphertext envelopes,
  including profile-specific length, nonempty, content-type, and
  `legacy_record_version` rules;
- parse and encode borrowed DTLS 1.2 plaintext/ciphertext envelopes and DTLS
  1.3 plaintext and unified ciphertext headers, including exact CID length,
  short/long sequence-number forms, and optional-length datagram semantics;
- preserve permitted legacy-version and unknown content-type bytes, reject RFC
  6520 Heartbeat content and extension negotiation in every modern profile,
  and keep all errors closed and payload-free;
- use caller-owned output only, preflight complete writes, and leave buffers
  unchanged on failure; perform no allocation, I/O, cryptography, decryption,
  authentication, replay processing, or handshake transition;
- bind reviewed source hashes, file-size and forbidden-boundary rules, 29
  negative policy fixtures, requirements and protocol-surface evidence, threat
  model, controls, status, release notes, and crate documentation.

Verification:

- exhaustively classify all 256 content-type bytes; test known, unknown, and
  forbidden Heartbeat values plus rejected Heartbeat extension admission;
- test TLS and DTLS profile/version separation, exact maximum lengths,
  ciphertext constants, empty-record rules, all header truncations, trailing
  stream/datagram bytes, DTLS epoch/CID/sequence layouts, and transactional
  short-output rejection;
- compile-fail private content-type construction, policy-field construction,
  and record formatting; run the crate tests, documentation tests, no-default
  and all-feature graphs, `no_std` targets, lint, package, and policy fixtures;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Implementation evidence:

- `crates/brynja-protocol/src/lib.rs` and
  `crates/brynja-protocol/src/tls/{content_type,error,record,dtls,dtls12_ciphertext}.rs`;
- `crates/brynja-protocol/tests/{wire_policy,tls_records,dtls_records}.rs`;
- `scripts/{record_framing_policy,check-record-framing,test-record-framing}.py`;
- `standards/protocol-surfaces.json` and the generated requirement matrix,
  indexes, and coverage artifacts.

Exit criteria:

- framing is deterministic, allocation-free, caller-buffer transactional,
  independent of version selection, and bounded before any future
  cryptographic or state-machine processing;
- because this is Brynja's first hostile protocol parser, v0.19.0 is an
  exceptional pentest trigger even though it remains an internal milestone
  with zero crates.io publication;
- `v0.19.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.20.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.21.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

## Phase 1: First-Party Cryptography, Identity Formats, And PKI

Import-only RSA and exact AEAD caller-buffer behavior precede audit gates.

### v0.22.0 - SHA-256

Status: planned

Plan scope: Freeze the reusable no_std `brynja-hash-core` interface and `brynja-hash-sha2` family boundary, then implement streaming and fixed-message SHA-256 with official vectors, boundary lengths, and exhaustion handling; make `brynja-crypto`, TLS, PKI, and later FIPS consumers use that exact implementation without exposing the post-1.0 standalone facade or admitting unrelated hash families.

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
- `v0.22.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.22.1 - SHA-256 x86_64 And AArch64 Acceleration

Status: planned

Plan scope: Add separately forced and reported SHA-256 backends using exact x86_64 SHA-extension bundles on AMD and Intel and exact AArch64 SHA2 bundles on Apple M2 and AWS Arm; preserve the scalar state and digest API, streaming and fixed-message equivalence, checked length and exhaustion behavior, safe std and static no_std dispatch, startup KAT quarantine, and per-compiler constant-time and emitted-code evidence without claiming register erasure.

Goal: accelerate SHA-256 on the available AMD, Intel, Apple and AWS Arm lanes without changing its portable semantics or widening its cleanup claims.

Deliverables:

- implement isolated x86_64 SHA-extension and AArch64 SHA2 compression backends behind the frozen per-operation contract and exact feature bundles;
- retain scalar ownership of padding, checked bit length, streaming state, finalization and exhaustion while exposing forced backend and actual-backend reporting;
- add backend-specific startup KATs, health generations, quarantine, no_std static selection, opt-in std detection and explicit register, spill and context-switch residuals.

Verification:

- run official vectors, every padding boundary, arbitrary chunk partitions, fixed-versus-streaming, maximum-length and exhaustion differentials through each direct backend;
- run unsupported-feature negative processes, KAT and corruption fault injection, dispatch precedence, quarantine, required mode and scalar fallback on local AMD, observed-feature AWS Intel, M2 and AWS Arm;
- inspect MIR, LLVM and assembly and collect constant-time, code-size, cold-start and representative TLS transcript and HMAC-size performance evidence across the supported compiler matrix.

Exit criteria:

- each admitted path is byte-identical to scalar, measurably useful on its named native lanes and unreachable without exact feature evidence;
- `v0.22.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.22.2 - SHA-256 RISC-V Acceleration Candidate

Status: planned

Plan scope: Implement a first-party RISC-V SHA-256 backend only for an exact ratified scalar-crypto or vector-crypto feature bundle expressible across the supported Rust line; run it on the available RISC-V host when its observed ISA qualifies, otherwise retain it as a non-dispatchable candidate with emulator and generated-code evidence, keep scalar fallback authoritative, and prohibit an accelerated support claim until matching native correctness, performance, and side-channel evidence exists.

Goal: prepare honest RISC-V SHA-256 acceleration without treating generic RISC-V, RVV presence or emulation as proof of a cryptographic instruction path.

Deliverables:

- select and document exact ratified RISC-V feature bundles, compiler and assembler support, ABI and vector-state assumptions, and the stable-Rust compatibility strategy;
- implement the isolated candidate, forced direct entry, KAT, health and static-token integration while leaving automatic activation disabled until admission evidence exists;
- preserve scalar support on every RISC-V target and publish candidate, admitted or unavailable status with the observed cloud-host ISA and residual gaps.

Verification:

- run official vectors, chunking, boundary, exhaustion and scalar differential corpora under cross-build and QEMU instruction coverage;
- inspect generated code on every supported compiler and run unsupported-feature images in isolated processes so safe selection cannot issue an unavailable instruction;
- when the cloud host qualifies, collect native correctness, timing and performance evidence; otherwise verify that reporting remains non-admitted and dispatch remains scalar.

Exit criteria:

- the candidate is either natively admitted with complete evidence or remains mechanically non-dispatchable with no RISC-V acceleration claim;
- `v0.22.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.23.0 - SHA-384 And SHA-512

Status: planned

Plan scope: Extend the reusable `brynja-hash-sha2` family with SHA-384 and SHA-512 using official vectors and checked length and exhaustion behavior; preserve one compression, padding, streaming, CPU-backend, and provider ownership model that later standalone SHA-2 variants can reuse without duplicating TLS cryptography.

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
- `v0.23.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.23.1 - SHA-384 And SHA-512 CPU Acceleration

Status: planned

Plan scope: Add benchmark-admitted x86_64, AArch64, and qualifying RISC-V SHA-384/SHA-512 backends using exact specialized or parallel feature bundles; require byte-for-byte scalar equivalence for every chunking and boundary, forced-path KAT and quarantine behavior, safe static and runtime selection, native AMD, Intel, M2, AWS Arm, and available qualifying RISC-V evidence, and an explicit scalar decision wherever a backend is unavailable or fails the frozen performance margin.

Goal: accelerate the SHA-512 family only where an exact native backend improves the TLS and signature workloads that use it.

Deliverables:

- implement separately identified specialized-instruction or parallel SHA-512-family kernels without changing scalar padding, truncation, streaming or exhaustion ownership;
- bind each operation and message-size admission range to exact x86_64, AArch64 or RISC-V feature evidence, KAT state and dispatch reporting;
- record reviewed scalar-only decisions for unavailable ISA support, poor short-message performance, compiler incompatibility or incomplete side-channel evidence.

Verification:

- differential-test official SHA-384 and SHA-512 vectors, every block and padding boundary, arbitrary chunking, truncation and exhaustion through every forced path;
- exercise native AMD, observed-feature Intel, M2, AWS Arm and qualifying RISC-V paths plus unsupported, KAT failure, quarantine and required-mode processes;
- inspect per-compiler emitted code and measure transcript, HMAC, certificate-signature and long-stream sizes without averaging unsupported paths into an admission result.

Exit criteria:

- every CPU family has an explicit evidenced backend or scalar-only decision and no wider ISA is admitted merely because it is available;
- `v0.23.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.24.0 - Keccak SHA-3 And SHAKE

Status: planned

Plan scope: Freeze a reusable no_std `brynja-hash-sha3` family around one private Keccak-f[1600] ownership boundary, then implement SHA3-256, SHA3-512, SHAKE128, and SHAKE256 as the required ML-KEM foundation; keep domain-separated fixed-output and XOF interfaces extensible for post-1.0 variants without exposing a raw permutation or duplicating protocol cryptography.

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
- `v0.24.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.24.1 - Keccak SHA-3 And SHAKE CPU Acceleration

Status: planned

Plan scope: Add architecture-specific Keccak-f[1600], SHA3, and SHAKE backends for admitted x86_64, AArch64, and RISC-V vector or bit-manipulation bundles only where native benchmarks justify them; preserve domain separation, absorb, squeeze, permutation, and arbitrary-output equivalence, force every backend and tail path, and record scalar-only decisions for CPUs or operations that do not beat the portable implementation.

Goal: improve SHA-3, SHAKE and later ML-KEM workloads without weakening Keccak domain or variable-output correctness.

Deliverables:

- implement isolated permutation backends and parallel lanes only for exact, reviewed feature bundles and operation-size ranges;
- retain scalar sponge state, domain suffix, padding, absorb and squeeze accounting as the semantic reference and expose each direct permutation symbol to tests;
- integrate KAT, quarantine, static no_std and opt-in std selection while keeping candidate and active backend reporting distinct.

Verification:

- run official permutation, SHA3 and SHAKE vectors, zero and long output, partial absorb and squeeze, every rate boundary and scalar differential corpus;
- force each width, lane count and tail, inject permutation and KAT faults, and test unsupported features, quarantine, required mode and scalar fallback;
- collect native AMD, Intel, M2, AWS Arm and qualifying RISC-V emitted-code, side-channel and performance evidence for hash and ML-KEM-size workloads.

Exit criteria:

- every admitted permutation is domain-correct, scalar-equivalent and useful for its declared operation and length range;
- `v0.24.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.25.0 - HMAC

Status: planned

Plan scope: Freeze a reusable no_std `brynja-mac-hmac` boundary over the admitted fixed-output hash interface, then implement HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with constant-time verification and misuse tests; keep MAC keys, tags, verification, and truncation distinct from unkeyed digest types so later standalone hashing reuses rather than copies the construction.

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
- `v0.25.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.26.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.27.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.27.1 - AES x86_64 And AArch64 Acceleration

Status: planned

Plan scope: Add isolated AES-128 and AES-256 encrypt backends for exact x86_64 AES-NI or VAES bundles and exact AArch64 AES bundles, with AMD, observed-feature AWS Intel, Apple M2, and AWS Arm native evidence; retain the portable constant-time implementation, typed key ownership, identical round and key-schedule semantics, startup KAT quarantine, no_std static selection, opt-in std runtime selection, and exact per-backend side-channel and destruction residuals.

Goal: admit hardware AES on the available x86_64 and AArch64 systems while preserving the portable implementation as the semantic and unsupported-target fallback.

Deliverables:

- implement isolated AES-NI, benchmark-qualified VAES and AArch64 AES encrypt and key-schedule paths with exact feature bundles and operation identities;
- bind secret key ownership, expanded-key destruction, KAT state, health generation and backend reporting to the existing AES API without exposing raw backend selection through safe protocol configuration;
- define single-block, parallel-block and message-size dispatch ranges from native evidence rather than ISA width and document all register, spill and termination exclusions.

Verification:

- run official AES-128 and AES-256 vectors, key-schedule and round differentials, every admitted block count, overlap contract and injected backend corruption;
- exercise local AMD, observed-feature AWS Intel, M2 and AWS Arm runtime and static selection, unsupported-feature processes, quarantine, required mode and scalar fallback;
- inspect MIR, LLVM and assembly and collect constant-time, cache, branch, code-size, initialization and performance evidence for every supported compiler and target path.

Exit criteria:

- each admitted AES backend is exact-feature guarded, scalar-equivalent, independently healthy and measurably useful on its named native systems;
- `v0.27.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.27.2 - AES RISC-V Acceleration Candidate

Status: planned

Plan scope: Add RISC-V AES backends for exact ratified scalar-crypto or vector-crypto bundles only when the supported compiler line and observed deployment ISA can express them safely; require official vectors, scalar differentials, forced dispatch, generated-code review, and qualifying native evidence before admission, while every unsupported RISC-V build remains portable scalar without an acceleration claim.

Goal: prepare RISC-V AES acceleration without conflating generic RV64, the base vector extension and the exact AES crypto extensions.

Deliverables:

- freeze exact scalar and vector AES extension bundles, stable compiler compatibility, ABI and vector-state assumptions, and candidate versus admitted status;
- implement isolated candidate key-schedule and encrypt paths, direct tests, KAT health and static selection without enabling automatic dispatch prematurely;
- keep portable AES available on every RISC-V build and make absent native evidence or insufficient performance an explicit non-admission.

Verification:

- run official vectors, round and key-schedule differentials, block-count and overlap cases under cross-build and QEMU coverage;
- inspect every supported compiler's output and test safe negative selection on images lacking one required feature;
- run on the RISC-V cloud host when its ISA qualifies and otherwise prove the candidate cannot become active or be reported as supported.

Exit criteria:

- RISC-V AES is natively evidenced before admission and all other RISC-V deployments stay visibly scalar;
- `v0.27.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.28.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.28.1 - GHASH CPU Acceleration

Status: planned

Plan scope: Add exact x86_64 carry-less multiplication, AArch64 PMULL, and qualifying RISC-V crypto/vector GHASH backends with identical field representation, reduction, incremental boundaries, and finalization; test every backend independently and paired with scalar AES, require native correctness, timing, and performance evidence, and keep feature detection, activation, KAT health, and FIPS identity explicit.

Goal: accelerate GHASH without hiding field-representation conversions, reduction errors or backend pairing assumptions inside AES-GCM.

Deliverables:

- implement isolated PCLMUL or VPCLMUL, PMULL and qualifying RISC-V multiplication and reduction paths with exact representation contracts;
- preserve bounded incremental state, length accounting, block and tail behavior, KAT health, quarantine and actual-backend reporting;
- define independent GHASH admission so an AES backend cannot implicitly activate an untested multiplication path.

Verification:

- run official and generated field multiplication, reduction, associativity reference, incremental partition, zero, maximum and tail differentials for each direct path;
- pair every GHASH backend with scalar AES, inject faults, exercise unsupported bundles, quarantine and scalar fallback, and reject mismatched representations;
- collect native AMD, Intel, M2, AWS Arm and qualifying RISC-V emitted-code, timing, cache, branch and performance evidence.

Exit criteria:

- every active GHASH path is independently admitted and representation-equivalent before AES-GCM may pair with it;
- `v0.28.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.29.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.29.1 - Integrated Accelerated AES-GCM

Status: planned

Plan scope: Integrate only admitted AES and GHASH backend pairs into an accelerated AES-GCM provider with per-operation dispatch, preserving nonce and use limits, exact in-place or disjoint buffer rules, partial-overlap rejection, authenticate-before-release, complete failure atomicity, cancellation, output equivalence, and scalar fallback; benchmark combined rather than component speed and prohibit mixed, unhealthy, or unvalidated pairings.

Goal: obtain real record-level AES-GCM performance without letting component acceleration weaken AEAD transactional security.

Deliverables:

- define an immutable compatible-pair register and combined backend identity covering AES, GHASH, operation, feature bundle, KAT generations and FIPS disposition;
- implement seal and open paths that complete every fallible precondition before mutation and stage or authenticate as required to preserve complete failure atomicity;
- add combined KAT, quarantine propagation, required-mode behavior, cancellation and actual-pair reporting with no implicit mixed-generation fallback.

Verification:

- run official AEAD vectors, nonce and use exhaustion, every AAD, plaintext and tag boundary, exact in-place, disjoint, partial-overlap and unchanged-failure matrices for each forced pair;
- inject AES, GHASH, KAT, generation, cancellation and tag faults and prove no unauthenticated plaintext or partial output becomes caller-visible;
- benchmark complete TLS-sized seal and open operations on AMD, Intel, M2, AWS Arm and qualifying RISC-V rather than admitting from isolated component throughput.

Exit criteria:

- every accelerated pair preserves scalar AEAD semantics and exceeds the frozen end-to-end margin on its declared native range;
- `v0.29.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.30.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

### v0.30.1 - ChaCha20 CPU Acceleration

Status: planned

Plan scope: Add benchmark-admitted x86_64, AArch64, and qualifying RISC-V ChaCha20 backends for parallel blocks while preserving the scalar quarter-round, counter, nonce, tail, overlap, and deterministic exhaustion contract; force each width and tail path, compare every output with scalar, and reject wider paths that regress representative TLS record sizes.

Goal: use parallel vector lanes where they benefit ChaCha20 while retaining exact scalar counter and exhaustion behavior.

Deliverables:

- implement isolated fixed-width parallel block backends for exact x86_64, AArch64 and qualifying RISC-V bundles;
- preserve scalar ownership of counter preflight, nonce formation, tails, overlap and all-or-no-operation exhaustion checks;
- bind operation size to benchmark-admitted dispatch ranges, KAT state, quarantine and visible backend identity.

Verification:

- run official vectors, quarter-round references, every counter boundary, block count, tail length, exact overlap and exhaustion differential through every forced width;
- exercise unsupported bundles, KAT and data-path faults, quarantine, required mode and scalar fallback on native and supplemental emulated lanes;
- inspect emitted code and collect timing and performance evidence for short records, common TLS records and long streams without frequency-biased width selection.

Exit criteria:

- every active width is scalar-equivalent and measurably beneficial over its complete admitted size range;
- `v0.30.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.31.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.31.1 - Poly1305 And ChaCha20-Poly1305 CPU Acceleration

Status: planned

Plan scope: Add benchmark-admitted x86_64, AArch64, and qualifying RISC-V Poly1305 backends and integrate them only with a compatible admitted ChaCha20 path; preserve one-time-key handling, canonical reduction, constant-time tag verification, exact buffer aliasing rules, authenticate-before-release, complete failure atomicity, startup and continuous backend health policy, and scalar equivalence for every message and tail length.

Goal: accelerate the complete ChaCha20-Poly1305 AEAD while keeping the one-time authenticator key and failure paths inside the existing secret and transactional contracts.

Deliverables:

- implement isolated Poly1305 arithmetic backends with exact limb representation, reduction, carry and final-tag contracts and architecture-specific identities;
- define compatible ChaCha20 and Poly1305 pairings, key derivation and destruction, KAT generations, quarantine propagation and required-mode behavior;
- integrate seal and open without exposing unauthenticated plaintext, partial failure output or a backend-dependent diagnostic.

Verification:

- run official Poly1305 and AEAD vectors, carry and reduction boundaries, every message and tail length, AAD partition, nonce, use-limit, overlap and unchanged-failure differential;
- fault-inject either component, KAT, health generation, tag, cancellation and scalar retry and verify one-time keys and staged plaintext follow exact destruction duties;
- collect per-compiler emitted-code, constant-time, code-size and end-to-end native performance evidence across AMD, Intel, M2, AWS Arm and qualifying RISC-V.

Exit criteria:

- admitted component pairs are scalar-equivalent, failure-atomic, independently reportable and useful at representative TLS sizes;
- `v0.31.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.32.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.33.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.34.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.35.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

### v0.35.1 - X25519 CPU Acceleration

Status: planned

Plan scope: Benchmark and, where the frozen margin and constant-time evidence pass, add fixed-schedule x86_64, AArch64, and qualifying RISC-V X25519 field and ladder backends; preserve clamping, canonical input policy, low-order and all-zero rejection, ephemeral lifecycle, immediate scalar destruction, and exact provider-token binding, and retain scalar for any CPU family whose optimized path is not independently evidenced.

Goal: optimize X25519 handshakes without changing its fixed ladder, input rejection or ephemeral-key lifecycle.

Deliverables:

- implement isolated field multiplication, squaring, reduction and ladder kernels only for exact feature bundles that retain a fixed schedule;
- reuse the scalar encoding, clamping, low-order, all-zero, key-consistency, lifecycle and provider-token authorities around each optimized kernel;
- register separate ECDH backend identities, KATs, health state, quarantine, static and runtime selection and scalar-only decisions.

Verification:

- run official vectors, iterative vectors, field and ladder differentials, non-canonical and low-order inputs, all-zero results, imported-key consistency and lifecycle cases;
- inspect full optimized ladders for secret-dependent control, indexing, instructions, memory access and compiler transformations across every admitted compiler;
- benchmark and side-channel test on AMD, Intel, M2, AWS Arm and qualifying RISC-V, including forced backend faults, quarantine and fallback.

Exit criteria:

- each admitted X25519 path retains the complete scalar security contract and independent native evidence;
- `v0.35.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.36.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.37.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.38.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.38.1 - P-256 CPU Acceleration

Status: planned

Plan scope: Benchmark and admit isolated x86_64, AArch64, and qualifying RISC-V P-256 field, group, scalar-multiplication, ECDH, and ECDSA backends only with complete-formula, scalar-range, nonce, strict-encoding, low-S, lifecycle, differential, fault, and per-target constant-time evidence; signing and verification backend identities remain explicit and independently quarantinable.

Goal: optimize P-256 operations as separate field, group, ECDH, signing and verification paths without hiding algorithm-specific failures behind one CPU label.

Deliverables:

- implement isolated fixed-width field and group kernels and separately identify scalar multiplication, ECDH, signing and verification operation paths;
- preserve complete formulas, point validation, scalar range, nonce policy, strict signatures, low-S decision, secret destruction and provider-token binding;
- define KATs, pairwise signing tests, fault detection, health and quarantine per operation and scalar-only decisions for paths failing evidence or performance gates.

Verification:

- run official group, ECDH and ECDSA vectors, exceptional points, invalid encodings, boundary scalars, nonce faults, malformed signatures and scalar differentials;
- use proof harnesses and emitted-code, cache, branch and statistical testing for field carries, reductions, complete group operations and secret scalar schedules;
- collect native AMD, Intel, M2, AWS Arm and qualifying RISC-V correctness and operation-specific performance evidence with forced faults and quarantine.

Exit criteria:

- no P-256 operation inherits admission from a different operation and every secret path retains fixed-schedule evidence;
- `v0.38.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.39.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.40.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.41.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.41.1 - P-384 CPU Acceleration

Status: planned

Plan scope: Benchmark and admit isolated x86_64, AArch64, and qualifying RISC-V P-384 field, group, scalar-multiplication, ECDH, and ECDSA backends under the same complete-formula, strict-encoding, nonce, lifecycle, differential, fault, and side-channel duties as scalar; record a reviewed scalar-only decision wherever code size, latency, or evidence does not justify acceleration.

Goal: optimize P-384 only where the larger field and operation mix produce a defensible native benefit without weakening its reviewed arithmetic.

Deliverables:

- implement separately identified field, group, scalar-multiplication, ECDH, signing and verification paths for exact feature bundles;
- preserve canonical point and scalar handling, complete formulas, strict signature encoding, nonce policy, destruction and provider binding;
- define per-operation KAT, health, fault and quarantine behavior plus code-size and stack budgets suitable for no_std deployments.

Verification:

- run official group, ECDH and ECDSA vectors, exceptional points, invalid encodings, scalar and nonce boundaries and arithmetic differentials;
- apply proof, emitted-code, constant-time, cache, branch, stack and fault-injection evidence to each secret operation;
- benchmark native AMD, Intel, M2, AWS Arm and qualifying RISC-V operations and retain scalar where the frozen margin or resource ceiling fails.

Exit criteria:

- every P-384 CPU path is independently useful and evidenced or explicitly rejected in favor of scalar;
- `v0.41.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.42.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.43.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.44.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.44.1 - RSA CPU Acceleration

Status: planned

Plan scope: Benchmark and admit architecture-specific fixed-limb multiplication, squaring, reduction, and exponentiation backends for x86_64, AArch64, and qualifying RISC-V without changing modulus policy, imported-key validation, blinding, fixed schedule, CRT consistency, fault detection, or intermediate destruction; verification and private-operation paths remain distinct and every optimized symbol receives arithmetic proof and native side-channel evidence.

Goal: improve RSA verification and blinded private operations without introducing attacker-selected widths, unblinded shortcuts or architecture-dependent validation.

Deliverables:

- implement exact-width arithmetic kernels with fixed limb counts and distinct verification and private-operation backend identities;
- retain scalar modulus, exponent, key-import, blinding, CRT, recombination, fault-detection, destruction and external-signer contracts;
- bind each optimized symbol to carry, borrow, multiplication, reduction and conversion proofs, KAT or pairwise tests, health and quarantine.

Verification:

- run official RSA-PSS and PKCS1 verification vectors, private-operation round trips, malformed keys, CRT inconsistencies, injected faults and scalar arithmetic differentials;
- prove fixed widths and schedules, inspect emitted code and collect timing, cache, branch, stack and destruction-residual evidence across admitted compilers;
- benchmark separate public and private operations on AMD, Intel, M2, AWS Arm and qualifying RISC-V and reject paths that trade security or resource ceilings for speed.

Exit criteria:

- accelerated RSA cannot bypass blinding, validation or fault detection and each arithmetic symbol has traceable proof and native evidence;
- `v0.44.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.45.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

### v0.45.1 - Ed25519 CPU Acceleration

Status: planned

Plan scope: Benchmark and admit fixed-schedule x86_64, AArch64, and qualifying RISC-V Ed25519 field, scalar, and group backends only when canonical encoding, small-order and malleability rejection, signing lifecycle, verification behavior, scalar differentials, fault handling, and per-target constant-time evidence remain identical; otherwise retain the portable implementation and record the decision.

Goal: optimize Ed25519 without accepting a faster but weaker verification equation, encoding policy or secret-scalar schedule.

Deliverables:

- implement isolated field, scalar and group kernels with explicit signing and verification operation identities;
- preserve canonical point and scalar encodings, small-order rejection, malleability rules, nonce and secret lifecycle and destruction duties;
- add operation-specific KATs, health, fault injection, quarantine, backend reporting and reviewed scalar-only outcomes.

Verification:

- run official vectors, non-canonical encodings, small-order points, scalar boundaries, malleability corpus, signing and verification differentials and injected faults;
- inspect every secret schedule and memory access with emitted-code, cache, branch and statistical tests across supported compilers;
- benchmark native AMD, Intel, M2, AWS Arm and qualifying RISC-V signing and verification separately and enforce code-size and stack ceilings.

Exit criteria:

- no optimized verification path weakens canonical or subgroup policy and every signing path retains fixed-schedule evidence;
- `v0.45.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.46.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.46.1 - Cross-Backend Performance And Admission Gate

Status: planned

Plan scope: Before the cryptographic-substrate audit, reconcile every implemented primitive and operation against the scalar reference and CPU-backend register; require an explicit admitted, candidate, rejected, or scalar-only decision for AMD x86_64, observed-feature AWS Intel x86_64, Apple M2, AWS AArch64, and RISC-V, verify dispatch precedence, required-mode failure, KAT and quarantine, no_std and std package isolation, code size, latency, throughput, side-channel and native-hardware evidence, and prohibit any backend whose exact symbol, feature bundle, residual risk, or FIPS disposition is missing.

Goal: close the entire pre-PQ CPU-backend surface before independent cryptographic review and protocol consumption.

Deliverables:

- generate a machine-readable register for every primitive, operation, implementation symbol, CPU family, feature bundle, size range, status, proof, native evidence, residual risk and FIPS disposition;
- reconcile scalar, static no_std, opt-in std, opportunistic, required and validated policies, dispatch precedence, KAT generations, quarantine propagation and backend reporting;
- freeze benchmark thresholds, code-size and stack ceilings, native runner freshness, compiler coverage and explicit candidate, rejected and scalar-only decisions.

Verification:

- schema-check completeness and uniqueness and use broken fixtures for orphan symbols, missing CPUs, stale evidence, unqualified emulation, absent scalar reference, hidden fallback and FIPS ambiguity;
- execute forced backend, unsupported feature, KAT failure, quarantine, concurrency, required-mode and scalar fallback matrices across every admitted primitive and package graph;
- rerun native AMD, Intel, M2, AWS Arm and available RISC-V correctness, side-channel and representative TLS workload measurements under the supported compiler matrix.

Exit criteria:

- no implemented cryptographic operation or CPU family has an unclassified acceleration status and only complete native evidence can produce admission;
- `v0.46.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.47.0 - Cryptographic Substrate Audit Gate

Status: planned

Plan scope: Complete independent cryptographic-substrate review of every scalar primitive, admitted and candidate CPU implementation symbol, dispatcher, capability token, KAT and quarantine path, optional std adapter, unsafe boundary, per-target constant-time and zeroization claim, and residual gap; remediate findings before PKI or TLS consumption.

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
- `v0.47.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.47.1 - Base64-ng Admission And Encoding Boundary

Status: planned

Plan scope: Audit the latest stable first-party `base64-ng` family against MSRV, `no_std`, allocator, feature, dependency, unsafe, native-code, license, advisory, target, streaming, canonical-encoding, strict-decoding, caller-buffer and resource policies; exact-pin only the smallest acceptable default-feature-disabled package edge, require an allocation-free OpenPGP armor profile before admitting `base64-ng-openpgp`, and otherwise use `base64-ng` solely for transforms behind Brynja-owned PEM and armor framing without duplicating Base64.

Goal: admit one narrow, reusable Base64 implementation boundary without
duplicating encoding code or weakening Brynja's portable production rules.

Deliverables:

- record the exact audited package, source, license, feature and resolved-graph hashes and the decision for `base64-ng` and `base64-ng-openpgp` separately;
- freeze a Brynja-owned streaming caller-buffer interface for strict decoding, canonical encoding, consumed and written lengths, transactional failure and work limits;
- keep the admitted edge outside cryptographic implementation, protocol state, legacy fallback, default activation and every `brynja-fips-module` artifact.

Verification:

- test canonical and non-canonical encodings, every truncation, invalid alphabet, padding, whitespace, overlap, capacity and streaming split across the supported Rust matrix;
- prove no allocator, `std`, unsafe, native code, build script, default feature or transitive package enters the admitted graph, and reject an allocation-requiring OpenPGP adapter;
- pass repository checks, promised Rust versions and targets, dependency and advisory policy, SBOM, package inspection, documentation and protocol isolation.

Exit criteria:

- the exact admitted boundary and its non-admitted alternatives are machine-readable, fail closed and narrow enough for later PEM and OpenPGP armor reuse;
- `v0.47.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.48.0 - PEM Base64 And Chain Containers

Status: planned

Plan scope: Using only the v0.47.1-admitted Base64 boundary, implement bounded strict PEM armor plus certificate-chain containers with label, count, size, whitespace, trailing-data, canonical-encoding, and resource policies; retain a documented non-admission path rather than weakening `no_std` or allocation-free guarantees.

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
- `v0.48.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.49.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.50.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.51.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.52.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.53.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.54.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.55.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.56.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.57.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.57.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.58.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.58.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.58.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.58.3 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.59.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.60.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.61.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.62.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.63.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.64.0 - TLS 1.3 Handshake Codec

Status: planned

Plan scope: Implement the complete TLS 1.3 handshake codec with duplicate, ordering, extension-context, unknown and GREASE extension, compatibility ChangeCipherSpec, and resource rules; bound known unsupported ClientHello extensions by outer framing and ignore opaque bodies without parsing, allocation, echo, negotiation, fetching, cryptography, or state mutation while rejecting unsolicited responses.

Goal: complete the **TLS 1.3 Handshake Codec** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- keep known unsupported ClientHello extension bodies opaque after the outer
  vector is bounded, and reject the same identifiers in unsolicited response
  contexts;
- separate early policy from post-engine routing while encoding record, transcript, HRR, certificate, PSK, ticket, secret, storage, effect, and failure invariants;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- run RFC vectors, fragmentation, versions, GREASE, client and server selection, HRR, transcript, downgrade, ticket, PSK timing, storage atomicity, and peer matrices;
- exercise premature routing, retry, cross-version state, replay, unknown PSKs, binder failure, crash consistency, zero-RTT races, key limits, and cleanup;
- inject arbitrary known unsupported extension bodies and prove no inner
  parsing, allocation, echo, negotiation, fetching, cryptography, or state
  mutation occurs;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.3 is audited independently and final routing later selects symmetrically after both engines exist;
- `v0.64.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.65.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.66.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.67.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.68.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.69.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.70.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.71.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.72.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.73.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.74.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.75.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.76.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.76.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.76.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.77.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.78.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.79.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.80.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.81.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.82.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.83.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.83.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.83.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.84.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.85.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.86.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.87.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.88.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.89.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.90.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

### v0.90.1 - TLS 1.2 RFC 6066 Extension Semantics

Status: planned

Plan scope: Implement TLS 1.2-specific SNI resumption association, status_request negotiation and CertificateStatus handling; bound and safely ignore unsupported peer ClientHello extensions without parsing their bodies, while rejecting unsolicited responses and keeping unsupported facilities absent from configuration, offers, echoes, negotiation, tickets, and imported state.

Goal: complete the **TLS 1.2 RFC 6066 Extension Semantics** implementation stop
without inheriting TLS 1.3 message targets or admitting unsupported RFC 6066
facilities.

Deliverables:

- implement the TLS 1.2 SNI, resumption, status_request, CertificateStatus, and
  extension-context state in `brynja-tls12`;
- length-check the outer Extension vector, treat unsupported ClientHello
  extension bodies as opaque, and ignore them without inner parsing,
  allocation, echo, negotiation, fetching, cryptography, or state mutation;
- reject unsolicited server responses and prohibit local configuration,
  offers, tickets, resumption, and imported state from enabling
  max_fragment_length, client_certificate_url, trusted_ca_keys, or
  truncated_hmac; and
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- test full and resumed TLS 1.2 handshakes with SNI association and
  status_request carried in the TLS 1.2 CertificateStatus message;
- inject empty, malformed, oversized-within-budget, duplicate, and arbitrary
  bodies for all four unsupported ClientHello extension identifiers and prove
  the bodies are not parsed, allocated, echoed, negotiated, fetched, or
  retained;
- reject every unsolicited response, configuration attempt, imported-state
  reference, ticket reference, and cross-version transfer for the unsupported
  facilities; and
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- TLS 1.2 owns every applicable RFC 6066 obligation independently from TLS
  1.3, and wire-level safe ignore is mechanically separate from local
  configuration rejection;
- `v0.90.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.91.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.92.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.93.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.94.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.95.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.96.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.97.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.98.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.99.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.99.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.100.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.101.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.102.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.103.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.104.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.105.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.106.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.107.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.108.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.109.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.110.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.111.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.111.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.112.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.113.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.114.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.115.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.116.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.117.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.118.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.119.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.119.1 - ML-KEM x86_64 And AArch64 Acceleration

Status: planned

Plan scope: Add isolated, benchmark-admitted x86_64 and AArch64 ML-KEM NTT, inverse-NTT, polynomial, sampling, encoding, key-generation, encapsulation, and decapsulation backends for AMD, observed-feature AWS Intel, Apple M2, and AWS Arm; preserve FIPS 203 and errata behavior, canonical encodings, randomness and stack bounds, constant-time implicit rejection, complete secret destruction, per-parameter KATs, scalar differentials, and backend-specific side-channel evidence.

Goal: accelerate complete ML-KEM operations on the available x86_64 and AArch64 systems without optimizing away canonical decoding or implicit rejection.

Deliverables:

- implement separately identified NTT, inverse-NTT, polynomial, sampling and encoding kernels and compose exact key-generation, encapsulation and decapsulation backend identities;
- preserve all ML-KEM-512, ML-KEM-768 and ML-KEM-1024 parameter, randomness, stack, canonical encoding, implicit-rejection, failure and destruction contracts;
- add per-parameter KAT, health, quarantine, static and runtime dispatch and explicit feature and size-range evidence for AMD, Intel, M2 and AWS Arm.

Verification:

- run FIPS 203 and errata vectors, scalar differentials, NTT round trips, reduction boundaries, malformed keys and ciphertexts, implicit rejection and every parameter set through direct kernels and complete operations;
- use proof harnesses, emitted-code, cache, branch, statistical, stack and destruction-residual evidence for secret-dependent paths and failure equivalence;
- fault-inject each component and KAT and benchmark complete key generation, encapsulation and decapsulation natively rather than admitting from isolated NTT throughput.

Exit criteria:

- each admitted complete ML-KEM operation is scalar-equivalent, constant-time on its secret failure path and natively useful on its declared CPU family;
- `v0.119.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.119.2 - ML-KEM RISC-V Acceleration Candidate

Status: planned

Plan scope: Add a RISC-V ML-KEM backend only for an exact ratified vector or crypto feature bundle supported by the compiler matrix, and require native qualification on the available RISC-V host when its observed ISA matches; otherwise keep it non-dispatchable with generated-code and emulator evidence, retain scalar ML-KEM support, and make the missing native acceleration evidence explicit through the final platform gate.

Goal: prepare useful RISC-V ML-KEM acceleration while keeping generic RISC-V support scalar and truthful about unavailable vector hardware.

Deliverables:

- freeze the exact RISC-V feature, vector-length, ABI, OS vector-state and stable-compiler contract for every candidate kernel;
- implement isolated NTT, polynomial and complete-operation candidates with forced entry, parameter KATs, health, quarantine and static tokens but no unsupported automatic activation;
- record observed cloud-host capabilities, candidate or admitted status, emulator limits and the native evidence still required by final qualification.

Verification:

- run all parameter vectors, scalar differentials, malformed input, implicit rejection, component faults, stack ceilings and direct candidate paths under cross-build and QEMU coverage;
- inspect supported-compiler code generation and execute negative images missing individual required features to prove safe selection remains scalar;
- when the RISC-V host qualifies, collect native correctness, constant-time and end-to-end performance evidence; otherwise enforce non-dispatchable status through the final evidence register.

Exit criteria:

- RISC-V ML-KEM acceleration is either natively admitted or remains an explicit candidate that cannot be selected or described as accelerated support;
- `v0.119.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.120.0 - Standard Hybrid Groups

Status: planned

Plan scope: Implement only final standardized X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024 encodings, component order, lengths, identifiers, and concatenated shared-secret construction under RFC 9954 and final Standards Track RFC 10024; provisional drafts and private code points never enter release artifacts.

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
- `v0.120.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.121.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.122.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.123.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.123.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.124.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.124.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.124.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.125.0 - Approved Provider And Mandatory Service Indicator

Status: planned

Plan scope: Implement the sealed approved-only provider and return an unambiguous per-service approval indicator through each mandatory typed service result or ActionV1, with SecurityEvent only duplicating that status for audit; make execution and approved status require an opaque unforgeable module-owned self-test attestation that no public or application-implementable trait can create, keep that attestation unobtainable until v0.127.0, and permit no additive fips feature or construction before attested self-test success.

Goal: complete the **Approved Provider And Mandatory Service Indicator** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- generate an approved-only policy from the exact validated service and
  parameter manifest while keeping connection failure distinct from module error;
- define an opaque, unforgeable module-owned self-test attestation as a mandatory
  execution-authority input, expose no public constructor or trait-based
  substitute, and keep it unobtainable until the v0.127.0 internal tests exist;
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
- compile-fail application construction, implementation, substitution, cloning,
  formatting, serialization, and cross-module reuse of self-test attestation;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- every service result carries mandatory approval status independently of audit
  delivery, while no service can execute or become approved without the
  still-unobtainable module-owned self-test attestation and architectural
  boundaries and catastrophic-latch semantics are preserved;
- `v0.125.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.126.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.127.0 - Module Integrity And Pre-Operational Self-Tests

Status: planned

Plan scope: After the final DRBG, provider, SSP, and algorithm implementations are linked, implement module-owned module-integrity verification and every required algorithm, DRBG, and component pre-operational self-test over the complete final image; only that internal path may issue the opaque artifact-, environment-, generation-, and test-plan-bound attestation required by provider execution and approved status, no public or application-implementable runner can issue or substitute it, no cryptographic service or output is available before success, and deterministic fault injection covers every test and integrity path.

Goal: complete the **Module Integrity And Pre-Operational Self-Tests** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- implement final-image integrity and required algorithm, DRBG, component, and
  dependency pre-operational tests with deterministic fault hooks;
- replace the trusted public-runner seam as an authority source with a
  module-owned internal test path that alone issues an opaque attestation bound
  to the exact artifact, operational environment, module generation, and test plan;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- corrupt every covered image region and every self-test expected result and
  require failure before any cryptographic service or output;
- test concurrent first use, repeated status queries, interrupted startup,
  unavailable dependencies, exact test coverage, and secret-free errors;
- compile-fail application runner, token construction, substitution, replay,
  cloning, formatting and serialization, and reject stale, wrong-artifact,
  wrong-environment, wrong-generation and wrong-plan attestations;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- complete-image integrity and pre-operational tests block every service until
  success, alone issue the exact module-owned attestation required by execution
  and approved status, and fail deterministically under every injected fault;
- `v0.127.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.127.1 - Conditional Self-Tests And Permanent Failure State

Status: planned

Plan scope: Implement required pairwise-consistency, conditional, on-demand, firmware or software load, and continuous health-test coordination; serialize concurrent test requests, destroy affected SSPs, block prohibited services, and enter one module-wide irreversible error state shared by every current or future session exactly for FIPS-defined integrity, self-test, and catastrophic failures, so constructing a sibling session can never clear or bypass failure.

Goal: complete the **Conditional Self-Tests And Permanent Failure State** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement every applicable conditional, pairwise-consistency, on-demand,
  load, and health-test transition with explicit concurrency semantics;
- freeze irreversible error-state entry, SSP destruction, allowed status and
  zeroization services, recovery requirements, and connection/module separation;
- replace caller-session-only failure with one module-owned latch shared by
  every current and future session before any executable or approved FIPS
  service exists; prevent construction of a sibling session from resetting,
  shadowing, or bypassing the latched failure;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- fault-inject each test before, during, and after concurrent services and prove
  affected outputs and SSPs never escape and prohibited services stay blocked;
- distinguish ordinary invalid inputs and approved-profile connection failures
  from integrity, self-test, entropy, and catastrophic module failures;
- create concurrent and sequential sibling sessions before and after every
  permanent-failure path and prove all observe the same irreversible latch,
  including newly constructed sessions and attempted service indications;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- conditional testing and the permanent module error state are complete,
  irreversible, shared by all sessions, impossible to bypass through fresh
  session construction, and never misused for connection policy;
- `v0.127.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.128.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.129.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.130.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.130.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.131.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.131.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.132.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.132.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.132.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.133.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.134.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.134.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.134.2 - Ergonomic Brynja FIPS Facade And Misconfiguration Gate

Status: planned

Plan scope: Implement and prepare for separate publication at the next scheduled or exceptional release checkpoint a no_std brynja-fips facade with obvious client and server constructors that require a validated-module handle and select the approved-only TLS profile, exact provider, DRBG, algorithms, strengths, certificate policy, resumption, PSK, and early-data rules from the manifest; expose only permitted choices, provide authoritative readiness and per-service results, prohibit a boolean Cargo fips feature, generic-provider injection, silent fallback, and any FIPS claim from ordinary brynja configuration, and compile-fail every mixed or incomplete configuration.

Goal: complete the **Ergonomic Brynja FIPS Facade And Misconfiguration Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the separate brynja-fips facade and minimal typed client and server
  builders that require a validated module and approved identity and trust
  inputs, while deferring crates.io publication to the next scheduled or
  exceptional release checkpoint;
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
- `v0.134.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.134.3 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.135.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.135.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.136.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.137.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.138.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.139.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.139.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.140.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.140.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.141.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.142.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.143.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.144.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.145.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.146.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.146.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.147.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.148.0 - Generated Optional-Feature Composition Gate

Status: planned

Plan scope: Generate a compatibility matrix for every pair of admitted optional features and their explicit stream TLS, DTLS, and QUIC applicability, plus targeted higher-order combinations across ECH, X.509 and RPK authentication, delegated credentials, tickets, resumption, imported and raw PSKs, pairwise external-PSK roles, zero-RTT, HybridRequired and HybridPreferred groups, the validated-module manifest and brynja-fips approved-only profile, noRevAvail, Must-Staple, ordinary and lightweight OCSP, versioned CT, HPKE export, certificate compression, rotating OCSP and SCT extensions, Record Size Limit, DTLS fragmentation, and return routability; keep RFC 6066 max_fragment_length, client_certificate_url, trusted_ca_keys, and truncated_hmac absent from every modern configuration, offer, echo, negotiation, ticket, and imported state while preserving the v0.90.1 bounded peer ClientHello ignore path; bind ECH tickets to inner identity, policy, and configuration generation; test ClientHello size, HRR, padding, transcript, downgrade, rotation, migration, cancellation, storage, and exhaustion; make forbidden combinations unrepresentable or reject them during configuration before any handshake.

Goal: complete the **Generated Optional-Feature Composition Gate** implementation stop without admitting or
claiming adjacent capability.

Deliverables:

- implement the Plan scope exactly and preserve its input, state, resource,
  secret, effect, storage, failure, dependency, and package boundaries;
- exercise optional receive and send paths and cross-feature combinations before freezing APIs, then qualify downstream host and Aesynx adapters;
- implement the exact RFC 6066 configuration-rejection boundary and prove that
  peer-directed certificate fetching, truncated authentication, legacy CA
  indication, and deprecated fragment negotiation cannot become available,
  without rejecting bounded unsupported ClientHello inputs;
- update requirements, threat model, controls, status, limitations, release
  notes, and permanent evidence index.

Verification:

- generate and execute every pairwise feature and protocol-applicability case plus targeted ECH, authentication, resumption, hybrid, FIPS and compression higher-order combinations;
- exercise ECH with hybrid ClientHello size, HRR, padding, transcript and downgrade, ECH with RPK, hybrid tickets, PSKs, resumption and zero-RTT, hybrid approved-only policy, rotating OCSP and SCT compression inputs, and configuration-time rejection of every forbidden combination;
- inject all four unsupported RFC 6066 extension identifiers in every stream
  TLS, DTLS, resumption, imported-state, and configuration context; require
  bounded opaque ignore only for permitted peer ClientHello inputs and bounded
  rejection for unsolicited responses and local admission before allocation,
  fetching, cryptography, or state change;
- pass repository checks, promised Rust versions and targets, dependency and
  advisory policy, SBOM, packages, documentation, and protocol isolation.

Exit criteria:

- optional modules compose safely before API freeze and remain downstream of validated and protocol interfaces;
- `v0.148.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.149.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.150.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.151.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.151.1 - Optional Ecosystem Adapter And Dependency Boundary

Status: planned

Plan scope: Freeze separately locked downstream companion workspaces for future brynja-rustls and brynja-tokio packages; keep both absent from the core workspace lockfile and every brynja facade, engine, crypto, default, all-features, legacy, bare-metal and FIPS-module edge; admit third-party Rust dependencies only inside the adapter that implements their API, with exact minimal features, freshness, advisory, license, MSRV, SBOM and native-code closure policy; and make the first-party Rust cryptography golden rule permanent and machine-enforced without implementing either adapter yet.

Goal: establish ecosystem integration without weakening Brynja's dependency-free core or first-party Rust cryptographic implementation boundary.

Deliverables:

- freeze the permanent golden rule that every shipped Brynja cryptographic and FIPS service is implemented from first-party Rust source and never by a foreign module, native library, wrapper or delegated provider;
- define separately locked downstream companion-workspace, publication, ownership, feature, lockfile, SBOM, advisory, freshness, native-code and no-reverse-dependency policies for brynja-rustls and brynja-tokio;
- extend repository policy to reject C, C++, Objective-C, external assembly, native objects and libraries, package build scripts, Cargo native links, build dependencies and foreign cryptographic ABI edges in Brynja-owned package trees;
- update requirements closure, threat model, controls, implementation architecture, limitations, release notes and permanent evidence index.

Verification:

- inject foreign sources, objects, archives, build scripts, build dependencies, Cargo links, foreign ABI declarations, native link attributes and included native binaries and require fail-closed policy rejection;
- construct broken dependency graphs in which an adapter enters the main workspace lockfile, facade, engine, crypto, default, all-features, legacy, bare-metal or FIPS-module closure and require every path to fail;
- validate exact adapter exception fields, minimal-feature and pure-Rust closure schemas, publication direction, separate-lockfile ownership and the absence of an implementation or FIPS claim at this boundary;
- pass repository checks, promised Rust versions and targets, dependency and advisory policy, SBOM, packages, documentation and protocol isolation.

Exit criteria:

- the core remains dependency-free, adapters have only narrow downstream dependency authority, and no policy path can turn integration into foreign cryptographic implementation or a FIPS claim;
- `v0.151.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.151.2 - Brynja Rustls Custom Provider Adapter

Status: planned

Plan scope: Implement and prepare for separate publication brynja-rustls as an explicitly selected rustls custom provider backed completely by Brynja primitives, groups, cipher suites, signature verification, signing, secure randomness and key loading; use rustls with defaults and built-in providers disabled, never enable rustls's fips feature or resolve or delegate to AWS-LC, ring or another cryptographic provider, distinguish rustls TLS evidence from Brynja TLS evidence, and report no FIPS status from ordinary Brynja.

Goal: let rustls applications explicitly select Brynja cryptography without importing a foreign cryptographic backend or confusing rustls protocol behavior with Brynja TLS behavior.

Deliverables:

- implement the complete current rustls custom-provider surface in brynja-rustls using only admitted Brynja primitives, groups, cipher suites, verification, signing, randomness and key-loading services;
- exact-pin the reviewed rustls line in the companion lockfile with default providers and rustls's fips feature disabled, no AWS-LC, ring, native cryptography, fallback provider or partially delegated provider in the resolved graph;
- provide explicit provider construction and installation examples, capability and unsupported-operation reporting, version-drift policy, and documentation that all TLS state-machine evidence belongs to rustls rather than Brynja TLS;
- keep ordinary provider and configuration FIPS status false and update package, SBOM, advisory, compatibility, release and verification inventories.

Verification:

- run every supported rustls cipher-suite, group, signature, certificate-verification, signing, randomness and key-loading path through direct Brynja KATs, scalar or admitted CPU differentials, provider-failure injection and independent peers;
- break or omit each provider element, enable each forbidden built-in/default/fips feature, inject AWS-LC, ring and fallback edges, and require graph and runtime checks to fail before a connection begins;
- test global and per-configuration selection, concurrent installation behavior, unsupported algorithms, key lifecycle, provider cancellation and exact rustls version/API drift without attributing rustls protocol coverage to Brynja TLS;
- pass the companion and core repository gates, promised Rust versions and targets, package archives, dependency, license, advisory, SBOM, native-code, documentation and isolation checks.

Exit criteria:

- rustls can use a complete explicitly selected Brynja provider with no foreign cryptographic implementation, built-in fallback, main-graph edge or ordinary FIPS claim;
- `v0.151.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.151.3 - Brynja Tokio TLS Stream Adapter

Status: planned

Plan scope: Implement and prepare for separate publication brynja-tokio with connector, acceptor and TlsStream types that implement Tokio AsyncRead and AsyncWrite over the stable Brynja TLS EngineV1 contract; use caller-owned bounded buffers and minimal Tokio I/O features, preserve full-duplex progress, partial-write, wakeup, cancellation, backpressure, flush, close_notify and shutdown semantics, and forbid raw AEAD-over-stream framing, tokio-rustls and every second TLS or cryptographic implementation.

Goal: provide conventional Tokio client and server streams while retaining Brynja's authenticated TLS framing, bounded Sans-I/O state and dependency direction.

Deliverables:

- implement separately selected connector, acceptor and TlsStream adapters over EngineV1 with explicit client/server configuration, handshake completion, plaintext and ciphertext flow, errors and terminal state;
- define caller-owned bounded buffering, exact poll progress, partial consumption, read/write independence, wake registration, cancellation, backpressure, flush, close_notify, peer EOF, truncation and shutdown contracts;
- exact-pin a minimal reviewed Tokio I/O feature closure in the companion lockfile and prohibit tokio-rustls, rustls, raw AEAD stream framing, another TLS stack, another cryptographic provider and any reverse edge into Brynja;
- publish examples for clients, servers, split/full-duplex operation and graceful shutdown while retaining explicit entropy, clock, trust and storage capabilities.

Verification:

- exhaustively vary Pending and Ready at every transport operation, every partial read/write boundary, zero-capacity buffers, wakeup order, duplex direction, cancellation point, flush and shutdown transition;
- inject malformed records, truncation, close_notify races, peer EOF, transport errors, provider delays, buffer exhaustion, task migration and repeated polls and prove no plaintext release, busy loop, lost wakeup, duplicated consumption or secret-bearing error;
- compare synchronous Sans-I/O traces and Tokio traces against independent TLS peers across fragmentation, coalescing, resumption, KeyUpdate, backpressure and graceful and abortive closure;
- pass companion and core gates, promised Rust versions and targets, package archives, dependency, license, advisory, SBOM, native-code, documentation and isolation checks.

Exit criteria:

- Tokio applications can opt into a bounded correct Brynja TLS stream without a second TLS or cryptographic implementation and without altering the main Brynja graph;
- `v0.151.3 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.151.4 - Ecosystem Adapter Isolation And Interoperability Gate

Status: planned

Plan scope: Qualify brynja-rustls and brynja-tokio dependency direction, exact lockfiles, feature allowlists, native-code absence, package archives, SBOMs, MSRV/latest-stable compatibility, cancellation and hostile-I/O behavior, independent-peer interoperability and framework upgrades; prove the main Brynja graph remains byte-for-byte independent of both; keep both outside brynja-fips-module; and permit any later adapter-level approved-operation claim only through an exact certificate-bound module handle, numbered review and applicable operational-environment evidence without enabling rustls's fips feature or changing the validated artifact.

Goal: close the ecosystem-adapter assurance boundary before resource proofs and final systems qualification consume the public integration surface.

Deliverables:

- freeze exact adapter dependency, feature, lockfile, package, SBOM, native-code, advisory, MSRV, latest-stable, upgrade and publication evidence independently from the core workspace;
- complete rustls-provider and Tokio-stream conformance, independent-peer interoperability, hostile-I/O, cancellation, concurrency, lifecycle, resource, error and documentation matrices;
- prove clean core source, manifest, lockfile, package archive, feature graph, SBOM and reproducible-build identity with and without each separately selected companion adapter;
- freeze FIPS claim separation: both adapters remain outside the module, ordinary paths report no validation, and a future approved-operation bridge needs an exact certificate-bound handle, numbered review and operational-environment evidence.

Verification:

- compare core artifacts and graphs byte for byte before and after building each companion workspace and inject reverse, optional, re-export, default, all-feature, legacy, bare-metal and FIPS-module edges;
- scan complete resolved adapter archives and build plans for native source, objects, libraries, build scripts, AWS-LC, ring, rustls fips, tokio-rustls, duplicate TLS and duplicate cryptographic providers;
- run supported/unsupported framework-version matrices, forced dependency and feature drift, independent client/server peers, cancellation and hostile scheduling, resource exhaustion and package-install smoke tests;
- audit every verification and FIPS statement so adapter evidence cannot be presented as Brynja TLS review, official validation or certificate coverage.

Exit criteria:

- both optional adapters are independently usable and upgradable while the dependency-free core, first-party Rust cryptography rule, protocol evidence and exact FIPS artifact remain unchanged and unambiguous;
- `v0.151.4 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.152.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.153.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.154.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.155.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.156.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.157.0 - Memory And Side-Channel Evidence

Status: planned

Plan scope: Complete Miri and sanitizer evidence plus compiler, target and CPU-backend constant-time assembly, owned-region zeroization-store survival, cache and branch, statistical side-channel, spill and register-residual matrices; test every forced scalar and accelerated path without extending owned-memory destruction claims to registers or OS context state.

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
- `v0.157.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.158.0 - Sustained Platform And Hostile-Load Qualification

Status: planned

Plan scope: Sustain Linux, Windows, macOS, BSD, Android, iOS, bare-metal, and Aesynx ABI or emulator qualification under concurrency, provider failure, resource exhaustion, and hostile load; sustain native AMD x86_64, observed-feature AWS Intel x86_64, Apple M2, AWS AArch64, and qualifying RISC-V scalar and admitted acceleration lanes with explicit candidate status where hardware is absent; separately qualify every claimed FIPS artifact only on its certificate-listed operational environments and exact dispatch paths.

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
- `v0.158.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.159.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.160.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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
- `v0.161.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

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
- `v0.162.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

## Phase 6: OpenPGP, Final Integration, And General Availability

RFC 9580 is admitted as an independent modern protocol family. It reuses exact
reviewed primitive crates but never TLS state, PKIX trust, implicit platform
effects, deprecated algorithm fallback, or a FIPS-approved-service claim.

### v0.163.0 - OpenPGP Authority, Registry, Threat Model, And Package Boundary

Status: planned

Plan scope: Pin RFC 9580, its obsoleted RFC lineage, errata, and the OpenPGP Parameters registry; classify every packet, version, algorithm, signature type, subpacket, armor form, criticality rule, compatibility surface and trust responsibility; freeze separate `brynja-openpgp-core`, `brynja-openpgp-armor`, `brynja-openpgp`, and optional `brynja-openpgp-legacy` boundaries with no implicit network, keyserver, filesystem, global trust, TLS, legacy-protocol, or FIPS-module edge.

Goal: close the complete OpenPGP standards and security scope before any
OpenPGP production code or dependency edge is admitted.

Deliverables:

- lock authenticated RFC, errata and IANA bytes and generate requirement, surface and algorithm-disposition registers with exact owning milestones;
- document hostile packet, compression, key, signature, oracle, downgrade, trust, metadata, traffic-analysis, secret-lifetime and plaintext-release threats;
- freeze package direction, publication class, feature isolation and explicit caller ownership of retrieval, persistence and identity trust.

Verification:

- reject missing, obsolete-as-current, orphan, contradictory and unclassified requirements or registry values with broken fixtures;
- graph-test absence of OpenPGP from TLS, legacy TLS, defaults and FIPS module artifacts and absence of implicit platform effects;
- independently review the complete scope against RFC 9580 and pass repository, documentation and standards-ledger checks.

Exit criteria:

- every planned OpenPGP surface has one disposition, owner, target and verification path before implementation;
- `v0.163.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.163.1 - OpenPGP Sans-I/O Resource And Effect Model

Status: planned

Plan scope: Define allocation-free caller-owned packet, message, certificate, keyring, compression, plaintext and output arenas; bound nesting, lengths, partial-body sequences, packet counts, decompressed output, recipients, signatures, keys, work and diagnostic detail; model entropy, time, key lookup, external signing, persistence and output as resumable typed effects with transactional failure and no unauthenticated plaintext release.

Goal: make resource use and all external authority explicit before packet and
message state can consume hostile bytes.

Deliverables:

- define private-field bounded domains, checked accounting, workspace formulas and typed exhaustion without attacker-controlled formatting;
- define affine pending effects, cancellation, retry, completion and terminal failure for entropy, time, key, signer, storage and output operations;
- freeze authenticated-output staging so no parser, decompressor or decryptor can expose unverified plaintext.

Verification:

- exhaust every counter, conversion, arena boundary, overlap rule, cancellation point and retry transition under reduced-width and full-width models;
- run no-allocator, no-atomics and pointer-width fixtures across OS-less targets and prove unchanged caller buffers on failure;
- pass repository checks, Rust matrix, documentation, graph policy and formal-harness review.

Exit criteria:

- every later OpenPGP operation is expressible without hidden allocation, platform access, authority or premature output;
- `v0.163.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.164.0 - OpenPGP Packet Header And Length Codec

Status: planned

Plan scope: Implement old- and new-format packet headers, one-, two- and five-octet lengths, bounded partial-body lengths and concatenation, exact consumption, truncation-at-every-byte, canonical writer policy and preservation of authenticated bytes without allocating or interpreting packet bodies.

Goal: establish a minimal panic-free wire boundary independent of packet
meaning, cryptography and key policy.

Deliverables:

- implement separate borrowed read and transactional write paths for both header formats and all admitted length forms;
- represent partial streams as bounded continuation state with checked cumulative length and work accounting;
- preserve exact consumed bytes and reject indeterminate, overflowing, over-limit or non-policy encodings without partial mutation.

Verification:

- test every truncation, boundary length, partial sequence, old/new transition, trailing byte, output capacity and pointer-width conversion;
- fuzz and differentially parse generated packet headers while proving no panic, over-read, wrap or unbounded loop;
- pass no_std, MSRV/latest, Miri, formal cursor proofs and repository gates.

Exit criteria:

- packet framing is exact, bounded, allocation-free and incapable of admitting a body interpretation;
- `v0.164.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.164.1 - OpenPGP Packet Values, Unknowns, And Criticality

Status: planned

Plan scope: Implement typed packet tags, versions, algorithm identifiers, signature types, subpacket headers and registries with exhaustive implemented, rejected, safely ignored, critical-failure, compatibility-read, private-use and experimental dispositions; retain unknown values without stringly dispatch or accidental capability admission.

Goal: prevent unknown or deprecated identifiers from becoming implicit
algorithm selection or silently weakened policy.

Deliverables:

- generate typed values and disposition tables from the locked registry while keeping unknown wire integers round-trippable where safe;
- encode context-specific criticality, duplicate, ordering, version and private-use decisions in non-exhaustive observation but exhaustive authority types;
- bind each executable disposition to a later milestone, provider capability and test target.

Verification:

- exercise every registered and boundary value, unknown critical and noncritical case, duplicate, reserved, experimental and private-use identifier;
- use broken fixtures to reject string dispatch, wildcard authorization, missing ownership and registry drift;
- pass source closure, generated artifact, no_std, fuzz, documentation and repository checks.

Exit criteria:

- no unrecognized identifier can select code or gain capability without a numbered review;
- `v0.164.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.164.2 - OpenPGP Packet Body Semantic Closure

Status: planned

Plan scope: Implement or explicitly disposition every RFC 9580 packet body and version not owned by a later cryptographic engine, including Marker, Trust, User ID, User Attribute and Image, MDC and Padding packets; preserve bounded opaque and private-use values where forward compatibility permits, prevent Trust or Marker data from gaining authority, and machine-check that every registered packet/version has an implementation, later owner, safe-ignore rule or normative rejection.

Goal: close packet-body semantics before armored or higher-level inputs can hide
an unowned packet, version, authority field or compatibility path.

Deliverables:

- implement bounded codecs and exact semantic dispositions for simple, metadata, compatibility and padding packet bodies;
- preserve safe opaque values and authenticated bytes while keeping Trust, Marker, image and private-use content informational and caller-owned;
- extend the generated packet/version register so every executable entry names its implementation milestone and every other entry names its normative rejection or ignore rule.

Verification:

- exercise every registered tag and version, malformed body, duplicate, placement, boundary length, unknown criticality and private-use case;
- use broken fixtures to reject missing owners, wildcard handling, accidental authority, unbounded image or padding data and registry drift;
- pass packet differentials, fuzz, formal length and state checks, no_std, documentation and repository gates.

Exit criteria:

- every RFC 9580 packet body has an exact tested disposition without granting metadata or unknown values implicit authority;
- `v0.164.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.165.0 - OpenPGP Wire And ASCII Armor Conformance Gate

Status: planned

Plan scope: Implement RFC 9580 ASCII Armor and CRC-24 policy through the admitted Base64 boundary, including multi-block, label, header, line, whitespace, checksum and trailing-data rules; differentially test packet framing and armor against independent implementations and pentest the cumulative v0.160.0-through-v0.165.0 delta before publication.

Goal: publish the first integrated OpenPGP boundary only after its framing and
encoding dependencies are independently exercised and cumulatively pentested.

Deliverables:

- implement `brynja-openpgp-armor` with caller buffers, exact labels and headers, bounded line handling and explicit required, optional or forbidden CRC-24 policy;
- integrate packet framing without interpreting or authenticating bodies and record exact Base64-ng package identity and features;
- update cumulative pentest, SBOM, package inventory, release notes and interoperability evidence for the checkpoint.

Verification:

- run official, generated, malformed, truncation, multi-block, checksum, whitespace, capacity, ambiguity and differential armor corpora;
- prove default-feature-disabled Base64 isolation, no allocation, no native code, transactional writes and exact packet/armor byte ownership;
- pass the complete tag gate, cumulative pentest, clean GitHub and CodeQL, package dry run and documentation review.

Exit criteria:

- framing and armor are independently usable but make no key, signature, encryption, trust or protocol-security claim;
- `v0.165.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

### v0.166.0 - OpenPGP Key Material, Fingerprints, And Key IDs

Status: planned

Plan scope: Implement bounded v4 and v6 public- and secret-key packet fields, algorithm-specific material framing, exact v4 fingerprint preimages, executable v6 fingerprints and both key-ID derivation rules, collision-aware lookup domains, exact-byte retention and uniform malformed-key rejection; defer v4 SHA-1 execution to v0.169.2 and do not yet authorize certificate validity or private-key use.

Goal: parse and identify key material without conflating identifiers with
authentication, trust or authority to execute cryptography.

Deliverables:

- implement bounded multiprecision and fixed-width key-field codecs with exact version and algorithm ownership;
- compute v6 fingerprints and derived key IDs through first-party SHA-256, retain exact v4 fingerprint preimages, and require explicit collision and full-fingerprint comparison policy;
- separate public, protected-secret and unlocked-secret representations and prohibit unvalidated key execution.

Verification:

- run RFC examples, generated key shapes, malformed lengths, leading-zero, invalid-point, collision-domain and truncation corpora;
- differentially compare fingerprints and key IDs and fault-inject hash, capacity and provider failure with uniform caller-visible state;
- pass secret-lifetime, zeroization, no_std, fuzz, formal length and repository checks.

Exit criteria:

- keys can be framed and identified, but only later certificate and cryptographic gates can authorize their use;
- `v0.166.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.166.1 - OpenPGP Signature Packets, Subpackets, And Hashing

Status: planned

Plan scope: Implement v4 and v6 signature packet framing, hashed and unhashed subpacket areas, required v6 salt and literal metadata, issuer and fingerprint rules, critical-subpacket handling, canonical hash preimages and trailers, and explicit SHA-256, SHA-384 and SHA-512 selection through existing first-party hash packages.

Goal: construct exact signature inputs while keeping signature mathematics and
certificate validity outside the codec.

Deliverables:

- implement bounded signature and subpacket readers and writers with exact hashed-area byte retention and criticality decisions;
- construct version-specific preimages, trailers, salt and metadata through streaming hash interfaces without allocation;
- distinguish unauthenticated unhashed hints from authenticated fields and forbid them from authorizing issuer or policy decisions.

Verification:

- test every truncation, nesting, duplicate, critical unknown, length boundary, version mismatch, trailer and salt rule;
- compare canonical preimages and digests with two independent implementations and inject hash/provider faults;
- pass no_std, formal length, fuzz, memory, graph and repository checks.

Exit criteria:

- every signature byte and hashed field is deterministic and bounded, with no verification claim before later milestones;
- `v0.166.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.166.2 - OpenPGP Signature-Subpacket Semantic Closure

Status: planned

Plan scope: Implement exact length, placement, multiplicity, authentication-domain and authority semantics for every RFC 9580 signature subpacket, including all preferred-algorithm sets, Features, Key Flags, revocation fields, Intended Recipient Fingerprint, Signature Target, Embedded Signature, Notation Data, Policy URI, Regular Expression and private or unknown values; require safe defaults to mandatory algorithms, preserve forward compatibility without trusting unhashed data, and prove every registry value has a tested disposition.

Goal: make every signature subpacket either executable under exact rules or
conspicuously non-authoritative before certificate validation consumes it.

Deliverables:

- implement typed codecs and context rules for all current signature subpackets, including required preference, feature, revocation and intended-recipient semantics;
- distinguish hashed authority, unhashed hints, caller-owned policy metadata, safely retained unknowns and critical validation failures in the type system;
- generate exhaustive subpacket ownership and disposition tables with mandatory-algorithm defaults and no wildcard authorization.

Verification:

- test every registered type, length, location, duplication, critical bit, version, signature-type context and hashed-versus-unhashed transition;
- exercise downgrade, surreptitious-forwarding, embedded-signature recursion, revocation-target, unknown-critical and preference-conflict corpora;
- pass differential, fuzz, formal state and bound, no_std, documentation, generated-artifact and repository checks.

Exit criteria:

- every RFC 9580 signature subpacket has exact tested semantics and no unauthenticated subpacket can influence cryptographic or trust authority;
- `v0.166.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.167.0 - OpenPGP Certificates, Bindings, Revocation, And Validity

Status: planned

Plan scope: Build bounded transferable public-key and secret-key certificate models; validate direct-key, user-ID, user-attribute and subkey bindings, designated revokers, revocations, expirations, primary-key rules, cross-certification and capability flags while separating structural and cryptographic validity from application identity trust and Web-of-Trust policy.

Goal: produce deterministic certificate validity results without pretending
that a valid self-signature proves a person's identity.

Deliverables:

- implement ordered certificate component assembly and binding graphs with count, depth, time and work ceilings;
- model self-signature selection, revocation precedence, expiration, key flags, primary identity and signing-subkey cross-certification;
- expose mandatory validity results and caller trust-policy inputs while excluding global trust, TOFU, keyserver and Web-of-Trust authority.

Verification:

- exercise conflicting, duplicate, expired, superseded, revoked, missing-binding, invalid-cross-certification and unknown-critical cases;
- differentially validate curated v4/v6 certificate corpora across time boundaries and provider failures;
- pass graph-cycle, work-bound, no_std, fuzz, formal state and repository checks.

Exit criteria:

- certificate structure and cryptographic validity are authoritative, bounded and visibly distinct from identity trust;
- `v0.167.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.167.1 - OpenPGP Secret-Key Protection Envelope

Status: planned

Plan scope: Implement secret-key packet protection framing, checksum and AEAD integrity states, protected-material lifetime, locked and unlocked representations, uniform password and corruption failures, caller-owned workspaces and immediate destruction; prohibit clear secret export and defer every S2K or cipher use to admitted providers.

Goal: freeze private-key custody and failure semantics before password
derivation or decryption algorithms are connected.

Deliverables:

- define non-cloneable locked and unlocked states with complete owned-region destruction and explicit external-store responsibilities;
- parse protection metadata into typed algorithm requests without executing unadmitted S2K, cipher or checksum paths;
- stage decrypted material transactionally and expose it only after integrity, structure and key-consistency validation succeeds.

Verification:

- test every truncation, malformed parameter, unsupported algorithm, wrong password, corrupt checksum/tag, output-capacity and cancellation state;
- inspect MIR, LLVM and assembly for complete secret-store survival and prove no diagnostic distinguishes password from corruption;
- pass no_std, Miri, fault injection, zeroization, graph and repository checks.

Exit criteria:

- protected secret material has a complete custody contract and cannot be exposed by a partial or unauthenticated transition;
- `v0.167.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.168.0 - First-Party Argon2 And OpenPGP S2K

Status: planned

Plan scope: Implement RFC 9106 Argon2id in first-party Rust with bounded memory and passes, caller-provided workspace, zeroization, KATs and hostile-parameter rejection; implement RFC 9580 Simple, Salted, Iterated and Argon2 S2K parsing and derivation with explicit deprecated-read policy, algorithm-use separation and no password-dependent diagnostics.

Goal: provide a from-scratch password derivation boundary that cannot allocate,
overcommit resources or import a foreign cryptographic implementation.

Deliverables:

- implement Argon2id compression, indexing and lane scheduling in small first-party modules with exact workspace ownership and parameter ceilings;
- implement all admitted S2K encodings and iteration-count semantics with modern-write and deprecated-read dispositions;
- bind derived keys to algorithm, purpose and lifetime and destroy password copies, intermediate blocks and obsolete outputs.

Verification:

- run RFC 9106 and RFC 9580 vectors, boundary parameters, reduced-memory models, differentials and malformed or hostile parameter corpora;
- prove checked indexing, no overflow, no secret-dependent diagnostics, exact memory use and zeroization across MSRV/latest and targets;
- complete side-channel, Miri, formal, fuzz, native resource and independent cryptographic review.

Exit criteria:

- S2K execution is bounded, first-party, independently evidenced and cannot weaken modern password policy silently;
- `v0.168.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.168.1 - First-Party OCB, EAX, GCM, And OpenPGP AEAD Profiles

Status: planned

Plan scope: Implement and independently evidence first-party OCB as the mandatory RFC 9580 AEAD, EAX as an optional first-party construction, and the exact optional OpenPGP GCM profile over existing first-party AES-GCM; bind nonces, associated data, chunk indices and final tags, enforce message and key limits, transactional output and uniform authentication failure, and keep OCB, EAX and every OpenPGP profile outside all FIPS-approved-service claims even when it reuses an individually approved primitive.

Goal: add the RFC 9580 AEAD requirements without creating a FIPS claim or an
external cryptographic dependency.

Deliverables:

- implement generic OCB and EAX constructions over admitted first-party AES with nonces, offsets, tags and checked use limits;
- add separate OpenPGP OCB, EAX and GCM profile adapters for associated data, chunk and final-tag construction and exact algorithm identifiers;
- classify all OpenPGP profile services non-approved and keep them outside the validated module and approved-only facade, including the profile that reuses AES-GCM.

Verification:

- run official, published and independently generated KATs, in-place/disjoint buffers, overlap rejection, nonce, length and tag boundaries;
- differentially test every admitted AES width and tag length and fault-inject authentication, capacity, counter and provider failures;
- complete constant-time, zeroization, formal, fuzz, emitted-code, independent crypto and FIPS-boundary review.

Exit criteria:

- OCB and EAX are reusable first-party constructions, all three exact OpenPGP profiles are bounded, and their non-FIPS status is unambiguous;
- `v0.168.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.169.0 - OpenPGP Ed25519, X25519, Ed448, And X448 Profiles

Status: planned

Plan scope: Bind RFC 9580 Ed25519 signature and X25519 encryption requirements to existing first-party curve symbols; add separately evidenced Ed448 and X448 only where admitted by the algorithm register; validate encodings, subgroup and low-order rules, ephemeral-key lifecycle, KDF context and algorithm-specific signature formatting without generic cross-protocol key reuse.

Goal: expose only exact OpenPGP curve profiles over already reviewed primitive
symbols, with no generic or cross-protocol key ambiguity.

Deliverables:

- define typed OpenPGP key, signature and encryption adapters for mandatory Ed25519 and X25519 and conditional Ed448/X448;
- bind version, algorithm, fingerprint, KDF parameters and operation purpose into every provider request and opaque handle;
- enforce validation, ephemeral destruction and public-key substitution defenses while prohibiting implicit conversion or reuse.

Verification:

- run RFC and independent vectors, invalid encodings, low-order points, wrong curves, context confusion, signature malleability and fault cases;
- compare provider and direct primitive paths and inspect constant-time and zeroization evidence per target and backend;
- pass formal, fuzz, no_std, interoperability, independent crypto and repository gates.

Exit criteria:

- mandatory modern curve operations are profile-exact and no OpenPGP key can cross an algorithm or protocol domain silently;
- `v0.169.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.169.1 - OpenPGP Compatibility Algorithm Containment

Status: planned

Plan scope: Freeze generation, encryption, signing, verification and decryption policy for RSA, DSA, Elgamal, IDEA, TripleDES, CAST5, SHA-1, RIPEMD-160 and every deprecated or reserved algorithm; permit only explicitly justified compatibility operations in optional `brynja-openpgp-legacy`, with signing or encryption limited to separately admitted strong v4 profiles and weak algorithms limited to necessary read, decrypt or verify paths; never generate weak key, digest or cipher forms, enable compatibility through the modern facade, or mistake interoperability for security approval.

Goal: make historical interoperability an explicit isolated risk boundary rather
than a fallback path in modern OpenPGP.

Deliverables:

- publish a per-operation matrix of modern, compatibility-read, legacy-only, rejected and unimplemented algorithms with normative rationale;
- freeze the optional legacy package graph, warnings, key separation and absence from modern features, defaults and re-exports;
- require uniform oracle-resistant RSA compatibility failures and prohibit new weak key, signature, ciphertext or digest generation.

Verification:

- graph-test modern and legacy isolation and broken fixtures for feature unification, re-export, default, FIPS and fallback regressions;
- exercise archived compatible material and reject every prohibited generation or encryption request with authoritative typed outcomes;
- pass source-closure, cryptographic, oracle, documentation, package and independent risk review.

Exit criteria:

- weak historical capability is either absent or conspicuously isolated and can never be negotiated or selected by the modern facade;
- `v0.169.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.169.2 - First-Party Brynja Legacy SHA-1

Status: planned

Plan scope: Implement complete streaming and fixed-message SHA-1 once in `brynja-legacy-sha1` with official vectors, boundary lengths, checked exhaustion, caller-owned state, constant-time applicability, zeroization policy, differential, formal, fuzz, emitted-code and independent cryptographic-risk evidence; publish conspicuous collision-resistance warnings, expose no MAC, signature, certificate or protocol policy, and keep the package outside `brynja`, every modern/default/general-hash/TLS/PKIX/FIPS graph and approved claim. Direct use is explicit and unsafe for collision-resistant purposes; each internal consumer requires its own numbered admission.

Goal: implement SHA-1 exactly once as a complete but visibly legacy primitive
whose dangerous properties and downstream authority cannot be hidden.

Deliverables:

- implement complete caller-buffer streaming, reset and fixed-message SHA-1 with checked bit-length accounting, exact digest output and no hidden allocation;
- publish warnings and types that never claim collision resistance, MAC safety, signature suitability, password security, certificate policy or FIPS approval;
- freeze package and feature isolation from `brynja`, modern/default/general-hash/TLS/PKIX/FIPS graphs while requiring a numbered review for every internal consumer.

Verification:

- run official and published SHA-1 vectors, million-byte, padding-boundary, chunking, reset, fixed/streaming equivalence, overflow and independent differential cases;
- fuzz state transitions and lengths, prove checked accounting and transactional output, inspect emitted code and document constant-time and zeroization applicability;
- complete independent cryptographic-risk, package-warning, no_std, MSRV/latest, graph-isolation and repository review.

Exit criteria:

- complete SHA-1 is reusable without reimplementation, but no Brynja internal graph may consume it until a separate numbered admission defines exact safe compatibility use;
- `v0.169.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.169.3 - OpenPGP V4 Fingerprint SHA-1 Integration

Status: planned

Plan scope: Admit the first `brynja-openpgp-legacy` consumer of `brynja-legacy-sha1`, solely for RFC 9580 v4 fingerprint and key-ID derivation; bind exact key-packet preimages, require full-fingerprint collision-aware comparisons, prohibit SHA-1 signatures and generation, and reserve the protected-key and v1 SEIPD consumers for their separate v0.169.5 and v0.171.2 reviews while proving no modern OpenPGP, facade, default, TLS, PKIX, password, MAC or FIPS edge. Later legacy protocols and the post-1.0 legacy hash facade may reuse the exact implementation only after their own numbered integration review, without reimplementing SHA-1.

Goal: admit one exact RFC 9580 compatibility use while preserving the complete
legacy primitive as the sole SHA-1 implementation.

Deliverables:

- connect exact v4 key-packet fingerprint preimages to `brynja-legacy-sha1` only inside `brynja-openpgp-legacy`;
- derive key IDs only from retained complete fingerprints and require full-fingerprint comparison with explicit collision and ambiguity outcomes;
- prohibit every SHA-1 signature, generation, modern OpenPGP, facade, default, TLS, PKIX, password, MAC and FIPS edge with machine graph policy.

Verification:

- run RFC 9580 and independent v4 fingerprint/key-ID vectors, malformed key-packet, substitution, ambiguity and chosen-prefix policy cases;
- graph-test sole-consumer authority and reject arbitrary SHA-1 operation routing through OpenPGP provider or algorithm selection;
- pass interoperability, fuzz, formal preimage/length, independent compatibility-risk, documentation and repository review.

Exit criteria:

- v4 fingerprints interoperate through one exact legacy edge while SHA-1 signing, generation and every unauthorized consumer remain impossible;
- `v0.169.3 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.169.4 - First-Party AES Key Wrap And OpenPGP Curve Wrapping Profiles

Status: planned

Plan scope: Implement RFC 3394 AES-128 and AES-256 key wrap and unwrap in first-party Rust with caller-owned buffers, exact integrity checks, uniform failures and zeroization; bind the exact RFC 9580 X25519 and X448 HKDF inputs, labels, output sizes and wrapped-session-key formats, and provide the separately typed ECDH wrapping primitive needed by admitted v4 compatibility profiles without generic cross-protocol key reuse.

Goal: make mandatory X25519 encryption executable through an exact reviewed
key-wrapping construction rather than an implicit provider promise.

Deliverables:

- implement RFC 3394 wrap and unwrap over exact first-party AES symbols with checked block counts, overlap policy and complete temporary destruction;
- implement profile-specific X25519/SHA-256/AES-128 and X448/SHA-512/AES-256 HKDF input, label, field and wrapped-session-key construction;
- expose a distinct ECDH wrapping primitive for separately admitted v4 profiles without generic key, context or protocol interchange.

Verification:

- run RFC 3394 and RFC 9580 vectors, every supported key and payload width, integrity corruption, truncation, overlap, output-capacity and exhaustion case;
- differentially test wrap/unwrap and complete X25519/X448 PKESK construction while fault-injecting HKDF, AES, entropy and provider failures;
- complete constant-time, zeroization, formal bounds, fuzz, no_std, independent cryptographic and repository review.

Exit criteria:

- mandatory modern curve encryption has an exact first-party key-wrap path and no malformed unwrap can release a session key;
- `v0.169.4 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.169.5 - OpenPGP CFB And Protected Secret-Key Compatibility

Status: planned

Plan scope: Implement first-party OpenPGP conventional CFB over admitted AES widths and the exact version 4 protected-secret-key usage-254 SHA-1 and usage-255 checksum formats inside `brynja-openpgp-legacy`; admit those narrowly defined additional `brynja-legacy-sha1` and checksum consumers, require verify-before-release, uniform password/corruption failures and immediate secret destruction, and prohibit weak S2K hashes, obsolete ciphers, automatic fallback or any modern/FIPS edge.

Goal: permit secure custody and import of common protected v4 secret keys
without allowing their historical protection formats into modern OpenPGP.

Deliverables:

- implement conventional CFB over admitted AES widths with exact IV, prefix, streaming, overlap, finalization and caller-buffer rules;
- connect usage 254 solely to exact SHA-1 integrity verification and usage 255 solely to the defined checksum after complete protected-secret decryption;
- isolate every compatibility operation, warning, key lifetime and dependency edge inside `brynja-openpgp-legacy` and prohibit weak S2K hash or obsolete-cipher execution.

Verification:

- run archived and independently generated protected-key vectors for every admitted AES/S2K combination, wrong passwords, corruption, truncation and malformed secret material;
- prove no decrypted secret escapes before checksum, hash, structure and public/private consistency validation and inspect complete failure-path destruction;
- pass oracle, side-channel, fuzz, formal state, Miri, no_std, graph-isolation, independent risk and repository gates.

Exit criteria:

- admitted protected v4 secret keys can be imported without exposing plaintext early or granting legacy protection a modern or FIPS claim;
- `v0.169.5 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.169.6 - OpenPGP Strong V4 Public-Key Compatibility Profiles

Status: planned

Plan scope: Implement explicitly selected strong-algorithm v4 compatibility profiles in `brynja-openpgp-legacy`, including RSA PKCS#1 v1.5 SHA-2 signatures, oracle-resistant RSA session-key encryption and decryption, Ed25519Legacy, Curve25519Legacy and admitted ECDSA/ECDH curves; permit existing-key signing or encryption only through conspicuous compatibility policy, never generate deprecated key forms, and give every omitted optional or obsolete algorithm an explicit tested rejection.

Goal: support common strong v4 certificates and messages through reviewed
profiles rather than claiming compatibility from packet parsing alone.

Deliverables:

- implement exact OpenPGP RSA signature and PKESK encodings with strict padding, blinding, fault checks, uniform failure and SHA-2-only generation policy;
- implement exact Ed25519Legacy, Curve25519Legacy and admitted ECDSA/ECDH key, signature, KDF, wrap and wire profiles over existing first-party primitives;
- publish an operation matrix for every RFC 9580 public-key algorithm and curve, including explicit generation, signing, encryption, verification, decryption or rejection decisions.

Verification:

- interoperate on archived and generated v4 RSA, legacy-25519 and admitted ECDSA/ECDH certificates, signatures and encrypted messages;
- exercise PKCS#1 oracles, invalid points, malformed MPIs, KDF confusion, weak hashes, key-size policy, cross-profile substitution and every rejected algorithm;
- pass constant-time, zeroization, formal, fuzz, no_std, graph-isolation, independent compatibility-risk and repository review.

Exit criteria:

- common strong v4 operations are executable only through explicit compatibility policy and every unsupported optional or obsolete profile fails predictably;
- `v0.169.6 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.170.0 - OpenPGP Key And Cryptography Audit Gate

Status: planned

Plan scope: Independently audit OpenPGP key parsing, fingerprints, certificate validity, signature hashing, secret-key protection, S2K, Argon2, OCB, EAX, RFC 3394 key wrap, modern curve profiles, OpenPGP CFB, protected-v4-key handling, strong v4 public-key profiles, compatibility isolation, constant-time behavior, zeroization and provider composition; remediate all admitted findings before message encryption or signature execution.

Goal: stop higher-level message construction until every key and cryptographic
foundation has clean independent evidence.

Deliverables:

- freeze exact audited source, symbols, features, algorithms, packages, compiler and evidence hashes;
- disposition every standards, cryptographic, memory, side-channel, resource, API and compatibility finding and retain permanent regressions;
- update verification status, residual gaps, threat model, requirements, release notes, pentest and publication closure.

Verification:

- rerun every primitive, key, certificate, S2K, AEAD, curve, failure, resource and isolation suite on the remediated commit;
- reproduce independent vectors, differentials, emitted-code, formal, fuzz and target evidence without unresolved critical or high findings;
- pass complete tag gate, cumulative pentest, green GitHub and CodeQL and package publication dry run.

Exit criteria:

- message-level code may consume only exact cleanly retested OpenPGP foundations with documented residual limits;
- `v0.170.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

### v0.171.0 - OpenPGP Session-Key Packets And Recipient Selection

Status: planned

Plan scope: Implement v3 and v6 Public-Key and Symmetric-Key Encrypted Session Key packets, hidden recipients, checksums, KDF and wrapping rules, bounded multi-key lookup, deterministic preferences, exact algorithm matching and uniform recipient, password, unwrap and unsupported-algorithm failures without releasing a session key early.

Goal: recover or create session keys only through an exact, bounded and
oracle-resistant recipient decision.

Deliverables:

- implement typed PKESK and SKESK codecs and algorithm-specific provider requests with exact version and fingerprint binding;
- define bounded visible and hidden-recipient search, key-store effects, preference order and constant-work policy where feasible;
- stage candidate session keys until wrapping integrity, algorithm consistency and authoritative recipient selection all succeed.

Verification:

- test malformed, duplicate, hidden, missing, wrong-key, wrong-password, algorithm-confusion, capacity and provider-fault cases;
- measure and review recipient and unwrap error behavior, RSA compatibility oracles and secret destruction across all paths;
- pass RFC vectors, differentials, fuzz, formal state, no_std and repository gates.

Exit criteria:

- session keys cannot escape before one exact recipient path is fully authenticated and policy-approved;
- `v0.171.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.171.1 - OpenPGP V2 SEIPD Chunked AEAD

Status: planned

Plan scope: Implement version 2 Symmetrically Encrypted Integrity Protected Data with RFC 9580 chunk sizing, nonce construction, associated data, chunk and final tags, checked indices and lengths, bounded streaming, truncation and reordering rejection, failure-atomic state, and withholding of every plaintext byte until its authentication decision is authoritative.

Goal: provide the modern OpenPGP encrypted-data engine with exact per-chunk
authentication and no ambiguous end-of-message state.

Deliverables:

- implement typed v2 SEIPD headers, chunk schedule, nonce and associated-data derivation and mandatory final-tag processing;
- define staged plaintext ownership, authenticated-chunk release policy, cancellation, rekey and checked exhaustion semantics;
- prohibit MDC-only generation in the modern profile and route any admitted historical read path through legacy policy.

Verification:

- test every chunk boundary, empty/final chunk, truncation, reordering, duplication, tag corruption, index overflow and output-capacity condition;
- differentially exercise supported AEAD/cipher combinations and prove no unauthenticated bytes or stale session keys escape failures;
- pass fuzz, formal state and arithmetic, Miri, side-channel, zeroization and repository gates.

Exit criteria:

- encrypted streaming is complete only after all required chunk and final authentication decisions succeed;
- `v0.171.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.171.2 - OpenPGP V1 SEIPD And MDC Compatibility

Status: planned

Plan scope: Implement RFC 9580 version 1 SEIPD decryption with OpenPGP CFB prefix handling, quick-check oracle resistance, exact MDC construction and constant-time SHA-1 verification entirely inside `brynja-openpgp-legacy`; allow AES-only generation solely through an explicit compatibility operation for recipients that cannot consume v2 SEIPD, never as automatic fallback, and withhold the complete plaintext until MDC, packet grammar and final-length validation succeed.

Goal: support the RFC-defined v1 encrypted-message compatibility path without
letting its malleability and oracle risks weaken the modern v2 engine.

Deliverables:

- implement exact random prefix, repeated-octet quick check, CFB stream, MDC packet and SHA-1 preimage processing over the separately admitted legacy primitives;
- stage the complete decrypted packet sequence until prefix, MDC, final length and nested message grammar are authoritative, returning one uniform failure class;
- expose optional AES-only v1 generation through an explicit legacy operation with recipient capability evidence, warnings and no negotiation or automatic-fallback edge.

Verification:

- run RFC 9580 Appendix A.12 and independent v1 SEIPD vectors, every AES width, boundary split, wrong key, corruption, truncation, extension and trailing-data case;
- exercise quick-check and MDC oracle corpora, timing distributions, provider faults and plaintext-release attempts across every failure point;
- pass differential, fuzz, formal state and bounds, Miri, zeroization, no_std, legacy-isolation, independent risk and repository gates.

Exit criteria:

- v1 SEIPD compatibility is complete, whole-message authenticated before release and unable to become an implicit alternative to modern v2 SEIPD;
- `v0.171.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.172.0 - OpenPGP Signed, One-Pass, And Detached Messages

Status: planned

Plan scope: Implement binary and canonical-text document signatures, standalone and timestamp signatures, one-pass nesting, detached signatures, multi-signature ordering, exact signed-data construction, time and policy effects, and authoritative mandatory verification outcomes that cannot be replaced by informational events.

Goal: make every supported signature form deterministic, streaming and
authoritative about what exact bytes and identity were verified.

Deliverables:

- implement one-pass and trailing-signature state machines with bounded nesting, signer count and exact packet pairing;
- define binary and canonical-text hashing, detached-input consumption and timestamp policy through caller-owned buffers and effects;
- return exhaustive validity, signer, key, certificate, policy and content-scope outcomes separately from observational events.

Verification:

- test reordered, missing, extra, duplicated, nested, wrong-key, expired, revoked, bad-hash and canonicalization edge cases;
- interoperate on detached, embedded, binary, text, standalone and multi-signature fixtures with independent implementations;
- pass fuzz, formal state, provider-fault, no_std, documentation and repository checks.

Exit criteria:

- callers cannot confuse parsed, mathematically valid, certificate-valid and policy-trusted signatures;
- `v0.172.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.172.1 - OpenPGP Cleartext Signature Framework

Status: planned

Plan scope: Implement dash-escaping, canonical text conversion, Hash headers, whitespace and line-ending rules, armor integration, streaming verification and generation, multiple-signature policy, ambiguity rejection and exact recovered-text boundaries without conflating display normalization with authenticated content.

Goal: support cleartext signatures without allowing presentation transforms to
change which bytes are authenticated.

Deliverables:

- implement a bounded state machine for cleartext headers, dash escaping, canonical line endings and following signature armor;
- retain explicit original, canonicalized and displayed content domains and caller-selected output policy;
- validate Hash header and signature algorithm agreement and reject ambiguous nested or trailing material.

Verification:

- test every line-ending, leading dash, trailing whitespace, missing newline, header, multi-signature, Unicode-byte and armor split boundary;
- compare exact hash preimages and recovered text with independent tools and malicious ambiguity corpora;
- pass streaming, fuzz, no-allocation, formal state, documentation and repository checks.

Exit criteria:

- cleartext verification reports the exact authenticated content and never silently normalizes display bytes into authority;
- `v0.172.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.173.0 - OpenPGP Literal And Compressed Packet Sequences

Status: planned

Plan scope: Implement bounded literal-data metadata and recursive message grammar plus Uncompressed, ZIP and ZLIB compression identifiers, nesting and content policies; require streaming output ceilings, expansion-ratio and total-work budgets before a decompressor can be selected.

Goal: describe complete message structure and compression authority before a
decompressor can consume attacker-controlled data.

Deliverables:

- implement literal packet metadata and a bounded non-recursive message-sequence machine with explicit allowed packet order and nesting;
- define compression provider ports, workspace, total output, ratio, nesting and work tokens with transactional decompressed output;
- classify Uncompressed as mandatory, ZIP/ZLIB support as planned and every unknown or unsupported compression identifier fail closed.

Verification:

- test empty, nested, reordered, duplicate, oversized, unknown, partial and trailing packet sequences and all metadata boundaries;
- model exhaustion and cancellation before, during and after decompression without exposing partial unauthenticated content;
- pass grammar fuzzing, formal work accounting, no_std, allocation-counter and repository gates.

Exit criteria:

- packet sequences are bounded and no compression path exists without explicit caller resource authority;
- `v0.173.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.173.1 - First-Party DEFLATE, ZIP, And ZLIB Profiles

Status: planned

Plan scope: Implement the smallest separately reusable first-party Rust DEFLATE decoder and ZLIB wrapper required by RFC 9580, with bounded history workspace, checksum, canonical error, malformed-stream and decompression-bomb defenses; add compression only when it preserves no-allocation and no-native-code rules, with compression generation remaining policy-selectable.

Goal: satisfy RFC 9580 decompression expectations without importing a native or
third-party compression engine into the protocol graph.

Deliverables:

- implement bit, Huffman, stored and back-reference decoding in small reviewed modules over caller-owned history storage;
- implement raw ZIP/DEFLATE and ZLIB framing, Adler-32, stream completion and exact consumed/written accounting;
- expose bounded decompression through the frozen provider port and keep compression generation separately selectable and nonessential.

Verification:

- run published, independently generated and adversarial fixed, dynamic and stored-block corpora including invalid trees and distances;
- test bombs, ratio, output, history, work, nesting, truncation, checksum, capacity and cancellation at every byte and bit boundary;
- complete differentials, fuzzing, formal bounds, Miri, no_std, independent parser audit and repository checks.

Exit criteria:

- ZIP and ZLIB decoding is bounded, allocation-free, first-party and incapable of bypassing message authentication or output policy;
- `v0.173.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.173.2 - First-Party BZip2 OpenPGP Compatibility Decoder

Status: planned

Plan scope: Implement an optional isolated first-party Rust BZip2 decoder sufficient for RFC 9580 Compressed Data packets, with caller-owned bounded workspace, exact block and stream checks, decompression-bomb and recursion defenses, no generation requirement and no default/facade edge; differentially qualify archived BZip2 OpenPGP messages and keep unsupported future compression identifiers fail closed.

Goal: read the remaining registered RFC 9580 compression form without making
an optional complex decoder part of modern or default dependency graphs.

Deliverables:

- implement bounded BZip2 framing, Huffman, move-to-front, Burrows-Wheeler reversal, run decoding and CRC verification in small first-party modules;
- require caller-owned workspace, exact input/output accounting, block, expansion, recursion and total-work ceilings and transactional decompressed output;
- expose the decoder only through an explicit OpenPGP compatibility capability with no compressor, default feature, native code or hidden allocation.

Verification:

- run published, generated and archived BZip2 OpenPGP corpora across block sizes, CRCs, randomized flags, truncation, malformed trees, cycles and trailing bytes;
- differentially decode against two independent process-isolated tools and attack expansion, recursion, CPU, memory and output limits;
- pass fuzz, formal bound and state, Miri, sanitizer, no_std, graph-isolation, emitted-code and repository checks.

Exit criteria:

- every RFC 9580 compression identifier is implemented or explicitly rejected, and optional BZip2 input cannot escape its bounded compatibility edge;
- `v0.173.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.174.0 - OpenPGP Encrypt, Decrypt, Sign, And Verify Pipelines

Status: planned

Plan scope: Compose packet, armor, compression, key, signature and encryption components into allocation-free Sans-I/O APIs for encryption, decryption, signing and verification; enforce verify-before-release, exact operation tokens, no implicit algorithm fallback, rollback-safe outputs, cancellation and terminal secret destruction.

Goal: expose complete high-level operations while preserving every lower-level
authority, resource and authentication boundary.

Deliverables:

- implement builders and resumable engines for the four operations using typed profiles and caller-owned arenas;
- bind keys, algorithms, recipients, signers, literal metadata, compression, armor and output decisions into immutable operation context;
- define exhaustive terminal outcomes and destroy session keys, password material, ephemeral keys and staged plaintext on all exits.

Verification:

- round-trip supported operation combinations across streaming splits, backpressure, cancellation, provider faults and minimal/exact/insufficient workspaces;
- inject failures at every effect and state transition and prove unchanged or explicitly invalidated outputs and no fallback;
- pass formal state, fuzz, Miri, side-channel, zeroization, no_std, interoperability and repository gates.

Exit criteria:

- the public operation engines are compositional, failure-atomic and cannot overstate authentication or trust;
- `v0.174.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.174.1 - OpenPGP Multi-Recipient And Preference Negotiation

Status: planned

Plan scope: Implement bounded multi-recipient encryption, shared-session-key handling, algorithm and feature preference intersection, anonymous-recipient policy, deterministic conflict resolution, downgrade rejection and constant-work recipient search where feasible; expose residual recipient-privacy and traffic-analysis limits explicitly.

Goal: make multi-recipient selection predictable and safe without claiming to
hide metadata the OpenPGP wire format exposes.

Deliverables:

- implement deterministic preference intersection over exact recipient certificate capabilities and modern policy minima;
- create one protected session key per operation with bounded recipient envelopes, hidden-recipient options and no cross-operation reuse;
- expose conflicts, downgrade refusal and residual search timing or recipient visibility as explicit typed outcomes and documentation.

Verification:

- test conflicting, empty, duplicate, revoked, expired, mixed-version, hidden and unsupported recipient sets and permutation invariance;
- measure recipient search and error behavior, verify identical ciphertext session key and distinct wrappers, and fault-inject every provider path;
- pass differential interoperability, fuzz, formal bounds, side-channel review and repository checks.

Exit criteria:

- multi-recipient operations cannot silently select a weaker common algorithm or conceal known privacy limitations;
- `v0.174.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.175.0 - OpenPGP Message Conformance And Audit Gate

Status: planned

Plan scope: Complete RFC 9580 vectors, generated edge cases, malformed and adversarial corpora, independent differential tests and interoperability for armored, signed, compressed, password-encrypted, public-key-encrypted and multi-recipient messages across v2 SEIPD and the isolated v1 SEIPD/MDC compatibility path; audit no-plaintext-release and cumulative resource guarantees before checkpoint publication.

Goal: stop key-management work until complete message operations have clean
conformance, interoperability and independent security evidence.

Deliverables:

- freeze exact message APIs, algorithm profiles, packages, features, resource formulas, external tool versions and evidence hashes;
- disposition all parser, compression, signature, encryption, oracle, memory, side-channel and API findings and retain regressions;
- update cumulative pentest, release notes, verification status, SBOM and publication closure for the checkpoint.

Verification:

- run the full message matrix, malicious corpus, every failure injection, cross-tool round trip and no-plaintext-release assertion;
- repeat formal, fuzz, Miri, sanitizer, timing, emitted-code, hostile-load and no_std campaigns on the remediated candidate;
- pass complete tag gate, cumulative pentest, clean GitHub and CodeQL and package dry run.

Exit criteria:

- supported messages interoperate and fail closed within published bounds, with no unresolved critical or high finding;
- `v0.175.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

### v0.176.0 - OpenPGP Keyring Import, Merge, And Trust Boundary

Status: planned

Plan scope: Implement transactional bounded certificate and keyring import, duplicate and conflict handling, self-signature selection, update and revocation merge, rollback resistance, provenance and application policy hooks; keep keyserver retrieval, WKD, DNS, TOFU and Web-of-Trust decisions caller-owned and impossible to activate implicitly.

Goal: make local key material updates deterministic without turning storage or
network discovery into hidden trust authority.

Deliverables:

- implement bounded import and merge plans with stable identity, provenance, monotonic update and atomic commit semantics;
- define conflict, rollback, revocation, supersession and invalid-component dispositions with mandatory caller decisions where policy is external;
- expose pure inputs and effects for persistence while excluding network retrieval, global stores and identity trust from protocol packages.

Verification:

- test duplicates, reorderings, partial updates, stale and malicious self-signatures, revocation races, conflicts and crash recovery;
- prove permutation determinism, rollback refusal, unchanged stores on failure and no implicit fetch or trust transition;
- pass formal merge, fuzz, hostile corpus, storage-fault, no_std and repository checks.

Exit criteria:

- imported key material changes only through an explicit atomic plan and never acquires identity trust automatically;
- `v0.176.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.176.1 - OpenPGP Key Generation, Rotation, Expiration, And Revocation

Status: planned

Plan scope: Implement modern v6 key and subkey generation, binding, expiration, designated usage, rotation, revocation certificate creation and recovery workflows with caller entropy, time and storage effects, safe defaults, deterministic failure recovery and immediate obsolete-secret destruction; do not generate v4 or deprecated algorithms by default.

Goal: provide an opinionated modern key lifecycle without silently generating
compatibility-era material.

Deliverables:

- define safe v6 primary and subkey profiles, usages, expiration ranges, protection policy and immutable generation recipes;
- implement rotation, replacement bindings, offline revocation artifacts, recovery and atomic store updates through explicit effects;
- destroy discarded candidates and obsolete unlocked secrets and expose backup, custody and compromise guidance.

Verification:

- test entropy and time failure, interrupted generation, duplicate identifiers, expiration boundaries, rotation races and revocation recovery;
- interoperate generated keys and revocations with independent tools while proving no deprecated default output;
- pass statistical key checks, lifecycle formal tests, zeroization, no_std, documentation and repository gates.

Exit criteria:

- modern keys can be created, rotated and revoked through recoverable, bounded workflows with explicit custody responsibilities;
- `v0.176.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.177.0 - OpenPGP External-Key And Sanitization Integration

Status: planned

Plan scope: Integrate opaque external signing and decryption handles, pending-operation tokens, cancellation and irreversible completion with OpenPGP workflows; optionally bridge caller-owned secret storage through `brynja-sanitization` without making it a protocol dependency or weakening the native destruction contract.

Goal: support hardware and external custody without treating a handle or an
informational event as proof that a mandatory key operation completed.

Deliverables:

- bind opaque handles to exact key fingerprint, algorithm, role, operation bytes, provider generation and single-consumption completion token;
- implement retry, cancellation, timeout, provider quarantine and irreversible-destruction acknowledgements in OpenPGP engines;
- provide an optional downstream sanitization adapter path with identical owned-region guarantees and no facade or FIPS implication.

Verification:

- inject replayed, swapped, stale, forged, duplicated, cancelled and late completions and external-store failures;
- prove ignored events cannot authorize signatures, plaintext, key destruction or operation success and test complete secret cleanup;
- pass formal token, concurrency, fault, no_std, adapter-isolation and repository checks.

Exit criteria:

- every external key effect is exact-operation bound and terminal outcomes remain authoritative under cancellation and failure;
- `v0.177.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.177.1 - OpenPGP no_std Resource And Hostile-Input Qualification

Status: planned

Plan scope: Prove allocation-free operation on supported bare-metal and OS-less targets with exact workspace sizing, stack ceilings, maximum packet, nesting, recipient, signature, certificate, S2K and decompression work; exercise truncation, mutation, bombs, exhaustion, cancellation and provider failure without panic, partial output or secret leakage.

Goal: convert the resource model into reproducible target evidence under
hostile inputs and worst-case supported policy.

Deliverables:

- publish deterministic workspace calculators, stack measurements and per-operation work formulas for minimal, recommended and maximum profiles;
- build first-party hostile-input harnesses for every packet, key, message, S2K, compression and effect boundary;
- record native and emulated target evidence while distinguishing compiler coverage from performance and side-channel claims.

Verification:

- run exact-minus-one, exact and over-capacity workspaces, every truncation and structured mutation, maximum nesting and decompression bombs;
- execute bare-metal/no-atomics builds and representative OS-less harnesses across the supported compiler range;
- pass allocation counters, stack budgets, fuzz, Miri, sanitizer, formal resource and repository gates.

Exit criteria:

- every supported operation has a tested finite memory and work envelope and failure reveals no secret or partial authoritative output;
- `v0.177.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.178.0 - OpenPGP External Interoperability Campaign

Status: planned

Plan scope: Interoperate through process-isolated harnesses with at least two independent current OpenPGP implementations across modern v6 keys, armor, signatures, encryption, compression, password protection, multi-recipient messages and negative cases; pin tool versions and retain exact transcripts without adding their libraries to Cargo graphs.

Goal: prove real wire compatibility without making external implementations
dependencies or normative oracles.

Deliverables:

- define a reproducible cross-product of operations, algorithms, key forms, compression, armor and negative behavior for two independent peers;
- pin external process tools and runner environments and retain byte artifacts, commands, versions and expected outcomes;
- distinguish peer limitation, optional behavior, Brynja defect and standards ambiguity in a reviewed disposition ledger.

Verification:

- generate and consume artifacts in both directions, including multiple recipients, detached and cleartext signatures, passwords and v4 compatibility;
- replay all retained artifacts offline and mutate interoperability specimens into permanent negative regressions;
- pass package-isolation, no external Cargo dependency, documentation, reproducibility and repository checks.

Exit criteria:

- every advertised interoperable profile has bidirectional independent evidence with no hidden library dependency;
- `v0.178.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.178.1 - OpenPGP V4 Compatibility And Legacy Isolation Gate

Status: planned

Plan scope: Qualify strong-algorithm v4 certificates, protected secret keys, public-key profiles, v1 SEIPD/MDC messages and optional BZip2 input; verify every admitted deprecated read path against archived corpora, prove modern generation never emits deprecated forms or silently falls back, and prove `brynja-openpgp-legacy` and optional compression compatibility are absent from the `brynja` facade, defaults, all modern protocol graphs and FIPS artifacts.

Goal: retain explicitly useful compatibility while guaranteeing modern users do
not acquire weak algorithms or formats transitively.

Deliverables:

- publish the final v4 strong-profile and legacy read-only algorithm matrix with warnings and artifact identity;
- separate modern and legacy credentials, configuration, APIs, package archives, SBOMs and interoperability evidence;
- machine-enforce absence of weak generation, feature forwarding, fallback and modern re-export edges.

Verification:

- test v4 strong profiles and every admitted legacy specimen, rejection, warning and no-generation invariant;
- inspect no-default and all-feature metadata, lockfiles, packages and symbols for modern/legacy/FIPS separation;
- pass independent compatibility, downgrade, oracle, documentation and repository audits.

Exit criteria:

- compatibility is bounded and conspicuous, and installing modern Brynja cannot activate or expose legacy OpenPGP code;
- `v0.178.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.178.2 - OpenPGP Downstream Client-Foundation Gate

Status: planned

Plan scope: Build and test independent downstream no_std and hosted client fixtures that use only published Brynja APIs to import and export keys, generate and revoke modern keys, encrypt and decrypt public-key and passphrase messages, sign and verify embedded, detached and cleartext content, process modern and admitted v4 compatibility data, and recover from bounded failures; document that UI, persistence, networking, key discovery, identity trust and PGP/MIME remain application-owned rather than hidden Brynja effects.

Goal: prove an independent developer can build a complete OpenPGP protocol
client without private APIs, hidden effects or reimplementing protocol logic.

Deliverables:

- provide downstream fixtures covering complete modern key, certificate, message, armor, signing, encryption, password, revocation and compatibility workflows;
- exercise hosted adapters through caller-provided files, clocks, entropy, key stores and network payloads while retaining the same Sans-I/O core and explicit effects;
- publish a client-foundation boundary showing which protocol services Brynja supplies and which UI, persistence, discovery, trust, MIME and transport responsibilities remain application-owned.

Verification:

- build every fixture from packaged crates on MSRV and latest Rust with no workspace path leakage, unpublished dependency or private symbol;
- interoperate fixture outputs and inputs with at least two independent implementations across modern and admitted v4 workflows and failure recovery;
- pass package, feature-graph, no_std, hosted-platform, documentation-example, resource, clean-room and repository gates.

Exit criteria:

- a downstream developer can implement a full OpenPGP protocol client using public Brynja packages while every non-protocol application responsibility remains explicit;
- `v0.178.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.179.0 - OpenPGP Public API And Documentation Freeze

Status: planned

Plan scope: Freeze OpenPGP package APIs, feature graph, supported and rejected algorithms, modern and compatibility profiles, resource formulas, trust boundary, key lifecycle, error semantics, security guidance, interoperability limits, verification status and migration policy without claiming independent verification or FIPS validation.

Goal: make the exact intended OpenPGP contract reviewable before final evidence
and independent audit.

Deliverables:

- freeze public types, methods, feature names, package relationships, errors, outcomes, limits and SemVer commitments;
- publish complete user guidance for signing, verification, encryption, passwords, key custody, rotation, revocation, trust and compatibility;
- synchronize READMEs, rustdoc, examples, requirements, security claims, verification table, release notes and non-goals.

Verification:

- build and test every documented example, feature combination, package archive, downstream MSRV/latest fixture and no_std target;
- review wording for authenticated-versus-trusted, modern-versus-compatible, tested-versus-verified and non-FIPS distinctions;
- pass API diff, docs links, package metadata, graph, source closure and repository checks.

Exit criteria:

- users can determine exactly what Brynja guarantees, does not guarantee and requires from application policy;
- `v0.179.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.179.1 - OpenPGP Formal, Fuzz, Memory, And Side-Channel Evidence

Status: planned

Plan scope: Complete applicable Kani proofs, first-party external-process fuzzing, Miri and sanitizer runs, differential corpora, constant-time and zeroization emitted-code review, statistical timing tests and hostile-load campaigns for every OpenPGP package, provider path and supported target; publish precise proof and residual-gap claims.

Goal: close automated and mathematical assurance across the frozen OpenPGP
surface without overstating reduced models or emulated targets.

Deliverables:

- complete proof harnesses for codecs, bounds, state reachability, authentication release, counters, merge and single-consumption effects;
- sustain corpus, differential, Miri, sanitizer, native timing, emitted-code, zeroization and hostile-load evidence by implementation symbol;
- extend the machine-readable claim register with exact properties, widths, targets, assumptions, methods and residual gaps.

Verification:

- independently reproduce every harness and reject stale, skipped, vacuous, reduced-width-overclaimed or wrong-symbol evidence;
- run forced provider, scalar and admitted accelerated paths on native supported hardware and label QEMU evidence supplemental;
- pass complete assurance, artifact-hash, target, Rust matrix and repository gates.

Exit criteria:

- every OpenPGP security claim maps to exact reproducible evidence and every unproved property remains explicit;
- `v0.179.1 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.179.2 - Independent OpenPGP Standards And Cryptography Audit

Status: planned

Plan scope: Obtain an exact-commit independent review of RFC 9580 requirement closure, packet and subpacket dispositions, registry decisions, message grammars, cryptographic composition, key wrap, key validity, trust separation, protected-key and v1 SEIPD compatibility, strong v4 profiles, Base64-ng and compression boundaries, downstream client completeness, resource limits, plaintext release, constant-time behavior, zeroization and documentation claims.

Goal: subject the complete frozen OpenPGP implementation and its external
encoding edge to independent expert review.

Deliverables:

- freeze source, dependencies, packages, compiler, features, requirements, threat model, evidence and review scope hashes;
- obtain separate standards, cryptographic and systems findings with severity, affected symbols, exploitability and required retest scope;
- record every finding without suppressing known limitations or treating project CI as independent verification.

Verification:

- reproduce reviewer cases and map them to requirements, code, tests, claims and affected package versions;
- independently verify audit identity, completeness and absence of scope exclusions that undermine production claims;
- pass repository checks while retaining an awaiting-remediation status and making no premature verified claim.

Exit criteria:

- the exact OpenPGP candidate has a complete actionable independent finding set and frozen remediation baseline;
- `v0.179.2 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.179.3 - OpenPGP Audit Remediation And Clean Retest

Status: planned

Plan scope: Remediate every OpenPGP audit finding, add permanent regressions, update requirement and claim registers, repeat affected interoperability and side-channel campaigns, and obtain a clean independent retest with no unresolved critical or high finding.

Goal: close the OpenPGP audit with independently confirmed fixes on the exact
candidate that can proceed to production-readiness review.

Deliverables:

- fix or explicitly reject affected capability, preserve one regression per finding and update all impacted claims and compatibility decisions;
- rebuild source, package, SBOM, proof, fuzz, interoperability, emitted-code and target evidence for changed symbols;
- obtain signed or otherwise authenticated reviewer dispositions and clean retest scope tied to the remediated commit.

Verification:

- rerun every finding reproducer, regression and all transitive affected suites and evidence campaigns;
- confirm no unresolved critical or high issue, no silently accepted medium risk and no documentation-only closure for code defects;
- pass complete repository, release, package, standards, assurance and independent retest gates.

Exit criteria:

- all admitted findings are fixed and independently retested, with residual limitations explicit and non-misleading;
- `v0.179.3 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.180.0 - OpenPGP Production-Readiness Gate

Status: planned

Plan scope: Freeze the independently reviewed OpenPGP artifact set and package publication closure, complete cumulative pentest from v0.175.0 through v0.180.0, prove installability and modern/legacy/FIPS isolation, and publish only claims linked to exact standards, test and audit evidence.

Goal: admit the OpenPGP packages to the final Brynja candidate only after clean
audit, cumulative pentest and publication evidence.

Deliverables:

- freeze selected package versions, archives, dependencies, SBOMs, checksums, release notes, README/rustdoc and verification status;
- commit the cumulative PASS pentest and bind it to the full post-v0.175.0 delta including remediation;
- prove modern facade selection is explicit and legacy and all OpenPGP algorithms remain outside FIPS-approved claims and artifacts.

Verification:

- install packaged crates into clean no_std and hosted downstream fixtures on MSRV and latest stable and compare archive contents;
- rerun full OpenPGP, graph isolation, audit regression, interoperability, reproducibility and security-claim suites;
- pass complete tag gate, cumulative pentest, clean GitHub and CodeQL and publication dry run.

Exit criteria:

- the exact OpenPGP artifact set is ready for integration freeze with honest, evidence-linked scope and no unresolved critical or high finding;
- `v0.180.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

### v0.181.0 - Integrated TLS And OpenPGP Package Freeze

Status: planned

Plan scope: Reconcile the complete TLS, PKI, cryptography, FIPS, OpenPGP and facade dependency graph, shared primitive identities, feature combinations, package versions, documentation and security claims; prove neither protocol stack creates implicit cross-protocol keys, trust, configuration, fallback, state or release authority.

Goal: freeze one coherent Brynja product graph without coupling independent
protocol security domains.

Deliverables:

- inventory every package, feature, dependency, provider symbol, credential type, configuration path, claim and publication decision;
- freeze typed cross-protocol key-use prohibitions, independent trust and state domains and explicit optional facade selection;
- synchronize requirements, APIs, READMEs, release notes, SBOMs, package policy and verification status across the full workspace.

Verification:

- exhaust no-default, all-feature and pairwise feature graphs, package archives and negative cross-protocol fixtures;
- attempt key, handle, configuration, trust, cache, event, error and fallback substitution between TLS and OpenPGP;
- pass complete MSRV/latest, no_std, FIPS-boundary, legacy-isolation, documentation and repository checks.

Exit criteria:

- the integrated graph is frozen while TLS and OpenPGP retain independent authority and failure boundaries;
- `v0.181.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.182.0 - Integrated Clean-Room Release Rehearsal

Status: planned

Plan scope: Repeat reproducible clean-room builds, package installation, artifact comparison, rollback, key-compromise, incident and disaster-recovery exercises for the complete TLS and OpenPGP publication set on every promised Rust version and representative supported targets.

Goal: rehearse the complete expanded v1 release from a clean environment before
the final external audit.

Deliverables:

- build every selected archive from pinned source and toolchain inputs and compare source, metadata, lock, SBOM and binary artifacts;
- install supported package combinations into clean downstream fixtures across Rust 1.90.0 through 1.97.1 and representative targets;
- execute release rollback, signing-key compromise, crate ownership, advisory, incident, recovery and documentation drills.

Verification:

- reproduce builds independently on Linux, Windows and macOS and run cross-target no_std and mobile checks;
- compare every byte and reject hidden generated input, undeclared network access, stale dependency or non-reproducible metadata;
- pass package dry runs, release-control, provenance, recovery, documentation and full repository gates.

Exit criteria:

- an independent clean environment can reproduce, install, verify and recover the entire intended v1 package set;
- `v0.182.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.183.0 - Final Whole-Project External Audit

Status: planned

Plan scope: Complete an exact-candidate independent audit spanning standards traceability, cryptography, PKI, TLS, DTLS, QUIC, PQ, FIPS boundaries and claims, OpenPGP, optional adapters, platform behavior, supply chain, release controls and all cross-component trust boundaries.

Goal: obtain one final independent assessment of the complete intended Brynja
v1 product rather than relying only on component reviews.

Deliverables:

- freeze exact candidate source, dependencies, features, packages, toolchains, artifacts, standards, evidence and deployment claims;
- commission standards, cryptographic, protocol, systems, supply-chain and release-control coverage with explicit cross-component attack paths;
- record severity, affected artifacts, exploitability, disclosure and required remediation or capability removal for every finding.

Verification:

- validate reviewer independence, scope, artifact identity and coverage of TLS/OpenPGP shared primitives and isolated trust domains;
- reproduce all findings and map affected versions, packages, claims, requirements and retest obligations;
- retain candidate status without production approval and pass evidence-integrity and repository checks.

Exit criteria:

- the exact complete candidate has a transparent actionable final finding set with no scope ambiguity;
- `v0.183.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.184.0 - Final Whole-Project Remediation And Retest

Status: planned

Plan scope: Remediate every final-audit finding, add permanent regressions, rebuild every affected evidence artifact, repeat all applicable external reviews and obtain clean retests with no unresolved critical or high finding before release-candidate freeze.

Goal: produce a clean independently retested whole-project candidate without
hiding residual risk behind component-level passes.

Deliverables:

- remediate or remove affected capabilities and update requirements, threat model, controls, claims, docs, release notes and affected-version records;
- rebuild proofs, corpora, differentials, side-channel, interoperability, package, SBOM and reproducibility evidence for every changed symbol;
- obtain independent closure of every critical and high finding and explicit disposition of all remaining severity levels.

Verification:

- run each finding reproducer, permanent regression and transitive protocol, package, target and operational-environment suite;
- compare remediated artifacts against audit scope and confirm no unreviewed capability or metadata drift entered;
- pass all independent retests, complete repository checks, package dry runs and release controls.

Exit criteria:

- no unresolved critical or high finding remains and all residual risk is accurately documented for the final pentest;
- `v0.184.0 development milestone reached. Commit the verified scope, obtain green GitHub and CodeQL, then create the signed tag without a scheduled pentest or crates.io publication unless an exceptional trigger applies.`

### v0.185.0 - Final Pre-RC Pentest And Publication Gate

Status: planned

Plan scope: Complete the cumulative v0.180.0-through-v0.185.0 pentest, commit its PASS report, freeze the selected crates.io closure and release notes, and require green GitHub, CodeQL, package, reproducibility and publication-dry-run evidence before the exact production candidate.

Goal: create the last public checkpoint before the byte-identical production
candidate with all integrated and remediated changes covered.

Deliverables:

- pentest the entire delta after v0.180.0 including integration, rehearsal, final audit and remediation and commit the exact PASS report;
- freeze publish order, package versions, dependencies, archives, checksums, SBOM, changelog, release notes and verification-status evidence;
- require explicit authorization only after all remote checks and publication simulations are green on the report-bearing commit.

Verification:

- rerun the full workspace, standards, security, assurance, protocol, target, package, reproducibility and release-control gates;
- compare publication selection against changed packages so dependencies publish first, unchanged crates do not republish and the facade publishes last;
- confirm green GitHub and CodeQL, cumulative PASS pentest, clean tree and signed-tag readiness without publishing or rebuilding early.

Exit criteria:

- the complete post-v0.180.0 delta and exact selected package set are ready to become the frozen production candidate;
- `v0.185.0 scheduled release checkpoint reached. Pentest all changes after the previous public tag through this candidate, commit the PASS report, obtain green GitHub and CodeQL, then create the signed tag and publish the selected crates.`

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

### v1.0.0 - First Serious Production-Ready Brynja TLS And OpenPGP Release

Status: planned

Plan scope: Promote only the byte-identical approved candidate without rebuild, source change, metadata drift, or expanded capability claim.

Goal: complete the **First Serious Production-Ready Brynja TLS And OpenPGP Release** implementation stop without admitting or
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
