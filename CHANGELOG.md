# Changelog

All notable changes to Brynja will be documented here. The format follows
Keep a Changelog and Semantic Versioning.

## [Unreleased]

## [0.5.0] - 2026-07-31

### Added

- Exhaustive TLS AlertDescription classification across all 256 registry
  bytes, preserving assigned, reserved, and unassigned identities.
- Protocol-version-aware assigned alerts with derived semantic class and
  hardened severity.
- Distinct orderly-close, cancellation, alert-failure, local-failure,
  provider-failure, and resource-exhaustion domains in `brynja-core 0.2.0`.
- Positive, negative, exhaustive, representation-bound, and compile-fail tests
  linked to the tested `BRY-REQ-TLS-0005` requirement.

### Security

- Failure envelopes accept no arbitrary text, bytes, provider-native codes,
  cryptographic material, or numeric limits and implement neither `Debug` nor
  `Display`.
- Close and cancellation cannot be ambiguously collapsed into `TlsFailure`;
  only error-class alerts can become alert failures.
- The alert registry is the only protocol surface marked implemented. TLS,
  DTLS, cryptography, PKI, providers, independent verification, production
  readiness, and FIPS validation remain explicitly unclaimed.

## [0.4.0] - 2026-07-31

### Added

- A first-party deterministic mutation runner covering empty, original,
  truncation, deletion, bit-flip, and zero/`0xff` insertion cases with exact
  replay indexes and SHA-256 failure identities.
- A canonical raw-stdin differential protocol requiring at least two distinct
  process adapters and rejecting crash, timeout, output exhaustion, malformed
  JSON, noncanonical hex, unsupported classes, and semantic mismatch.
- OS-less all-feature workspace checks for ARMv7E-M, RV32IMAC, and x86_64.
- Deterministic assurance evidence binding policy, runners, CI, and every Cargo
  manifest, with 24 positive and broken fixtures.

### Security

- Child processes run without a shell and both output streams are capped while
  produced. Inputs are explicitly public test data, and campaign launchers
  must provide OS network, filesystem, process, and device isolation.
- Kani 0.67.0, AFL++ 5.02c, honggfuzz 2.6, Miri, and Rust sanitizers have exact
  upstream source revisions and cannot enter repository Cargo manifests.
- Stable Rust 1.97.1 remains the release compiler; Kani 0.67.0 uses a separate
  compatible Rust 1.90.0 verifier pairing. No proof harness is admitted, and
  policy-only status cannot be claimed as formal verification.
- Bare-metal compilation does not claim startup, allocation, interrupts,
  entropy, time, transport, storage, emulator, hardware, or Aesynx support.

## [0.3.5] - 2026-07-31

### Added

- Fifty optional, HPKE, ECH, ML-KEM, entropy, operational, legacy, and
  residual requirements, bringing the deterministic matrix to 167 records.
- Local-only checksum pins for final FIPS 203, SP 800-227, SP 800-90B, and
  SP 800-90C.
- Exact residual coverage of 33 authorities, 182 normative RFC sections, and
  all 743 surfaces left by the foundation, domain, and transport bundles.
- A generated closure report mapping all 126 locked authorities, 206 roadmap
  rows, 4,424 protocol surfaces, and 167 requirements in both directions.
- Twenty-two residual broken fixtures, bringing the requirement suite to 110
  positive and negative tests.

### Security

- Concrete ECDHE-ML-KEM groups remain blocked because the current IANA values
  are provisional and the group specification is not yet a final RFC; drafts
  and private code points cannot satisfy the gate.
- Non-RFC legacy implementations remain blocked on authenticated source bytes,
  hashes, errata, redistribution rights, cipher decisions, isolation review,
  and a separate pentest.
- FIPS validation milestones remain blocked on a dated, rights-reviewed FIPS,
  ISO, CMVP, laboratory, certificate, caveat, and operational-environment
  baseline; no current package or profile claims FIPS validation.
- Every local NIST/ITU authority has an explicit local-only distribution
  record, while all eight IANA registries and five mutable NIST publication
  pages have dependent-milestone refresh owners.
- Raw Public Keys, Delegated Credentials, certificate-compression receive,
  artifact, and send phases, HPKE context/base/export phases, ECH phases, and
  entropy phases now match their exact roadmap owners.
- Two Medium pentest findings are remediated: all 741 residual surfaces are
  explicit, reciprocal, independently validated, and homogeneous by code/test
  boundary; all 182 residual normative sections have one or more of 165 exact
  mappings or one of 17 reviewed exclusions instead of RFC-wide inheritance.
- Three additional Medium retest findings are remediated: section decisions
  reconcile globally across bundles, RFC 9853 RRC extension and registry
  ownership is confined to the v0.111.1 DTLS boundary, and SSL 2, WTLS, PCT,
  SNP, and SSL 1 requirements remain mechanically source-blocked.
- Two further Medium retest findings are remediated: RFC 9853 ContentType 27
  is confined to a dedicated DTLS-only admission boundary, and RFC 6066
  sections are split among exact SNI, status, alert, exclusion, and
  cross-bundle delegation decisions instead of being attributed wholesale to
  OCSP.
- Three final Medium retest findings are remediated: unsupported RFC 6066 peer
  ClientHello extensions use a bounded opaque ignore path distinct from
  rejected local configuration and unsolicited responses; RFC 6066 has an
  independent TLS 1.2 owner at v0.90.1; and generated `delegated` section
  evidence is declared and contract-tested against the schema.
- The repository-owner retest of the complete ten-finding remediation passed
  with zero open findings; the permanent v0.3.5 report is `PASS`/`PASS`.

## [0.3.4] - 2026-07-30

### Added

- Sixty-three stable TLS, hardened TLS 1.2, QUIC-TLS, DTLS 1.2, and
  DTLS 1.3 semantic surfaces, one for every owning implementation milestone
  from the shared secret contract through the DTLS audit gate.
- Seventy transport requirements, bringing the deterministic matrix to 116
  stable records and explicitly covering 40 authorities, 550 normative RFC
  sections, and 480 transport surfaces.
- Exact current, compatibility, evidence, exclusion, and caller-owned source
  roles plus explicit requirements for Heartbeat, legacy TLS 1.3 PKCS1 client
  signatures, post-handshake authentication, certificate-with-external-PSK,
  and the QUIC transport boundary.
- A generated transport-coverage artifact and eight positive and
  broken-fixture tests for milestone, authority, role, binding, identity,
  surface, and reproducibility failures.
- Reviewed domain and transport section policies that bind all 914 normative
  RFC sections to exact requirements, extraction anchors, and section hashes,
  plus seven dedicated positive and broken section-binding fixtures.

### Security

- Every planned transport state transition has one stable owner, target
  symbol, positive and negative test target, work bound, evidence gap, and
  residual-risk statement without claiming protocol code exists.
- QUIC packet, frame, recovery, congestion, Retry, migration, and transport
  semantics remain mechanically caller-owned; TLS, TLS 1.2, TLS 1.3, DTLS,
  and QUIC requirements cannot hide behind a generic cross-version mapping.
- RFC 9850 key logging and four optional TLS facility groups remain explicit
  v0.3.5 deferrals; the status_request_v2 exclusion remains bound to its
  already reviewed v0.3.3 OCSP requirement.
- Protocol-surface and requirement artifacts now bind the separate transport
  policies and reject missing owner milestones, authority drift, role swaps,
  duplicate identities, and stale projections.
- The pentest's two Medium governance-integrity findings are remediated:
  every linked surface must independently match authority and owner or use an
  exact structured exception, and every normative section must have an
  explicit requirement binding or reviewed disposition. External retest of
  the remediated candidate passed with zero open findings; the permanent
  v0.3.4 report is `PASS`/`PASS`.

## [0.3.3] - 2026-07-30

### Added

- Thirty-four cryptography, encoding, PKIX, OCSP, and Certificate
  Transparency requirements, bringing the deterministic matrix to 46 stable
  records.
- Exact authority-role coverage for all 53 assigned sources, section-hash
  coverage for 364 normative RFC sections, and requirement or explicit
  deferral coverage for all 3,322 selected protocol surfaces.
- Local-only checksum pins for FIPS 202 and the in-force ITU-T X.690 (2021)
  plus Erratum 1.
- Explicit SHA-3/SHAKE, GHASH, and ChaCha20 semantic decisions and corrected
  SHA-2, HMAC, HKDF, and AES milestone ownership.
- A generated domain-coverage artifact and 15 positive and broken-fixture
  tests for authority, scope, role, ownership, work-bound, invariant,
  test-polarity, surface-group, and reproducibility failures.

### Security

- Every new requirement records explicit resource or work assurance,
  positive and negative target tests, unresolved evidence, and residual risk
  without claiming planned code exists.
- Current, compatibility, evidence, and exclusion authorities cannot be
  silently interchanged; every in-scope source must be cited and every
  selected surface must be assigned.
- ML-KEM algorithm and PKIX credential surfaces remain explicitly deferred to
  the complete hybrid review at v0.3.5.
- Five newly reported RFC Editor errata were reviewed as
  `track-not-applied`; no reported erratum was silently incorporated.
- The repository-owner pentest passed the signed v0.3.3 implementation
  candidate with zero findings and required no remediation.

## [0.3.2] - 2026-07-27

### Added

- A stable normative-requirement policy and deterministic schema, resolved
  matrix, bidirectional indexes, and human-readable coverage report.
- A 12-requirement authority pilot spanning all eight lifecycle states and
  binding exact RFC, errata, IANA, source-ledger, and protocol-surface
  evidence.
- Fifty-one positive and broken-fixture tests for identity, source, section,
  lifecycle, transition, ownership, target, evidence, SHOULD-deviation, drift,
  symlink-escape, immutable history, revision, semantic-link, and stale-output
  failures.

### Security

- Protocol requirements cannot claim implemented, tested, or evidenced status
  before their owning implementation milestone and existing anchors.
- Ordinary and release checks now fail closed on requirement-policy or
  generated-evidence drift.
- Actual target validation resolves symlinks and rejects paths that leave the
  repository root.
- Requirement changes are compared with the immutable parent matrix; IDs
  cannot disappear, lifecycle transitions must be legal, and content changes
  require exactly one revision increment.
- Exact-source decision mappings now enforce source, disposition, and owner
  consistency, while broader governance mappings require explicit reviewed
  rationale.
- Reviewed-global mappings are restricted to governance requirements, and a
  released requirement cannot change between governance and protocol scope.
- Ordinary CI accepts only a well-formed, current, committed
  `RETEST REQUIRED`/`PENDING` pentest report while remediation awaits external
  retest; release and tag gates continue to require `PASS`/`PASS`.
- The repository-owner retest passed after all v0.3.2 remediations, leaving
  zero open findings and the permanent report in `PASS`/`PASS` state.

## [0.3.1] - 2026-07-27

### Added

- A deterministic protocol-surface register containing 45 explicit semantic
  decisions, 192 nested IANA registries, and all 4,106 individual records from
  the eight pinned registry collections.
- Required disposition, normative-source, milestone-owner, planned-code-target,
  planned-test-target, and rationale fields for all 4,343 classified surfaces.
- Explicit decisions for Heartbeat, status_request_v2, production and
  test-only SSLKEYLOGFILE handling, TLS 1.3 post-handshake authentication,
  certificate-with-external-PSK, legacy PKCS1 client signatures, ML-KEM PKIX
  credentials, HPKE non-base modes, unsigned X.509 certificates, QUIC
  version-specific cryptography, and certificate compression.
- Human-readable generated disposition, kind, and domain coverage.
- Twenty-five positive and broken-fixture tests for completeness, ownership,
  source binding, classification, override, parser, and reproducibility
  failures.

### Security

- Bound the surface policy to the byte-exact v0.3.0 source ledger so RFC
  status, errata, registry, source, and classification drift cannot remain
  silent.
- Rejected missing or duplicate collections, registries, semantic IDs, JSON
  keys, and overrides; unknown sources, milestones, dispositions, and targets;
  overlapping rules; unmatched selectors; unsafe XML declarations; and any
  premature `implemented` claim.

## [0.3.0] - 2026-07-27

### Added

- A deterministic standards ledger covering all 103 locked RFCs, eight
  local-only NIST authorities, eight exact IANA registry snapshots, and every
  owning roadmap milestone.
- A complete reviewed inventory of 285 official errata with fail-closed
  dispositions based on RFC Editor status.
- Offline source, checksum, lifecycle, relationship, ownership, blocker, and
  reproducibility validation with 28 positive and broken-fixture tests.
- A networked release check that rejects RFC index, errata, or IANA drift.
- A permanent evidence index and explicit final-RFC plus final-IANA admission
  blocker for concrete ECDHE-ML-KEM groups.

### Fixed

- Replaced refresh-time trust-on-first-use hashes with independently reviewed,
  non-self-replacing RFC, NIST, RFC-index, errata, and IANA pins.
- Enforced the exact HTTPS source and redirect allowlist in the Python
  standards pipeline.
- Bounded all upstream responses and rejected XML DTD and entity declarations
  before parsing to prevent compromised-source expansion and memory denial of
  service.
- Kept local-only, redistribution-restricted NIST bytes optional in clean CI
  while still validating their complete manifest and automatically checking
  every byte whenever a local cache exists.

## [0.2.0] - 2026-07-27

### Added

- Machine-readable classification and exact dependency/feature/publication
  policy for all 24 workspace packages.
- Separate no-default and all-feature graph validation with modern, legacy,
  QUIC, repository, target, pin, and feature-smuggling negative fixtures.
- Machine-checked GitHub main-branch release controls matching the protected
  `eth` ruleset model.

### Changed

- Required pentest reports to be regular committed files synchronized against
  every prior report-bearing parent.
- Required release tags to be directly targeted, signed and annotated with the
  exact `brynja vX.Y.Z` subject.
- Extended Clippy enforcement to both all-feature and no-default-feature
  workspace configurations.
- Supplied step-scoped GitHub workflow authentication to the live protected
  release-control validator and enforced that wiring in release metadata.
- Documented the intentional fail-closed release panic posture and its
  availability tradeoff.

## [0.1.0] - 2026-07-26

### Added

- Security-first, dependency-free, `no_std` workspace foundation.
- Modern and legacy protocol package boundaries.
- Standards provenance, toolchain, platform, and release planning policies.
- Guarded independent-version crates.io planning and dependency-order
  publication with mandatory facade releases.
- Committed per-version pentest reports that must stay synchronized with every
  later release-candidate fix before green CI and explicit tagging.
- Versioned admission and conditional implementation stops for one optional
  protocol-neutral `brynja-sanitization` downstream adapter, with no
  `zeroize`, third-party activated dependency, facade, engine, or FIPS-module
  path.
- Independently pinned and verified CI security-tool archive checksums.

### Changed

- Made truncating-cast and sign-loss Clippy lints non-overridable.
- Enforced publication of `brynja` for every official tag, selected the full
  initial modern dependency closure, and added non-uploading package-archive
  validation to the guarded publisher.
