# Changelog

All notable changes to Brynja will be documented here. The format follows
Keep a Changelog and Semantic Versioning.

## [Unreleased]

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
