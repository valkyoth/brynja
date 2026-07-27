# Changelog

All notable changes to Brynja will be documented here. The format follows
Keep a Changelog and Semantic Versioning.

## [Unreleased]

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
