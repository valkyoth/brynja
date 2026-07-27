# Brynja 0.3.1 Release Notes

Status: release-ready locally; pentest complete and awaiting green GitHub CI

Brynja 0.3.1 is a protocol-surface decision milestone. It does not implement
TLS, cryptography, PKI, QUIC, DTLS, platform services, or legacy protocols and
must not be used to secure network traffic.

## Machine-Readable Decisions

The new `standards/surface-policy.json` is bound to the byte-exact v0.3.0
source ledger. It records reviewed semantic decisions, collection defaults,
registry-specific rules, and exact entry overrides. The deterministic
generator joins that policy with the pinned IANA XML and source ledger to
produce:

- 45 explicit semantic protocol, algorithm, format, facility, and legacy
  decisions;
- 192 nested IANA registry decisions;
- 4,106 individual IANA record decisions; and
- 4,343 total classified surfaces.

Every row contains exactly one disposition, its normative sources, owning
roadmap milestone, planned code target, planned test target, and review
rationale. The allowed dispositions are `implemented`,
`intentionally-rejected`, `safely-ignored`, `caller-owned`, `legacy-only`, and
`future-work`. This planning-only release requires the `implemented` count to
remain zero.

## Explicit High-Risk Boundaries

The register makes the roadmap's security-sensitive choices directly
reviewable:

- Heartbeat and status_request_v2 are intentionally rejected;
- production SSLKEYLOGFILE support is rejected while a future repository-only
  test-support boundary is recorded separately;
- TLS 1.3 post-handshake authentication and
  certificate-with-external-PSK are rejected for version one;
- legacy PKCS1 client CertificateVerify values, ML-KEM PKIX credentials, HPKE
  non-base modes, and unsigned X.509 certificates are rejected;
- QUIC version-specific cryptography and bounded certificate compression are
  explicit future work; and
- unknown extensions are safely ignored only where the governing protocol
  explicitly permits that behavior.

Modern, compatibility, legacy, caller-owned, and future boundaries remain
separate. A registry entry, compiled crate, or `future-work` decision is never
an implementation or security claim.

## Fail-Closed Verification

Normal checks regenerate the JSON register and Markdown coverage and compare
both byte for byte. Twenty-five positive and broken-fixture tests exercise:

- exact source-ledger binding, including RFC status, errata, and registry
  evidence;
- complete coverage of all eight collections, nested registries, and records;
- duplicate and unknown identifiers, sources, dispositions, milestones, and
  targets;
- overlapping registry rules, missing and duplicated entry overrides, and
  unmatched selectors;
- classification changes, stale generated output, snapshot hash drift,
  duplicate JSON keys, duplicate registry IDs, and unsafe XML declarations;
  and
- rejection of every premature `implemented` classification.

The existing networked release gate still compares RFC, errata, and IANA
evidence against the official sources. Any accepted upstream change requires a
separately reviewed pin update, semantic review, regenerated ledger, updated
surface decisions, tests, pentest, and clean CI.

## Publication

Only `brynja 0.3.1` is selected for crates.io publication. All unchanged
modern supporting crates retain version `0.1.0` and are not republished.
Legacy and repository-only packages remain unpublished.

The repository owner pentested signed implementation candidate
`8785252d9ae16d59e9bb27787d63bd4684bcb493` and reported no findings. The
permanent PASS report records zero open findings. Hosted GitHub checks and
explicit tag authorization remain required.

## Limitations

This release classifies planning surfaces; it does not extract individual
normative requirements. Requirement extraction and domain population remain
scheduled for v0.3.2 through v0.3.5. Concrete ECDHE-ML-KEM groups remain
blocked until both final Standards Track text and final IANA code points
exist.
