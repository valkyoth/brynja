# Brynja 0.3.5 Release Notes

Date: 2026-07-30

Brynja 0.3.5 completes the optional, legacy, operational, and residual
normative closure that precedes implementation. It does not implement TLS,
cryptography, PKI, QUIC, DTLS, platform services, or legacy protocols and must
not be used to secure network traffic.

## Highlights

- Adds 47 stable residual requirements, bringing the matrix to 163 records.
- Covers 33 residual authorities and reviews 182 normative RFC sections
  through 165 exact mappings and 17 explicit exclusions.
- Assigns all 741 surfaces left by the foundation, domain, and transport
  bundles, closing all 4,422 protocol surfaces.
- Generates complete source-to-plan, plan-to-source,
  source-to-requirement, surface-to-requirement, and
  requirement-to-owner reports across 126 authorities and 205 roadmap rows.
- Pins final FIPS 203, SP 800-227, SP 800-90B, and SP 800-90C as local-only
  checksum-locked authorities.
- Adds explicit local-rights, mutable-authority refresh, hybrid, legacy, and
  FIPS-validation blocker records.

## Corrected Roadmap Ownership

The semantic register now follows the exact optional-feature sequence:

- Record Size Limit: `0.136.0`;
- Raw Public Keys: `0.137.0`;
- HPKE context foundation: `0.138.0`;
- HPKE base mode: `0.139.0`;
- HPKE export and context lifecycle: `0.139.1`;
- ECH origin policy through retry and rotation: `0.140.0` through `0.143.0`;
- Delegated Credentials: `0.144.0`;
- certificate-decompression receive provider: `0.145.0`;
- precompressed artifact validation: `0.146.0`; and
- certificate-compression send integration: `0.146.1`.

The entropy register separately identifies the secure-random contract,
SP 800-90B source and health-test work, SP 800-90A DRBG implementation, and
SP 800-90C construction milestones.

## Fail-Closed Authority Handling

Concrete ECDHE-ML-KEM groups are not admitted. As of this release, the IANA
entries remain provisional and the group document is not a final RFC. A final
Standards Track RFC and final non-provisional assignments are both mandatory;
draft or private code points are forbidden.

SSL 2, WTLS, PCT, SNP, and SSL 1 research remain blocked until their non-RFC
source material has authenticated provenance, exact bytes, hashes, errata,
redistribution-rights review, per-protocol cipher decisions, isolation review,
and the separately required legacy pentest.

FIPS 140-3 validation work remains blocked until the dependent milestone pins
a dated, rights-reviewed baseline covering applicable FIPS and ISO material,
the SP 800-140 series, CMVP manuals and implementation guidance, RFG and CMVP
resolutions, validation wording, certificate status and caveats, laboratories,
and tested operational environments. Brynja is not FIPS validated.

## Pentest Remediation

The initial pentest found two Medium traceability defects. Residual groups
previously copied one representative surface into a requirement while marking
every group member covered, and RFC citations inherited every normative
section without a reviewed semantic assignment.

Every one of the 741 residual surfaces is now explicitly listed and linked
back from its requirement. Groups cannot cross code or test boundaries, and
every member is independently checked for source, owner, disposition, and
identity. Nine mixed groups were split into separate requirements.

The new reviewed residual section policy assigns all 182 inventoried sections
to exact requirements or explicit exclusions. Generated evidence records 266
exact requirement links instead of 541 blanket associations. Twenty-two
residual fixtures reproduce both findings and their non-representative
variants. External remediation retest remains required.

A subsequent retest found three additional Medium integrity defects. Global
reconciliation now prevents any domain, transport, or residual policy from
excluding a section another bundle maps. RFC 9853 sections 3 through 9 belong
only to `BRY-REQ-DTLS-1111`; its terminology and designated-expert sections
are explicitly excluded or caller-owned. The RRC extension and message
registry now share the `brynja-dtls-core` v0.111.1 boundary.

RFC 7568 section 3 now maps only to the SSLv3 prohibition requirement. SSL 2,
WTLS, PCT, SNP, and SSL 1 carry explicit source-blocker identities, blocked
lifecycles, and exact authority-claim blocker targets until their actual
specifications pass provenance and rights review.

## Verification

The release candidate verifies:

- 163 deterministic stable requirements;
- all 126 locked source authorities;
- all 205 roadmap rows;
- all 4,422 protocol surfaces;
- 182 residual normative RFC sections with exact anchors and hashes;
- 106 requirement positive and broken-fixture tests, including 22 dedicated
  residual-closure fixtures;
- deterministic standards, surface, matrix, coverage, closure, package, and
  SBOM artifacts;
- no external Cargo packages and `no_std` production packages;
- Rust 1.90.0 through 1.97.1 compatibility; and
- source files no larger than 500 lines.

## Publication

Only `brynja 0.3.5` is selected for crates.io publication. All unchanged
supporting crates retain their independently published `0.1.0` versions and
are not republished. Legacy and repository-only crates remain unpublished.

Publication remains blocked until the repository owner passes the v0.3.5
remediation retest, the committed report records `PASS`/`PASS` with zero open
findings, GitHub checks are green, and the user explicitly authorizes tagging.

## Limitations

This release provides planning, traceability, source integrity, and release
governance only. Planned targets, tests, vectors, interoperability, formal
evidence, cryptographic review, protocol audit, FIPS validation, and
production readiness remain work for their owning future milestones.
