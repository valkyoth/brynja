# Security Controls

Status: v0.3.5 complete pre-implementation normative enforcement

| Control | Foundation enforcement |
| --- | --- |
| Dependency surface | Cargo manifests and `cargo metadata` must contain no external packages |
| CI tool provenance | Exact versions and independently pinned `.crate` SHA-256 hashes are verified before installing security and SBOM tools |
| Unsafe Rust | Workspace lint forbids it |
| `no_std` | Every package declares `#![no_std]` |
| Package classification | Committed policy classifies all 24 packages and exact direct, optional, feature, target, source, and publication boundaries |
| Modern/legacy isolation | No-default and all-feature graph validators reject either facade reaching the other package class, research, or repository tooling |
| TLS version isolation | Both resolved graphs require the evergreen router to reach separate TLS 1.2 and TLS 1.3 engines while QUIC reaches only the recordless TLS 1.3 handshake |
| Review size | Source files over 500 lines fail checks |
| Toolchain | Pinned stable plus explicit MSRV matrix |
| Standards | Exact HTTPS host/path and redirect allowlists, independently reviewed non-self-replacing pins, bounded responses, DTD/entity rejection, 103 immutable RFCs, 15 local-only NIST/ITU authorities, exact RFC-index and eight IANA snapshots, 290 reviewed errata decisions, lifecycle and milestone ownership, complete updated-by/obsoleted-by closure, deterministic ledger generation, broken fixtures, and release-time live drift rejection |
| Protocol surfaces | Deterministic classification of 124 semantic decisions, 192 nested registries, and 4,106 individual records across all eight pinned IANA collections with exact source-ledger binding, disposition, milestone, code target, test target, and broken-fixture enforcement |
| Normative requirements | 154 stable identifiers bind exact source, section, status, errata, authority role, strength, applicability, decision, mapping scope, owner, lifecycle, revision, assurance invariants, work bound, residual risk, target, positive and negative tests, and evidence gap; the generated closure covers all 126 authorities, 205 roadmap rows, and 4,422 surfaces, including 38 residual requirements, 33 residual authorities, 182 residual normative sections, and 741 formerly uncovered surfaces; immutable history and 95 requirement fixtures reject omissions, drift, role errors, stale revisions, illegal transitions, unrelated mappings, weak bounds, missing anchors, rights gaps, stale mutable guidance, orphaned plans, repository-escaping targets, and premature claims |
| Authority refresh and rights | Every local NIST/ITU source is local-only with an explicit distribution review; all eight mutable IANA registries and five dependent NIST publication pages have exact refresh owners; unavailable hybrid, legacy-source-rights, and FIPS-validation baselines remain machine-readable blockers |
| Hybrid admission | Concrete ECDHE-ML-KEM groups remain blocked until both a final Standards Track RFC and final IANA code points exist; drafts and private values are forbidden |
| Release | Regular committed PASS/PASS report, zero open findings, report update against every parent carrying the report, clean GitHub, explicit tag authorization, exact signed annotated tag and subject, release notes, SBOM, and strict local gate required |
| GitHub protection | Active machine-checked main ruleset requires signed linear history, review and CodeQL while retaining explicit accountable owner/admin bypass |
| CI | Read-only permissions, full-SHA action pins, live release-control verification, Clippy enforcement for both all-feature and no-default-feature configurations, and fail-closed acceptance of only current committed PASS/PASS or remediation-stage RETEST REQUIRED/PENDING pentest reports |
| CodeQL | GitHub Default setup; no advanced workflow |
| Panic posture | Panics are forbidden by workspace lint; release builds retain overflow checks and abort if an otherwise unreachable panic occurs, accepting process termination as the final fail-closed response rather than permitting recovery from a violated invariant |
