# Permanent Evidence Index

Status: v0.4.0 implementation stop; pentest required

This index identifies durable review evidence. A generated artifact is valid
only while its source, policy, checksum, generator, and verifier remain
consistent in the same commit.

| Evidence | Authority or scope | Enforcement |
| --- | --- | --- |
| `rfc/SOURCES`, `rfc/SHA256SUMS`, `rfc/rfc*.txt` | Exact RFC Editor source bytes and reviewed roles | `scripts/verify-rfcs.sh` |
| `references/LOCAL_SOURCES`, `references/LOCAL_SHA256SUMS` | Local-only NIST and ITU authority bytes and roles | `scripts/verify-local-references.sh` |
| `standards/source-policy.toml` | Lifecycle, domain, milestone, registry, closure-exclusion, admission, independent hash-pin, and pin-provenance policy | `scripts/check-standards-ledger.py` |
| `standards/snapshots/rfc-index.json` | RFC status and update/obsolescence relationships | Checksum lock, ledger checker, and networked release drift check |
| `standards/snapshots/iana/*.xml` | Exact official registry state | XML identity, checksum lock, ledger checker, and networked release drift check |
| `standards/ERRATA.json` | Complete locked-RFC errata inventory and reviewed disposition | Ledger checker and networked release drift check |
| `standards/source-ledger.json` | Deterministic joined inventory of every admitted authority and owner | Byte-for-byte regeneration and 28 positive/broken-fixture tests |
| `standards/surface-policy.json` | Reviewed dispositions and ownership for semantic surfaces, complete IANA collections, nested registries, and exact entry overrides | Schema, source, owner, target, uniqueness, completeness, and override validation |
| `standards/transport-surfaces/*.toml` | Sixty-four reviewed TLS, DTLS, and QUIC-TLS implementation-milestone surfaces | Exact ledger binding, stable requirement identity, owner, source, target, and uniqueness validation |
| `standards/protocol-surfaces.json` | Deterministic classification of 4,424 semantic and registry surfaces | Byte-for-byte regeneration and 30 positive/broken-fixture tests |
| `standards/protocol-surface-coverage.md` | Human-readable disposition, kind, and domain counts | Generated and byte-compared with the machine register |
| `requirements/policy.json` | Reviewed stable requirement identifiers, lifecycles, decisions, owners, targets, tests, evidence, and residual risk | Schema, source, lifecycle, transition, anchor, ownership, and claim validation |
| `requirements/domain-scope.toml`, `requirements/domains/*.toml` | Reviewed v0.3.3 authority, invariant, work-bound, test-polarity, surface-group, and deferral policy | Exact field, role, owner, lifecycle, domain, mapping, and completeness validation |
| `requirements/domain-sections.toml` | Reviewed per-requirement bindings for all 364 domain normative RFC sections | Exact source/requirement pairs, semantic revisions, extraction anchors, section hashes, and explicit disposition validation |
| `requirements/transport-scope.toml`, `requirements/transport-exceptions.toml` | Reviewed v0.3.4 transport authority, owner, rejection, caller boundary, registry-group, and deferral policy | Exact field, role, owner, lifecycle, domain, mapping, completeness, and broken-fixture validation |
| `requirements/transport-sections.toml` | Reviewed per-requirement bindings for all 550 transport normative RFC sections | Exact source/requirement pairs, semantic revisions, extraction anchors, section hashes, and explicit disposition validation |
| `requirements/residual-policy.toml` | Reviewed v0.3.5 optional, HPKE, ECH, ML-KEM, entropy, operational, legacy, and residual surface groups with all 743 surface identities explicit | Exact per-surface source, owner, lifecycle, disposition, reciprocal requirement link, homogeneous code/test boundary, and prior-coverage complement validation |
| `requirements/residual-sections.toml` | Reviewed per-requirement bindings or explicit dispositions for all 182 residual normative RFC sections | Exact source/requirement pairs, semantic revisions, extraction anchors, section hashes, explicit exclusion validation, and global reconciliation with domain and transport policies |
| `requirements/authority-claims.toml` | Local distribution rights, mutable-authority refresh rules, source-free plan boundaries, and hybrid, legacy, and FIPS blockers | Exact authority, roadmap, surface, owner, URL, status, rights, blocker, and completeness validation |
| `requirements/schema.json` | Deterministic lifecycle and transition contract | Byte-for-byte regeneration |
| `requirements/matrix.json` | 167 resolved requirements bound to exact source, section, errata, authority role, registry, surface, and immutable parent-history evidence | Byte-for-byte regeneration and 110 positive/broken-fixture tests |
| `requirements/indexes.json` | Bidirectional source, decision, owner, target, test, and evidence mappings | Generated from and cross-checked against the matrix |
| `requirements/coverage.md` | Human-readable pilot lifecycle, strength, scope, and index coverage | Generated and byte-compared with the machine evidence |
| `requirements/domain-coverage.json` | Exact coverage of 53 cryptography/encoding/PKIX authorities, 364 normative RFC sections, and 3,322 selected surfaces | Deterministic generation, byte comparison, 352 mapped sections, eleven cross-bundle delegations, one explicit exclusion, exact hashes, and domain fixtures |
| `requirements/transport-coverage.json` | Exact coverage of 40 transport authorities, 550 normative RFC sections, 64 owner milestones, and 485 selected surfaces | Deterministic generation, byte comparison, 539 mapped sections, eleven explicit dispositions, exact DTLS RRC and RFC 6066 ownership, and transport fixtures |
| `requirements/residual-coverage.json` | Exact coverage of 33 residual authorities, 182 normative RFC sections, and 743 formerly uncovered surfaces | Deterministic generation, byte comparison, explicit-surface complement proof, 165 exact section mappings, 17 reviewed exclusions, exact anchors and hashes, and 22 residual fixtures |
| `requirements/closure.json` | Bidirectional closure across 126 sources, 206 roadmap rows, 4,424 surfaces, and 167 requirements | Complete source-to-plan, plan-to-source, source-to-requirement, reciprocal surface-to-requirement, requirement-to-owner, rights, refresh, and blocker validation |
| `package-policy.toml` | Complete package and dependency boundary | Workspace metadata validators and fixtures |
| `github-release-controls.toml` | Protected release branch requirements | Local fixtures and authenticated live release check |
| `sbom/brynja.spdx.json` | Complete Cargo dependency graph | Deterministic SBOM comparison |
| `security/pentest/vX.Y.Z.md` | Permanent per-version pentest and remediation outcome | Release-readiness and report-history validators |
| `assurance/policy.toml` | Bounded first-party mutation and differential contracts, three OS-less targets, separate stable/Kani toolchains, and five exact external assurance-tool pins | Schema, bounds, target, workflow, manifest-isolation, pin, source-kind, owner, and broken-fixture validation |
| `assurance/evidence.json` | Deterministic binding of assurance policy, runners, process-tree and bounded-input controls, CI, stable/Kani toolchain documentation, and every Cargo manifest | Byte-for-byte regeneration and 40 positive/broken assurance fixtures |

The v0.3.0 ledger, v0.3.1 decisions, v0.3.2 matrix foundation, v0.3.3
cryptography/encoding/PKIX population, v0.3.4 TLS/DTLS/QUIC-TLS population,
and v0.3.5 optional, legacy, operational, and residual closure are planning
and governance evidence only. Protocol implementation occurs afterward. No
ledger, surface, or planned
protocol-requirement entry is an implementation, interoperability, security,
or FIPS validation claim.
