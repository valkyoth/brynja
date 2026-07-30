# Permanent Evidence Index

Status: v0.3.3 implementation stop reached; awaiting pentest

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
| `standards/protocol-surfaces.json` | Deterministic classification of 4,346 semantic and registry surfaces | Byte-for-byte regeneration and 25 positive/broken-fixture tests |
| `standards/protocol-surface-coverage.md` | Human-readable disposition, kind, and domain counts | Generated and byte-compared with the machine register |
| `requirements/policy.json` | Reviewed stable requirement identifiers, lifecycles, decisions, owners, targets, tests, evidence, and residual risk | Schema, source, lifecycle, transition, anchor, ownership, and claim validation |
| `requirements/domain-scope.toml`, `requirements/domains/*.toml` | Reviewed v0.3.3 authority, invariant, work-bound, test-polarity, surface-group, and deferral policy | Exact field, role, owner, lifecycle, domain, mapping, and completeness validation |
| `requirements/schema.json` | Deterministic lifecycle and transition contract | Byte-for-byte regeneration |
| `requirements/matrix.json` | Forty-six resolved requirements bound to exact source, section, errata, authority role, registry, surface, and immutable parent-history evidence | Byte-for-byte regeneration and 66 positive/broken-fixture tests |
| `requirements/indexes.json` | Bidirectional source, decision, owner, target, test, and evidence mappings | Generated from and cross-checked against the matrix |
| `requirements/coverage.md` | Human-readable pilot lifecycle, strength, scope, and index coverage | Generated and byte-compared with the machine evidence |
| `requirements/domain-coverage.json` | Exact coverage of 53 cryptography/encoding/PKIX authorities, 364 normative RFC sections, and 3,322 selected surfaces | Deterministic generation, byte comparison, explicit deferral checks, and domain fixtures |
| `package-policy.toml` | Complete package and dependency boundary | Workspace metadata validators and fixtures |
| `github-release-controls.toml` | Protected release branch requirements | Local fixtures and authenticated live release check |
| `sbom/brynja.spdx.json` | Complete Cargo dependency graph | Deterministic SBOM comparison |
| `security/pentest/vX.Y.Z.md` | Permanent per-version pentest and remediation outcome | Release-readiness and report-history validators |

The v0.3.0 ledger, v0.3.1 decisions, v0.3.2 matrix foundation, and v0.3.3
cryptography/encoding/PKIX population are planning and governance evidence
only. Remaining domain population occurs at v0.3.4 and v0.3.5, and protocol
implementation afterward. No ledger, surface, or planned
protocol-requirement entry is an implementation, interoperability, security,
or FIPS validation claim.
