# Permanent Evidence Index

Status: v0.3.2 implementation complete; awaiting pentest

This index identifies durable review evidence. A generated artifact is valid
only while its source, policy, checksum, generator, and verifier remain
consistent in the same commit.

| Evidence | Authority or scope | Enforcement |
| --- | --- | --- |
| `rfc/SOURCES`, `rfc/SHA256SUMS`, `rfc/rfc*.txt` | Exact RFC Editor source bytes and reviewed roles | `scripts/verify-rfcs.sh` |
| `references/LOCAL_SOURCES`, `references/LOCAL_SHA256SUMS` | Local-only NIST authority bytes and roles | `scripts/verify-local-references.sh` |
| `standards/source-policy.toml` | Lifecycle, domain, milestone, registry, closure-exclusion, admission, independent hash-pin, and pin-provenance policy | `scripts/check-standards-ledger.py` |
| `standards/snapshots/rfc-index.json` | RFC status and update/obsolescence relationships | Checksum lock, ledger checker, and networked release drift check |
| `standards/snapshots/iana/*.xml` | Exact official registry state | XML identity, checksum lock, ledger checker, and networked release drift check |
| `standards/ERRATA.json` | Complete locked-RFC errata inventory and reviewed disposition | Ledger checker and networked release drift check |
| `standards/source-ledger.json` | Deterministic joined inventory of every admitted authority and owner | Byte-for-byte regeneration and 28 positive/broken-fixture tests |
| `standards/surface-policy.json` | Reviewed dispositions and ownership for semantic surfaces, complete IANA collections, nested registries, and exact entry overrides | Schema, source, owner, target, uniqueness, completeness, and override validation |
| `standards/protocol-surfaces.json` | Deterministic classification of 4,343 semantic and registry surfaces | Byte-for-byte regeneration and 25 positive/broken-fixture tests |
| `standards/protocol-surface-coverage.md` | Human-readable disposition, kind, and domain counts | Generated and byte-compared with the machine register |
| `requirements/policy.json` | Reviewed stable requirement identifiers, lifecycles, decisions, owners, targets, tests, evidence, and residual risk | Schema, source, lifecycle, transition, anchor, ownership, and claim validation |
| `requirements/schema.json` | Deterministic lifecycle and transition contract | Byte-for-byte regeneration |
| `requirements/matrix.json` | Resolved pilot requirements bound to exact source, section, errata, registry, and surface evidence | Byte-for-byte regeneration and 32 positive/broken-fixture tests |
| `requirements/indexes.json` | Bidirectional source, decision, owner, target, test, and evidence mappings | Generated from and cross-checked against the matrix |
| `requirements/coverage.md` | Human-readable pilot lifecycle, strength, scope, and index coverage | Generated and byte-compared with the machine evidence |
| `package-policy.toml` | Complete package and dependency boundary | Workspace metadata validators and fixtures |
| `github-release-controls.toml` | Protected release branch requirements | Local fixtures and authenticated live release check |
| `sbom/brynja.spdx.json` | Complete Cargo dependency graph | Deterministic SBOM comparison |
| `security/pentest/vX.Y.Z.md` | Permanent per-version pentest and remediation outcome | Release-readiness and report-history validators |

The v0.3.0 ledger, v0.3.1 decisions, and v0.3.2 requirement pilot are planning
and governance evidence only. Domain population occurs at v0.3.3 through
v0.3.5, and protocol implementation afterward. No ledger, surface, or planned
protocol-requirement entry is an implementation, interoperability, security,
or FIPS validation claim.
