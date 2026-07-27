# Permanent Evidence Index

Status: v0.3.0 implementation candidate

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
| `package-policy.toml` | Complete package and dependency boundary | Workspace metadata validators and fixtures |
| `github-release-controls.toml` | Protected release branch requirements | Local fixtures and authenticated live release check |
| `sbom/brynja.spdx.json` | Complete Cargo dependency graph | Deterministic SBOM comparison |
| `security/pentest/vX.Y.Z.md` | Permanent per-version pentest and remediation outcome | Release-readiness and report-history validators |

The v0.3.0 ledger is source-level evidence only. Protocol surface decisions
begin at v0.3.1, normative statement extraction at v0.3.2, domain population at
v0.3.3 through v0.3.5, and implementation afterward. No ledger entry is an
implementation, interoperability, security, or FIPS validation claim.
