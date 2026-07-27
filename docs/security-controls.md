# Security Controls

Status: v0.2.0 release and isolation enforcement

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
| Standards | HTTPS allowlist, immutable RFC bytes, SHA-256 lock, current update-closure audit; machine-enforced surface and normative traceability are gated at v0.3.0-v0.3.5 |
| Release | Regular committed PASS report, zero open findings, report update against every parent carrying the report, clean GitHub, explicit tag authorization, exact signed annotated tag and subject, release notes, SBOM, and local gate required |
| GitHub protection | Active machine-checked main ruleset requires signed linear history, review and CodeQL while retaining explicit accountable owner/admin bypass |
| CI | Read-only permissions, full-SHA action pins, and live release-control verification |
| CodeQL | GitHub Default setup; no advanced workflow |
