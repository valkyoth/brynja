# Security Controls

Status: v0.3.0 standards source-ledger enforcement

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
| Standards | HTTPS allowlists, immutable RFC/NIST bytes, exact RFC-index and IANA snapshots, 285 reviewed errata decisions, lifecycle and milestone ownership, complete updated-by/obsoleted-by closure, deterministic ledger generation, broken fixtures, and release-time live drift rejection |
| Hybrid admission | Concrete ECDHE-ML-KEM groups remain blocked until both a final Standards Track RFC and final IANA code points exist; drafts and private values are forbidden |
| Release | Regular committed PASS report, zero open findings, report update against every parent carrying the report, clean GitHub, explicit tag authorization, exact signed annotated tag and subject, release notes, SBOM, and local gate required |
| GitHub protection | Active machine-checked main ruleset requires signed linear history, review and CodeQL while retaining explicit accountable owner/admin bypass |
| CI | Read-only permissions, full-SHA action pins, live release-control verification, and Clippy enforcement for both all-feature and no-default-feature configurations |
| CodeQL | GitHub Default setup; no advanced workflow |
| Panic posture | Panics are forbidden by workspace lint; release builds retain overflow checks and abort if an otherwise unreachable panic occurs, accepting process termination as the final fail-closed response rather than permitting recovery from a violated invariant |
