# Security Controls

Status: foundation

| Control | Foundation enforcement |
| --- | --- |
| Dependency surface | Cargo manifests and `cargo metadata` must contain no external packages |
| Unsafe Rust | Workspace lint forbids it |
| `no_std` | Every package declares `#![no_std]` |
| Modern/historical isolation | Graph validator rejects historical edges into modern crates |
| Review size | Source files over 500 lines fail checks |
| Toolchain | Pinned stable plus explicit MSRV matrix |
| Standards | HTTPS allowlist, immutable RFC bytes, SHA-256 lock, current update-closure audit; machine-enforced surface and normative traceability are gated at v0.3.0-v0.3.5 |
| Release | Release notes, SBOM, exact pentest metadata, and local gate required |
| CI | Read-only permissions and full-SHA action pins |
| CodeQL | GitHub Default setup; no advanced workflow |
