# Security Controls

Status: foundation

| Control | Foundation enforcement |
| --- | --- |
| Dependency surface | Cargo manifests and `cargo metadata` must contain no external packages |
| Unsafe Rust | Workspace lint forbids it |
| `no_std` | Every package declares `#![no_std]` |
| Modern/legacy isolation | Graph validator requires `brynja-legacy-*` engine names and rejects legacy edges into modern crates |
| TLS version isolation | Graph validator requires the evergreen router to reach separate TLS 1.2 and TLS 1.3 engines while QUIC reaches only the recordless TLS 1.3 handshake |
| Review size | Source files over 500 lines fail checks |
| Toolchain | Pinned stable plus explicit MSRV matrix |
| Standards | HTTPS allowlist, immutable RFC bytes, SHA-256 lock, current update-closure audit; machine-enforced surface and normative traceability are gated at v0.3.0-v0.3.5 |
| Release | Versioned committed PASS report, zero open findings, report update on every later candidate change, clean GitHub, explicit tag authorization, release notes, SBOM, and local gate required |
| CI | Read-only permissions and full-SHA action pins |
| CodeQL | GitHub Default setup; no advanced workflow |
