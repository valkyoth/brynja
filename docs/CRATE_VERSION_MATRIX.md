# Crate Version Matrix

Status: foundation

All workspace packages are currently version `0.1.0` and `publish = false`.
No crate has a published or production-ready implementation.

| Package group | Version | Publish | Meaning |
| --- | --- | --- | --- |
| `brynja` and modern production crates | `0.1.0` | no | Compile-time architecture only |
| `brynja-historical` and historical engines | `0.1.0` | no | Isolation boundary only |
| `brynja-ssl1-research` | `0.1.0` | never by default | Research boundary only |
| Test, interop, xtask, and proof packages | `0.1.0` | no | Repository tooling |

After the foundation release, crates use independent versions. A crate is
republished only for code/API changes, required dependency-range changes, or
immutable metadata corrections. Release metadata must name the exact package
set and publish in dependency order.

## Rust Compatibility

| Rust | Evidence |
| --- | --- |
| `1.90.0` through `1.97.0` | `cargo check --workspace --all-features` on each listed stable release |
| `1.97.1` | Full release gate and all target checks |

