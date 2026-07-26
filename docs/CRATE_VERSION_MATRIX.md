# Crate Version Matrix

Status: foundation

All workspace packages are currently version `0.1.0` and `publish = false`.
No crate has a published or production-ready implementation.

| Package group | Version | Publish | Meaning |
| --- | --- | --- | --- |
| `brynja`, `brynja-tls`, and modern production crates | `0.1.0` | no | Compile-time architecture only |
| `brynja-tls12`, `brynja-tls13`, and `brynja-tls13-handshake` | `0.1.0` | no | Version-specific modern TLS boundaries only |
| `brynja-historical` and `brynja-historical-*` engines | `0.1.0` | no | Explicit legacy isolation boundary only |
| `brynja-historical-ssl1-research` | `0.1.0` | never | Research boundary only |
| Test, interop, xtask, and proof packages | `0.1.0` | no | Repository tooling |

After the foundation release, crates use independent versions. A crate is
republished only for code/API changes, required dependency-range changes, or
immutable metadata corrections. Release metadata must name the exact package
set and publish in dependency order.

The future `brynja-fips-module` and `brynja-fips` packages also use independent
versions. A validated module version is immutable and bound to its exact
certificate, artifact hashes, caveats, and tested operational environments.
Any changed module is a different artifact and cannot reuse the validation
claim; the facade may update only when its manifest, API, or approved profile
changes without mutating the validated module.

## Rust Compatibility

| Rust | Evidence |
| --- | --- |
| `1.90.0` through `1.97.0` | `cargo check --workspace --all-features` on each listed stable release |
| `1.97.1` | Full release gate and all target checks |
