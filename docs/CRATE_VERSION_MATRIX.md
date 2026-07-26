# Crate Version Matrix

Status: foundation

All workspace packages are currently version `0.1.0` and `publish = false`.
No crate has a published or production-ready implementation.

| Package group | Version | Publish | Meaning |
| --- | --- | --- | --- |
| `brynja`, `brynja-tls`, and modern production crates | `0.1.0` | no | Compile-time architecture only |
| `brynja-tls12`, `brynja-tls13`, and `brynja-tls13-handshake` | `0.1.0` | no | Version-specific modern TLS boundaries only |
| `brynja-legacy` and `brynja-legacy-*` engines | `0.1.0` | no | Explicit legacy isolation boundary only |
| `brynja-research-ssl1` | `0.1.0` | never | Research boundary only |
| Test, interop, xtask, and proof packages | `0.1.0` | no | Repository tooling |

## Enforced crates.io Release Policy

`release-crates.toml` is the release-specific source of truth.
`scripts/release_crates.py --check` compares it with Cargo metadata and rejects
inventory drift, manifest-version drift, non-exact internal dependency pins,
invalid version bumps, unavailable dependencies, publication-order errors, or
an accidentally publishable repository-only package.

After crates.io admission, every official modern `vX.Y.Z` or `vX.Y.Z-rc.N`
release tag publishes `brynja` at exactly `X.Y.Z` or `X.Y.Z-rc.N`. The main
facade is always the final crate in the publication sequence. An unchanged
facade entry or `publish = false` is invalid for a public release.

Supporting crates use independent versions and are published only when their
own package changes or an internal dependency must move outside the currently
published exact requirement:

| Change | Required supporting-crate version | Publish |
| --- | --- | --- |
| `initial` | Explicit first admitted version; previous version is `unpublished` | yes |
| `code` | Next independent minor version | yes |
| `bugfix` | Next patch version | yes |
| `dependency` | Next patch version | yes |
| `metadata` | Next patch version for immutable crates.io metadata correction | yes |
| `unchanged` | Exact previous version | no |
| `unpublished` | Retain an unadmitted package boundary | no |
| `repository` | Permanently repository-only | never |

Changed dependencies publish first and must be visible on crates.io before a
dependent crate is published. Unchanged supporting crates retain their
existing versions and are not republished. Internal published dependencies
remain exact-pinned; a required pin change is a package change.

`brynja-interop`, `brynja-proofs`, `brynja-research-ssl1`,
`brynja-test-support`, and `brynja-xtask` are mechanically prohibited from
publication. Legacy packages may publish only through their separately
admitted legacy release line and never become dependencies of the modern
facade.

The future `brynja-fips-module` and `brynja-fips` packages also use independent
versions. A validated module version is immutable and bound to its exact
certificate, artifact hashes, caveats, and tested operational environments.
Any changed module is a different artifact and cannot reuse the validation
claim; the facade may update only when its manifest, API, or approved profile
changes without mutating the validated module.

Actual publication requires a clean worktree, the matching release tag at
`HEAD`, a current committed PASS pentest report, user-confirmed green GitHub
checks, the complete versioned release gate, advisory and dependency-policy
checks, and typed version confirmation. The publisher provides no dirty-tree,
untagged, skipped-check, or `--no-verify` production bypass.

## Rust Compatibility

| Rust | Evidence |
| --- | --- |
| `1.90.0` through `1.97.0` | `cargo check --workspace --all-features` on each listed stable release |
| `1.97.1` | Full release gate and all target checks |
