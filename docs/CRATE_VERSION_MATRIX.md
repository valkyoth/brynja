# Crate Version Matrix

Status: initial public release candidate

All workspace packages are currently version `0.1.0`. The modern dependency
closure is selected for initial crates.io publication; legacy and
repository-only packages remain unpublished. Package publication does not
imply protocol implementation or production readiness.

| Package group | Version | Publish | Meaning |
| --- | --- | --- | --- |
| `brynja`, `brynja-core`, `brynja-crypto`, and `brynja-pki` | `0.1.0` | yes | Initial foundation publication |
| `brynja-tls`, `brynja-tls12`, `brynja-tls13`, and `brynja-tls13-handshake` | `0.1.0` | yes | Initial modern TLS boundary publication |
| `brynja-dtls`, `brynja-quic-tls`, and `brynja-platform` | `0.1.0` | yes | Initial optional normal-dependency publication |
| `brynja-legacy` and `brynja-legacy-*` engines | `0.1.0` | no | Explicit legacy isolation boundary only |
| `brynja-research-ssl1` | `0.1.0` | never | Research boundary only |
| Test, interop, xtask, and proof packages | `0.1.0` | no | Repository tooling |
| Future `brynja-sanitization` | not admitted | no | Conditional downstream adapter after v0.11.1 review |

## Enforced crates.io Release Policy

`release-crates.toml` is the release-specific source of truth.
`scripts/release_crates.py --check` compares it with Cargo metadata and rejects
inventory drift, manifest-version drift, non-exact internal dependency pins,
invalid version bumps, unavailable dependencies, publication-order errors, or
an accidentally publishable repository-only package.

Every official modern `vX.Y.Z` or `vX.Y.Z-rc.N` release tag publishes `brynja`
at exactly `X.Y.Z` or `X.Y.Z-rc.N`, including the foundation release. The main
facade is always the final crate in the publication sequence. An unchanged
facade entry, `publish = false`, or non-public release stage is invalid.

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

If v0.11.1 admits it, `brynja-sanitization` also uses an independent SemVer
line and publishes only when its adapter code or exact `sanitization` pin
changes. The approved `sanitization` package must publish first and be visible
on crates.io. The adapter never enters the modern, legacy, or FIPS facade
publication set automatically. Until admission, it is absent from
`release-crates.toml` and the workspace rather than represented by a placeholder
package.

Actual publication requires a clean worktree, the matching release tag at
`HEAD`, a current committed PASS pentest report, user-confirmed green GitHub
checks, the complete versioned release gate, advisory and dependency-policy
checks, and typed version confirmation. The publisher provides no dirty-tree,
untagged, skipped-check, or `--no-verify` production bypass.

For `v0.1.0`, the enforced initial publication order is:
`brynja-core`, `brynja-crypto`, `brynja-pki`, `brynja-platform`,
`brynja-tls13-handshake`, `brynja-tls12`, `brynja-tls13`, `brynja-tls`,
`brynja-dtls`, `brynja-quic-tls`, then `brynja`.

## Rust Compatibility

| Rust | Evidence |
| --- | --- |
| `1.90.0` through `1.97.0` | `cargo check --workspace --all-features` on each listed stable release |
| `1.97.1` | Full release gate and all target checks |
