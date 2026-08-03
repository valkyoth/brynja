# Crate Version Matrix

Status: v0.7.0 pentest and retest passed; awaiting GitHub

The `brynja` facade advances to `0.7.0`. `brynja-core` advances to `0.4.0` for
the borrowed read cursor; every published modern package whose exact internal
pin changes advances to `0.1.3`. `brynja-crypto` remains
unchanged at `0.1.0`.
Legacy and repository-only packages remain unpublished. Package publication
does not imply a TLS implementation or production readiness.

| Package group | Version | Publish | Meaning |
| --- | --- | --- | --- |
| `brynja` | `0.7.0` | yes | Mandatory facade release exposing the v0.7 foundation domains |
| `brynja-core` | `0.4.0` | yes | Prior value domains plus transactional borrowed input consumption |
| `brynja-crypto` | `0.1.0` | no | Published and unchanged |
| `brynja-pki`, `brynja-platform` | `0.1.3` | yes | Exact dependency pin changed; functionality remains a boundary |
| `brynja-tls`, `brynja-tls12`, `brynja-tls13`, and `brynja-tls13-handshake` | `0.1.3` | yes | Exact dependency pins changed; engines remain unimplemented |
| `brynja-dtls`, `brynja-quic-tls` | `0.1.3` | yes | Exact dependency pins changed; engines/adapters remain unimplemented |
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
at exactly `X.Y.Z` or `X.Y.Z-rc.N`. The facade is always the final crate in the
publication sequence. An unchanged facade entry, `publish = false`, or
non-public release stage is invalid.

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

The future FIPS packages use independent versions. A validated module version
is immutable and bound to its exact certificate, artifact hashes, caveats, and
tested operational environments. Any changed module is a different artifact
and cannot reuse the validation claim.

If v0.11.1 admits it, `brynja-sanitization` also uses an independent SemVer
line and publishes only when its adapter code or exact `sanitization` pin
changes. Until admission, it is absent from the release manifest and workspace.

Actual publication requires a clean worktree, matching release tag at `HEAD`,
current committed PASS pentest report, user-confirmed green GitHub checks,
complete versioned release gate, advisory and dependency-policy checks, SBOM,
packages, and typed version confirmation. Signed tag subjects may use the
proper `Brynja vX.Y.Z` capitalization or the historical lowercase project
name. There is no production bypass.

For `v0.7.0`, publication order is `brynja-core 0.4.0`, `brynja-pki 0.1.3`,
`brynja-platform 0.1.3`, `brynja-tls13-handshake 0.1.3`, `brynja-tls12
0.1.3`, `brynja-tls13 0.1.3`, `brynja-tls 0.1.3`, `brynja-dtls 0.1.3`,
`brynja-quic-tls 0.1.3`, and finally `brynja 0.7.0`. The publisher waits for
each new dependency to be indexed before continuing.

## Rust Compatibility

| Rust | Evidence |
| --- | --- |
| `1.90.0` through `1.97.0` | Workspace all-feature compatibility check on each listed stable release |
| `1.97.1` | Full release gate, host targets, and three OS-less all-feature targets |
| Kani Rust `1.90.0` | Separate verifier pairing for `cargo-kani 0.67.0`; not a release compiler or proof result at v0.7.0 |
