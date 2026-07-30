# Crate Version Matrix

Status: v0.3.3 pentest passed; awaiting green GitHub checks and tag authorization

The `brynja` facade advances to `0.3.3`. Every unchanged modern supporting
crate retains its published `0.1.0` version and is not republished. Legacy and
repository-only packages remain unpublished. Package publication does not
imply protocol implementation or production readiness.

| Package group | Version | Publish | Meaning |
| --- | --- | --- | --- |
| `brynja` | `0.3.3` | yes | Mandatory facade release for cryptography, encoding, and PKIX normative coverage |
| `brynja-core`, `brynja-crypto`, and `brynja-pki` | `0.1.0` | no | Published and unchanged |
| `brynja-tls`, `brynja-tls12`, `brynja-tls13`, and `brynja-tls13-handshake` | `0.1.0` | no | Published and unchanged |
| `brynja-dtls`, `brynja-quic-tls`, and `brynja-platform` | `0.1.0` | no | Published and unchanged |
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
packages, and typed version confirmation. There is no production bypass.

For `v0.3.3`, only `brynja 0.3.3` is selected. Its complete exact-pinned
supporting closure is already available at `0.1.0`.

## Rust Compatibility

| Rust | Evidence |
| --- | --- |
| `1.90.0` through `1.97.0` | Workspace all-feature compatibility check on each listed stable release |
| `1.97.1` | Full release gate and all target checks |
