# Crate Version Matrix

Status: v0.10.0 published; v0.11.0-v0.13.0 tagged; v0.13.1 awaiting green CI

The `brynja` facade advances to `0.13.1` for the current development line but
is not selected for crates.io publication. The latest signed development tag
is v0.13.0 and the latest public
checkpoint remains `brynja 0.10.0`, `brynja-core 0.7.0`, eight modern support
packages at `0.1.6`, and `brynja-crypto 0.1.0`. Supporting, legacy, and
repository-only package versions remain unchanged during this development
milestone. Package publication does not imply a TLS implementation or
production readiness.

The optional adapter is a material production secret-storage boundary. Its
exceptional v0.11.2 assessment passed with zero findings. The v0.12.0
exceptional assessment and retest passed after one High RV32 timing flaw and
two Medium assurance-scanner bypasses were closed. Signed v0.12.0 selected no
publication. The v0.13.0 internal stage also selects zero crates and adds only
upstream provider capability and opaque-handle contracts. Its three High and
one Medium voluntary-assessment findings were remediated, and the
repository-owner retest passed with zero open findings. Signed v0.13.0 selected
no publication. The v0.13.1 internal stage adds only upstream CPU-backend
capability, health, and dispatch contracts and likewise selects no crate.

| Package group | Version | Publish | Meaning |
| --- | --- | --- | --- |
| `brynja` | `0.13.1` | no | Current development version; latest signed tag is `v0.13.0` and latest crates.io checkpoint is `0.10.0` |
| `brynja-core` | `0.7.0` | no | Published v0.10 boundary retained while cumulative v0.11 zeroization, v0.12 constant-time, v0.13 provider-contract, and v0.13.1 backend-contract code remain unreleased on crates.io |
| `brynja-crypto` | `0.1.0` | no | Published code boundary retained; shared documentation clarifies its provider/composition role above future leaf-family crates |
| `brynja-pki`, `brynja-platform` | `0.1.6` | no | Published boundaries retained; platform effects remain unimplemented downstream from the new core contracts |
| `brynja-tls`, `brynja-tls12`, `brynja-tls13`, and `brynja-tls13-handshake` | `0.1.6` | no | Published boundaries retained; engines remain unimplemented |
| `brynja-dtls`, `brynja-quic-tls` | `0.1.6` | no | Published boundaries retained; engines/adapters remain unimplemented |
| `brynja-legacy` and `brynja-legacy-*` engines | `0.1.0` | no | Explicit legacy isolation boundary only |
| `brynja-research-ssl1` | `0.1.0` | never | Research boundary only |
| Test, interop, xtask, and proof packages | `0.1.0` | no | Repository tooling |
| `brynja-sanitization` | `0.1.0` | no | Implemented separately over exact `sanitization 2.0.3`; first publication deferred to a cumulative public checkpoint |

## Enforced crates.io Release Policy

`release-crates.toml` is the release-specific source of truth.
`scripts/release_crates.py --check` compares it with Cargo metadata and rejects
inventory drift, manifest-version drift, non-exact internal dependency pins,
invalid version bumps, a package tree changed since the previous public tag but
marked unchanged, unavailable dependencies, publication-order errors, or an
accidentally publishable repository-only package.

Every signed modern `vX.Y.Z` or `vX.Y.Z-rc.N` tag advances the `brynja`
manifest to exactly `X.Y.Z` or `X.Y.Z-rc.N`. A development tag selects no
crates.io packages, including an exceptionally pentested development tag. At
scheduled or deliberately early public checkpoints, the facade must publish
and remain the final crate in the publication sequence.

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

The `brynja-sanitization` package uses an independent SemVer
line and publishes only when its adapter code or exact `sanitization` pin
changes. Its v0.1.0 implementation is present but held from crates.io during
the current v0.13.1 internal development line.

Every tag requires a clean worktree, signed commit, complete automated tag
gate, user-confirmed green GitHub and CodeQL, and explicit authorization.
Actual publication additionally requires a matching release tag at `HEAD`,
current committed cumulative PASS pentest report,
complete versioned release gate, advisory and dependency-policy checks, SBOM,
packages, and typed version confirmation. Signed tag subjects may use the
proper `Brynja vX.Y.Z` capitalization or the historical lowercase project
name. There is no production bypass.

For released checkpoint `v0.10.0`, publication order was `brynja-core 0.7.0`, `brynja-pki 0.1.6`,
`brynja-platform 0.1.6`, `brynja-tls13-handshake 0.1.6`, `brynja-tls12
0.1.6`, `brynja-tls13 0.1.6`, `brynja-tls 0.1.6`, `brynja-dtls 0.1.6`,
`brynja-quic-tls 0.1.6`, and finally `brynja 0.10.0`. The publisher waits for
each new dependency to be indexed before continuing.

## Rust Compatibility

| Rust | Evidence |
| --- | --- |
| `1.90.0` through `1.97.0` | Workspace all-feature compatibility plus host zeroization and constant-time MIR/LLVM/assembly evidence on each listed stable release |
| `1.97.1` | Full release gate, every promised target, and zeroization plus constant-time emitted-code checks across all nine targets |
| Kani Rust `1.90.0` | Separate verifier pairing for `cargo-kani 0.67.0`; not a release compiler or proof result at v0.10.0 |
