# Crate Version Matrix

Status: v0.10.0 published; v0.11.0-v0.14.0 tagged; v0.15.0 awaiting scheduled pentest

The `brynja` facade advances to `0.15.0` for the scheduled cumulative public
checkpoint. The latest signed development tag is v0.14.0 and the latest
published checkpoint remains `brynja 0.10.0`, `brynja-core 0.7.0`, eight
modern support packages at `0.1.6`, and `brynja-crypto 0.1.0`. The candidate
selects fourteen packages, but selection does not authorize publication and
does not imply a TLS implementation or production readiness.

The optional adapter is a material production secret-storage boundary. Its
exceptional v0.11.2 assessment passed with zero findings. The v0.12.0
exceptional assessment and retest passed after one High RV32 timing flaw and
two Medium assurance-scanner bypasses were closed. Signed v0.12.0 selected no
publication. The v0.13.0 internal stage also selects zero crates and adds only
upstream provider capability and opaque-handle contracts. Its three High and
one Medium voluntary-assessment findings were remediated, and the
repository-owner retest passed with zero open findings. Signed v0.13.0 selected
no publication. Signed v0.13.1 adds only upstream CPU-backend capability,
health, and dispatch contracts. The v0.13.2 stage reserves two inert CPU
package boundaries and likewise selects no crate. Its one High and one Medium
assessment findings are remediated, and repository-owner retest of exact signed
candidate `2fa60d05d8c4472426cdb979243f53e2e959c231` passed with zero open
findings. The v0.13.3 stage adds repository-only CPU evidence and performance-
admission contracts while all eight reserved backends remain unadmitted. Its
two High findings passed first remediation retest; the resulting Low parser
finding passed repository-owner retest on exact signed second remediation
candidate `1f08ca0fd9be6bf1995a22a9ca806addc17641e0`, with zero open findings.
The v0.14.0 stage adds affine raw-entropy and initialized secure-random
contracts plus a production-unreachable deterministic fault provider. It
implements no algorithm, entropy source, OS integration, or FIPS service. Its
one Medium explicit-teardown handler omission is remediated, and repository-
owner retest passed with zero open findings.
The v0.15.0 candidate adds typed wall and monotonic clock contracts, checked
time arithmetic, explicit source unavailability, and terminal rollback
detection. Its scheduled pentest covers all changes after v0.10.0 through the
exact candidate and remains mandatory before tagging or publication.

| Package group | Version | Publish | Meaning |
| --- | --- | --- | --- |
| `brynja` | `0.15.0` | pending | Public-checkpoint candidate; publish last only after pentest, green hosted checks, signed tag, and authorization |
| `brynja-core` | `0.8.0` | pending | Cumulative v0.11-v0.15 foundation code, including typed clock contracts |
| `brynja-crypto` | `0.1.1` | pending | Exact core dependency update; provider/composition boundary remains effect-free |
| `brynja-crypto-cpu`, `brynja-crypto-cpu-std` | `0.1.0` | pending | Initial inert package boundaries; no kernel, runtime detector, native result, low-level allowance, performance claim, or FIPS claim |
| `brynja-pki`, `brynja-platform` | `0.1.7` | pending | Exact core dependency updates; PKI and platform effects remain unimplemented |
| `brynja-tls`, `brynja-tls12`, `brynja-tls13`, and `brynja-tls13-handshake` | `0.1.7` | pending | Exact internal dependency updates; engines remain unimplemented |
| `brynja-dtls`, `brynja-quic-tls` | `0.1.7` | pending | Exact internal dependency updates; engines/adapters remain unimplemented |
| `brynja-legacy` and `brynja-legacy-*` engines | `0.1.0` | no | Explicit legacy isolation boundary only |
| `brynja-research-ssl1` | `0.1.0` | never | Research boundary only |
| Test, interop, xtask, and proof packages | `0.1.0` | no | Repository tooling; test support now includes a deterministic/fault engine that production cannot reach |
| `brynja-sanitization` | `0.1.0` | pending | Initial separate adapter over exact `sanitization 2.0.3`; absent from every facade, engine, default, and FIPS boundary |

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
changes. Its v0.1.0 initial publication is selected for v0.15.0 but remains
blocked behind the complete public-checkpoint gates.

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
