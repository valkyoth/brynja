# Crate Version Matrix

Status: v0.15.0 published; v0.16.0 awaiting green CI

The `brynja` facade advances to `0.16.0` for the current development milestone
and selects no crates.io publication. The latest signed and published
checkpoint is v0.15.0: `brynja 0.15.0`, `brynja-core 0.8.0`,
`brynja-crypto 0.1.1`, the eight modern support packages at `0.1.7`, and the
initial CPU-boundary and sanitization packages at `0.1.0`. Package publication
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
The v0.15.0 checkpoint added typed wall and monotonic clock contracts, checked
time arithmetic, explicit source unavailability, and terminal rollback
detection. Its scheduled pentest covered all changes after v0.10.0 through
exact signed candidate `1aa4ad938438f0f2dc996b74b6364f1026c05e0f` and
passed with zero findings. Hosted checks passed, the signed tag was created,
and all fourteen selected packages were published. The v0.16.0 stage adds
bounded affine pending certificate, external-signature, and accelerator
lifecycles with authoritative provider-state destruction. It implements no
provider effect or algorithm and selects no package publication.
Its exceptional assessment found three High and two Medium issues across the
initial candidate and follow-up reviews. All are remediated, and the final
repository-owner retest of exact signed candidate
`f0557b8419b77129d1763e9469ae4e7deeffc2e7` passed with zero open findings.

| Package group | Version | Publish | Meaning |
| --- | --- | --- | --- |
| `brynja` | `0.16.0` | no | Current development version; latest crates.io checkpoint is `0.15.0` |
| `brynja-core` | `0.8.0` | no | Published v0.15 boundary retained while v0.16 pending-lifecycle code remains unreleased on crates.io |
| `brynja-crypto` | `0.1.1` | no | Published provider/composition boundary retained; cryptographic effects remain unimplemented |
| `brynja-crypto-cpu`, `brynja-crypto-cpu-std` | `0.1.0` | no | Published inert boundaries; no kernel, runtime detector, native result, low-level allowance, performance claim, or FIPS claim |
| `brynja-pki`, `brynja-platform` | `0.1.7` | no | Published boundaries retained; PKI and platform effects remain unimplemented |
| `brynja-tls`, `brynja-tls12`, `brynja-tls13`, and `brynja-tls13-handshake` | `0.1.7` | no | Published boundaries retained; engines remain unimplemented |
| `brynja-dtls`, `brynja-quic-tls` | `0.1.7` | no | Published boundaries retained; engines/adapters remain unimplemented |
| `brynja-legacy` and `brynja-legacy-*` engines | `0.1.0` | no | Explicit legacy isolation boundary only |
| `brynja-research-ssl1` | `0.1.0` | never | Research boundary only |
| Test, interop, xtask, and proof packages | `0.1.0` | no | Repository tooling; test support now includes a deterministic/fault engine that production cannot reach |
| `brynja-sanitization` | `0.1.0` | no | Published separate adapter over exact `sanitization 2.0.3`; absent from every facade, engine, default, and FIPS boundary |

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
changes. Its v0.1.0 initial publication completed at v0.15.0.

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

For released checkpoint `v0.15.0`, the guarded publisher selected fourteen
packages in dependency order: `brynja-core 0.8.0`, `brynja-crypto 0.1.1`, the
two CPU boundary packages at `0.1.0`, eight modern supporting packages at
`0.1.7`, `brynja-sanitization 0.1.0`, and finally `brynja 0.15.0`.

## Rust Compatibility

| Rust | Evidence |
| --- | --- |
| `1.90.0` through `1.97.0` | Workspace all-feature compatibility plus host zeroization and constant-time MIR/LLVM/assembly evidence on each listed stable release |
| `1.97.1` | Full release gate, every promised target, and zeroization plus constant-time emitted-code checks across all nine targets |
| Kani Rust `1.90.0` | Separate verifier pairing for `cargo-kani 0.67.0`; not a release compiler or proof result at v0.10.0 |
