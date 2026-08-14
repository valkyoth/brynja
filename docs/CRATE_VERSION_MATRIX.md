# Crate Version Matrix

Status: v0.20.0 signed and published; v0.21.0 pentest PASS/PASS and awaiting green hosted checks

The latest signed and published checkpoint is v0.20.0. The `brynja` facade now
advances to internal `0.21.0`; `brynja-pki` gains canonical ASN.1 values while
retaining published package version `0.2.0`, and every other support package
retains its published version. This milestone selects zero crates.io packages.
Package publication does not imply a TLS implementation or production
readiness.

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
Signed tag v0.16.0 contains that remediation and selected no publication. The
v0.17.0 stage adds only inert FIPS-aware non-approved operation, build,
environment, provider-derived SSP-destruction, self-test, permanent-failure and
non-authorizing service-indicator contracts. Its exceptional assessment found
two High design issues; both are remediated, and repository-owner retest of
exact signed candidate `bc83f44a9c8fdb710d03429b1669ee6c4449b054` passed
with zero open findings. A final full-delta review through exact signed
candidate `3f889a2c07ae513235fd8cb9056faa983f2135e9` substantiated no open
Critical, High, or Medium vulnerability. The report retains caller-session-
scoped failure and application-implementable self-test success as
non-exploitable future constraints gated by module-wide failure at v0.127.1
and opaque module-owned attestation at v0.125.0/v0.127.0. It implements no module,
service, algorithm or validation and selects no package publication.
Signed tag v0.17.0 contains the final reviewed remediation. The v0.18.0 stage
adds only sealed mandatory decision domains, one caller-owned authoritative
state machine, exhaustive typed outcomes, and token-gated external-key
destruction. Its assessment findings are remediated by making public positive
resolutions non-authorizing, requiring explicit affine outcome commitment,
terminalizing abandoned pending/outcome values, and permanently latching
mandatory self-test failure. Its first retest found one remaining High
disposition-relabeling flaw; opaque non-interchangeable outcome types, private
validated reasons, and exact disposition retention/checking now close that
bypass. The clean second repository-owner retest of exact signed candidate
`635b229296be45b195d37d8111fd8ad8f8b1e571` records `PASS`/`PASS` with
zero open findings. Signed tag v0.18.0 contains that remediation. It implements
no policy, authentication, protocol engine, provider effect, external key
store, event schema, algorithm, independent verification, or validation and
selects no package publication. The v0.18.1 stage adds only opaque bounded
observational events, one-way caller timestamp enrichment, a fixed caller-owned
FIFO, and visible saturating loss accounting. Events duplicate mandatory v0.18
state but cannot authorize, commit, complete, latch, alert, call a provider, or
mutate security state. It adds no sink, delivery, persistence, protocol,
cryptographic, independent-review, or FIPS claim and selects no publication.
Signed tag v0.18.1 contains its zero-finding exceptional assessment candidate.
The v0.19.0 stage adds unpublished `brynja-protocol 0.1.0`, directly exposes it
from the facade, and wires it into the TLS 1.2, TLS 1.3, and DTLS package
boundaries. It implements shared bounded record-envelope parsing and encoding,
not negotiation, protection, replay, handshake, I/O, or an engine. Its first
hostile-parser boundary requires an exceptional pentest and selects no package
publication. Its initial assessment found one High TLS 1.3 cleartext-
application-data flaw. Repository-owner retest of exact signed remediation
candidate `238d4bac75eecce9dde63700c53f13e6f7a9aaed` passed with
`PASS`/`PASS` and zero open findings; signed tag v0.19.0 contains that
remediation. The v0.20.0 stage adds bounded DER framing in `brynja-pki`,
promotes the unpublished shared protocol crate, and selects every package
changed since v0.15.0 plus exact-pin dependents for publication only after the
scheduled cumulative assessment passes.
That assessment found no Critical, High, or Medium issue and one Low nested
DER header semantic-boundary oracle. The reader now enforces the parent before
every identifier/length byte read; local regression and policy checks pass,
and repository-owner retest of the exact signed remediation candidate passed
with zero open findings.
Hosted checks became green, signed v0.20.0 was created, and all 15 selected
packages were published. The v0.21.0 stage adds canonical ASN.1 primitive and
container values to `brynja-pki` without schema decoding, X.509, or
cryptography. Its exceptional assessment reported no findings, required no
source remediation, and records `PASS`/`PASS` with zero open findings. The
schema-validation and independent-review cautions remain explicit. The stage
awaits green hosted checks and selects no crates.io publication.

| Package group | Version | Publish | Meaning |
| --- | --- | --- | --- |
| `brynja` | `0.21.0` | no | Internal facade milestone; v0.20.0 is published |
| `brynja-core` | `0.9.0` | no | Published at v0.20.0; README metadata only |
| `brynja-crypto` | `0.1.2` | no | Published at v0.20.0; cryptographic effects remain unimplemented |
| `brynja-crypto-cpu` | `0.1.1` | no | Published inert CPU boundary; no executable kernel |
| `brynja-crypto-cpu-std` | `0.1.1` | no | Published inert adapter boundary; no runtime detector |
| `brynja-pki` | `0.2.0` | no | Published DER package now gains unpublished canonical ASN.1 value code for v0.25.0 |
| `brynja-protocol` | `0.1.0` | no | Published shared TLS/DTLS record-envelope boundary |
| `brynja-platform`, `brynja-tls13-handshake`, `brynja-tls12`, `brynja-tls13`, `brynja-tls`, `brynja-dtls`, `brynja-quic-tls` | `0.1.8` | no | Published versions retained; README metadata only |
| `brynja-legacy` and `brynja-legacy-*` engines | `0.1.0` | no | Explicit legacy isolation boundary only |
| `brynja-research-ssl1` | `0.1.0` | never | Research boundary only |
| Test, interop, xtask, and proof packages | `0.1.0` | no | Repository tooling; test support now includes a deterministic/fault engine that production cannot reach |
| `brynja-sanitization` | `0.1.1` | no | Published exact core-pin adapter; absent from every facade, engine, default, and FIPS boundary |

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

For released checkpoint `v0.20.0`, the guarded publisher selected fifteen
packages in dependency order: `brynja-core 0.9.0`, `brynja-crypto 0.1.2`, the
two CPU boundary packages at `0.1.1`, `brynja-pki 0.2.0`, initial
`brynja-protocol 0.1.0`, seven modern supporting packages at `0.1.8`,
`brynja-sanitization 0.1.1`, and finally `brynja 0.20.0`.

## Rust Compatibility

| Rust | Evidence |
| --- | --- |
| `1.90.0` through `1.97.0` | Workspace all-feature compatibility plus host zeroization and constant-time MIR/LLVM/assembly evidence on each listed stable release |
| `1.97.1` | Full release gate, every promised target, and zeroization plus constant-time emitted-code checks across all nine targets |
| Kani Rust `1.90.0` | Separate verifier pairing for `cargo-kani 0.67.0`; not a release compiler or proof result at v0.10.0 |
