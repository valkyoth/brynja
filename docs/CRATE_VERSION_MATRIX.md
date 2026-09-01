# Crate Version Matrix

Status: v0.20.0 signed and published; v0.21.0 through v0.24.5 signed; v0.24.6 implementation and complete local repository verification passed, pentest and signed candidate pending

The latest signed and published checkpoint is v0.20.0. The `brynja` facade now
advances to internal `0.24.6`. `brynja-hash-core 0.1.0`,
`brynja-hash-sha2 0.1.0` retains reusable byte-oriented interfaces and correct
portable implementations of all six FIPS 180-4 SHA-2 algorithms, and new
unpublished `brynja-hash-sha3 0.1.0` owns correct byte-oriented implementations
of all six FIPS 202 functions. Arbitrary-bit and hardened secret-bearing
profiles remain in progress through v0.24.11. Published
`brynja-crypto-cpu 0.1.1` now contains implemented but unadmitted x86_64 SHA,
AArch64 SHA2, and RV64 Zknh candidates; `brynja-crypto-cpu-std 0.1.1` contains
the separate opt-in x86/AArch64 host detector and runtime selection API while
RISC-V automatic detection remains disabled. Supporting manifest
versions remain unchanged until the v0.25.0 public checkpoint. The new
repository-only API-profile register closes 129 semantic capabilities across
22 dimensions and inventories eight current plus 75 planned secret owners; it
changes no supporting package or production behavior. This milestone selects
zero crates.io packages. Package publication does not imply a TLS
implementation or production readiness.

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
is signed and selects no crates.io publication. The v0.22.0 stage adds the
first executable cryptographic primitive: portable SHA-256 in two new leaf
packages, reused through `brynja-crypto` and the facade. It requires an
exceptional pentest before tagging, remains unpublished until the v0.25.0
checkpoint, and makes no independent-review or FIPS-validation claim. Its
assessment found no vulnerability, required no source remediation, and records
`PASS`/`PASS` with zero open findings. The report retains the future requirement
to harden and verify SHA working-state cleanup before keyed HMAC use.
The v0.22.1 stage implements isolated x86_64 SHA and AArch64 SHA2 compression
candidates plus static `no_std` and separate opt-in `std` selection. The scalar
implementation remains authoritative. Both accelerated candidates remain
unadmitted. Exact-commit native candidate observations passed on local AMD,
observed-feature AWS Intel, Apple M2, and AWS Arm, but remain private and
explicitly non-authorizing. Authenticated runner, CPU-migration, performance,
side-channel, and final admission evidence remains absent, so ordinary
opportunistic use falls back and required acceleration fails closed. The
exceptional assessment and final retest of signed commit
`7d6dc573d8aaf049085d4bc4007642ee3b9ed82f` passed with zero open
findings. The stage selects no package publication and makes no independent-
review, register-erasure, FIPS-validation, or complete hardware-support claim.
The v0.22.2 stage added the RV64 `Zknh` scalar-crypto candidate through four
hash-bound first-party Rust inline-assembly instructions. Both endpoint
compilers emit the exact instruction set and QEMU differentials pass, but no
qualifying native RISC-V evidence exists. The registered native lane has Rust
1.97.1 but lacks scalar and vector SHA extensions on every hart, so its
preflight stopped before candidate execution. Automatic RISC-V detection
remains disabled, the backend remains unadmitted, and the new unsafe boundary
received an exceptional assessment with zero Critical, High, or Medium
findings, no remediation, and `PASS`/`PASS`. Signed tag v0.22.2 contains that
green report candidate. The v0.22.3 stage adds a standalone public-only
`no_std` downstream SHA-256 consumer, version-only packaged-crate installation,
authoritative real inputs, irregular streaming, scalar and admitted-backend
accounting, public exhaustion preflight, and executable negative fixtures. It
closes the SHA-256 implementation chain without changing a support-package
version or selecting a crates.io publication. Its voluntary repository-owner
assessment and retest through exact signed candidate
`399c9e7c5092d755dfbc22a3adf5500f85a8877e` passed with zero open findings and
required no cryptographic source remediation. It remains an internal tag in the
scheduled v0.20.0-to-v0.25.0 cumulative range.
The v0.23.0 stage adds complete portable SHA-224 with its distinct FIPS 180-4
initial value, exact 28-byte output, one-shot and streaming APIs, checked
length domain, official vectors, Monte Carlo evidence, exhaustive split and
chunking coverage, Kani bounds, and pinned dynamic-analysis execution. Its
exceptional repository-owner assessment and retest of exact signed candidate
`8877bda1e697db98e77637d82bdc0d0d6ecad237` passed with zero open findings
and required no remediation. It remains an internal tag, selects no crates.io
publication, makes no independent-review or FIPS-validation claim, and stays
inside the scheduled v0.20.0-to-v0.25.0 cumulative range.
The v0.23.1 stage adds complete portable SHA-384 and SHA-512 over one private
80-round 64-bit compression owner and one private 128-byte buffered state. It
exposes exact distinct IVs, checked 128-bit length accounting, typed one-shot
and streaming APIs, official vectors, Monte Carlo, padding, partition,
exhaustion, proof, Miri, sanitizer, compiler, target, and package evidence.
It requires an exceptional new-algorithm pentest, selects no crates.io
publication, and makes no independent-review, state-erasure, acceleration, or
FIPS-validation claim. Its repository-owner assessment of exact candidate
`22c1dcdc7594a34bc14b53b42d1d56f7aa66047b` reported no finding and required
no remediation. The permanent report records `PASS`/`PASS` with zero open
findings; hosted GitHub and CodeQL passed and the milestone is signed.
The v0.23.2 stage completes portable SHA-512/224 and SHA-512/256 as distinct
named algorithms over the shared SHA-512-family foundation. Exact FIPS
SHA-512/t IV derivation is executable and bound to the normative constants;
official short, long, Monte Carlo, million-byte, padding, partition,
exhaustion, trait, and negative ordinary-truncation evidence passes. It selects
no crates.io publication and makes no independent-review, state-erasure,
acceleration, or FIPS-validation claim. Its repository-owner assessment of
exact candidate `0129013eaae7ee3f1cd2ca5cf9671b8ea5834165` reported no finding
and required no remediation. The permanent report records `PASS`/`PASS` with
zero open findings; hosted GitHub and CodeQL passed and the milestone is
signed.

The v0.23.3 stage extends the optional CPU surface to every SHA-2 identity.
SHA-224 reuses the three exact SHA-256-family kernels. AArch64 SHA-512 and RV64
Zknh SHA-512 candidates serve all four 64-bit family identities behind static,
thread-bound, direct-KAT sessions; forced AArch64 and RISC-V QEMU differential
and emitted-code checks pass. Exact-commit native correctness passes on local
AMD, observed-feature AWS Intel, Apple M2 and AWS Arm; the non-qualifying
RISC-V lane remains QEMU-only. x86_64 SHA-512 remains an explicit scalar-only
decision, and all five candidates remain unadmitted pending authenticated,
performance, migration and side-channel evidence. The exceptional pentest
records `PASS`/`PASS`, and the internal tag selects no crates.io packages.

The v0.23.4 stage closes complete-family usability through a standalone
downstream `no_std` consumer of only public leaf and facade APIs. It runs all
six identities over independent one-shot and irregular-streaming expectations
and repeats them from a safely extracted exact 15-package offline archive
closure. Negative fixtures reject digest, API, documentation, width, backend,
feature, and package regressions. It changes no support-package version,
admits no CPU backend, requires no scheduled pentest, and selects no crates.io
packages.

The voluntary repository-owner assessment of exact signed v0.23.4 candidate
`7864a8f3a8766d16fc9bb2ea89893351f29aa842` records `PASS`/`PASS` with zero
open findings and no remediation. It does not alter the zero-package
selection or replace the scheduled cumulative v0.25.0 assessment.

The v0.24.0 stage creates unpublished `brynja-hash-sha3 0.1.0` with one
private safe-Rust Keccak-f[1600] owner and complete portable SHA3-224 and
SHA3-256 one-shot and streaming APIs. Official examples, million-byte and
padding-boundary cases, every bounded partition, raw-Keccak negatives, two
Kani bounds, 17 source-policy mutations, and a 328-message independent-library
differential corpus pass. SHA3-384, SHA3-512, SHAKE, acceleration, complete-
family public acceptance, secret-state erasure, independent review, and FIPS
validation remain later work. The family stays **In progress**, the stage
requires an exceptional new-primitive pentest, and zero crates are selected
for publication.

The v0.24.1 stage adds complete portable SHA3-384 and SHA3-512 over the same
private sponge owner, with distinct 104-byte/72-byte rates and 48-byte/64-byte
outputs. Official, million-byte, padding-boundary, streaming, raw-Keccak
negative and all-four-algorithm differential evidence passes. SHAKE, final
family acceptance, acceleration, secret-state erasure, independent review and
FIPS validation remain later work. Zero crates are selected for publication.

The v0.24.3 stage freezes complete portable package-external usability for all
six FIPS 202 identities. The standalone `no_std` leaf/facade consumer checks
official and independent fixed-output/XOF expectations, irregular input and
multi-squeeze output, exact rates, zero output, checked failures and domain
separation, then repeats from the safely extracted exact sixteen-package
offline archive closure. This changes no cryptographic implementation,
dependency or backend admission. Byte-oriented v0.24.4 backend work and the
v0.24.7-v0.24.11 arbitrary-bit, hardened-state, and combined acceptance remain;
zero crates are selected for publication. Its voluntary assessment's one Low
missing fixture-Clippy enforcement control is remediated, and independent
retest of exact candidate `c7bd354e5bcf9a816c366cf24d0d88347771afc5`
passed with zero open findings.

The v0.24.4 stage adds unadmitted x86_64 AVX2 and AArch64 SHA3
Keccak-f[1600] candidates under the existing zero-dependency `no_std` CPU
package. Direct KAT, quarantine, scalar differential, six-identity fixed/XOF,
compiler-endpoint instruction, and supplemental AArch64 QEMU checks pass.
RISC-V is scalar-only for Keccak under the pinned ratified ISA authorities.
The facade advances without changing support-package versions; exceptional
pentest passed with zero open findings, qualifying native observations remain
incomplete, both candidates stay unadmitted, and zero crates are selected for
publication.

The v0.24.2 stage adds complete portable SHAKE128 and SHAKE256 over the same
private sponge owner. Separate consuming absorb and incremental output types,
exact 168-byte/136-byte rates, the `0x1f` suffix, caller-owned zero-length and
multi-squeeze output, and checked input/output domains pass official examples,
rate boundaries, 343-byte partition campaigns, fixed-output domain negatives,
dynamic analysis, a 328-message six-function differential corpus, a ninth Kani
bound, bounded assurance stdin/cases/output with child timeouts, and 51 source-policy mutations. Final package-external and cross-backend
family acceptance, acceleration, secret-state erasure, independent review and
FIPS validation remain later work. Zero crates are selected for publication.

| Package group | Version | Publish | Meaning |
| --- | --- | --- | --- |
| `brynja` | `0.24.6` | no | Internal repository-only cryptographic API-profile and secret-state closure milestone; production cryptography is unchanged and v0.20.0 remains published |
| `brynja-core` | `0.9.0` | no | Published at v0.20.0; README metadata only |
| `brynja-hash-core` | `0.1.0` | no | Unpublished allocation-free fixed-output and XOF interfaces |
| `brynja-hash-sha2` | `0.1.0` | no | Unpublished six-algorithm FIPS 180-4 byte APIs, forced candidate routes, and package-external byte acceptance; arbitrary-bit and hardened secret-bearing profiles remain in progress |
| `brynja-hash-sha3` | `0.1.0` | no | Unpublished SHA3-224/SHA3-256/SHA3-384/SHA3-512/SHAKE128/SHAKE256 byte APIs with packaged portable acceptance; arbitrary-bit, hardened secret-bearing, and final cross-backend profiles remain in progress |
| `brynja-crypto` | `0.1.2` | no | Published version retained while its unpublished source reexports all six SHA-2 and six FIPS 202 leaf implementations |
| `brynja-crypto-cpu` | `0.1.1` | no | Published version retained; five SHA-2 plus two Keccak candidates remain unadmitted; x86 SHA-512 and RISC-V Keccak are scalar-only |
| `brynja-crypto-cpu-std` | `0.1.1` | no | Published version retained; unpublished complete-family reporting falls back or fails closed; RISC-V auto-detection is disabled |
| `brynja-pki` | `0.2.0` | no | Published DER package now gains unpublished canonical ASN.1 value code for v0.25.0 |
| `brynja-protocol` | `0.1.0` | no | Published shared TLS/DTLS record-envelope boundary |
| `brynja-platform`, `brynja-tls13-handshake`, `brynja-tls12`, `brynja-tls13`, `brynja-tls`, `brynja-dtls`, `brynja-quic-tls` | `0.1.8` | no | Published versions retained; README metadata only |
| `brynja-legacy` and `brynja-legacy-*` engines | `0.1.0` | no | Explicit legacy isolation boundary only |
| `brynja-research-ssl1` | `0.1.0` | never | Research boundary only |
| Test, interop, xtask, and proof packages | `0.1.0` | no | Repository tooling; test support now includes a deterministic/fault engine that production cannot reach |
| `brynja-sanitization` | `0.1.1` | no | Published exact core-pin adapter; absent from every facade, engine, default, and FIPS boundary |

## Enforced crates.io Release Policy

`release-crates.toml` is the release-specific source of truth.
`scripts/release/release_crates.py --check` compares it with Cargo metadata and rejects
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
| `1.90.0` through `1.97.1` | Workspace all-feature compatibility plus host zeroization and constant-time MIR/LLVM/assembly evidence on each listed stable release |
| `1.98.0` | Full release gate, every promised target, and zeroization plus constant-time emitted-code checks across all nine targets |
| Kani Rust `1.90.0` | Separate verifier pairing for `cargo-kani 0.67.0`; not a release compiler or proof result at v0.10.0 |
