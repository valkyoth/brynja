<p align="center">
  <b>Security-first, dependency-free, no_std TLS in Rust.</b><br>
  Built in small audited releases with strict modern/legacy protocol isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja">Crates.io</a>
  |
  <a href="https://docs.rs/brynja">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md">Release Plan</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md">Threat Model</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/brynja">
    <img src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja Rust TLS crate overview">
  </a>
</p>

# brynja

Brynja is a security-first, dependency-free, `no_std` TLS project in Rust. It
is being developed in small reviewable milestones toward a serious
production-ready TLS implementation at `1.0.0`.

> **Development status:** Brynja is pre-1.0, incomplete, and not ready to
> secure application traffic. Every version receives an immutable signed tag
> only after the complete automated gate and green GitHub and CodeQL. Scheduled
> pentesting and crates.io publication occur at the cumulative checkpoints
> described below; a tag without a matching committed pentest report was not a
> scheduled pentest checkpoint.

Version `0.11.2` implements the separately selected, protocol-neutral
`brynja-sanitization 0.1.0` adapter admitted at v0.11.1. It exact-pins
first-party `sanitization 2.0.3`, disables every upstream feature, activates no
transitive package, owns opaque fixed-size wrappers, and provides only explicit
copies to and from Brynja's caller-owned regions. It is absent from every
facade, engine, default feature, and FIPS module closure. Brynja's v0.11.0
affine owned-region primitive remains mandatory and authoritative. See the
[admission review](https://github.com/valkyoth/brynja/blob/main/docs/sanitization-admission-review.md)
for package hashes, unsafe inventory, target evidence, residual risks, and
re-review triggers. These foundations do **not** implement TLS framing, a
protocol state machine, or cryptography and must not be used to secure network
traffic.

An exceptional v0.11.1 repository-owner assessment found that the initial
review fixture accepted and discarded arbitrary source-error payloads. The
remediated boundary accepts only a payload-free Brynja-owned error, and the
retest of signed commit `cd1c881d2eb6c9aa925f1527a326330c1cf3b80a` passed
with zero open findings. The permanent
[v0.11.1 report](https://github.com/valkyoth/brynja/blob/main/security/pentest/v0.11.1.md)
records the finding, remediation, limits, and exact evidence; no affected code
ever entered the production graph.

## Development Tags And Pentesting

The `brynja` facade version advances at every roadmap milestone, including
patch milestones, and each completed milestone receives the ordinary signed
`vX.Y.Z` tag after its signed commit passes the complete local gate and GitHub
and CodeQL are green. Development tags between public checkpoints are not
published to crates.io. Supporting crates keep independent versions and are
published only when their cumulative changes require it at a checkpoint.

Pentests look backwards over the complete change range between public
checkpoints. The v0.15.0 assessment covers all changes after signed public tag
v0.10.0 through the exact v0.15.0 candidate, including every v0.11.0-v0.14.0
and patch milestone. The v0.20.0 assessment then covers all changes after
v0.15.0 through v0.20.0, and the same pattern continues every fifth minor
version. Each checkpoint report records its previous public tag as `Baseline`
and names both ends of the reviewed range in `Scope`. Material security changes
can require an earlier exceptional pentest; that does not weaken the next
scheduled cumulative review.

Permanent outcomes are committed under
[`security/pentest/`](https://github.com/valkyoth/brynja/tree/main/security/pentest).
These reports make the assessed versions and ranges explicit; automated tests,
CI, CodeQL, fuzzing, Miri, or Kani are valuable evidence but are not themselves
an independent pentest.

## Install

Brynja is not ready for application use and does not implement TLS. The latest
crates.io checkpoint is `0.10.0`; the repository is preparing the tagged
v0.11.2 development milestone without crates.io publication. The published
dependency is:

```toml
[dependencies]
brynja = "0.10"
```

Every tag advances the `brynja` facade manifest to the tag version. Only
scheduled or exceptional public checkpoint tags publish it to crates.io.
Supporting crates keep independent versions and are published only when their
cumulative package or exact-pin changes require it; unchanged support crates
are not republished. The guarded publisher validates and packages the exact
selected set in dependency order and publishes the facade last.

## Design Boundaries

- **Golden rule:** every Brynja cryptographic primitive, construction, key
  operation, protocol cryptographic operation, CPU backend, and FIPS module
  service is implemented from first-party Rust source. Brynja never wraps,
  links, vendors, calls, or delegates those duties to C, C++, Objective-C,
  OpenSSL, BoringSSL, AWS-LC, a system cryptographic library, or another
  foreign/native cryptographic module.
- The modern `brynja` facade can never enable SSL or other legacy
  protocols through its features.
- Legacy implementations live in explicitly named packages and use
  separate APIs, state, configuration, negotiation, caches, and ticket keys.
- Every legacy engine uses a `brynja-legacy-*` package name so its
  presence is obvious in manifests, lockfiles, SBOMs, and policy reports.
- `brynja-tls` is an evergreen facade and one-pass router over independently
  versioned modern TLS engines; a new TLS generation does not redefine an
  existing engine package or automatically make its predecessor legacy.
- Runtime and build dependencies are forbidden in the core workspace. Future
  separately selected `brynja-rustls` and `brynja-tokio` companion adapters may
  depend only on the exact pure-Rust ecosystem API they implement, in separate
  lockfiles and graphs that can never enter or be enabled by `brynja`.
- Version `0.11.2` implements one separately selected
  `brynja-sanitization` adapter over admitted exact `sanitization 2.0.3`. It
  uses an exact pin with default features disabled,
  never activates `zeroize`, and is not a dependency or feature of a facade,
  protocol engine, legacy engine, or FIPS module.
- Every production crate is `no_std` by default. Platform services enter
  through explicit caller-provided interfaces.
- v0.9 arena domain names classify raw caller storage only. v0.10 adds the
  abstract destruction-duty contract. v0.11 adds a separate exclusive borrowed
  region owner with exact initialization and volatile complete-region clearing;
  a raw `SecretDomain` arena is not automatically that owner and
  `CertificateDomain` is not private-key storage.
- FIPS 140-3 support is planned through separate `brynja-fips-module` and
  `brynja-fips` packages, not a boolean Cargo feature. Only an exact issued,
  certificate-bound module and tested operational environment may carry a
  validation claim; the current project is not FIPS validated.
- Source files are limited to 500 lines and milestones are split before they
  become too large to review safely.
- Assurance runners are first-party, deterministic, bounded, and shell-free.
  Inputs use descriptor-bound, no-follow, limit-plus-one reads and differential
  corpora and generated mutation cases stream one at a time. Windows uses a
  suspended-start kill-on-close Job Object. A POSIX process group is only
  cooperative cleanup: hostile execution fails closed unless the launcher
  declares enforced cgroup, PID-namespace, container/VM, or fork-and-setsid
  denial. That declaration is a launcher contract, not sandbox evidence.
  External campaign launchers must provide and record OS containment. Kani uses
  its separately documented Rust 1.90.0 verifier pairing while release code
  stays on latest stable Rust; policy-only status is never a proof claim.
- A feature being compiled is never evidence that a protocol is implemented,
  secure, interoperable, audited, or production-ready.
- The locked RFC closure and its roadmap mapping are recorded in the
  [RFC coverage audit](https://github.com/valkyoth/brynja/blob/main/docs/RFC_COVERAGE_AUDIT.md);
  the generated
  [protocol-surface coverage](https://github.com/valkyoth/brynja/blob/main/standards/protocol-surface-coverage.md)
  classifies every pinned IANA record and explicit non-registry decision;
  the generated
  [requirement coverage](https://github.com/valkyoth/brynja/blob/main/requirements/coverage.md)
  proves complete lifecycle and bidirectional mapping across the foundation,
  cryptography, encoding, PKIX, TLS, DTLS, QUIC-TLS, optional, HPKE, ECH,
  entropy, legacy, operational, and residual domains before implementation.

## Cryptography Verification Status

No cryptographic or protocol code in this repository has been independently
reviewed. A component only moves from ❌ to ✅ when a named independent
reviewer signs off and that evidence is linked from its status entry in this
table. Passing the project's own tests, CI, Kani, Miri, sanitizers, fuzzing,
differential testing, or release pentests does not, by itself,
constitute independent cryptographic or protocol verification.

FIPS validation is a separate official claim. Brynja has no FIPS 140-3
validation, certificate, validated module, approved security policy, or
certificate-bound operational-environment claim.

| Component | Cryptographic or protocol scope | Independent review or official validation status |
| --- | --- | --- |
| `brynja-crypto` | Hashes, MACs, AEADs, KDFs, RSA, and ECC | ❌ Not verified |
| `brynja-pki` | ASN.1, DER, X.509, path validation, and revocation | ❌ Not verified |
| `brynja-tls` | Modern TLS version routing and policy | ❌ Not verified |
| `brynja-tls12` | TLS 1.2 record and handshake engine | ❌ Not verified |
| `brynja-tls13` / `brynja-tls13-handshake` | TLS 1.3 record and handshake engine | ❌ Not verified |
| `brynja-quic-tls` | QUIC/TLS handshake integration | ❌ Not verified |
| `brynja-dtls` | DTLS record and handshake engines | ❌ Not verified |
| `brynja-sanitization` | Fixed-size secret ownership and explicit Brynja-region copies | ❌ Not verified |
| `brynja-legacy` / `brynja-legacy-*` | TLS 1.1/1.0, SSL, WTLS, PCT, and SNP obsolete-protocol boundaries | ❌ Not verified |
| `brynja-research-ssl1` | Unpublished SSL 1.0 provenance reconstruction | ❌ Not verified |
| Future `brynja-fips-module` / `brynja-fips` | FIPS 140-3 cryptographic module and policy boundary | ❌ Not FIPS validated |

Only the shared alert/failure, bounded numeric/resource, borrowed read,
transactional caller-buffer write, exact workspace/arena, abstract secret
lifetime, and owned-region zeroization foundations described for `brynja-core`
plus the separately selected sanitization adapter are implemented. No
cryptographic primitive, PKI processor, protocol parser, or protocol engine in
this table is implemented.
Independent-review status cannot be inferred from implementation, testing,
formal proof, pentest, or release status.

## Workspace

| Package | Role | Current status |
| --- | --- | --- |
| `brynja` | Modern production facade | Exposes v0.11 foundation domains; no TLS engine |
| `brynja-core` | Bounded wire, buffer, error, state, and provider domains | Prior domains plus affine owned-region zeroization implemented |
| `brynja-crypto` | First-party hashes, MACs, AEADs, KDFs, RSA, and ECC | Foundation only |
| `brynja-pki` | ASN.1, DER, X.509, path validation, and revocation | Foundation only |
| `brynja-tls` | Evergreen modern TLS facade and one-pass version router | Foundation only |
| `brynja-tls13` | Version-specific TLS 1.3 stream engine | Foundation only |
| `brynja-tls13-handshake` | Record-independent TLS 1.3 handshake shared with QUIC | Foundation only |
| `brynja-tls12` | Version-specific explicitly hardened TLS 1.2 engine | Foundation only |
| `brynja-quic-tls` | QUIC/TLS handshake integration | Foundation only |
| `brynja-dtls` | Modern DTLS engines | Foundation only |
| `brynja-platform` | Explicit entropy, time, storage, and I/O integration | Foundation only |
| `brynja-sanitization` | Optional protocol-neutral first-party sanitization adapter | v0.1.0 implemented over exact `sanitization 2.0.3`; separately selected and not yet published |
| `brynja-legacy` | Opt-in legacy facade; no default features | Boundary only |
| `brynja-legacy-*` engines | TLS 1.1/1.0, SSL, WTLS, PCT, and SNP isolation | Boundary only |
| `brynja-test-support` | RFC 9850 test-only key-log encoder and future fixtures | Implemented, unpublished, production-unreachable |
| Other repository-only crates | Tests, interop, tasks, and proof harnesses | Unpublished |

See the [legacy protocol plan](https://github.com/valkyoth/brynja/blob/main/docs/LEGACY_PROTOCOL_PLAN.md)
for the independent warning, containment, audit, and pentest line required for
every obsolete protocol.

## Platform Policy

The protocol and cryptographic cores must remain portable `no_std` Rust.
Day-one CI is designed to compile the workspace for Linux, Windows, FreeBSD,
macOS, Android, and iOS, and to run host tests on Linux, Windows, and macOS.
Aesynx is a planned portability target: no API may assume a current operating
system, allocator, socket type, filesystem, clock, or platform RNG.

See [Platform Support](https://github.com/valkyoth/brynja/blob/main/docs/platform-support.md).

## Trust Dashboard

| Area | Policy |
| --- | --- |
| License | `MIT OR Apache-2.0` |
| MSRV | Rust `1.90.0` |
| Pinned stable toolchain | Rust `1.97.1` |
| Kani verifier pairing | `cargo-kani 0.67.0` on Rust `1.90.0`; separate evidence only |
| Default target | `no_std` |
| Cryptographic implementation | First-party Rust only; foreign/native cryptographic modules and wrappers are forbidden |
| Third-party crates | Forbidden in the core workspace and every Brynja facade, engine, crypto, legacy, bare-metal, and FIPS graph; future rustls/Tokio companion adapters own isolated exact API dependencies |
| First-party companion crates | Exact `sanitization 2.0.3` is reachable only through the optional adapter with no feature or transitive package |
| Unsafe Rust | One v0.11 volatile-store block admitted in a private module; every other site is mechanically forbidden |
| Default networking | None |
| Legacy protocols in `brynja` | Impossible by package boundary |
| FIPS 140-3 status | Planned Level 1 software-module path; not validated |
| Production readiness | Not before an exact reviewed `1.0.0-rc.N` candidate |

## Rust Version Support

The MSRV is Rust `1.90.0`. Development and full release evidence are pinned
to Rust `1.97.1`, the current stable patch release checked on 2026-08-09.
The release preflight queries upstream again and fails closed if the pin or
tooling is stale.

Kani does not set the crate compiler baseline. Its compiler-sensitive proof
path is separately pinned to `cargo-kani 0.67.0` with Rust `1.90.0`, following
the documented `base64-ng` model. v0.10.0 admits no Kani proof harness, so the
successful policy check is not formal-verification evidence.

| Rust toolchain | Required evidence |
| --- | --- |
| `1.90.0` | Workspace all-feature compatibility check |
| `1.91.0` | Workspace all-feature compatibility check |
| `1.92.0` | Workspace all-feature compatibility check |
| `1.93.0` | Workspace all-feature compatibility check |
| `1.94.0` | Workspace all-feature compatibility check |
| `1.95.0` | Workspace all-feature compatibility check |
| `1.96.0` | Workspace all-feature compatibility check |
| `1.96.1` | Workspace all-feature compatibility check |
| `1.97.0` | Workspace all-feature compatibility check |
| `1.97.1` | Full format, lint, test, platform, policy, docs, package, and security gate |

Patch releases are listed separately when they are stable releases that the
project promises to support. The authoritative matrix is
[CRATE_VERSION_MATRIX.md](https://github.com/valkyoth/brynja/blob/main/docs/CRATE_VERSION_MATRIX.md).

## Checks

```bash
scripts/checks.sh
scripts/check-rust-version-matrix.sh
scripts/release_crates.py --check
scripts/release_crates.py --package-check
python3 scripts/check-verification-status.py
python3 scripts/test-verification-status.py
python3 scripts/check-assurance.py
python3 scripts/test-assurance.py
scripts/check-bare-metal.sh
scripts/check-kani.sh
python3 scripts/check-unsafe-policy.py
python3 scripts/check-first-party-rust-crypto.py
python3 scripts/test-first-party-rust-crypto.py
python3 scripts/check-zeroization-evidence.py
scripts/check-zeroization-codegen.sh 1.97.1 x86_64-unknown-linux-gnu
scripts/check-sanitization-adapter-codegen.sh 1.97.1 x86_64-unknown-linux-gnu
scripts/check-zeroization-miri.sh
scripts/check-zeroization-sanitizer.sh
scripts/check-github-release-controls.py
python3 scripts/check-standards-ledger.py
python3 scripts/check-protocol-surfaces.py
python3 scripts/check-requirements.py
cargo deny check
cargo audit
scripts/tag_gate.sh v0.11.2
```

The networked `scripts/check_latest_tools.sh` check is mandatory before a
signed tag. `scripts/tag_gate.sh vX.Y.Z` runs the complete automated tag gate
and applies the stage-specific final check: ordinary development milestones
require no scheduled pentest, exceptional development milestones require their
PASS report without publication, and public checkpoints require their
cumulative PASS report. GitHub CodeQL uses Default setup; this repository
intentionally does not add an advanced CodeQL workflow.

After an exact green public-checkpoint candidate is pentested and tagged, the
interactive crates.io publisher is, for example:

```bash
scripts/release_crates.py --version 0.15.0
```

It reruns the complete release gate, publishes changed dependencies in order,
waits for crates.io indexing between dependent packages, and publishes
`brynja` last. Publication accepts signed annotated tag subjects using the
proper project capitalization, `Brynja vX.Y.Z`, and retains compatibility with
the historical lowercase `brynja vX.Y.Z` form.

Every milestone waits for green GitHub and CodeQL before the user authorizes
its signed tag. At scheduled or exceptional public checkpoints, the
implementation and cumulative versioned PASS report are committed together.
Any later CI-driven fix must update that report in the same commit before the
candidate can be tagged and published.

## Documentation

- [Initial idea and final architecture decision](https://github.com/valkyoth/brynja/blob/main/docs/initial-idea.md)
- [Implementation plan](https://github.com/valkyoth/brynja/blob/main/docs/IMPLEMENTATION_PLAN.md)
- [Release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md)
- [Version plan](https://github.com/valkyoth/brynja/blob/main/docs/VERSION_PLAN.md)
- [Threat model](https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md)
- [First-party Rust cryptography golden rule](https://github.com/valkyoth/brynja/blob/main/docs/first-party-rust-cryptography.md)
- [Standards source policy](https://github.com/valkyoth/brynja/blob/main/docs/rfc-source-policy.md)
- [Machine-readable standards evidence](https://github.com/valkyoth/brynja/blob/main/standards/README.md)
- [Normative requirement evidence](https://github.com/valkyoth/brynja/blob/main/requirements/README.md)
- [Permanent evidence index](https://github.com/valkyoth/brynja/blob/main/docs/evidence-index.md)
- [Assurance harness policy](https://github.com/valkyoth/brynja/blob/main/assurance/README.md)
- [Kani verifier policy](https://github.com/valkyoth/brynja/blob/main/docs/KANI.md)
