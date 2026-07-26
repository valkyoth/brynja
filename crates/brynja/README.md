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

Version `0.1.0` is a repository foundation only. It establishes crate,
platform, standards, test, and security boundaries. It does **not** implement
TLS and must not be used to secure network traffic.

## Install

Brynja is not published or ready for application use. Once a milestone is
published, the normal dependency will be:

```toml
[dependencies]
brynja = "0.1"
```

For every admitted modern release tag, the `brynja` facade is published at the
tag version. Supporting crates keep independent versions and are published only
when they change; unchanged support crates are not republished. The guarded
publisher validates the exact package set and dependency order and publishes
the facade last.

## Design Boundaries

- The modern `brynja` facade can never enable SSL or other legacy
  protocols through its features.
- Legacy implementations live in explicitly named packages and use
  separate APIs, state, configuration, negotiation, caches, and ticket keys.
- Every legacy engine uses a `brynja-legacy-*` package name so its
  presence is obvious in manifests, lockfiles, SBOMs, and policy reports.
- `brynja-tls` is an evergreen facade and one-pass router over independently
  versioned modern TLS engines; a new TLS generation does not redefine an
  existing engine package or automatically make its predecessor legacy.
- Runtime and build dependencies are forbidden. Any future exception requires
  a dedicated adapter crate, written admission review, tests, and release gate.
- Every production crate is `no_std` by default. Platform services enter
  through explicit caller-provided interfaces.
- FIPS 140-3 support is planned through separate `brynja-fips-module` and
  `brynja-fips` packages, not a boolean Cargo feature. Only an exact issued,
  certificate-bound module and tested operational environment may carry a
  validation claim; the current project is not FIPS validated.
- Source files are limited to 500 lines and milestones are split before they
  become too large to review safely.
- A feature being compiled is never evidence that a protocol is implemented,
  secure, interoperable, audited, or production-ready.
- The locked RFC closure and its roadmap mapping are recorded in the
  [RFC coverage audit](https://github.com/valkyoth/brynja/blob/main/docs/RFC_COVERAGE_AUDIT.md);
  v0.3.2 through v0.3.5 later turn every applicable normative statement into
  lifecycle-correct source-to-plan-to-code-and-test traceability.

## Workspace

| Package | Role | 0.1.0 status |
| --- | --- | --- |
| `brynja` | Modern production facade | Foundation only |
| `brynja-core` | Bounded wire, buffer, error, state, and provider domains | Foundation only |
| `brynja-crypto` | First-party hashes, MACs, AEADs, KDFs, RSA, and ECC | Foundation only |
| `brynja-pki` | ASN.1, DER, X.509, path validation, and revocation | Foundation only |
| `brynja-tls` | Evergreen modern TLS facade and one-pass version router | Foundation only |
| `brynja-tls13` | Version-specific TLS 1.3 stream engine | Foundation only |
| `brynja-tls13-handshake` | Record-independent TLS 1.3 handshake shared with QUIC | Foundation only |
| `brynja-tls12` | Version-specific explicitly hardened TLS 1.2 engine | Foundation only |
| `brynja-quic-tls` | QUIC/TLS handshake integration | Foundation only |
| `brynja-dtls` | Modern DTLS engines | Foundation only |
| `brynja-platform` | Explicit entropy, time, storage, and I/O integration | Foundation only |
| `brynja-legacy` | Opt-in legacy facade; no default features | Boundary only |
| `brynja-legacy-*` engines | TLS 1.1/1.0, SSL, WTLS, PCT, and SNP isolation | Boundary only |
| Repository-only crates | Tests, interop, tasks, and proof harnesses | Unpublished |

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
| Default target | `no_std` |
| Third-party crates | Forbidden |
| Unsafe Rust | Forbidden until a versioned, audited exception is approved |
| Default networking | None |
| Legacy protocols in `brynja` | Impossible by package boundary |
| FIPS 140-3 status | Planned Level 1 software-module path; not validated |
| Production readiness | Not before an exact reviewed `1.0.0-rc.N` candidate |

## Rust Version Support

The MSRV is Rust `1.90.0`. Development and full release evidence are pinned
to Rust `1.97.1`, the current stable patch release checked on 2026-07-21.
The release preflight queries upstream again and fails closed if the pin or
tooling is stale.

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
cargo deny check
cargo audit
```

The networked `scripts/check_latest_tools.sh` check is mandatory before a
release. GitHub CodeQL uses Default setup; this repository intentionally does
not add an advanced CodeQL workflow.

At each implementation stop, the user pentests the release candidate. The
implementation and current versioned PASS report are committed together. Any
later CI-driven fix must update that report in the same commit, and tagging
occurs only after GitHub is green and the user explicitly requests it.

## Documentation

- [Initial idea and final architecture decision](https://github.com/valkyoth/brynja/blob/main/docs/initial-idea.md)
- [Implementation plan](https://github.com/valkyoth/brynja/blob/main/docs/IMPLEMENTATION_PLAN.md)
- [Release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md)
- [Version plan](https://github.com/valkyoth/brynja/blob/main/docs/VERSION_PLAN.md)
- [Threat model](https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md)
- [Standards source policy](https://github.com/valkyoth/brynja/blob/main/docs/rfc-source-policy.md)
