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

Version `0.4.0` establishes the first-party assurance harness and true
bare-metal compile matrix on top of the complete 167-requirement,
126-authority, 4,424-surface normative baseline. Deterministic mutation and
external-process differential runners enforce input, output, case, timeout,
canonical-result, and replay bounds. The complete workspace builds for three
OS-less targets, and exact Kani, Miri, sanitizer, AFL++, and honggfuzz source
pins remain outside every Cargo manifest. It does **not** implement TLS and
must not be used to secure network traffic.

## Install

Brynja is not ready for application use. Version `0.4.0` is an assurance
infrastructure release; it does not implement TLS. The dependency is:

```toml
[dependencies]
brynja = "0.4"
```

Every official release tag publishes the `brynja` facade at the tag version.
Supporting crates keep independent versions and are published only when they
change; unchanged support crates are not republished. The initial release also
publishes the complete modern dependency closure required by the facade. The
guarded publisher validates and packages the exact set in dependency order and
publishes the facade last.

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
- Versions `0.11.1` and `0.11.2` evaluate and conditionally implement one
  separately selected `brynja-sanitization` adapter to the first-party
  `sanitization` crate. It uses an exact pin with default features disabled,
  never activates `zeroize`, and is not a dependency or feature of a facade,
  protocol engine, legacy engine, or FIPS module.
- Every production crate is `no_std` by default. Platform services enter
  through explicit caller-provided interfaces.
- FIPS 140-3 support is planned through separate `brynja-fips-module` and
  `brynja-fips` packages, not a boolean Cargo feature. Only an exact issued,
  certificate-bound module and tested operational environment may carry a
  validation claim; the current project is not FIPS validated.
- Source files are limited to 500 lines and milestones are split before they
  become too large to review safely.
- Assurance runners are first-party, deterministic, bounded, and shell-free.
  External campaign launchers must provide OS sandboxing. Kani uses its
  separately documented Rust 1.90.0 verifier pairing while release code stays
  on latest stable Rust; policy-only status is never a proof claim.
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

## Workspace

| Package | Role | Current status |
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
| Future `brynja-sanitization` | Optional protocol-neutral first-party sanitization adapter | Not admitted |
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
| Kani verifier pairing | `cargo-kani 0.67.0` on Rust `1.90.0`; separate evidence only |
| Default target | `no_std` |
| Third-party crates | Forbidden |
| First-party companion crates | Conditional adapter-only admission review |
| Unsafe Rust | Forbidden until a versioned, audited exception is approved |
| Default networking | None |
| Legacy protocols in `brynja` | Impossible by package boundary |
| FIPS 140-3 status | Planned Level 1 software-module path; not validated |
| Production readiness | Not before an exact reviewed `1.0.0-rc.N` candidate |

## Rust Version Support

The MSRV is Rust `1.90.0`. Development and full release evidence are pinned
to Rust `1.97.1`, the current stable patch release checked on 2026-07-31.
The release preflight queries upstream again and fails closed if the pin or
tooling is stale.

Kani does not set the crate compiler baseline. Its compiler-sensitive proof
path is separately pinned to `cargo-kani 0.67.0` with Rust `1.90.0`, following
the documented `base64-ng` model. v0.4.0 admits no Kani proof harness, so the
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
python3 scripts/check-assurance.py
python3 scripts/test-assurance.py
scripts/check-bare-metal.sh
scripts/check-kani.sh
scripts/check-github-release-controls.py
python3 scripts/check-standards-ledger.py
python3 scripts/check-protocol-surfaces.py
python3 scripts/check-requirements.py
cargo deny check
cargo audit
```

The networked `scripts/check_latest_tools.sh` check is mandatory before a
release. GitHub CodeQL uses Default setup; this repository intentionally does
not add an advanced CodeQL workflow.

After the exact green candidate is tagged, the interactive crates.io publisher
is:

```bash
scripts/release_crates.py --version 0.4.0
```

It reruns the complete release gate, publishes changed dependencies in order,
waits for crates.io indexing between dependent packages, and publishes
`brynja` last.

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
- [Machine-readable standards evidence](https://github.com/valkyoth/brynja/blob/main/standards/README.md)
- [Normative requirement evidence](https://github.com/valkyoth/brynja/blob/main/requirements/README.md)
- [Permanent evidence index](https://github.com/valkyoth/brynja/blob/main/docs/evidence-index.md)
- [Assurance harness policy](https://github.com/valkyoth/brynja/blob/main/assurance/README.md)
- [Kani verifier policy](https://github.com/valkyoth/brynja/blob/main/docs/KANI.md)
