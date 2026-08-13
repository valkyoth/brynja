<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
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
    <img src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
  </a>
</p>

# brynja

Brynja is a security-first, first-party Rust, `no_std` cryptography and
secure-protocol ecosystem. Its first production goal remains a serious
production-ready TLS implementation at `1.0.0`; its primitive boundaries are
being designed so later standalone cryptographic families can reuse the exact
same reviewed implementations. The core cryptographic and protocol graph uses
only Brynja-owned Rust code; explicitly isolated companion adapters follow
their separately documented dependency policy.

> **Development status:** Brynja is pre-1.0, incomplete, and not ready to
> secure application traffic. Every version receives an immutable signed tag
> only after the complete automated gate and green GitHub and CodeQL. Scheduled
> pentesting and crates.io publication occur at the cumulative checkpoints
> described below; a tag without a matching committed pentest report was not a
> scheduled pentest checkpoint.

## Project Direction

The roadmap through `1.0.0` remains TLS-first. Standalone hashing does not
expand or delay the v1 TLS claim. SHA-2, SHA-3, SHAKE, and HMAC are already
required by TLS, PKI, and ML-KEM, so their planned implementation ownership now
lives in small reusable family crates instead of private copies inside a
protocol crate.

| Boundary | Responsibility |
| --- | --- |
| `brynja-hash-core` | Small fixed-output and XOF interfaces; no algorithm or protocol |
| `brynja-hash-sha2` / `brynja-hash-sha3` | Portable family implementations reused by standalone callers and Brynja protocols |
| `brynja-mac-hmac` | Keyed HMAC construction with MAC-specific types and verification |
| `brynja-crypto` | Provider contracts, algorithm policy and composition, AEADs, KDFs, RSA, ECC, and integration of exact primitive-family implementations |
| `brynja` | TLS-first facade; a future hash convenience surface remains default-off and curated |

`brynja-crypto` therefore remains essential. It is the protocol-facing
cryptographic substrate above the small leaf-family crates; those crates never
depend on TLS or pull the complete crypto graph. This direction prevents both
duplicate SHA implementations and a standalone hash user acquiring every
Brynja algorithm.

After `1.0.0`, Brynja may expand into separately selectable modern, legacy,
utility, and research hashing families. Checksums and MACs remain distinct from
cryptographic hashes, legacy algorithms remain visibly isolated, and the main
facade will never gain an `all-hashes` feature. The versionless
[post-1.0 hashing plan](https://github.com/valkyoth/brynja/blob/main/docs/POST_1_0_HASH_PLAN.md)
contains the full candidate inventory, missing families, crate graph,
implementation order, and security gates. It is planning only: no listed
algorithm is implemented, admitted, independently verified, or FIPS validated
by appearing there.

The current `0.16.0` development milestone adds an affine pending-operation
lifecycle to `brynja-core`. Exact certificate-path, external-signature, and
accelerator-eligible requests require the same provider's poll, cancellation,
and applicable destruction duties. Checked caller limits bound every effect
attempt and backpressure response. The effect must prove its exact opaque
provider identity before begin and every later transition. Provider-derived,
effect-free nonzero costs are charged before the lifecycle issues a
non-forgeable work permit. Inert local state is prepared first and placed under
lifecycle ownership; provider identity is checked again after preparation and
immediately before activation may create any external resource.
Activation, resume, and cancellation only borrow lifecycle-owned state, so an
unwind leaves even partially initialized state available for mandatory `Drop`
cleanup.
Completion or cancellation becomes authoritative only after a non-cloneable
token is consumed to assert external-key,
accelerator, cache, DMA, and other declared cleanup. Provider failure,
exhaustion, and `Drop` use the same cleanup path. No provider effect,
certificate validation, signature, accelerator implementation, protocol
engine, cryptographic result, or FIPS evidence is implemented.

Version `0.15.0` added non-interchangeable typed wall and monotonic clocks
to `brynja-core`. Signed Unix wall values support checked arithmetic and
inclusive validity ranges for later PKI policy. Opaque monotonic instants bind
an explicit runtime/boot generation, redact raw ticks, reject cross-generation
arithmetic, and permanently fail their source wrapper after rollback.

Version `0.14.0` implemented the upstream entropy and initialized secure-random
contract in `brynja-core`. Caller-provided raw
entropy is affine, exact-purpose, exact-strength, exact-length secret input;
it is not an OS entropy source, a DRBG, or a validation claim. Initialized
secure-random state is non-cloneable, requires an exact runtime generation,
forces reseed after fork or its configured request interval, writes only into
transactional caller-owned secret memory, and permanently quarantines engine
underfill, rollback, or terminal failure. The wrapper supplies no algorithm,
platform RNG, FFI, FIPS status, or automatic fallback.

Intentionally non-production deterministic clock sources and a
non-cryptographic deterministic and fault-injecting random engine
lives only in permanently unpublished `brynja-test-support`. Machine policy
rejects making those fixtures publishable, moving them into a production graph,
adding OS randomness, OS clocks, or foreign code to the reviewed boundaries,
exposing monotonic ticks, weakening rollback latching, granting secret states
cloning or formatting, or changing reviewed source files without reopening
review.

Version `0.13.2` reserved `brynja-crypto-cpu` as a
zero-dependency `no_std` package and `brynja-crypto-cpu-std` as its separately
selected future host detector. Both remain independent of the main facade,
defaults, and protocol engines. Eight x86_64, AArch64, and RISC-V backend
module identities now carry
exact reserved paths, instruction and ABI preconditions, safe-wrapper
invariants, and a fail-closed amendment checklist. Both packages are inert:
there is no detector, intrinsic, assembly, executable backend, new low-level-
code allowance, performance claim, or FIPS validation.

Version `0.13.1` added a version-neutral CPU-backend
contract to `brynja-core`. Sealed scalar, x86, AArch64, RISC-V, and
validated-module identities bind exact feature and provider-operation profiles.
Opaque backend-instance identity binds a measured artifact and operational
environment, and KAT evidence borrows the exact session and instance rather
than matching reusable profile values. Caller-owned health state separates
detection evidence, direct startup KATs, per-operation dispatch authority,
permanent quarantine, runtime generations, and secret-free reporting.
Accelerated entry additionally requires an opaque platform-issued CPU lease and
a sealed context that acquires a migration-excluding guard while revalidating
logical CPU or hart identity, migration generation, the complete usable feature
predicate, and required OS or architectural state. Logical authority is checked
again after every platform callback, then a sealed kernel executes directly
while the guard remains live; application closures cannot enter this boundary.
Opportunistic policy reports scalar fallback; required-accelerated and
validated-module policies fail closed. This milestone adds no CPU detection,
public lease, context, guard, kernel, or instance constructor, intrinsic,
assembly, executable accelerated kernel implementation, unsafe backend
boundary, provider effect, performance claim, or FIPS validation.

Version `0.13.0` added provider capability and opaque-handle contracts to
`brynja-core`. Nineteen exact operations remain direction-specific,
including separate MAC generation and verification. Capabilities, caller
resource/work limits, and mandatory secret-destruction duties freeze through
transactional installation. Protocol code explicitly chooses one opaque
borrowed provider handle, receives authorization for one declared operation,
and prepares immutable version-neutral request metadata that retains that exact
provider identity. Unsupported operations fail without registry search or
fallback. Request holders cannot manufacture success or failure receipts, and
work can only be charged against the installed provider's monotonic meter. No
provider effect, algorithm, entropy source, clock, certificate-chain engine,
or storage backend is implemented by that authority layer.

Version `0.12.0` implemented Brynja's first constant-time foundation in
`brynja-core`: normalized one-byte `Choice` and `CtMask` values,
constant-time equality, conditional selection and swap for unsigned words and
compile-time-sized byte arrays, and an explicit compiler barrier. The source
policy, exhaustive byte tests, compile-fail API tests, and optimized LLVM and
assembly witnesses cover every supported Rust release and promised target.
This is implementation evidence, not a mathematical proof, timing measurement,
independent cryptographic review, or guarantee for an arbitrary downstream
composition. Version `0.11.2` implemented the
separately selected, protocol-neutral
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

The exceptional v0.11.2 repository-owner assessment of the production adapter
passed with no findings and zero open findings. Its permanent
[v0.11.2 report](https://github.com/valkyoth/brynja/blob/main/security/pentest/v0.11.2.md)
records the assessed implementation commit, scope, exact release evidence, and
residual risks. The v0.11.2 tag published no crate; the adapter was later
included in the completed v0.10.0-through-v0.15.0 cumulative assessment and
published at the v0.15.0 checkpoint.

The initial v0.12.0 pentest found a High RV32 timing flaw: LLVM selection was
lowered into branches controlled by `Choice`, while the assembly gate inspected
symbols but not function bodies. The source now barriers each expanded mask
before XOR/AND selection, and the gate rejects target-specific conditional
branches and direct RV32 secret-address operands in every concrete root.
Permanent negative fixtures cover RV32, x86_64, and AArch64 regressions. Local
remediation is green. Retest then found that a synthetic backward fixed-array
branch directly on the RV32 `Choice` register could bypass the loop classifier;
the validator and a sixth fixture closed that assurance gap. A second retest
found numeric register aliases plus omitted pseudo/compressed RISC-V branches;
the gate now canonicalizes argument registers, recognizes all eighteen
conditional forms, and retains ten focused negative fixtures. The exact signed
third candidate, `7ce43fffdf81a349c7c44aae33b229d077d4512d`, passed the
repository-owner retest with zero open findings. The permanent report records
PASS/PASS; signed tag v0.12.0 contains the remediated implementation and no
crates.io publication.

## Development Tags And Pentesting

The `brynja` facade version advances at every roadmap milestone, including
patch milestones, and each completed milestone receives the ordinary signed
`vX.Y.Z` tag after its signed commit passes the complete local gate and GitHub
and CodeQL are green. Development tags between public checkpoints are not
published to crates.io. Supporting crates keep independent versions and are
published only when their cumulative changes require it at a checkpoint.

Pentests look backwards over the complete change range between public
checkpoints. The v0.15.0 assessment covered all changes after signed public tag
v0.10.0 through v0.15.0. The v0.20.0 assessment covers all changes after
v0.15.0 through v0.20.0, including the current v0.16.0 milestone, and the same
pattern continues every fifth minor version. Each checkpoint report records
its previous public tag as `Baseline`
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
crates.io checkpoint and signed tag are `0.15.0`. The current `0.16.0`
pending-operation milestone selects no crates.io publication and awaits its
repository-owner security retest, complete local and hosted gates, and explicit
signed-tag authorization.
The published dependency is:

```toml
[dependencies]
brynja = "0.15"
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
- Portable scalar primitives belong to the smallest reusable semantic family:
  SHA-2 in `brynja-hash-sha2`, SHA-3/SHAKE in `brynja-hash-sha3`, and HMAC in
  `brynja-mac-hmac`. `brynja-crypto` consumes those exact symbols and retains
  provider, composition, policy, AEAD, KDF, RSA, ECC, and other unsplit
  cryptographic responsibilities; it never reimplements a family privately.
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
- The v0.12 constant-time API is intentionally limited to unsigned fixed-width
  words and compile-time-sized byte arrays. It has one explicitly named public
  declassification operation; dynamic slices, secret-dependent lengths,
  protocol-level timing claims, and platform microarchitectural guarantees are
  outside this foundation.
- The v0.13 provider boundary freezes capabilities, limits, destruction duties,
  opaque handles, and request metadata only. It has no provider registry or
  fallback, mutable effect buffer, algorithm/key identifier, platform effect,
  request-side completion or FIPS approval claim. Pending lifecycle is owned
  separately by the v0.16 upstream contract, still without an effect. MAC
  generation and verification are distinct, verification cannot request byte
  output, requests retain exact provider identity, and actual work must be
  charged by a later trusted effect boundary.
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
| `brynja-core` | Constant-time operations plus provider, CPU-backend, entropy, secure-random, clock, and pending-operation state contracts | ❌ Not verified |
| Future `brynja-hash-*` / `brynja-mac-*` | Reusable hashes, XOFs, and MACs | ❌ Not implemented or verified |
| `brynja-crypto` | Provider contracts, cryptographic composition, AEADs, KDFs, RSA, and ECC | ❌ Not verified |
| `brynja-crypto-cpu` | Future first-party ISA-specific cryptographic kernels and static selection | ❌ Not implemented or verified |
| `brynja-crypto-cpu-std` | Future host CPU detection and dispatch initialization | ❌ Not implemented or verified |
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
lifetime, owned-region zeroization, fixed-width constant-time, and provider
capability/authorization, entropy/secure-random, typed-clock, and pending-
operation foundations
described for `brynja-core` plus the
separately selected sanitization adapter are implemented. No
cryptographic primitive, PKI processor, protocol parser, or protocol engine in
this table is implemented.
Independent-review status cannot be inferred from implementation, testing,
formal proof, pentest, or release status.

## Workspace

| Package | Role | Current status |
| --- | --- | --- |
| `brynja` | Modern production facade | Exposes cumulative v0.15 foundation domains; no TLS engine or provider implementation |
| `brynja-core` | Bounded wire, buffer, error, state, provider, entropy, and time domains | Prior domains plus affine zeroization, fixed-width constant-time operations, provider capabilities, entropy/secure-random state, and typed wall/monotonic clock contracts implemented |
| Future `brynja-hash-core` | Fixed-output and XOF interfaces without algorithms | Planned at v0.22.0 |
| Future `brynja-hash-sha2` / `brynja-hash-sha3` | Reusable SHA-2, SHA-3, and SHAKE family ownership | Planned across v0.22.0-v0.24.0 |
| Future `brynja-mac-hmac` | Reusable HMAC construction over admitted hash interfaces | Planned at v0.25.0 |
| `brynja-crypto` | Provider contracts, cryptographic composition, policy, AEADs, KDFs, RSA, ECC, and exact family integration | Foundation only |
| `brynja-crypto-cpu` | Optional zero-dependency no_std ISA-kernel boundary | v0.1.0 reserved; zero admitted backends |
| `brynja-crypto-cpu-std` | Directly selected future host detector adapter | v0.1.0 inert no_std placeholder; absent from facade and FIPS graphs |
| `brynja-pki` | ASN.1, DER, X.509, path validation, and revocation | Foundation only |
| `brynja-tls` | Evergreen modern TLS facade and one-pass version router | Foundation only |
| `brynja-tls13` | Version-specific TLS 1.3 stream engine | Foundation only |
| `brynja-tls13-handshake` | Record-independent TLS 1.3 handshake shared with QUIC | Foundation only |
| `brynja-tls12` | Version-specific explicitly hardened TLS 1.2 engine | Foundation only |
| `brynja-quic-tls` | QUIC/TLS handshake integration | Foundation only |
| `brynja-dtls` | Modern DTLS engines | Foundation only |
| `brynja-platform` | Explicit entropy, time, storage, and I/O integration | Foundation only |
| `brynja-sanitization` | Optional protocol-neutral first-party sanitization adapter | v0.1.0 published over exact `sanitization 2.0.3`; absent from facade and FIPS graphs |
| `brynja-legacy` | Opt-in legacy facade; no default features | Boundary only |
| `brynja-legacy-*` engines | TLS 1.1/1.0, SSL, WTLS, PCT, and SNP isolation | Boundary only |
| `brynja-test-support` | RFC 9850 key-log encoder plus deterministic random and clock fixtures | Implemented, unpublished, production-unreachable; never a randomness or production time source |
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
to Rust `1.97.1`, the current stable patch release checked on 2026-08-11.
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

The v0.12 constant-time emitted-code witness additionally runs on every listed
stable compiler for the x86_64 Linux host and on all nine promised targets with
Rust 1.97.1. This matrix is compiler evidence for the bounded witness, not a
timing or independent-verification claim.

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
python3 scripts/check-constant-time.py
python3 scripts/test-constant-time.py
scripts/check-constant-time-codegen.sh 1.97.1 x86_64-unknown-linux-gnu
python3 scripts/test-constant-time-codegen.py
python3 scripts/check-constant-time-evidence.py
python3 scripts/test-constant-time-evidence.py
python3 scripts/check-provider-contract.py
python3 scripts/test-provider-contract.py
python3 scripts/check-entropy-contract.py
python3 scripts/test-entropy-contract.py
python3 scripts/check-clock-contract.py
python3 scripts/test-clock-contract.py
python3 scripts/check-pending-contract.py
python3 scripts/test-pending-contract.py
python3 scripts/check-backend-contract.py
python3 scripts/test-backend-contract.py
python3 scripts/check-cpu-evidence.py
python3 scripts/test-cpu-evidence.py
scripts/check-cpu-admission-fixture.sh
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
scripts/tag_gate.sh v0.16.0
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
