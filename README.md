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
secure-protocol ecosystem. Its first production goal is a serious
production-ready TLS and RFC 9580 OpenPGP implementation at `1.0.0`; its
primitive boundaries are designed so both protocol families and later
standalone cryptographic families reuse the exact same reviewed
implementations. Cryptography remains Brynja-owned Rust. Narrow encoding and
companion-adapter exceptions follow explicit admission and isolation policy.

> **Development status:** Brynja is pre-1.0, incomplete, and not ready to
> secure application traffic. Every version receives an immutable signed tag
> only after the required automated checks and green GitHub and CodeQL. Scheduled
> pentesting and crates.io publication occur at the cumulative checkpoints
> described below; a tag without a matching committed pentest report was not a
> scheduled pentest checkpoint.

## Cryptography Verification Status

These tables track concrete public capabilities and the named implementation
families in Brynja's active pre-1.0 roadmap. A capability is listed as
implemented only after its complete public API and required acceptance evidence
for that named milestone pass; a planned row is not yet usable.
The broader crate-level audit inventory remains available in the
[component verification status](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md).

✅ Implemented means a named capability is ready; ✅ Fully implemented means
every named member of that exact family is ready. Both require documented,
consumer-usable public APIs and the repository's required evidence. A green
implementation status does not mean independently verified. Independent status moves from ❌ to ✅ only
when a named independent reviewer signs off and linked evidence identifies the
reviewed implementation. The project's own tests, CI, Kani, Miri, sanitizers,
fuzzing, differential testing, and pentests do not by themselves constitute
independent cryptographic or protocol verification.

### Modern Hash Functions

Acceleration is separate from portable algorithm completion. Default hash APIs
remain portable. [Ordinary SHA-2 execution](docs/sha2-ordinary-execution.md)
adds default-off complete hash APIs over static and platform-limited hosted
authority. Separate [hardened SHA-2 execution](docs/sha2-hardened-execution.md)
adds erasing owners and typed secret outputs. [Ordinary SHA-3/SHAKE execution](docs/sha3-ordinary-execution.md)
connects explicit CPU routes to complete public-data hashing and XOF APIs;
its owner retest and [native functional collection](assurance/sha3-execution-observations/v0.24.35/README.md) passed. Further family integration remains planned.
The [cSHAKE and hosted sponge candidate](docs/cshake-ordinary-execution.md) extends
this opt-in public-data surface; its exceptional retest passed and native collection is pending.
See the [acceleration guide](docs/static-cpu-execution.md) for supported routes and
deployment requirements. Independent review and FIPS status are separate claims.

SHA-2 covers SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256;
SHA-3/SHAKE covers SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256.

| Hash family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| SHA-2 | ✅ Fully implemented | `brynja-hash-sha2` | ❌ Not independently verified |
| General SHA-512/t extension (portable) | ✅ Fully implemented | `brynja-hash-sha2` (opt-in) | ❌ Not independently verified |
| SHA-3/SHAKE | ✅ Fully implemented | `brynja-hash-sha3` | ❌ Not independently verified |
| TupleHash/TupleHashXOF | ✅ Fully implemented | `brynja-hash-tuple` | ❌ Not independently verified |
| ParallelHash/ParallelHashXOF | ✅ Fully implemented | `brynja-hash-parallel` | ❌ Not independently verified |
| SP 800-185 family | ✅ Fully implemented | `brynja-hash-sha3`, `brynja-mac-kmac`, `brynja-hash-tuple`, `brynja-hash-parallel` | ❌ Not independently verified |

### Modern Message Authentication

The complete KMAC/KMACXOF family here comprises KMAC128, KMAC256,
KMACXOF128, and KMACXOF256.

| Construction family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| KMAC/KMACXOF | ✅ Fully implemented | `brynja-mac-kmac` | ❌ Not independently verified |

### Legacy Hash Functions

Legacy hashes remain outside the modern `brynja` facade and require an explicit
legacy crate dependency even after implementation.

| Hash family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| SHA-1 | ✅ Fully implemented | `brynja-legacy-sha1` | ❌ Not independently verified |
| MD5 | ✅ Fully implemented | `brynja-legacy-md5` | ❌ Not independently verified |

### Protocol And PKI Building Blocks

| Capability | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| TLS and DTLS record-envelope parsing and encoding | ✅ Implemented | `brynja-protocol` | ❌ Not independently verified |
| Bounded DER framing and admitted canonical ASN.1 values | ✅ Implemented | `brynja-pki` | ❌ Not independently verified |

### Security Foundations

| Capability | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| Fixed-width constant-time operations and secret-region lifecycle | ✅ Implemented | `brynja-core` | ❌ Not independently verified |
| Fixed-size secret ownership and explicit sanitization adapter | ✅ Implemented | `brynja-core`, `brynja-sanitization` | ❌ Not independently verified |

### Official Validation

FIPS validation is a separate official claim from implementation and
independent source review.
Brynja has no FIPS 140-3 validation, certificate, validated module, approved
security policy, or certificate-bound operational-environment claim.

| Validation scope | Implementation status | Owning crate | Official validation |
| --- | --- | --- | --- |
| FIPS 140-3 cryptographic module | ❌ Not implemented | Future `brynja-fips-module`, `brynja-fips` | ❌ Not FIPS validated |

## Project Direction

Brynja is building reusable cryptographic primitives, constructions and secure
protocols in small, separately selectable Rust crates. Modern APIs are the
default; obsolete algorithms and protocols belong to explicit `brynja-legacy-*`
packages. Research and utility algorithms have separate classifications and
must not inherit security claims from cryptographic hashes.

The [release plan](docs/RELEASE_PLAN.md) and [version plan](docs/VERSION_PLAN.md)
cover the complete pre-1.0 scope: modern and legacy hashes, MACs, KDFs, ciphers,
signatures, PKI, TLS/DTLS, QUIC-TLS, OpenPGP and additional protocol families.
Planned scope is not implemented functionality. The tables above show current
usable capabilities; [current status](docs/current-status.md) and
[release notes](release-notes/) track individual milestones.

Each algorithm has one implementation owner. Small family crates can be used
without importing the full protocol graph. `brynja-crypto` remains the
composition and policy layer above those primitives; it does not duplicate
them. The modern facade does not expose an indiscriminate `all-hashes` feature.

## Usage And Availability

The repository can contain capabilities not yet published on crates.io.
Check the [crate version matrix](docs/CRATE_VERSION_MATRIX.md) before choosing a
registry version. The [facade README](crates/brynja/README.md) and each leaf
crate's README provide usage examples and exact feature requirements.

- [SHA-2](crates/brynja-hash-sha2/README.md): named hashes and opt-in general SHA-512/t.
- [SHA-3, SHAKE and cSHAKE](crates/brynja-hash-sha3/README.md): fixed and extendable output.
- [KMAC](crates/brynja-mac-kmac/README.md), [TupleHash](crates/brynja-hash-tuple/README.md),
  [ParallelHash](crates/brynja-hash-parallel/README.md): SP 800-185 constructions.
- [Legacy SHA-1](crates/brynja-legacy-sha1/README.md) and
  [legacy MD5](crates/brynja-legacy-md5/README.md): isolated compatibility only.

Ordinary hash states are intended for public/unkeyed data and do not promise
internal erasure. Use the distinct hardened APIs for secret-bearing input;
Brynja clears its owned internal state, while caller-owned inputs and copied
outputs remain the caller's responsibility. Registers, compiler-created copies,
spills, caches, swap, dumps, aborts and forced termination remain documented
limitations—not guarantees that portable Rust can provide.

Record framing and bounded DER/ASN.1 values are building blocks, not complete
TLS engines or X.509 validation. Brynja must not yet secure network traffic.

## Design Boundaries

- **Golden rule:** cryptographic primitives, constructions, CPU backends and
  future FIPS module services are first-party Rust. No C/C++ crypto wrappers,
  OpenSSL, AWS-LC or system cryptographic delegation.
- Production leaves are `no_std`, with explicit platform interfaces and
  default-off acceleration. Optional `-std` adapters stay outside default and
  bare-metal graphs. Cargo features alone never prove CPU support.
- Modern, legacy and research packages remain isolated. Legacy algorithms do
  not become safe merely because their implementation is complete.
- No unreviewed third-party dependency enters the core. The optional
  `brynja-sanitization` adapter uses exact-pinned `sanitization 2.1.0`,
  with default features disabled. Planned `base64-ng` admission is
  encoding-only; future rustls/Tokio adapters remain separately selected.
- Source files stay below 500 lines. Hostile inputs, work limits, output
  failure behavior and secret lifetimes require explicit tests.
- FIPS-aware design is not FIPS validation. Any future validation claim must
  name the exact certified module and supported operational environment.

See the [threat model](docs/threat-model.md),
[cryptography golden rule](docs/first-party-rust-cryptography.md),
[unsafe policy](docs/unsafe-policy.md) and [standards policy](docs/rfc-source-policy.md).

## Development Tags And Pentesting

Every development version receives a signed, immutable tag only after its
required local checks, green GitHub/CodeQL and explicit owner approval.
Crates.io publication and scheduled pentests occur every fifth minor series
at its registered final patch—not at each intermediate tag.

Checkpoint pentests look backwards over the complete delta since the previous
public checkpoint, including every intermediate patch and remediation.
For example, the next checkpoint covers all changes after `0.20.0` through
`0.25.2`; the following covers changes after that checkpoint through the
registered end of the `0.30.x` series. Exceptional pentests remain mandatory
for material security-boundary changes and serious findings.

Findings, fixes, retests and residual limitations are recorded in
[versioned pentest reports](security/pentest/). These project assessments do
not replace named independent cryptographic review or official FIPS validation.
Detailed release-by-release history belongs in those reports and
[release notes](release-notes/).

## Workspace

| Package group | Responsibility |
| --- | --- |
| `brynja` | Curated modern facade |
| `brynja-core`, `brynja-hash-core` | Bounded ownership, constant-time and hash interfaces |
| `brynja-hash-*`, `brynja-mac-*` | Reusable algorithm and construction families |
| `brynja-crypto` | Cryptographic composition, provider contracts and policy |
| `brynja-crypto-cpu`, optional `-std` adapters | Explicit CPU/SIMD execution boundaries |
| `brynja-protocol`, `brynja-pki` | Record framing and ASN.1/DER building blocks |
| `brynja-tls*`, `brynja-dtls`, `brynja-quic-tls` | Protocol engine boundaries; complete engines remain planned |
| `brynja-legacy-*` | Explicit obsolete-algorithm and protocol compatibility |
| `brynja-sanitization` | Separately selected first-party clearing adapter |
| Future OpenPGP, FIPS and platform-security packages | Separately scoped protocol, validation and deployment work |

The [crate version matrix](docs/CRATE_VERSION_MATRIX.md) lists exact packages,
versions and publication status. Each crate has its own README.

## Platform Policy

The project targets Linux, Windows, BSD, macOS, Android, iOS and bare-metal
`no_std`. Aesynx remains a future integration target. Portable compilation,
native execution and ISA qualification are separate evidence levels.
RISC-V instruction results based on QEMU are not native hardware qualification.

## Rust Version Support

MSRV is Rust `1.90.0`; the default full-check compiler is Rust `1.98.1`.
Release preflight checks tool freshness. Kani uses its separately pinned
`cargo-kani 0.67.0` / Rust `1.90.0` pairing; it does not lower the production
compiler or make a policy check a proof. See [Kani evidence](docs/KANI.md).

| Rust toolchain | Required evidence |
| --- | --- |
| `1.90.0`–`1.98.0` | Workspace all-feature compatibility check |
| `1.98.1` | Full format, lint, test, platform, policy, docs, package, and security gate |

The exact tested compiler versions, including selected patch releases, remain
listed in [the Rust matrix](scripts/ci/check-rust-version-matrix.sh).
Compiler evidence does not imply timing safety or independent verification.

## Checks

```sh
scripts/checks.sh
scripts/ci/check-rust-version-matrix.sh
scripts/release/release_crates.py --check
```

The [scripts guide](scripts/README.md) groups assurance by component.
[Focused assurance](docs/focused-assurance.md) runs full Miri campaigns for
affected groups and smoke tests for unchanged groups; public checkpoints and
unknown impacts require full coverage. Long Miri, sanitizer and Kani evidence
runs locally. GitHub retains bounded checks and CodeQL Default.

## License

MIT OR Apache-2.0.

## Documentation

- [Initial idea and final architecture decision](https://github.com/valkyoth/brynja/blob/main/docs/initial-idea.md)
- [Implementation plan](https://github.com/valkyoth/brynja/blob/main/docs/IMPLEMENTATION_PLAN.md)
- [Release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md)
- [Version plan](https://github.com/valkyoth/brynja/blob/main/docs/VERSION_PLAN.md)
- [Threat model](https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md)
- [First-party Rust cryptography golden rule](https://github.com/valkyoth/brynja/blob/main/docs/first-party-rust-cryptography.md)
- [Component verification status](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md)
- [Standards source policy](https://github.com/valkyoth/brynja/blob/main/docs/rfc-source-policy.md)
- [Machine-readable standards evidence](https://github.com/valkyoth/brynja/blob/main/standards/README.md)
- [Normative requirement evidence](https://github.com/valkyoth/brynja/blob/main/requirements/README.md)
- [Permanent evidence index](https://github.com/valkyoth/brynja/blob/main/docs/evidence-index.md)
- [Assurance harness policy](https://github.com/valkyoth/brynja/blob/main/assurance/README.md)
- [Kani verifier policy](https://github.com/valkyoth/brynja/blob/main/docs/KANI.md)
