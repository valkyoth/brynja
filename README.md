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
    <img width="840" src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
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

**Verification workflow from v0.25.3:** implement a component, complete its
agreed scoped checks, record the evidence, and close it. Unrelated development
does not reopen completed components. The local
[brynja-verify tracker](docs/assurance/brynja-verify.md) reports actual executions
and input freshness separately; it is not a release gate or certification.
Releases follow clean pentest/retest → finite final checks → green GitHub →
publication of that same candidate, without restarting verification at upload.
See the [completion rule](docs/assurance/component-completion.md) and
[release handoff and transition status](docs/release/scoped-release.md).

These tables track concrete public capabilities and the named implementation
families in Brynja's active pre-1.0 roadmap. A capability is listed as
implemented after its complete public API and functional acceptance checks
pass; a planned row is not yet usable. Release qualification and platform-specific
assurance are separate from implementation completion.
The broader crate-level audit inventory remains available in the
[component verification status](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md).

✅ Implemented means a named capability is implemented and acceptance-tested;
✅ Fully implemented means every named member of that exact family has a
documented, consumer-usable public API and passing functional acceptance. A green
implementation status does not mean independently verified. Independent status moves from ❌ to ✅ only
when a named independent reviewer signs off and linked evidence identifies the
reviewed implementation. The project's own tests, CI, Kani, Miri, sanitizers,
fuzzing, differential testing, and pentests do not by themselves constitute
independent cryptographic or protocol verification.

Implementation completion does not authorize publication or imply platform qualification.

### Modern Hash Functions

Acceleration is separate from portable algorithm completion. Default hash APIs
remain portable. [Ordinary SHA-2 execution](docs/sha2-ordinary-execution.md)
adds default-off complete hash APIs over static and platform-limited hosted
authority. Separate [hardened SHA-2 execution](docs/sha2-hardened-execution.md)
adds erasing owners and typed secret outputs. [Ordinary SHA-3/SHAKE execution](docs/sha3-ordinary-execution.md)
connects explicit CPU routes to complete public-data hashing and XOF APIs;
its owner retest and [native functional collection](assurance/sha3-execution-observations/v0.24.35/README.md) passed. Further family integration remains planned.
The [cSHAKE and hosted sponge candidate](docs/cshake-ordinary-execution.md) extends
this opt-in public-data surface; its exceptional retest, [native collection](assurance/cshake-execution-observations/v0.24.36/README.md) and full local release verification passed, followed by green GitHub/CodeQL and a signed tag.
Separate [hardened Keccak execution](docs/hardened-keccak-execution.md) provides
opt-in erasing SHA-3/SHAKE/cSHAKE owners and typed secret outputs. Its owner retest,
three-platform native functional evidence and required local release checks passed.
These observations do not establish register/spill erasure or universal platform safety.
See the [acceleration guide](docs/static-cpu-execution.md) for supported routes and
deployment requirements. Independent review and FIPS status are separate claims.

SHA-2 covers SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256;
SHA-3/SHAKE covers SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256.

| Hash family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| SHA-2 | ✅ Fully implemented | `brynja-hash-sha2` | ❌ Not independently verified |
| General SHA-512/t extension (portable) | ✅ Fully implemented | `brynja-hash-sha2` (opt-in) | ❌ Not independently verified |
| SHA-3/SHAKE | ✅ Fully implemented | `brynja-hash-sha3` | ❌ Not independently verified |
| cSHAKE128 and cSHAKE256 | ✅ Implemented | `brynja-hash-sha3` | ❌ Not independently verified |
| TupleHash/TupleHashXOF | ✅ Fully implemented | `brynja-hash-tuple` | ❌ Not independently verified |
| ParallelHash/ParallelHashXOF | ✅ Fully implemented | `brynja-hash-parallel` | ❌ Not independently verified |
| SP 800-185 family | ✅ Fully implemented | `brynja-hash-sha3`, `brynja-mac-kmac`, `brynja-hash-tuple`, `brynja-hash-parallel` | ❌ Not independently verified |

### Modern Message Authentication

The complete KMAC/KMACXOF family here comprises KMAC128, KMAC256,
KMACXOF128, and KMACXOF256.

| Construction family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| KMAC/KMACXOF | ✅ Fully implemented | `brynja-mac-kmac` | ❌ Not independently verified |
| HMAC over modern SHA-2/SHA-3 | ✅ Fully implemented | `brynja-mac-hmac` | ❌ Not independently verified |

HMAC completion covers the ten named SHA-2/SHA-3 identities, streaming and
one-shot use, long keys, canonical final-bit messages, protocol-selected byte
truncation, mismatch rejection and typed public/secret tags. General SHA-512/t
is separately constrained by the modern 128-bit minimum. Protected/resident
and accelerated APIs retain their documented target and qualification limits;
SIMD HMAC batching and Windows enclave HMAC are not implemented.
The [v0.25.2 record](security/pentest/v0.25.2.md#author-operated-checkpoint-completion-2026-10-31)
records the supplied remediation retest and completed project checkpoint;
green implementation rows do not authorize publication.

### Ciphers, Authenticated Encryption And Key Derivation

| Capability | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| Raw AES-128/192/256 single blocks | ✅ Implemented | `brynja-cipher-aes` | ❌ Not independently verified |
| AES external-key adapter contracts (no device driver) | ✅ Implemented | `brynja-cipher-aes` | ❌ Not independently verified |
| Raw IETF ChaCha20 (RFC 8439) | ✅ Implemented | `brynja-cipher-chacha` | ❌ Not independently verified |
| GHASH over pre-framed blocks (not a MAC) | ✅ Implemented | `brynja-universal-hash-ghash` | ❌ Not independently verified |
| Detached AES-GCM (AES-128/192/256) | ✅ Implemented | `brynja-aead-gcm` | ❌ Not independently verified |
| GMAC authentication (AES-128/192/256) | ✅ Implemented | `brynja-aead-gcm` | ❌ Not independently verified |
| HKDF over six SHA-2 identities, including TLS 1.3 label framing | ✅ Implemented | `brynja-crypto` | ❌ Not independently verified |

Use AES-GCM for authenticated encryption, GMAC for authentication without encryption, and raw AES, ChaCha20 or GHASH only inside a construction that specifies them. ChaCha20 here is a stream cipher, not ChaCha20-Poly1305 or XChaCha20. HKDF label framing is not a TLS key schedule.

### Legacy Hash Functions

Legacy hashes remain outside the modern `brynja` facade and require an explicit
legacy crate dependency even after implementation.

| Hash family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| SHA-1 | ✅ Fully implemented | `brynja-legacy-sha1` | ❌ Not independently verified |
| MD5 | ✅ Fully implemented | `brynja-legacy-md5` | ❌ Not independently verified |

### Legacy Message Authentication

Legacy HMAC is explicitly selected for compatibility, outside the modern facade.
The [v0.25.1 security retest](security/pentest/v0.25.1.md) and that tagged
release's required checks passed. Hosted owners cover GNU/Linux protected and
Apple Silicon resident sessions; the latter do not claim dump exclusion.
The [completed v0.25.2 checkpoint](security/pentest/v0.25.2.md#author-operated-checkpoint-completion-2026-10-31)
records project verification, not independent cryptographic certification or
authorization to publish.

| Construction family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| HMAC over legacy MD5/SHA-1 | ✅ Fully implemented | `brynja-legacy-hmac` | ❌ Not independently verified |
| Hosted legacy HMAC | ✅ Implemented | `brynja-legacy-hmac-std` | ❌ Not independently verified |
| Legacy HKDF-SHA-1 (explicit acknowledgement) | ✅ Implemented | `brynja-legacy-hkdf` | ❌ Not independently verified |

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

Start with the [official crate directory](#workspace) to choose between the
modern façade, a standalone leaf and a repository-only development package.

The repository can contain capabilities not yet published on crates.io.
Check the [crate version matrix](docs/CRATE_VERSION_MATRIX.md) before choosing a
registry version. The [facade README](crates/brynja/README.md) and each leaf
crate's README provide usage examples and exact feature requirements.

- [SHA-2](crates/brynja-hash-sha2/README.md): named hashes and opt-in general SHA-512/t.
- [SHA-3, SHAKE and cSHAKE](crates/brynja-hash-sha3/README.md): fixed and extendable output.
- [KMAC](crates/brynja-mac-kmac/README.md), [TupleHash](crates/brynja-hash-tuple/README.md),
  [ParallelHash](crates/brynja-hash-parallel/README.md): SP 800-185 constructions.
- [HMAC](crates/brynja-mac-hmac/README.md) authenticates messages. [Modern HKDF](docs/assurance/hkdf-public-api.md)
  derives keys; [legacy HKDF-SHA-1](crates/brynja-legacy-hkdf/README.md) is a separate compatibility crate.
- [AES](crates/brynja-cipher-aes/README.md) and [ChaCha20](crates/brynja-cipher-chacha/README.md):
  single-block and stream primitives, respectively. Neither authenticates messages.
- [AES-GCM and GMAC](crates/brynja-aead-gcm/README.md): choose the `aes-gcm` or `gmac` feature.
  [GHASH](crates/brynja-universal-hash-ghash/README.md) is their universal-hash building block, not a standalone tag.
- [Legacy SHA-1](crates/brynja-legacy-sha1/README.md) and
  [legacy MD5](crates/brynja-legacy-md5/README.md): isolated compatibility only.

Ordinary hash states are intended for public/unkeyed data and do not promise
internal erasure. Use the distinct hardened APIs for secret-bearing input;
Brynja clears its owned internal state, while caller-owned inputs and copied
outputs remain the caller's responsibility. Registers, compiler-created copies,
spills, caches, swap, dumps, aborts and forced termination remain documented
limitations—not guarantees that portable Rust can provide.

The separate [Windows enclave APIs](docs/windows-enclave-deployment.md) provide
development-tested x64 sessions for modern hashes, MACs and batching through
`brynja-strict`. They are not the Linux host-slice sessions. Hardware/SIMD routes
are opt-in; Windows ARM64, production-signed deployment and independent
qualification are not claimed. See the [conditional cleanup scope](docs/windows-enclave-whole-image-cleanup.md#bounded-cleanup-claim-and-evidence-map)
before choosing this profile; SDK/OS and whole-process erasure are not guaranteed.

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
  `brynja-sanitization` adapter uses exact-pinned `sanitization 2.2.0`,
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
required scoped pentest/retest and local checks, green GitHub/CodeQL and explicit
owner approval. Crates.io publication and cumulative checkpoint pentests occur
every fifth minor series at its registered final patch—not at each intermediate
tag. A scoped development pentest does not automatically reopen completed
component verification or launch a repository-wide campaign.

Checkpoint pentests look backwards over the complete delta since the previous
public checkpoint, including every intermediate patch and remediation.
For example, the next checkpoint covers all changes after `0.20.0` through
`0.25.3`; the following covers changes after that checkpoint through the
registered end of the `0.30.x` series. Exceptional pentests remain mandatory
for material security-boundary changes and serious findings.

Findings, fixes, retests and residual limitations are recorded in
[versioned pentest reports](security/pentest/). These project assessments do
not replace named independent cryptographic review or official FIPS validation.
Detailed release-by-release history belongs in those reports and
[release notes](release-notes/).

## Workspace

This is the **official Brynja crate directory**. The `brynja-` prefix alone does not establish project affiliation. Start at the [`brynja` façade on crates.io](https://crates.io/crates/brynja) for modern APIs. If you need a standalone primitive, hosted adapter or legacy implementation, follow its exact registry link below rather than guessing the name.

Each package name links to its source README with features, examples and limitations. A registry link means the package has been published, **not** that a planned engine works or that it is independently verified. GitHub describes the development branch; use the matching tag or versioned docs.rs page for an installed release. The [feature guide](docs/facade-features.md) lists the façade flags; the [crate version matrix](docs/CRATE_VERSION_MATRIX.md) explains how versions are assigned.

### Start here and shared foundations

| Workspace crate | Purpose | Registry |
| --- | --- | --- |
| [`brynja`](crates/brynja/README.md) | Modern façade | [crates.io](https://crates.io/crates/brynja) |
| [`brynja-core`](crates/brynja-core/README.md) | Bounded buffers, secrets and provider contracts | [crates.io](https://crates.io/crates/brynja-core) |
| [`brynja-crypto`](crates/brynja-crypto/README.md) | Modern algorithm composition and compatibility imports | [crates.io](https://crates.io/crates/brynja-crypto) |
| [`brynja-hash-core`](crates/brynja-hash-core/README.md) | Hash/XOF interfaces and canonical bit strings | [crates.io](https://crates.io/crates/brynja-hash-core) |
| [`brynja-protocol`](crates/brynja-protocol/README.md) | TLS/DTLS record-envelope framing | [crates.io](https://crates.io/crates/brynja-protocol) |
| [`brynja-pki`](crates/brynja-pki/README.md) | Borrowed ASN.1/DER building blocks | [crates.io](https://crates.io/crates/brynja-pki) |
| [`brynja-sanitization`](crates/brynja-sanitization/README.md) | Optional secret-storage adapter | [crates.io](https://crates.io/crates/brynja-sanitization) |

### Modern cryptography

| Workspace crate | Purpose | Registry |
| --- | --- | --- |
| [`brynja-hash-sha2`](crates/brynja-hash-sha2/README.md) | SHA-2 | [crates.io](https://crates.io/crates/brynja-hash-sha2) |
| [`brynja-hash-sha3`](crates/brynja-hash-sha3/README.md) | SHA-3, SHAKE and cSHAKE | [crates.io](https://crates.io/crates/brynja-hash-sha3) |
| [`brynja-hash-tuple`](crates/brynja-hash-tuple/README.md) | TupleHash and TupleHashXOF | [crates.io](https://crates.io/crates/brynja-hash-tuple) |
| [`brynja-hash-parallel`](crates/brynja-hash-parallel/README.md) | ParallelHash and ParallelHashXOF | [crates.io](https://crates.io/crates/brynja-hash-parallel) |
| [`brynja-mac-hmac`](crates/brynja-mac-hmac/README.md) | Modern HMAC | [crates.io](https://crates.io/crates/brynja-mac-hmac) |
| [`brynja-mac-kmac`](crates/brynja-mac-kmac/README.md) | KMAC and KMACXOF | [crates.io](https://crates.io/crates/brynja-mac-kmac) |
| [`brynja-cipher-aes`](crates/brynja-cipher-aes/README.md) | Raw AES block operations | [crates.io](https://crates.io/crates/brynja-cipher-aes) |
| [`brynja-cipher-chacha`](crates/brynja-cipher-chacha/README.md) | Raw IETF ChaCha20 | [crates.io](https://crates.io/crates/brynja-cipher-chacha) |
| [`brynja-universal-hash-ghash`](crates/brynja-universal-hash-ghash/README.md) | GHASH universal hashing | [crates.io](https://crates.io/crates/brynja-universal-hash-ghash) |
| [`brynja-aead-gcm`](crates/brynja-aead-gcm/README.md) | AES-GCM and GMAC | [crates.io](https://crates.io/crates/brynja-aead-gcm) |

### Execution and hosted adapters

| Workspace crate | Purpose | Registry |
| --- | --- | --- |
| [`brynja-crypto-cpu`](crates/brynja-crypto-cpu/README.md) | Low-level CPU kernels and authority | [crates.io](https://crates.io/crates/brynja-crypto-cpu) |
| [`brynja-crypto-cpu-std`](crates/brynja-crypto-cpu-std/README.md) | Hosted CPU observation and admission | [crates.io](https://crates.io/crates/brynja-crypto-cpu-std) |
| [`brynja-hash-parallel-std`](crates/brynja-hash-parallel-std/README.md) | Bounded OS-thread scheduling for ParallelHash | [crates.io](https://crates.io/crates/brynja-hash-parallel-std) |
| [`brynja-strict`](crates/brynja-strict/README.md) | Platform-specific protected sessions | [crates.io](https://crates.io/crates/brynja-strict) |

### Protocol and platform boundaries

| Workspace crate | Purpose | Registry |
| --- | --- | --- |
| [`brynja-tls`](crates/brynja-tls/README.md) | Modern TLS router boundary | [crates.io](https://crates.io/crates/brynja-tls) |
| [`brynja-tls12`](crates/brynja-tls12/README.md) | TLS 1.2 engine boundary | [crates.io](https://crates.io/crates/brynja-tls12) |
| [`brynja-tls13`](crates/brynja-tls13/README.md) | TLS 1.3 stream engine boundary | [crates.io](https://crates.io/crates/brynja-tls13) |
| [`brynja-tls13-handshake`](crates/brynja-tls13-handshake/README.md) | Record-independent TLS 1.3 handshake boundary | [crates.io](https://crates.io/crates/brynja-tls13-handshake) |
| [`brynja-dtls`](crates/brynja-dtls/README.md) | DTLS engine boundary | [crates.io](https://crates.io/crates/brynja-dtls) |
| [`brynja-quic-tls`](crates/brynja-quic-tls/README.md) | QUIC handshake boundary | [crates.io](https://crates.io/crates/brynja-quic-tls) |
| [`brynja-platform`](crates/brynja-platform/README.md) | Platform integration boundary | [crates.io](https://crates.io/crates/brynja-platform) |

### Legacy compatibility (never enabled by the modern façade)

| Workspace crate | Purpose | Registry |
| --- | --- | --- |
| [`brynja-legacy-hkdf`](crates/brynja-legacy-hkdf/README.md) | HKDF-SHA-1 | [crates.io](https://crates.io/crates/brynja-legacy-hkdf) |
| [`brynja-legacy-hmac`](crates/brynja-legacy-hmac/README.md) | HMAC-SHA-1 and HMAC-MD5 | [crates.io](https://crates.io/crates/brynja-legacy-hmac) |
| [`brynja-legacy-hmac-std`](crates/brynja-legacy-hmac-std/README.md) | Hosted legacy HMAC | [crates.io](https://crates.io/crates/brynja-legacy-hmac-std) |
| [`brynja-legacy-md5`](crates/brynja-legacy-md5/README.md) | MD5 | [crates.io](https://crates.io/crates/brynja-legacy-md5) |
| [`brynja-legacy-md5-std`](crates/brynja-legacy-md5-std/README.md) | Hosted legacy MD5 | [crates.io](https://crates.io/crates/brynja-legacy-md5-std) |
| [`brynja-legacy-sha1`](crates/brynja-legacy-sha1/README.md) | SHA-1 | [crates.io](https://crates.io/crates/brynja-legacy-sha1) |
| [`brynja-legacy-sha1-std`](crates/brynja-legacy-sha1-std/README.md) | Hosted legacy SHA-1 | [crates.io](https://crates.io/crates/brynja-legacy-sha1-std) |

### Unpublished workspace members

| Workspace crate | Purpose | Registry |
| --- | --- | --- |
| [`brynja-legacy`](crates/brynja-legacy/README.md) | Legacy protocol façade boundary | Unpublished |
| [`brynja-legacy-ssl2`](crates/brynja-legacy-ssl2/README.md) | SSL 2.0 compatibility boundary | Unpublished |
| [`brynja-legacy-ssl3`](crates/brynja-legacy-ssl3/README.md) | SSL 3.0 compatibility boundary | Unpublished |
| [`brynja-legacy-tls10`](crates/brynja-legacy-tls10/README.md) | TLS 1.0 compatibility boundary | Unpublished |
| [`brynja-legacy-tls11`](crates/brynja-legacy-tls11/README.md) | TLS 1.1 compatibility boundary | Unpublished |
| [`brynja-legacy-wtls`](crates/brynja-legacy-wtls/README.md) | WTLS compatibility boundary | Unpublished |
| [`brynja-legacy-snp`](crates/brynja-legacy-snp/README.md) | SNP compatibility boundary | Unpublished |
| [`brynja-legacy-pct`](crates/brynja-legacy-pct/README.md) | PCT compatibility boundary | Unpublished |
| [`brynja-research-ssl1`](crates/brynja-research-ssl1/README.md) | SSL 1.0 historical research | Unpublished |
| [`brynja-proofs`](crates/brynja-proofs/README.md) | Proof-harness boundary | Unpublished |
| [`brynja-interop`](crates/brynja-interop/README.md) | Interoperability-harness boundary | Unpublished |
| [`brynja-test-support`](crates/brynja-test-support/README.md) | Deterministic test fixtures | Unpublished |
| [`brynja-xtask`](crates/brynja-xtask/README.md) | Repository maintenance-tool boundary | Unpublished |

The [brynja-verify developer tool](tools/brynja-verify/README.md) lives outside the library workspace. Install it from the repository; it is not an application dependency. Assurance fixtures and archived research are not registry packages in this directory.

## Platform Policy

The project targets Linux, Windows, BSD, macOS, Android, iOS and bare-metal
`no_std`. Aesynx remains a future integration target. Portable compilation,
native execution and ISA qualification are separate evidence levels.
RISC-V instruction results based on QEMU are not native hardware qualification.

The [AES usage guide](docs/aes-usage.md) explains the current development
checkout's portable, static, hosted and external-key APIs, caller-owned storage, tested
examples and explicit qualification limits.

The v0.28.0 [portable GHASH development interface](docs/security-controls.md#portable-ghash-development-contract-v0280)
requires `hazmat-ghash`, accepts pre-framed blocks and returns a secret intermediate, not a GCM tag.
Since v0.28.2, `ghash-runtime-execution` adds an explicit
constructor for Linux/Windows x86_64 PCLMUL, Linux RV64 scalar Zbc, or little-endian
AArch64 PMULL on Linux and macOS. `Ghash::new` stays portable.
[Arm timing qualification remains open](docs/assurance/ghash-acceleration.md#arm-public-pmull-route). No GCM service
or validated cryptographic module is implied.
The [v0.28.1 downstream example and replay command](assurance/ghash-public-api/README.md)
exercise the portable interface from unpacked Cargo archives on Rust 1.90.0 and 1.100.0.
For runtime selection and the native versus emulated results, see the
[v0.28.3 public API acceptance fixture](assurance/ghash-runtime-consumer/README.md).

The checkout provides [portable AES-GCM](docs/assurance/aes-gcm-development.md)
and [portable GMAC](docs/assurance/gmac-development.md) at all three AES key
sizes. Enable `aes-gcm` or `gmac` on `brynja` or `brynja-crypto`; neither
public raw primitive feature is required. Use separate keys for GCM and
GMAC, and reserve sending nonce ranges in the application.

The [v0.29.3 internal milestone](release-notes/RELEASE_NOTES_0.29.3.md)
adds `aes-gcm-execution` and `gmac-execution`. Only the new owners under
`execution` require a complete pair: AES-NI/PCLMUL on Linux or Windows x86-64,
or AES/PMULL on Linux ARM64 or Apple Silicon. Enabling
either feature leaves ordinary constructors portable. This is not a
crates.io release or a general constant-time qualification.

The [v0.29.4 consumer fixture](assurance/aead-installed-consumer/README.md)
shows how to check the portable and paired APIs against known answers from
installed downstream binaries. These checks do not confer FIPS validation.

The [portable RFC 8439 stream](docs/assurance/chacha20-development.md) is
available from `brynja-cipher-chacha` or through `brynja_crypto::chacha20`.
Enable `hazmat-chacha20` on the chosen dependency. The development branch
also forwards that flag on `brynja`, at `brynja::crypto::chacha20`;
the published `brynja 0.30.6` façade does not. SIMD owners remain leaf-only.
It is not ChaCha20-Poly1305: raw ciphertext has no integrity protection.
The [installed consumer](assurance/chacha20-consumer/README.md) shows how to
test both portable imports and the explicit SSE2 and NEON owners.

For authenticated encryption, use `brynja_aead_gcm::aes_gcm` with the `aes-gcm` feature. For AAD-only authentication, enable `gmac` and use `brynja_aead_gcm::gmac`. Both [standalone APIs](crates/brynja-aead-gcm/README.md) retain their existing compatibility imports.

For framed GHASH blocks, enable `hazmat-ghash` in the [standalone GHASH crate](crates/brynja-universal-hash-ghash/README.md), or keep the existing `brynja_crypto::ghash` and `brynja::crypto::ghash` imports. The result is secret; it is not a MAC or a GCM tag.

For raw AES blocks the development tree provides `brynja-cipher-aes` with
the default-off `hazmat-aes-block` feature. The [standalone crate](crates/brynja-cipher-aes/README.md)
and the existing `brynja_crypto::aes` and `brynja::crypto::aes` imports
share the same AES-128/192/256 owners. This is not a message encryption mode.

The v0.27.6 [provider API candidate](docs/assurance/aes-provider-completion.md)
adds distinct AES-128/192/256 external-key bindings. Applications supply their
own trusted adapters; Brynja adds no device client or OpenBao integration and
requires no HSM. Mock and package tests are not hardware qualification.

The v0.27.4 [RISC-V AES candidate](docs/assurance/aes-riscv-development.md)
implements RV64 scalar Zkne/Zknd only behind the explicit evidence build cfg.
Ordinary static and hosted AES dispatch remain unadmitted on RISC-V, even when
the compiler enables these instructions. Its QEMU and linked-code checks are
development evidence, not a new production acceleration or timing guarantee.

Apple Silicon macOS has separate, default-off resident/clearing session APIs
for modern hashes, KMAC, TupleHash, batching and ParallelHash, with separately
scoped legacy adapters. They require locked guarded storage and joined workers,
but do **not** guarantee core-dump exclusion and are not a fallback for
`brynja-strict`. Native project tests are recorded in the
[v0.25.2 report](security/pentest/v0.25.2.md#author-native-refresh--ea97052b-2026-10-28);
they do not establish dump exclusion or independent cryptographic certification.
See the [resident profile contract](docs/macos-resident-profile.md).

## Rust Version Support

MSRV is Rust `1.90.0`; the default full-check compiler is Rust `1.100.0`.
The Apple Silicon resident-profile development checks continue to use `1.99.1`.
Historical qualification records retain their original compiler identities;
updating the default does not relabel them or qualify new platform support.
Release preflight requires the latest stable Rust in the executable compatibility
and emitted-code matrices; those checks must still pass. It does not automatically
advance the native-evidence compiler or relabel old results. Other tool freshness
checks remain unchanged. Kani uses its separately pinned
`cargo-kani 0.68.0` / Rust `1.90.0` launcher pairing, with Kani's bundled
`nightly-2026-08-21` verifier compiler. It does not lower the production compiler
or make a policy check a proof. See [Kani evidence](docs/KANI.md).

| Rust toolchain | Required evidence |
| --- | --- |
| `1.90.0`–`1.100.0` (listed versions) | Workspace all-feature compatibility, public API acceptance, and x86-64 clearing/constant-time codegen checks |
| `1.100.0` | Full format, lint, test, platform, policy, docs, package, and security gate |

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
[Focused assurance](docs/focused-assurance.md) selects changed implementations
and affected consumers, with validated reuse of unchanged results. Routine
development tags do not require Miri; crates.io releases require affected-code
Miri. Full extended campaigns are explicitly selected assurance checkpoints,
not automatic consequences of publication. v0.25.2 retains its full checkpoint.
See [Miri coverage by release](docs/assurance/miri-coverage.md) for tested
snapshots and pending coverage. Unknown scope stops for review. Long verifier
runs stay off ordinary GitHub CI, which retains bounded checks and CodeQL.

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
