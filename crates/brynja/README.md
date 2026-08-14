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

`brynja` is the small modern facade for the Brynja cryptography and
secure-protocol workspace. It is allocation-independent `no_std` Rust and does
not depend on a C cryptographic library.

> **Development status:** Brynja is pre-1.0, incomplete, and must not yet be
> used to secure application traffic. The current facade provides completed
> security foundations, portable SHA-256, bounded TLS/DTLS record-envelope
> framing, bounded DER framing, and selected canonical ASN.1 values. It does
> not yet provide a TLS connection, certificate validator, or working protocol
> engine.

## Design Boundaries

| Boundary | Current rule |
| --- | --- |
| Runtime | `no_std`; no allocator, operating system, socket, filesystem, or runtime detector is assumed |
| Cryptography | First-party Rust implementations; foreign C cryptographic modules and wrappers are forbidden |
| Dependencies | No third-party dependency in the main facade graph; narrowly admitted adapters remain separate |
| Unsafe Rust | Forbidden except for individually reviewed, hash-locked boundaries |
| Legacy protocols | Isolated in explicit `brynja-legacy-*` packages and unreachable from this facade |
| Portability | Rust 1.90.0 through 1.97.1; Linux, Windows, BSD, macOS, Android, iOS, and bare-metal-aware design |
| Production readiness | Not claimed before the independently reviewed `1.0.0` candidate |

## Add The Crate

```bash
cargo add brynja --no-default-features
```

Optional facade integrations are selected explicitly:

```bash
cargo add brynja --no-default-features --features dtls
```

## Examples

### Constant-Time Equality

```rust
use brynja::core::ConstantTimeEq;

let expected = [0x42_u8; 32];
let received = [0x42_u8; 32];

let matches = expected.ct_eq(&received);
assert!(matches.expose_public());
```

Exposing the resulting choice is an explicit public branch decision. The
comparison itself examines every byte in the fixed-size array.

### Parse A Bounded TLS 1.3 Record Envelope

```rust
use brynja::core::ProtocolVersion;
use brynja::protocol::{ContentType, TlsPlaintext, WirePolicy};

let wire = [22, 3, 3, 0, 3, 1, 2, 3];
let policy = WirePolicy::for_version(ProtocolVersion::Tls13);
let (record, remaining) = TlsPlaintext::parse(policy, &wire).unwrap();

assert_eq!(record.content_type(), ContentType::Handshake);
assert_eq!(record.fragment(), &[1, 2, 3]);
assert!(remaining.is_empty());
```

This parses only the bounded record envelope. It does not negotiate TLS,
authenticate data, decrypt a record, or perform network I/O.

### Compute Portable SHA-256

```rust
let digest = brynja::crypto::sha256(b"abc").unwrap();

assert_eq!(
    digest.as_bytes(),
    &[
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    ]
);
```

SHA-256 is an unkeyed digest, not authentication, a MAC, or password hashing.

## Cryptography Verification Status

These tables track concrete public capabilities, not internal crate names or
reserved architecture. A capability is listed as implemented only after its
complete public API and required downstream usability acceptance pass. For
example, SHA-256 will be added after v0.22.3, rather than when an internal
module or partial implementation first exists. The broader crate-level audit
inventory remains available in the
[component verification status](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md).

✅ Implemented means the named capability has a documented, consumer-usable
public API and passed the repository's required acceptance evidence. It does
not mean independently verified. Independent status moves from ❌ to ✅ only
when a named independent reviewer signs off and linked evidence identifies the
reviewed implementation. The project's own tests, CI, Kani, Miri, sanitizers,
fuzzing, differential testing, and pentests do not by themselves constitute
independent cryptographic or protocol verification.

### Hash Functions

| Hash | Implemented | Independently verified |
| --- | --- | --- |
| _No accepted hash implementation yet_ | — | — |

### Protocol And PKI Building Blocks

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| TLS and DTLS record-envelope parsing and encoding | ✅ Implemented | ❌ Not independently verified |
| Bounded DER framing and admitted canonical ASN.1 values | ✅ Implemented | ❌ Not independently verified |

### Security Foundations

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Fixed-width constant-time operations and secret-region lifecycle | ✅ Implemented | ❌ Not independently verified |
| Fixed-size secret ownership and explicit sanitization adapter | ✅ Implemented | ❌ Not independently verified |

### Official Validation

FIPS validation is a separate official claim from implementation and
independent source review. Brynja has no FIPS 140-3 validation, certificate,
validated module, approved security policy, or certificate-bound
operational-environment claim.

| Validation scope | Implemented | Officially validated |
| --- | --- | --- |
| FIPS 140-3 cryptographic module | ❌ Not implemented | ❌ Not FIPS validated |

## Workspace

Depend directly on a leaf crate when the complete facade is unnecessary.

| Package | Purpose |
| --- | --- |
| `brynja` | Modern curated facade |
| `brynja-core` | Bounded state, constant-time, secret-memory, provider, entropy, time, and security-outcome foundations |
| `brynja-hash-core` | Small allocation-free fixed-output hash interfaces |
| `brynja-hash-sha2` | Portable SHA-256 implementation and future SHA-2 family ownership |
| `brynja-crypto-cpu`, `brynja-crypto-cpu-std` | Optional first-party ISA kernels and separate host runtime detection; absent from this facade |
| `brynja-crypto` | Cryptographic policy, composition, and protocol-facing provider boundary |
| `brynja-pki` | DER, ASN.1, X.509, path validation, and revocation ownership |
| `brynja-protocol` | Shared allocation-free TLS and DTLS record envelopes |
| `brynja-tls12`, `brynja-tls13`, `brynja-dtls`, `brynja-quic-tls` | Separately reviewable modern protocol engines |
| Future `brynja-hash-sha3` and `brynja-mac-*` | Further small reusable algorithm-family crates |
| `brynja-platform` | Explicit operating-system integrations |
| `brynja-sanitization` | Optional first-party secret-sanitization adapter |
| `brynja-legacy-*` | Explicitly isolated obsolete-protocol compatibility |

Many workspace packages are boundaries awaiting later roadmap milestones. A
package name alone does not mean that its planned implementation exists.

## More Information

- [Full project README](https://github.com/valkyoth/brynja#readme)
- [API documentation](https://docs.rs/brynja)
- [Release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md)
- [Version plan](https://github.com/valkyoth/brynja/blob/main/docs/VERSION_PLAN.md)
- [Threat model](https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md)
- [Verification inventory](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md)
- [Security policy](https://github.com/valkyoth/brynja/blob/main/SECURITY.md)
- [Changelog](https://github.com/valkyoth/brynja/blob/main/CHANGELOG.md)

Licensed under either Apache-2.0 or MIT, at your option.
