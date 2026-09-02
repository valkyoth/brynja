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

`brynja` is the small modern facade for the Brynja cryptography and secure-protocol
workspace. It is allocation-independent `no_std` Rust without a C cryptographic library.

> **Development status:** Brynja is pre-1.0, incomplete, and must not yet secure application traffic. It provides security foundations, all six portable FIPS 180-4 SHA-2 algorithms,
> all six portable FIPS 202 SHA-3 and SHAKE functions, and bounded record and DER/ASN.1 framing—but no TLS connection, certificate validator, or working protocol engine.

All six SHA-2 APIs and all six portable FIPS 202 APIs pass separately packaged
downstream `no_std` acceptance through the leaf and facade. Both families
accept canonical arbitrary-bit messages, and SHAKE supports arbitrary-bit
output. That is not independent review or FIPS validation. The SHA-3/SHAKE
hardened-state and final combined acceptance chain remains in progress.

## Design Boundaries

| Boundary | Current rule |
| --- | --- |
| Runtime | `no_std`; no allocator, operating system, socket, filesystem, or runtime detector is assumed |
| Cryptography | First-party Rust implementations; foreign C cryptographic modules and wrappers are forbidden |
| Dependencies | No third-party dependency in the main facade graph; narrowly admitted adapters remain separate |
| Unsafe Rust | Forbidden except for individually reviewed, hash-locked boundaries |
| Legacy protocols | Isolated in explicit `brynja-legacy-*` packages and unreachable from this facade |
| Portability | Rust 1.90.0 through 1.98.0; Linux, Windows, BSD, macOS, Android, iOS, and bare-metal-aware design |
| Production readiness | Not claimed before the independently reviewed `1.0.0` candidate |

## Add The Crate

```bash
cargo add brynja --no-default-features
```

## Examples

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

### Compute Portable SHA-2

```rust
let shorter = brynja::crypto::sha224(b"abc").unwrap();
let digest = brynja::crypto::sha256(b"abc").unwrap();
let truncated_256 = brynja::crypto::sha512_256(b"abc").unwrap();
assert_eq!(shorter.as_bytes().len(), 28);
assert_eq!(truncated_256.as_bytes().len(), 32);
assert_eq!(digest.as_bytes().len(), 32);

let bits = brynja::crypto::BitString::new(&[0b0110_0000], 3).unwrap();
let bit_digest = brynja::crypto::sha256_bits(bits).unwrap();
assert_eq!(&bit_digest.as_bytes()[..4], &[0x1f, 0x77, 0x94, 0xd4]);
```

These SHA-2 functions are unkeyed digests, not authentication, a MAC, or password hashing.
Ordinary states do not erase private secret-input remnants. Secret-bearing callers must use
the distinct hardened states added at v0.24.8; they clear Brynja-owned regions, while callers
remain responsible for the original secret buffers they own.

### Hash Secret-Bearing Input With Hardened SHA-2

```rust
use brynja::crypto::{HardenedSha256, PublicDeclassification};

let mut state = HardenedSha256::new();
state.update(b"secret-derived input").unwrap();
let mut public_digest = [0_u8; 32];
state
    .finalize_public(&mut public_digest, PublicDeclassification::acknowledge())
    .unwrap();
```

Use `finalize_secret` instead when the digest remains secret. It returns a typed
secret-region owner and clears the complete destination when that owner drops.
Hardened cleanup covers Brynja-owned source-declared memory, not registers,
caches, compiler-created copies, dumps, forgotten owners, abort, or power loss.

### Compute Portable SHA-3 And SHAKE

```rust
let digest = brynja::crypto::sha3_256(b"abc").unwrap();
assert_eq!(digest.as_bytes().len(), 32);

let mut shake128 = [0_u8; 32];
brynja::crypto::shake128(b"abc", &mut shake128).unwrap();

let bits = brynja::crypto::Fips202BitString::new(&[0b0001_0011], 5).unwrap();
let bit_digest = brynja::crypto::sha3_256_bits(bits).unwrap();
assert_eq!(bit_digest.as_bytes().len(), 32);

let mut partial_xof = [0xff_u8; 13];
let destination = brynja::crypto::Fips202Output::new(&mut partial_xof, 4).unwrap();
brynja::crypto::shake128_bits(bits, destination).unwrap();
assert_eq!(partial_xof[12] & 0xf0, 0);
```

These are FIPS 202 SHA-3 functions, not raw Keccak. Their ordinary unkeyed
states make no secret-remanence cleanup claim. Distinct hardened SHA-3/SHAKE
states and final combined acceptance close through v0.24.11.

## Cryptography Verification Status

These tables track concrete public capabilities after a complete public API and required acceptance. The
crate-level audit inventory remains available in the
[component verification status](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md).

✅ Implemented means a capability is ready; ✅ Fully implemented covers every named family member. A green implementation status does not mean independently verified.
Only linked sign-off from a named independent reviewer can change independent status. CI, Kani, Miri, sanitizers, fuzzing, differential testing, and pentests do not constitute independent verification.

### Hash Functions

| Hash | Implemented | Independently verified |
| --- | --- | --- |
| SHA-2 (FIPS 180-4: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256 have complete ordinary and hardened byte and arbitrary-bit APIs; combined acceptance pending) | 🚧 In progress | ❌ Not independently verified |
| SHA-3/SHAKE (all six FIPS 202 identities have complete ordinary byte and arbitrary-bit message APIs plus arbitrary-bit SHAKE output; hardened secret-bearing and final acceptance profiles pending) | 🚧 In progress | ❌ Not independently verified |

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

FIPS validation is a separate official claim from implementation and independent review. Brynja has no FIPS 140-3 validation, certificate, validated module, approved security policy, or certificate-bound operational-environment claim.

| Validation scope | Implemented | Officially validated |
| --- | --- | --- |
| FIPS 140-3 cryptographic module | ❌ Not implemented | ❌ Not FIPS validated |

## Workspace

Depend directly on a leaf crate when the complete facade is unnecessary.

| Package | Purpose |
| --- | --- |
| `brynja` | Modern curated facade |
| `brynja-core` | Bounded state, constant-time, secret-memory, provider, entropy, time, and security-outcome foundations |
| `brynja-hash-sha2` | All six FIPS 180-4 ordinary and hardened byte and arbitrary-bit APIs; final combined acceptance pending |
| `brynja-hash-sha3` | All six FIPS 202 ordinary byte and arbitrary-bit message APIs plus arbitrary-bit SHAKE output; hardened and final acceptance pending |
| `brynja-crypto` | Cryptographic policy, composition, and protocol-facing provider boundary |
| `brynja-pki` | DER, ASN.1, X.509, path validation, and revocation ownership |
| `brynja-protocol` | Shared allocation-free TLS and DTLS record envelopes |
| `brynja-tls12`, `brynja-tls13`, `brynja-dtls`, `brynja-quic-tls` | Separately reviewable modern protocol engines |
| `brynja-legacy-*` | Explicitly isolated obsolete-protocol compatibility |

## More Information

- [Release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md)
- [Threat model](https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md)
- [Verification inventory](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md)
- [Security policy](https://github.com/valkyoth/brynja/blob/main/SECURITY.md)

Licensed under either Apache-2.0 or MIT, at your option.
