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

> **Development status:** Brynja is pre-1.0, incomplete, and must not yet secure application traffic. It provides all six SHA-2 and FIPS 202 functions,
> complete cSHAKE, KMAC/KMACXOF, and TupleHash/TupleHashXOF families, plus security and bounded framing foundations,
> but no TLS connection, certificate validator, or working protocol engine.

All six SHA-2 APIs and all six portable FIPS 202 APIs pass separately packaged and combined downstream `no_std` acceptance through the leaf and facade. Both families accept canonical arbitrary-bit messages, and SHAKE supports arbitrary-bit output. Distinct hardened states clear all source-declared Brynja-owned regions and classify output explicitly as public or typed secret. Both exact families are fully implemented; that is not independent review or FIPS validation.

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

This parses only the bounded record envelope. It does not negotiate TLS, authenticate data, decrypt a record, or perform network I/O.

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

These SHA-2 functions are unkeyed digests, not authentication, a MAC, or password hashing. Ordinary states do not erase private secret-input remnants. Secret-bearing callers must use the distinct hardened states added at v0.24.8; they clear Brynja-owned regions, while callers remain responsible for the original secret buffers they own.

Use `finalize_secret` instead when the digest remains secret. It returns a typed secret-region owner and clears the complete destination when that owner drops. Hardened cleanup covers Brynja-owned source-declared memory, not registers, caches, compiler-created copies, dumps, forgotten owners, abort, or power loss.

### Compute Portable SHA-3 And SHAKE

```rust
let digest = brynja::crypto::sha3_256(b"abc").unwrap();
assert_eq!(digest.as_bytes().len(), 32);

let mut shake128 = [0_u8; 32];
brynja::crypto::shake128(b"abc", &mut shake128).unwrap();

```

These are FIPS 202 SHA-3 functions, not raw Keccak. Ordinary states are for
public inputs. Secret-derived use selects hardened states and explicit public
or typed-secret output; secret owners clear complete destinations on `Drop`.

### Compute Customized SHAKE

```rust
let mut output = [0_u8; 32];
brynja::crypto::cshake128(&[0, 1, 2, 3], b"", b"Email Signature", &mut output).unwrap();
assert_eq!(&output[..4], &[0xc1, 0xc3, 0x69, 0x25]);
```

Empty N/S is exactly SHAKE. Ordinary cSHAKE is public-data-only; hardened cSHAKE owners clear secret-bearing internal state.

### Authenticate Or Derive With KMAC

```rust
use brynja::crypto::{Kmac128, KmacPublicDeclassification, KmacXof256};

let key = [0x42_u8; 32];
let mut mac = Kmac128::new(&key, b"example protocol").unwrap();
mac.update(b"authenticated message").unwrap();
let mut tag_bytes = [0_u8; 32];
let tag = mac.finalize_tag(&mut tag_bytes).unwrap();
assert!(tag.verify_candidate(tag.as_bytes()).expose_public());

let mut reader = KmacXof256::new(&key, b"example PRF").unwrap().finalize_xof().unwrap();
let mut derived = [0_u8; 64];
reader
    .squeeze_public(&mut derived, KmacPublicDeclassification::acknowledge())
    .unwrap();
```

Production constructors require full-strength keys and fixed tags. Exact conformance constructors retain all standards-valid inputs but are absent from
default builds, require the leaf crate's explicit `conformance-testing` feature, and report weak parameters as non-approved. Brynja has no FIPS validation.
Callers must enforce their protocol's maximum candidate-tag length before KMAC verification.

## Cryptography Verification Status

These tables track concrete public capabilities and active pre-1.0 roadmap families. Implementation requires a complete public API and acceptance; a planned row is not yet usable. See the [component verification status](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md) for the crate-level audit inventory.
✅ Implemented means a capability is ready; ✅ Fully implemented covers every named family member. A green implementation status does not mean independently verified.
Only linked sign-off from a named independent reviewer can change independent status. CI, Kani, Miri, sanitizers, fuzzing, differential testing, and pentests do not constitute independent verification.

### Modern Hash Functions

SHA-2 covers SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256; SHA-3/SHAKE covers SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256.

| Hash family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| SHA-2 | ✅ Fully implemented | `brynja-hash-sha2` | ❌ Not independently verified |
| SHA-3/SHAKE | ✅ Fully implemented | `brynja-hash-sha3` | ❌ Not independently verified |
| TupleHash/TupleHashXOF | ✅ Fully implemented | `brynja-hash-tuple` | ❌ Not independently verified |
| SP 800-185 family | 🚧 In progress — encodings, cSHAKE, KMAC, and TupleHash complete; ParallelHash pending | `brynja-hash-sha3`, `brynja-mac-kmac`, `brynja-hash-tuple` | ❌ Not independently verified |

### Modern Message Authentication

The complete KMAC/KMACXOF family here comprises KMAC128, KMAC256,
KMACXOF128, and KMACXOF256.

| Construction family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| KMAC/KMACXOF | ✅ Fully implemented | `brynja-mac-kmac` | ❌ Not independently verified |

### Legacy Hash Functions

| Hash family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| SHA-1 | 🗓 Planned — v0.24.18–v0.24.23 | `brynja-legacy-sha1` | ❌ Not independently verified |
| MD5 | 🗓 Planned — v0.24.19–v0.24.23 | `brynja-legacy-md5` | ❌ Not independently verified |

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

FIPS validation is a separate official claim from implementation and independent review. Brynja has no FIPS 140-3 validation, certificate, validated module, approved security policy, or certificate-bound operational-environment claim.

| Validation scope | Implementation status | Owning crate | Official validation |
| --- | --- | --- | --- |
| FIPS 140-3 cryptographic module | ❌ Not implemented | Future `brynja-fips-module`, `brynja-fips` | ❌ Not FIPS validated |

## Workspace

| Package | Purpose |
| --- | --- |
| `brynja` | Modern curated facade |
| `brynja-core` | Bounded state, constant-time, secret-memory, provider, entropy, time, and security-outcome foundations |
| `brynja-hash-sha2` | All six fully implemented FIPS 180-4 ordinary and hardened byte and arbitrary-bit APIs |
| `brynja-hash-sha3` | All six fully implemented FIPS 202 ordinary and hardened byte/arbitrary-bit APIs plus arbitrary-bit SHAKE output |
| `brynja-mac-kmac` | Complete hardened KMAC128/256 and KMACXOF128/256 APIs with in-place source clearing and feature-gated exact conformance |
| `brynja-hash-tuple` | Complete TupleHash128/256 and TupleHashXOF128/256 APIs with structural tuple items and hardened ownership |
| `brynja-crypto` | Cryptographic policy, composition, and protocol-facing provider boundary |
| `brynja-pki` | DER, ASN.1, X.509, path validation, and revocation ownership |
| `brynja-protocol` | Shared allocation-free TLS and DTLS record envelopes |
| `brynja-tls12`, `brynja-tls13`, `brynja-dtls`, `brynja-quic-tls` | Separately reviewable modern protocol engines |
| `brynja-legacy-*` | Explicitly isolated obsolete-protocol compatibility |

More: [release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md), [threat model](https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md), [verification inventory](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md), and [security policy](https://github.com/valkyoth/brynja/blob/main/SECURITY.md). Licensed under either Apache-2.0 or MIT, at your option.
