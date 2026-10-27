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

`brynja` is the small modern facade for the Brynja cryptography and secure-protocol workspace. It is allocation-independent `no_std` Rust without a C cryptographic library. Select the separate [brynja-strict facade](https://github.com/valkyoth/brynja/blob/main/crates/brynja-strict/README.md) for protected-memory/worker-stack APIs: upgrading `brynja` does not enable them. Strict constructors reject unsupported platforms or unavailable resources; qualification remains pending.

> **Development status:** Brynja is pre-1.0, incomplete, and must not yet secure application traffic. It provides all six SHA-2 and FIPS 202 functions,
> complete cSHAKE, KMAC/KMACXOF, TupleHash/TupleHashXOF, and ParallelHash/ParallelHashXOF families, modern SHA-2/SHA-3 HMAC, plus security and bounded framing foundations,
> but no TLS connection, certificate validator, or working protocol engine.

## Cryptography Verification Status

These tables track concrete public capabilities and active pre-1.0 roadmap families. Implementation requires a complete public API and passing functional acceptance; a planned row is not yet usable. See the [component verification status](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md) for the crate-level audit inventory.
✅ Implemented means a capability is implemented and acceptance-tested; ✅ Fully implemented covers every named family member. Release qualification is separate and remains pending for this candidate. A green implementation status does not mean independently verified.
Only linked sign-off from a named independent reviewer can change independent status. CI, Kani, Miri, sanitizers, fuzzing, differential testing, and pentests do not constitute independent verification.

Implementation completion does not authorize publication or imply platform qualification.

### Modern Hash Functions

SHA-2 covers SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256; SHA-3/SHAKE covers SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256. Portable family completion is separate from optional CPU execution qualification.

| Hash family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| SHA-2 | ✅ Fully implemented | `brynja-hash-sha2` | ❌ Not independently verified |
| General SHA-512/t extension (portable) | ✅ Fully implemented | `brynja-hash-sha2` (opt-in) | ❌ Not independently verified |
| SHA-3/SHAKE | ✅ Fully implemented | `brynja-hash-sha3` | ❌ Not independently verified |
| TupleHash/TupleHashXOF | ✅ Fully implemented | `brynja-hash-tuple` | ❌ Not independently verified |
| ParallelHash/ParallelHashXOF | ✅ Fully implemented | `brynja-hash-parallel` | ❌ Not independently verified |
| SP 800-185 family | ✅ Fully implemented | `brynja-hash-sha3`, `brynja-mac-kmac`, `brynja-hash-tuple`, `brynja-hash-parallel` | ❌ Not independently verified |

### Modern Message Authentication

| Construction family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| KMAC/KMACXOF | ✅ Fully implemented | `brynja-mac-kmac` | ❌ Not independently verified |
| HMAC over modern SHA-2/SHA-3 | ✅ Fully implemented | `brynja-mac-hmac` | ❌ Not independently verified |

HMAC covers all ten named SHA-2/SHA-3 identities, streaming and one-shot use,
long keys, byte/bit messages, preselected byte truncation, mismatch rejection
and typed public/secret tags. General SHA-512/t retains the modern 128-bit
minimum. Platform-specific acceleration and protected/resident qualification
remain separate; there is no SIMD-batched or Windows enclave HMAC API.

### Legacy Hash Functions

| Hash family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| SHA-1 | ✅ Fully implemented | `brynja-legacy-sha1` | ❌ Not independently verified |
| MD5 | ✅ Fully implemented | `brynja-legacy-md5` | ❌ Not independently verified |

### Legacy Message Authentication

These compatibility APIs require separate legacy dependencies and are not
exported by this modern facade. Hosted owners cover GNU/Linux protected and
Apple Silicon resident sessions, not a portable guarantee of protected memory.
The current checkpoint's release qualification remains pending; no independent
cryptographic certification is claimed.

| Construction family | Implementation status | Owning crate | Independent verification |
| --- | --- | --- | --- |
| HMAC over legacy MD5/SHA-1 | ✅ Fully implemented | `brynja-legacy-hmac` | ❌ Not independently verified |
| Hosted legacy HMAC | ✅ Implemented | `brynja-legacy-hmac-std` | ❌ Not independently verified |

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

## Add The Crate

Default hash APIs remain portable. Separate CPU packages expose default-off raw static and platform-limited [hosted execution authority](https://github.com/valkyoth/brynja/blob/main/docs/hosted-cpu-execution.md). Opt-in leaf features provide complete ordinary SHA-2, [SHA-3/SHAKE](https://github.com/valkyoth/brynja/blob/main/docs/sha3-ordinary-execution.md) and [cSHAKE execution](https://github.com/valkyoth/brynja/blob/main/docs/cshake-ordinary-execution.md). Separate [hardened SHA-2](https://github.com/valkyoth/brynja/blob/main/docs/sha2-hardened-execution.md) and [hardened Keccak execution](https://github.com/valkyoth/brynja/blob/main/docs/hardened-keccak-execution.md) provide erasing owners and typed secret outputs. These paths have project-owned retest, native functional evidence and local release checks, not independent verification or FIPS validation. Register/spill erasure and universal platform safety are not guaranteed. See the [acceleration plan](https://github.com/valkyoth/brynja/blob/main/docs/ACCELERATION_USABILITY_AUDIT.md) and linked guides for exact platform restrictions.

Select a release containing the modern APIs described here. Older foundation-only
packages do not expose the complete hash/MAC surface.

After this source version is published, install from the registry:

```sh
cargo add brynja --no-default-features
```

For an unpublished candidate or matching local checkout instead:

```sh
cargo add brynja --path /path/to/brynja/crates/brynja --no-default-features
```

## Hardware and SIMD

The facade defaults to portable execution. Explicit per-family features forward
existing execution and batch APIs through `crypto::sha2`, `crypto::sha3`,
`crypto::kmac`, `crypto::tuplehash` and `crypto::parallelhash`. The separate
`general-sha512-t` feature exposes general SHA-512/t. See the
[feature and deployment guide](https://github.com/valkyoth/brynja/blob/main/docs/facade-features.md).
Optional execution supports x86-64 SHA/AVX2 and AArch64 SHA2/SHA-512/SHA3,
depending on family and platform authority; dedicated x86 SHA-512 remains
emulated qualification only. Cargo features do not establish CPU support.
Host detection stays in separate companion crates. Legacy algorithms remain
separate; existing unadmitted CPU candidates are not made operational by a
facade feature. ParallelHash accelerated scheduling retains its qualification
limits; portable family completion does not close that work.

## Examples

### Authenticate And Reject A Forged HMAC

```rust
use brynja::crypto::hmac::{Error, Hmac, Sha256};

let key = [0x42; 32]; // Demonstration only; applications supply a secret key.
let mut output = [0; 32];
let tag = Hmac::<Sha256>::authenticate(&key, b"message", &mut output)?;

let mut verifier = Hmac::<Sha256>::new(&key)?;
verifier.update(b"message")?;
verifier.verify(tag.as_bytes())?; // Only a match returns Ok(()).

let mut forged = [0; 32];
forged.copy_from_slice(tag.as_bytes());
forged[0] ^= 1;
let mut verifier = Hmac::<Sha256>::new(&key)?;
verifier.update(b"message")?;
assert_eq!(verifier.verify(&forged), Err(Error::Mismatch));
# Ok::<(), Error>(())
```

Choose a protocol's tag length before processing keys or messages; never infer
it from an incoming tag. The modern minimum is 128 bits. This portable API
clears its owned secret state but does not lock caller buffers or worker stacks.
Use the distinct protected/resident APIs when those storage properties are
required. Legacy HMAC-MD5/SHA-1 requires a separate legacy crate dependency.

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

These SHA-2 functions are unkeyed digests, not authentication, a MAC, or password hashing. Ordinary states do not erase private secret-input remnants. Secret-bearing callers must use the distinct hardened states; they clear Brynja-owned regions, while callers remain responsible for the original secret buffers they own.

Use `finalize_secret` instead when the digest remains secret. It returns a typed secret-region owner and clears the complete destination when that owner drops. Hardened cleanup covers Brynja-owned source-declared memory, not registers, caches, compiler-created copies, dumps, forgotten owners, abort, or power loss.

### Compute Portable SHA-3 And SHAKE

```rust
let digest = brynja::crypto::sha3_256(b"abc").unwrap();
assert_eq!(digest.as_bytes().len(), 32);

let mut shake128 = [0_u8; 32];
brynja::crypto::shake128(b"abc", &mut shake128).unwrap();
```

These are FIPS 202 SHA-3 functions, not raw Keccak. Ordinary states are for public inputs. Secret-derived use selects hardened states and explicit public or typed-secret output; secret owners clear complete destinations on `Drop`.

### Compute Customized SHAKE

```rust
let mut output = [0_u8; 32];
brynja::crypto::cshake128(&[0, 1, 2, 3], b"", b"Email Signature", &mut output).unwrap();
assert_eq!(&output[..4], &[0xc1, 0xc3, 0x69, 0x25]);
```

Empty N/S is exactly SHAKE. Ordinary cSHAKE is public-data-only; hardened cSHAKE owners clear secret-bearing internal state.

### Authenticate Or Derive With KMAC

```rust
use brynja::crypto::{Kmac128, KmacXof256};

let key = [0x42_u8; 32]; // Example only; applications supply a real secret key.
let mut mac = Kmac128::new(&key, b"example protocol").unwrap();
mac.update(b"authenticated message").unwrap();
let mut tag_bytes = [0_u8; 32];
let tag = mac.finalize_tag(&mut tag_bytes).unwrap();
assert!(tag.verify_candidate(tag.as_bytes()).expose_public());

let mut reader = KmacXof256::new(&key, b"example PRF").unwrap().finalize_xof().unwrap();
let mut derived = [0_u8; 64];
{
    let secret = reader.squeeze_secret(&mut derived).unwrap();
    assert_eq!(secret.expose().len(), 64);
}
assert_eq!(derived, [0; 64]);
```

Production constructors require full-strength keys and fixed tags. KMAC
conformance constructors live on distinct leaf-only test types under
`brynja_mac_kmac::conformance`, require `conformance-testing`, and report weak
parameters as non-approved. They do not appear on production aliases, including
execution and scoped owners, even when that feature is unified. Hidden cSHAKE
composition methods remain available on its reexported types; they are not
KMAC constructors. Brynja has no FIPS validation.
Callers must enforce their protocol's maximum candidate-tag length before KMAC verification.

## Workspace

| Package | Purpose |
| --- | --- |
| `brynja` | Modern curated facade |
| `brynja-core` | Bounded state, constant-time, secret-memory, provider, entropy, time, and security-outcome foundations |
| `brynja-hash-*`, `brynja-mac-kmac` | Algorithm leaves with ordinary/hardened ownership and opt-in execution; see capability tables above |
| `brynja-mac-hmac` | Modern SHA-2/SHA-3 HMAC; typed tags and success-only verification |
| `brynja-crypto` | Cryptographic policy, composition, and protocol-facing provider boundary |
| `brynja-pki` | Implemented DER/ASN.1 foundations; X.509, path validation and revocation planned |
| `brynja-protocol` | Shared allocation-free TLS and DTLS record envelopes |
| `brynja-tls12`, `brynja-tls13`, `brynja-dtls`, `brynja-quic-tls` | Planned modern protocol engines, not yet implemented |
| `brynja-legacy-*` | Isolated obsolete protocol boundaries, SHA-1/MD5, legacy HMAC and explicit hosted companions |

More: [release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md), [threat model](https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md), [verification inventory](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md), and [security policy](https://github.com/valkyoth/brynja/blob/main/SECURITY.md). Licensed under either Apache-2.0 or MIT, at your option.
