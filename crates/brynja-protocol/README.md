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

# brynja-protocol

Allocation-free `no_std` TLS and DTLS record-envelope parsing and encoding.
An explicit typed wire policy selects the protocol; input bytes cannot choose
a downgrade or fallback.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| TLS 1.2/1.3 record-envelope parsing and encoding | ✅ Implemented | ❌ No |
| DTLS 1.2/1.3 record-envelope parsing and encoding | ✅ Implemented | ❌ No |
| Handshake, record encryption and authenticated connections | ❌ Not implemented | ❌ No |

These are framing utilities, not a TLS/DTLS engine or FIPS-validated module.

## Use

```sh
cargo add brynja-protocol brynja-core --no-default-features
```

For unpublished changes use the matching local checkout paths.

```rust
use brynja_core::ProtocolVersion;
use brynja_protocol::{ContentType, TlsPlaintext, WirePolicy};
let wire = [22, 3, 3, 0, 3, 1, 2, 3];
let policy = WirePolicy::for_version(ProtocolVersion::Tls13);
let (record, rest) = TlsPlaintext::parse(policy, &wire).unwrap();
assert_eq!(record.content_type(), ContentType::Handshake);
assert_eq!(record.fragment(), &[1, 2, 3]);
assert!(rest.is_empty());
```

Parsers borrow input and validate lengths before returning a record. Encoders
preflight complete caller buffers and preserve them on failure. TLS 1.3 and
DTLS 1.3 legacy-version handling follows RFC 9846; permitted unknown
content-type bytes remain explicit rather than selecting another protocol.

Modern profiles reject RFC 6520 Heartbeat. TLS 1.3 unprotected application
data is rejected on parse and construction; application content classification
belongs to the distinct post-decryption inner-content API.

## Hardware and SIMD

None. Framing uses portable Rust and performs no cryptography. Callers supply
policy, I/O, authentication, decryption, handshake processing, replay handling,
DTLS sequence reconstruction and application resource limits.

[Protocol API](https://github.com/valkyoth/brynja/tree/main/crates/brynja-protocol/src)
· [Verification inventory](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md).
MIT OR Apache-2.0.
