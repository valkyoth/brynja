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

# brynja-pki

Borrowed, allocation-free `no_std` DER traversal and canonical ASN.1 value
decoding. This is a PKI foundation, not a certificate validator.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Bounded, non-recursive DER framing reader | ✅ Implemented | ❌ No |
| Admitted ASN.1 primitive and canonical container values | ✅ Implemented | ❌ No |
| General DER encoding and schema-driven ASN.1 decoding | ❌ Not implemented | ❌ No |
| X.509, certificate paths, revocation and signature verification | ❌ Not implemented | ❌ No |

There is no named independent review or FIPS 140-3 validation.

## Use

Published packages provide the framing foundation; canonical value APIs
include unpublished workspace functionality. To use this checkout:

```sh
cargo add brynja-pki --path /path/to/brynja/crates/brynja-pki --no-default-features
```

```rust
use brynja_pki::{DerEvent, DerLimits, Reader};
let limits = DerLimits::builder()
    .input_bytes(4096).unwrap()
    .depth(8).unwrap()
    .nodes(64).unwrap()
    .children(32).unwrap()
    .identifier_octets(10).unwrap()
    .length_octets(9).unwrap()
    .value_bytes(2048).unwrap()
    .work(16384).unwrap()
    .build().unwrap();
let input = [4, 3, 0xaa, 0xbb, 0xcc]; // OCTET STRING, three bytes.
let mut reader = Reader::<8>::new(&input, limits).unwrap();
let Some(DerEvent::Primitive(value)) = reader.next_event().unwrap() else {
    panic!("expected primitive");
};
assert_eq!(value.contents(), &[0xaa, 0xbb, 0xcc]);
assert!(reader.next_event().unwrap().is_none());
```

Named limits bound input, nesting, nodes, children, identifiers, lengths, values
and total work. The const stack capacity bounds traversal memory. Truncation,
overflow, indefinite/non-minimal lengths, invalid tags, parent escape and
exhaustion fail without advancing the reader.

Canonical value support covers BOOLEAN, INTEGER, BIT/OCTET STRING, OBJECT
IDENTIFIER, selected character strings, UTCTime and GeneralizedTime.
SEQUENCE/SET/SET OF wrappers enforce admitted ordering and nesting rules.
Canonical containers are not schema validation: DEFAULT omission,
AlgorithmIdentifier and certificate semantics require additional APIs.

## Hardware and SIMD

None. Decoding does not invoke hash/signature kernels or access the OS.
Successful DER parsing does not establish trust, certificate validity,
authorization or authenticity.

[PKI roadmap](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).
MIT OR Apache-2.0.
