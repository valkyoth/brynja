# Brynja 0.21.0 Release Notes

Status: implementation complete; awaiting exceptional pentest

Brynja 0.21.0 is an internal development milestone. It selects zero crates.io
packages. The signed v0.20.0 checkpoint remains the latest published release,
and every v0.21.0 change remains inside the future cumulative
v0.20.0-to-v0.25.0 assessment.

## Added

- Borrowed, allocation-free canonical DER BOOLEAN, INTEGER, BIT STRING, OCTET
  STRING, OBJECT IDENTIFIER, character-string, UTCTime, and GeneralizedTime
  value types in `brynja-pki`.
- Checked signed and unsigned integer conversion plus allocation-free OID arc
  iteration.
- Validated SEQUENCE, SET, and SET OF wrappers using the existing immutable DER
  resource ceilings, direct-component tag order, and X.690 trailing-zero-
  padded octet order.
- A closed `CanonicalValue` dispatch boundary for only the admitted universal
  types.
- Implemented `BRY-REQ-ENC-0002` revision 3 and the exact
  `format.asn1.values` protocol surface.

## Verification

- Nine integration-test groups cover canonical, malformed, truncation,
  overflow, calendar, nesting, and ordering behavior.
- Exhaustive corpora classify all 256 one-octet BOOLEAN values, all 65,536
  two-octet BIT STRING payloads, and all 65,536 two-octet OID bodies.
- Six compile-fail examples preserve private construction and non-formatting
  boundaries across DER and ASN.1 APIs.
- Ten reviewed source hashes and forty adversarial mutation fixtures reject
  allocation, unsafe or foreign code, I/O, provider/crypto coupling, public
  fields, missing canonical checks, graph drift, source drift, and source files
  above 500 lines.
- The complete Rust 1.90.0 through 1.97.1 and promised-target gates remain
  mandatory before the release candidate can be committed.

## Deliberate exclusions

This milestone does not implement schema-driven ASN.1 decoding, DEFAULT
omission, escape-bearing ISO 2022 string types, AlgorithmIdentifier, X.509,
path validation, signatures, cryptography, independent verification, or FIPS
validation. It must not be used to secure application traffic.

## Release process

Canonical value decoding extends a hostile parser boundary, so v0.21.0 is an
exceptional pentest trigger. After implementation verification, the exact
signed candidate must receive a committed PASS/PASS report with zero open
findings, pass green GitHub and CodeQL, and receive explicit authorization
before the signed tag is created. No crates.io publication follows this tag.
