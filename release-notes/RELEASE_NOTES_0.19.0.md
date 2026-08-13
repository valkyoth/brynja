# Brynja v0.19.0 Development Milestone

Status: initial High finding remediated; exceptional retest required before tag

Brynja v0.19.0 adds the first hostile protocol parser boundary in unpublished
`brynja-protocol 0.1.0`. The `brynja` facade advances to `0.19.0`; all
previously published support versions remain unchanged, and no crate is
selected for crates.io publication.

## Shared Record Framing

- One private-field `WirePolicy` identifies an already selected TLS 1.2, TLS
  1.3, DTLS 1.2, or DTLS 1.3 profile. Wire bytes cannot negotiate, downgrade,
  fall back, or cross protocol engines.
- Borrowed TLS plaintext and ciphertext parsers enforce distinct TLS 1.2 and
  TLS 1.3 content, version, empty-fragment, and maximum-length rules.
- Borrowed DTLS parsers cover DTLS 1.2 plaintext/ciphertext headers and DTLS
  1.3 plaintext and unified ciphertext headers, with exact epoch, CID,
  short/long sequence-number, and optional-length semantics.
- Unknown content-type bytes and permitted legacy-version bytes retain their
  exact wire identity. RFC 6520 Heartbeat content and extension negotiation are
  rejected in every modern profile.
- TLS 1.3 application data is categorically rejected from plaintext wire
  records during both hostile parsing and caller construction. Application data
  remains available only to the separate post-decryption inner classifier.
- Encoders preflight complete caller-owned output and preserve every byte and
  position on insufficient capacity.

## Security Boundary

The crate is `no_std`, allocation-free, safe Rust, and contains no networking,
I/O, cryptography, decryption, authentication, record protection, replay
window, DTLS sequence reconstruction, protocol negotiation, handshake
transition, alert selection, provider effect, or global state. Successful
framing never implies authenticity, freshness, protocol validity, or engine
acceptance.

## Verification

- Eighteen integration tests exhaustively classify all 256 content-type
  bytes and cover profile separation, exact bounds, empty rules, every header
  truncation, malformed constants, stream/datagram suffixes, DTLS header
  layouts, and transactional output failure.
- Three compile-fail examples reject raw content-type construction, forged
  wire-policy fields, and record formatting.
- Seven source files are SHA-256 locked and remain below 500 lines.
- Thirty broken fixtures reject protocol selection, cleartext TLS 1.3
  application data, Heartbeat admission,
  allocation, I/O, cryptography, unsafe/FFI, public internals, oversized files,
  graph drift, and reviewed-source drift.
- The complete workspace gate covers Rust 1.90.0 through 1.97.1, all promised
  targets, dependency and advisory policy, SBOM, packages, documentation, and
  modern/legacy isolation.

## Pentest And Release Process

As Brynja's first hostile protocol parser, v0.19.0 is an exceptional pentest
trigger. The initial assessment found one High cleartext-exposure flaw because
TLS 1.3 plaintext admission inherited TLS 1.2 application-data allowance. The
profiles are now separated, parsing and construction return a dedicated closed
error, and focused regression and policy fixtures enforce the remediation. The
exact signed remediation candidate must receive a committed
`PASS`/`PASS` report with zero open findings, followed by green GitHub and
CodeQL, before the signed tag is created. The milestone publishes no crate.
Its complete delta also remains inside the scheduled cumulative review of all
changes after v0.15.0 through v0.20.0.
