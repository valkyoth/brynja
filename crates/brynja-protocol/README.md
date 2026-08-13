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

`brynja-protocol 0.1.0` is Brynja's shared allocation-free TLS and DTLS
record-envelope boundary. An already selected typed `WirePolicy` controls the
parser: record bytes cannot select, downgrade, or fall back to another protocol
version. Parsers borrow input, preserve legacy-version and unknown content-type
bytes where permitted, and reject malformed lengths before exposing a record.
Encoders preflight caller buffers and leave them unchanged on failure.

The boundary covers TLS 1.2 and TLS 1.3 plaintext/ciphertext envelopes, DTLS
1.2 plaintext/ciphertext envelopes, and DTLS 1.3 plaintext and unified
ciphertext headers. TLS 1.3 and DTLS 1.3 legacy-version handling follows RFC
9846. RFC 6520 Heartbeat content and extension negotiation are rejected in
every modern profile. TLS 1.3 application data is categorically rejected from
unprotected wire records during both parsing and construction; it remains
available only through the separate post-decryption inner-content classifier.

This crate does not negotiate versions, decrypt or authenticate records,
reconstruct DTLS sequence numbers, enforce replay policy, process handshakes,
perform I/O, allocate, implement cryptography, or provide a TLS/DTLS engine.
It is selected for initial publication at v0.20.0. Its v0.19.0 initial High
cleartext-exposure finding passed repository-owner remediation retest with zero
open findings, and it remains inside the cumulative v0.15.0-to-v0.20.0 review
range. That scheduled assessment and its DER remediation retest record
`PASS`/`PASS` with zero open findings. It stays unpublished until the committed
release-check candidate and hosted gates pass.

## Cryptography Verification Status

No protocol code in this crate has been independently reviewed. Project tests,
CI, fuzzing, formal tools, and pentesting do not by themselves constitute
independent protocol verification.

| Component | Protocol scope | Independently verified |
| --- | --- | --- |
| `brynja-protocol` | TLS and DTLS record-envelope parsing and encoding | ❌ Not verified |

The project-wide first-party Rust, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
