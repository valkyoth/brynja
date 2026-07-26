# Current Status

Status: repository foundation pentest passed; awaiting green GitHub CI

Brynja has no TLS, cryptographic, PKI, QUIC, DTLS, platform, or legacy
protocol implementation. The workspace compiles only to prove the intended
package graph and isolation boundaries: legacy engines use explicit
`brynja-legacy-*` names, while the evergreen `brynja-tls` facade reaches
separate TLS 1.2 and TLS 1.3 engine packages. Do not use it for network
security.
Brynja is not FIPS 140-3 validated and no current package, feature, build,
profile, or configuration may state or imply a FIPS validation claim.
No `brynja-sanitization` package or dependency exists in the foundation.
Versions v0.11.1 and v0.11.2 now gate evaluation and possible implementation
of one protocol-neutral, explicitly selected adapter to the first-party
`sanitization` crate. It will not replace Brynja's mandatory internal
destruction primitive, enter a facade or engine graph, activate `zeroize`, or
inherit a FIPS claim.
The 2026-07-26 planning check found `sanitization` `2.0.3` as the latest stable
crates.io release and confirmed its declared Rust `1.90.0` MSRV, pinned Rust
`1.97.1` development toolchain, `no_std` core, and MIT OR Apache-2.0 license.
This is planning evidence only; v0.11.1 must recheck and formally admit or
reject the then-current release.

The `v0.1.0` repository policy and evidence automation are implemented. The
committed pentest report records PASS, zero open findings, and clean retest
evidence after both low-severity hardening findings were remediated. GitHub must
now become green and the user must explicitly authorize the tag. No tag or
package publication is currently authorized.
The 2026-07-26 RFC planning audit locks a 103-document protocol source closure
and records roadmap dispositions; machine-readable normative source-to-code-
and-test traceability remains planned for v0.3.0 through v0.3.5.
