# Current Status

Status: v0.2.0 pentest complete; awaiting green GitHub CI

Brynja has no TLS, cryptographic, PKI, QUIC, DTLS, platform, or legacy
protocol implementation. The workspace compiles only to prove the intended
package graph and isolation boundaries: legacy engines use explicit
`brynja-legacy-*` names, while the evergreen `brynja-tls` facade reaches
separate TLS 1.2 and TLS 1.3 engine packages. Do not use it for network
security.
Brynja is not FIPS 140-3 validated and no current package, feature, build,
profile, or configuration may state or imply a FIPS validation claim.
No `brynja-sanitization` package or dependency exists in the current workspace.
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

The signed `v0.1.0` foundation and all eleven selected crates are published.
The `v0.2.0` candidate advances only `brynja`; unchanged supporting crates
remain at `0.1.0`. It adds a committed 24-package class policy, exact
no-default and all-feature graph validation, modern and legacy negative
fixtures, regular committed-report enforcement, exact signed-tag comparison,
and a live-checked active GitHub ruleset matching the protected `eth` model.
The v0.2.0 pentest remediation adds no-default-feature Clippy coverage and
documents the intentional fail-closed panic posture. The committed PASS report
records zero open findings and the owner-accepted solo-maintainer governance
risks. No `v0.2.0` tag exists; the candidate must receive green GitHub CI
before explicit tag authorization.
The 2026-07-26 RFC planning audit locks a 103-document protocol source closure
and records roadmap dispositions; machine-readable normative source-to-code-
and-test traceability remains planned for v0.3.0 through v0.3.5.
