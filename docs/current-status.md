# Current Status

Status: repository foundation implemented; awaiting pentest

Brynja has no TLS, cryptographic, PKI, QUIC, DTLS, platform, or legacy
protocol implementation. The workspace compiles only to prove the intended
package graph and isolation boundaries: legacy engines use explicit
`brynja-legacy-*` names, while the evergreen `brynja-tls` facade reaches
separate TLS 1.2 and TLS 1.3 engine packages. Do not use it for network
security.
Brynja is not FIPS 140-3 validated and no current package, feature, build,
profile, or configuration may state or imply a FIPS validation claim.

The `v0.1.0` repository policy and evidence automation are implemented.
Release readiness intentionally fails closed until a current versioned pentest
PASS report is committed with zero open findings and clean retest evidence.
After that commit, GitHub must be green and the user must explicitly authorize
the tag. No tag or package publication is currently authorized.
The 2026-07-26 RFC planning audit locks a 103-document protocol source closure
and records roadmap dispositions; machine-readable normative source-to-code-
and-test traceability remains planned for v0.3.0 through v0.3.5.
