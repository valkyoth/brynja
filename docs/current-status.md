# Current Status

Status: repository foundation implemented; awaiting pentest

Brynja has no TLS, cryptographic, PKI, QUIC, DTLS, platform, or historical
protocol implementation. The workspace compiles only to prove the intended
package graph and isolation boundaries. Do not use it for network security.
Brynja is not FIPS 140-3 validated and no current package, feature, build,
profile, or configuration may state or imply a FIPS validation claim.

The `v0.1.0` repository policy and evidence automation are implemented.
Release readiness intentionally fails closed until an exact-commit pentest PASS
report exists. No tag or package publication is authorized.
