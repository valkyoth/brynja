# Brynja 0.3.4 Release Notes

Status: implementation complete; repository-owner pentest required

Brynja 0.3.4 completes the TLS, DTLS, and QUIC-TLS normative-coverage
pass. It does not implement TLS, cryptography, PKI, QUIC, DTLS, platform
services, or legacy protocols and must not be used to secure network traffic.

## Transport Domain Coverage

The normative matrix grows from 46 to 116 stable requirements. Seventy new
records cover current and compatibility TLS 1.3, hardened TLS 1.2, QUIC-TLS,
DTLS 1.2, and DTLS 1.3. Every one of the 63 future transport implementation
milestones now has a dedicated semantic surface and requirement recording:

- exact authority and lifecycle roles;
- version-specific ownership and intentional rejection boundaries;
- one planned implementation symbol or caller/rejection boundary;
- positive and negative test targets;
- explicit work and resource bounds;
- unresolved vector, state-model, fault, fuzz, interoperability, and audit
  evidence; and
- residual implementation and integration risk.

The generated transport artifact covers 40 admitted authorities, 550 normative
RFC sections, 63 owner milestones, and all 480 selected TLS, TLS 1.2, TLS 1.3,
QUIC, and DTLS surfaces.

## Explicit Security Boundaries

The transport bundle distinguishes current, compatibility, evidence,
exclusion, and caller-owned authority. Heartbeat, legacy TLS 1.3 PKCS1 client
signatures, post-handshake authentication, and certificate authentication
combined with an external PSK remain explicit modern-profile rejections.

QUIC packet, frame, stream, loss-recovery, congestion, Retry, migration, path,
and transport-version semantics remain caller-owned. Brynja's future
`brynja-quic-tls` package is limited to the recordless TLS handshake and
explicitly bounded helpers.

RFC 9850 key logging and four optional TLS facility groups remain exact v0.3.5
deferrals. The TLS 1.2 status_request_v2 exclusion remains bound to the
completed v0.3.3 OCSP review rather than being duplicated or silently
reclassified.

## Fail-Closed Verification

The protocol-surface register now consumes separately reviewed transport
policies and contains 4,409 classified surfaces, including 111 semantic
decisions. The requirement schema and immutable-history chain include the new
`tls-dtls-quic` profile and caller-owned authority role.

Eight dedicated transport fixtures reject missing owner milestones,
source-ledger or surface-register drift, authority-role swaps, missing or
duplicated stable identities, incomplete source closure, and nondeterministic
evidence. Existing foundation, domain, history, lifecycle, standards, and
surface fixtures continue to apply.

## Publication

Only `brynja 0.3.4` is selected for crates.io publication. All unchanged
modern supporting crates retain version `0.1.0` and are not republished.
Legacy and repository-only packages remain unpublished.

Publication requires a committed PASS pentest report, green hosted GitHub
checks, explicit tag authorization, and the exact signed tag at `HEAD`.

## Pentest

The v0.3.4 repository-owner pentest has not started. This release note will be
updated with the exact signed candidate, findings, remediation, and retest
outcome before tagging.

## Limitations

This release proves reviewed requirement coverage, not implementation,
interoperability, cryptographic correctness, side-channel resistance, protocol
security, or FIPS 140-3 validation. Planned targets and tests do not exist yet.
v0.3.5 covers optional, legacy, operational, residual, and hybrid requirements
before implementation begins.
