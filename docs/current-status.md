# Current Status

Status: v0.3.1 pentest complete; awaiting green GitHub CI

Brynja still has no TLS, cryptographic, PKI, QUIC, DTLS, platform, or legacy
protocol implementation. The Rust workspace remains package scaffolding and
must not be used to secure network traffic. Brynja is not FIPS 140-3 validated,
and no package, feature, build, profile, or configuration may imply otherwise.

Signed releases v0.1.0 through v0.3.0 established the workspace, hardened
release and isolation controls, and made standards authority executable. The
v0.3.1 candidate advances only `brynja`; unchanged supporting crates remain at
their independently published `0.1.0` versions and are not selected again.

Version 0.3.0 provides the exact source foundation:

- 103 locked RFCs and eight local NIST authorities map to lifecycle, domain,
  and roadmap ownership;
- RFC status and update/obsolescence relationships are closed or explicitly
  excluded;
- eight exact IANA XML snapshots preserve registry state;
- all 285 official errata have fail-closed reviewed dispositions; and
- ordinary checks reproduce the ledger offline while the release gate rejects
  live official-source drift.

Version 0.3.1 adds explicit protocol-surface decisions:

- 45 semantic decisions cover current and compatibility TLS, DTLS, QUIC-TLS,
  PKIX, OCSP, CT, HPKE, ECH, cryptographic algorithms, certificate and key
  formats, legacy protocols, and operational facilities;
- all 192 nested registries and all 4,106 individual records across the eight
  pinned IANA collections receive a deterministic disposition;
- every one of the 4,343 total surfaces records normative sources, owning
  milestone, planned code target, planned test target, and rationale;
- required exclusions explicitly cover Heartbeat, status_request_v2,
  production SSLKEYLOGFILE, TLS 1.3 post-handshake authentication,
  certificate-with-external-PSK, legacy PKCS1 client signatures, ML-KEM PKIX
  credentials, HPKE non-base modes, and unsigned X.509 certificates;
- QUIC version-specific cryptography and certificate compression remain
  explicit bounded future work, while unknown extensions are safely ignored
  only where protocol rules permit; and
- 25 positive and broken-fixture tests reject source-ledger drift, registry
  omissions, duplicate or unknown decisions, invalid owners or targets,
  overlapping rules, unmatched overrides, stale output, and premature
  implementation claims.

This is decision and planning evidence, not implementation. A `future-work`
entry does not admit code or interoperability. v0.3.2 through v0.3.5 will
extract and populate normative requirement mappings before protocol work
begins. Concrete ECDHE-ML-KEM groups remain blocked until both a final
Standards Track RFC and final IANA values exist.

No `brynja-sanitization` package or dependency exists yet; its admission
decision remains gated at v0.11.1.

The repository owner pentested signed implementation candidate
`8785252d9ae16d59e9bb27787d63bd4684bcb493` and reported no findings. The
permanent report records PASS, zero open findings, and a green result. The
candidate now waits only for hosted GitHub checks and explicit tag
authorization.
