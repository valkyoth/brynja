# RFC Coverage Audit

Status: source and surface traceability complete through v0.3.1; requirement
foundation complete at v0.3.2; cryptography, encoding, and PKIX population
complete at v0.3.3; TLS, DTLS, and QUIC-TLS population complete at v0.3.4;
optional, legacy, operational, and residual closure complete at v0.3.5

## Scope And Method

This audit compared every protocol, cipher, key format, PKIX function, and
optional facility promised by the version and release plans with:

- the exact RFC Editor text locked under `rfc/`;
- each base RFC's current updated-by and obsoleted-by closure;
- normative language, protocol invariants, security considerations, registries,
  and algorithm or extension identifiers;
- current compatibility baselines needed for TLS 1.2 and legacy packages;
- explicit caller-owned, rejected, legacy-only, and future surfaces.

The repository now locks 104 RFCs. Fifty-three were added by the original audit,
and final RFC 10024 was admitted by the reviewed v0.13.1 authority refresh. The source
ledger deliberately retains obsolete documents only when current specifications
require compatibility behavior or an isolated legacy package needs them.

This document records planning coverage, not protocol conformance. v0.3.2
establishes stable machine-readable identifiers, lifecycle states, exact
authority binding, bidirectional mappings, and fail-closed pilot verification.
v0.3.3 populates every currently scoped cryptography, encoding, PKIX, OCSP,
and CT rule across 53 authorities and 3,322 surfaces. v0.3.4 populates 70 TLS,
DTLS, and QUIC-TLS rules across 40 authorities, 550 normative sections, 63
owner milestones, and 483 surfaces. v0.3.5 adds 49 optional, HPKE, ECH,
ML-KEM, entropy, operational, legacy, and residual requirements across 33
authorities, 182 reviewed normative sections, and 765 formerly uncovered
surfaces.
The complete closure covers 127 locked authorities, 231 roadmap rows, and
4,446 surfaces. Planned targets become actual code, tests, and evidence only
in their owning milestone.

## Coverage By Implementation Domain

| Domain | Current and compatibility authorities | Owning plan blocks | Audit result |
| --- | --- | --- | --- |
| Normative language and registries | RFC 2119, RFC 8174, RFC 8126, RFC 8447 as updated by RFC 9847, current IANA snapshots | v0.3.0-v0.3.5 | Covered; source/status/errata and registry drift must fail closed. |
| AEAD, HMAC, HKDF, ChaCha20-Poly1305 | RFC 2104, RFC 4231, RFC 5116, RFC 5869, RFC 8439 | v0.25.0-v0.31.0 | Covered, including bounds, failure, nonce, counter, and interface requirements. |
| RSA, ECDSA, Ed25519, X25519 and PKIX identifiers | RFC 3279, RFC 4055, RFC 5480, RFC 5756, RFC 5758, RFC 6979, RFC 7748, RFC 8017, RFC 8032, RFC 8410, RFC 8813, RFC 9295 | v0.32.0-v0.45.0, v0.50.0 | Covered; current AlgorithmIdentifier presence/absence rules and ambiguous encodings are explicit. |
| Key and certificate containers | RFC 5958, RFC 7468, RFC 8017, RFC 5912 | v0.20.0-v0.21.0, v0.48.0-v0.50.0 | Covered; encrypted private-key containers remain an explicit v1 exclusion. |
| PKIX path validation and names | RFC 5280 as updated by RFC 6818, RFC 9549, RFC 9598, RFC 9608, RFC 9618, RFC 9925, and RFC 10007; RFC 5890-RFC 5892 as updated by RFC 8753; RFC 9525 | v0.50.0-v0.57.1 | Gaps closed: current internationalized names, bounded policy graphs, noRevAvail, unsigned-certificate rejection, and v3 CRL-issuer cRLSign checks are explicit. |
| OCSP and TLS Feature | RFC 5754, RFC 6960 as updated by RFC 9654, RFC 9919; RFC 6066, RFC 6961, RFC 7633 | v0.58.0-v0.58.3, v0.71.0 | Gaps closed: current nonce bounds, Must-Staple, and the opt-in SHA-256 lightweight message and transport profiles have separate gates; status_request_v2 is an explicit TLS 1.2 v1 exclusion. |
| Certificate Transparency | RFC 6962 and RFC 9162 | v0.59.0, v0.71.0 | Covered through strictly versioned formats and caller-supplied verifier policy; v1 bytes can never be treated as v2 or vice versa. |
| TLS 1.3 | RFC 9846, RFC 8448, RFC 6066, RFC 7301, RFC 7685, RFC 8701, RFC 8996, RFC 9325, RFC 9850, RFC 9852, RFC 9963 | v0.10.0, v0.61.0-v0.82.0 | Covered. Production key logging, legacy PKCS1 client CertificateVerify, post-handshake authentication, and Heartbeat are deliberate v1 exclusions. |
| TLS 1.3 PSK, tickets, exporters and channel binding | RFC 5077 compatibility baseline, RFC 5705, RFC 5929, RFC 9257, RFC 9258, RFC 9266, RFC 9846, RFC 9973 | v0.74.0-v0.79.0 | Gaps closed: pairwise role and provisioning security now complement importer domain separation; certificate-with-external-PSK remains rejected for v1. |
| Hardened TLS 1.2 | RFC 5246 compatibility baseline; RFC 5288, RFC 5289, RFC 5746, RFC 6176, RFC 7465, RFC 7507, RFC 7627, RFC 7905, RFC 8422, RFC 9155, RFC 9325, RFC 9846, RFC 9851, RFC 10015 | v0.83.0-v0.93.0 | Gaps closed: current deprecations and the TLS-only feature freeze have dedicated gates. The current name Extended Main Secret is used while preserving the wire label. |
| QUIC TLS | RFC 9000-RFC 9002 and RFC 9369 | v0.94.0-v0.101.0 | Covered. TLS owns the recordless handshake; version-specific Initial secrets, Retry integrity, packet protection, key phase, and QUIC v2 remain caller transport responsibilities. |
| DTLS 1.2 and 1.3 | RFC 6347, RFC 9146, RFC 9147 as updated by RFC 9853, RFC 9325, RFC 10015 | v0.102.0-v0.116.0 | Gap closed: CID path changes now receive a separate basic/enhanced return-routability milestone. Early data remains explicitly excluded for v1. |
| ML-KEM and hybrid TLS | RFC 9935, RFC 9954, RFC 10024 plus FIPS 203 and SP 800-227 | v0.117.0-v0.122.0 | Generic construction and the three final standardized ECDHE-ML-KEM groups are covered as planning authority; ML-KEM PKIX credentials are excluded, implementation remains future work, and drafts and private identifiers remain forbidden. |
| HPKE | RFC 9180 | v0.138.0-v0.139.1 | Gap closed: Context.Export, export-only policy, ordered delivery, loss invalidation, role separation, unsupported modes, and complete context destruction are explicit. |
| ECH and DNS bootstrap boundary | RFC 9180, RFC 9460, RFC 9848, RFC 9849 | v0.140.0-v0.143.0 | Covered. DNS resolution and caching remain caller-owned; hostile ECHConfigList parsing, provenance, retry, and downgrade policy remain protocol-owned. |
| Raw public keys, delegated credentials, record size, and certificate compression | RFC 7250, RFC 8449, RFC 8879, RFC 9345 | v0.136.0-v0.137.0, v0.144.0-v0.146.1 | Covered with distinct trust, authorization, transcript, algorithm-provider, and resource boundaries. |
| Legacy TLS and SSL | RFC 2246, RFC 4346, RFC 6101, RFC 6151 plus authenticated local-only SSL, WTLS, PCT, and SNP sources | independent H0.1.0-H0.8.0 lines | Gap closed: H0.1.1 now freezes each package's exact cipher and protocol-surface subset before any weak primitive or codec work. |

## Explicitly Rejected Or Caller-Owned Surfaces

The following are deliberate boundaries rather than omissions:

- RFC 6520 Heartbeat is rejected in all modern TLS and DTLS profiles.
- RFC 6961 status_request_v2 is rejected for the hardened TLS 1.2 v1
  profile; the RFC 6066 status_request facility remains admitted.
- RFC 6066 max_fragment_length, client_certificate_url, trusted_ca_keys, and
  truncated_hmac remain absent from local configuration, offers, negotiation,
  tickets, and imported state; bounded peer ClientHello bodies are safely
  ignored without inner parsing or effects, while unsolicited responses are
  rejected. Record Size Limit and modern certificate-authority negotiation
  retain separate owners.
- RFC 9853 ContentType 27, RRC extension, message registry, and state are
  admitted only by the DTLS v0.111.1 return-routability boundary and rejected
  in stream TLS.
- RFC 9850 key logging is available only from a separately compiled
  test-support artifact and can never enter production crates or features.
- TLS 1.3 post-handshake client authentication is rejected for v1; ordinary
  handshake client authentication remains admitted future work.
- RFC 9963 legacy PKCS1 client CertificateVerify code points and RFC 9973
  certificate-with-external-PSK authentication are rejected for v1.
- RFC 9935 ML-KEM certificates and private-key containers are not admitted;
  ML-KEM is used only in the separately gated ephemeral hybrid key exchange.
- TLS 1.2 and DTLS 1.2 reject static RSA, finite-field DH, static ECDH, CBC,
  compression, MD5/SHA-1 signatures, renegotiation, and automatic fallback.
- HPKE v1 admits Base mode only. PSK, Auth, and AuthPSK modes require a future
  separately versioned decision.
- QUIC transport versions, Initial secrets, packet protection, Retry integrity,
  packet numbers, loss recovery, congestion control, key phase, and transport
  semantic enforcement remain outside `brynja-quic-tls`.
- ECH DNS, SVCB, and HTTPS resolution and network caching remain caller-owned;
  Brynja validates the supplied configuration bytes and their typed provenance.
- Certificate decompression algorithms remain bounded caller providers.
  Planned Brynja code owns negotiation, exact lengths, canonical comparison,
  transcript bytes, failure behavior, and artifact invalidation.
- `id-alg-unsigned` certificates are never accepted in a signature-verification
  context.
- Legacy packages implement only the exact H0.1.1 admitted interoperability
  subset; they do not imply every cipher ever registered for that protocol.

## Reviewed Update-Chain Exclusions

Reviewing an updated-by edge does not automatically admit or locally lock an
inapplicable document. The following direct updates were reviewed and excluded:

- RFC 4491 and RFC 8692 add GOST and SHAKE-based PKIX signature identifiers that
  are not admitted by v1; their families remain owned by v0.46.0.
- RFC 7320 and RFC 8820 govern URI scheme ownership and design rather than the
  admitted certificate-name comparison rules.
- RFC 4680, RFC 4681, and RFC 5878 define unadmitted TLS supplemental-data,
  user-mapping, and authorization extensions; v0.3.1 retains explicit
  rejection decisions.
- RFC 3546 and RFC 4366 are superseded TLS-extension baselines replaced by the
  locked RFC 6066/current TLS authorities; RFC 8446, RFC 5019, and RFC 8773 are
  likewise replaced by locked RFC 9846, RFC 9919, and RFC 9973 authorities.
- RFC 8398, RFC 8399, and RFC 8954 are superseded by the locked RFC 9598,
  RFC 9549, and RFC 9654 authorities.
- RFC 9480 and RFC 9810 update the RFC 5912 ASN.1 modules for CMP, which is not
  a Brynja protocol surface, and RFC 9907 is a YANG-document guideline unrelated
  to the RFC 8126 registry-policy rules used here.

## Residual Standards Gates

- Final RFC 10024 and matching IANA assignments resolve the ECDHE-ML-KEM source
  gate for exactly three planned groups. No draft bytes, private identifiers,
  or implementation outside v0.120.0 may ship.
- Current IANA TLS, DTLS, HPKE, QUIC, PKIX, and CT registries must be snapshotted
  again at each dependent implementation freeze.
- Verified errata and every later updated-by, obsoleted-by, BCP, NIST, or CMVP
  change require an applicability decision; a source update never silently
  changes an already reviewed implementation baseline.
- Legacy non-RFC sources remain machine-readably blocked until exact
  provenance, hashes, rights review, and per-protocol cipher decisions exist.
- FIPS validation milestones remain blocked until their dated FIPS, ISO,
  CMVP, laboratory, certificate, caveat, and operational-environment baseline
  is rights-reviewed and pinned at the dependent milestone.
