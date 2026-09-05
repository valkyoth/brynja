# Public Operation And Prerequisite Roadmap Audit

Date: 2026-09-05
Scope: planning review during v0.24.16, not an implementation or security audit

## Outcome

Standalone DER encode/decode completion now has an explicit closing gate at
**v0.33.9**, before ECDSA signature encoding, encrypted-key containers and
PKIX issuance consume it. The existing v0.20.0 reader and v0.21.0 value APIs
remain accurately described as implemented foundations, not a complete
bidirectional codec. No defect in those implementations is asserted here.

The initial operation-direction review expanded 528 stops to 556. The subsequent
catalogue consolidation adds 630 stops, producing **1186 ordered milestones**,
including the release candidate. It maps all 104 original hash inventory rows,
reuses existing owners, brings SSL1 provenance research before 1.0 and moves
final integration/audit after the catalogue. The generated requirements
closure contains **1185 non-RC rows**, 130 locked authorities, 4,459 registered
surfaces and 172 requirements. Newly planned capabilities remain fenced by
explicit authority admission; these counts do not mean their standards or
implementations have already been reviewed.

This is not a proof that no future requirement or implementation defect will
be discovered. It is a roadmap-level operation and dependency audit, not a new
line-by-line audit of every RFC, cipher or protocol. No cryptographic source,
current algorithm status, dependency, CPU admission or release cadence changes.

## Corrections And Exact Owners

| Gap or ambiguity | Implementation and closing boundary |
| --- | --- |
| DER reading existed, but no reusable writer or full type/schema acceptance was assigned | v0.33.3 ownership/type inventory; .4 length/framing writer; .5 basic value pairs; .6 extended value pairs; .7 schema/constructed rules; .8 hardened serialization; .9 standalone final acceptance |
| A DER writer inside PKI would force crypto to depend on PKI or duplicate encoders | One future `brynja-encoding-der` leaf; existing `brynja-pki` APIs re-export it, and ECDSA/key-format consumers depend downward on the same owner |
| P-521 closed ECDH but had no explicit ECDSA stop | v0.45.15 complete P-521 signing/verifying and portable fixture; v0.45.16 signature-specific backend/final acceptance |
| Ephemeral-only key-lifecycle wording could prevent legitimate static agreement | v0.45.17 explicitly reusable static owners; v0.45.18 static/ephemeral acceptance; single-use ephemeral rules remain intact |
| PEM scope did not explicitly close public output APIs | v0.48.0 bounded decoding; v0.48.1 transactional encoding; v0.48.2 paired acceptance |
| Private-key formats were explicit, standalone public-key formats less so | v0.49.5 SPKI; v0.49.6 raw and PKCS1 public formats; v0.49.7 independent format/operation acceptance |
| QUIC transport parameters named parsing without equally explicit caller-facing encoding | Both directions in v0.97.0; v0.97.1 public codec acceptance, without moving transport authority into Brynja |
| PKIX completion wording ran ahead of executable ML-KEM and possible hybrid components | v0.60.11/.13 remain structural where primitives are unavailable; .14/.15 close only the then-executable surface; v0.122.1-.3 close executable PQ PKIX integration after its prerequisites |
| Argon2 depended on an unnamed private BLAKE2b implementation | v0.167.2 sequential BLAKE2b and keyed mode; .3 hardened unkeyed ownership; .4 portable acceptance; .5 backend/final acceptance; Argon2 reuses it and owns its exact H-prime composition |
| EAX could hide a second MAC implementation | v0.167.6 reusable AES-CMAC generation/verification; .7 public/backend acceptance; EAX reuses it for its specified domain-separated OMAC operations |
| OpenPGP client acceptance promised export but had no equally explicit implementation owner | v0.176.2 public/protected-secret and explicitly authorized typed-secret unprotected export, paired with import; non-exportable handles stay non-exportable |
| Early RSA wording incorrectly said v1 would not generate keys | v0.44.0 now defers generation only until the already planned v0.46.55 owner |
| An early substrate gate could demand algorithms intentionally scheduled much later | v0.46.93 distinguishes completed consumer dependencies from explicitly numbered later owners; no executable forward dependency is permitted |
| A late protocol integration could conceal an unfinished standalone direction | v0.281.1 whole-project public-operation closure before integrated release rehearsal |

The DER rule/type inventory is derived from authenticated ASN.1 and DER
authorities, including edition-specific rules and errata. DER is not shorthand
for all ASN.1 transfer syntaxes or an ASN.1 compiler. The source baseline is
[ITU-T X.690](https://www.itu.int/rec/T-REC-X.690/en); additional necessary
ASN.1 authorities must pass source and redistribution review before the new
codec work begins.

The key-format audit uses the separation between raw keys and SPKI/private-key
containers described by [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480.html)
and [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html). Serialization,
mathematical key validity and application trust are different claims.

Argon2 explicitly uses BLAKE2b and its H-prime composition; it cannot use a
private copy while the reusable hash is deferred to post-1.0.
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html#section-3.3) and
[RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html) anchor that dependency.
Only sequential BLAKE2b is moved before Argon2: BLAKE2s, BLAKE2X and standalone
tree/parallel variants retain distinct later scopes and cannot be claimed
complete merely because BLAKE2b is complete.

The reusable MAC prerequisite follows the OMAC composition in the
[EAX specification](https://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf) and the
[CMAC specification](https://csrc.nist.gov/pubs/sp/800/38/b/upd1/final).
EAX still owns its exact domain separation and AEAD rules; a standalone CMAC
test does not establish correct EAX composition.

## Remaining Roadmap Pass

| Area reviewed | Existing coverage or explicit boundary retained |
| --- | --- |
| SHA-2, SHA-3/SHAKE, SP 800-185 and legacy hashes | Mathematical hashes/XOFs have no inverse; byte/bit and ordinary/hardened profiles retain their explicit acceptance chains. SP 800-185 integer framing is an algorithm input construction, not a promised general decoder. |
| HMAC, KMAC, Poly1305, GMAC and KDFs | MAC tag generation/verification and derivation are already assigned; a KDF has no password-recovery or inverse API. |
| AES, ChaCha20, block modes and AEADs | Cipher directions, seal/open, overlap, counter limits and authenticated plaintext release are already assigned through v0.27-v0.31 and v0.46 mode closures. |
| RSA, other ECC, DSA, ElGamal and regional algorithms | Key operations and sign/verify, agreement or encrypt/decrypt are assigned to named owners and acceptance rows; the P-521 and static-owner additions close the explicit gaps above. |
| ML-DSA, SLH-DSA and ML-KEM | Sign/verify or keygen/encapsulate/decapsulate already have full chains; PQ PKIX use now closes after executable prerequisites. |
| Compression | DEFLATE, ZLIB, Brotli, Zstandard, LZS and BZip2 already assign both encoding and decoding plus public acceptance. Checksums are verification values, not reversible encodings. |
| PKCS8, SEC1, PKCS1 and encrypted containers | Private import/export already has v0.49.0-.4 acceptance; it now explicitly reuses earlier DER and is complemented by public-key container acceptance. |
| PKIX requests, certificates, CRLs and OCSP | Validation and generation/issuance are separately assigned at v0.50-v0.60; extended PQ closure is explicit at v0.122.3. Trust/path validation is not simply the inverse of issuance. |
| TLS 1.3 and TLS 1.2 | Codec, client/server, record protection, session and extension directions close through conformance and optional/legacy integration gates; incomplete handshake stages are not complete TLS products. |
| QUIC/TLS | The handshake and parameter boundary has input/output APIs; full QUIC packet transport, loss recovery and network I/O remain caller-owned. |
| DTLS | Record/epoch, fragment/reassembly, flights, timers and client/server operations close through v0.116; standard-forbidden or out-of-profile operations retain explicit dispositions. |
| Entropy, DRBG and FIPS | Generation, reseeding, lifecycle and self-tests are operation sets rather than reversible codecs; validation is a distinct artifact/certificate process, not API completeness. |
| HPKE, ECH, delegated credentials and certificate compression | KEM encapsulation/decapsulation, seal/open, both ECH roles and compression receive/send already have explicit owners and acceptance. Static key reuse now has a separate underlying lifecycle owner. |
| Ecosystem and platform adapters | Host effects and framework traits remain optional downstream boundaries; adapter convenience cannot replace a missing core operation or add native cryptography. |
| OpenPGP | Packet, key, sign/verify, encrypt/decrypt, wrap/unwrap, armor and both compression directions are assigned; explicit key export and primitive prerequisites are added above. Application trust, storage and discovery remain caller-owned. |
| Named legacy protocols | Both client/server and applicable send/receive operations remain scheduled through v0.180.24, with dangerous selection and source-rights blockers rather than silent modern fallback. |
| Final product | v0.281.1 checks the complete public operation inventory, followed by integrated rehearsal, external audit, remediation and exact-candidate gates. |

## Enforcement And Follow-Up

Both plans repeat identical ordered titles and scopes. The release-plan checker
now also validates critical prerequisite edges and public-direction scope
contracts. Its new regression cases remove prerequisites, move consumers ahead
of them and weaken both plans' operation wording together. These checks detect
specific planning regressions; they are not a semantic proof of completeness.

Each new implementation stop must populate exact source requirements, safe API
profiles, resource and secret-state owners, public examples and independent
test oracles before code is admitted. If a type, algorithm or profile grows
beyond reviewable scope, split it into further numbered stops before its
consumer. Preserve the normal exceptional pentest triggers for hostile
parsers, cryptography and secret handling.

Current README implementation tables must not turn green because this plan was
expanded. Only the corresponding implemented and evidenced closing gate can
change a capability's status; independent verification and FIPS validation
remain separate throughout.

## Validation Of This Planning Change

- Both plans: 1186 matching, ordered and scope-locked sections.
- Catalogue: every one of 104 inherited inventory rows maps to named owners;
  93 family sequences and their source/API/lifecycle/acceptance boundaries are
  checked, including reuse instead of duplicate SHA, MAC and password owners.
- Prerequisites: corrected SHA-512/t reuse to v0.23.2 and bound MDC to complete
  DES acceptance at v0.46.18; Threefish, scrypt internals and research arithmetic
  precede their consumers. Missing newly authenticated dependencies require
  explicit child patches before implementation, never private partial copies.
- Regression coverage: 416 catalogue-specific negative fixtures reject lost
  inventory mappings, missing API stages, late prerequisites, weakened paired
  scopes, classification escape and backend work preceding portable acceptance.
- Operation-direction and prerequisite regression suite: 61 negative cases.
- Requirements: deterministic regeneration, 1185 non-RC rows, and all 22
  residual-closure tests pass after updating the frozen count for added rows.
- Complete `scripts/checks.sh`, both hash acceptance bindings, documentation
  links, committed SBOM comparison and `git diff --check`: pass.
- Production Rust, Cargo manifests/lockfile, crate selections and CPU
  admissions: unchanged. These checks validate the planning/tooling change,
  not the future implementations described in the new milestones.
