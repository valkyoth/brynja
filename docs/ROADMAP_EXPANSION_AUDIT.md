# Five-Part Roadmap Expansion Review

Date: 2026-09-05. Baseline: `b3c92ce`. Planning only; no cryptographic code or current implementation status changed.

## Result and sequence

All five groups from the gap review now have explicit owners in both
[VERSION_PLAN.md](VERSION_PLAN.md) and [RELEASE_PLAN.md](RELEASE_PLAN.md).
The [expansion register](ROADMAP_EXPANSION_REGISTER.json) binds 126 family/API
contracts and their prerequisites; the original 104-row catalogue inventory
remains intact. There are **802 new stops**, **2004 total milestones**,
**111 public checkpoints** and **1893 tagged development milestones**.
The final pre-RC gate moves to **v0.480.0**. This is not a package version bump.

- Existing v0.24.0–v0.24.23 identities are unchanged; next work is still v0.24.17.
- General SHA-512/t is v0.24.24–v0.24.29, before HMAC/catalogue consumers.
  The original named /224 and /256 APIs are not reclassified as incorrect.
- CT signature and proof verification is v0.100.1–v0.100.6 before the next audit.
- Added primitives, constructions, API backfills and research families occupy
  v0.351–v0.447. Formats occupy v0.448–v0.455.
- Larger protocols are deliberately last, v0.456–v0.474, followed by complete
  expansion integration at v0.475.0 and the preserved final gates v0.476–v0.480.
  Each larger protocol needs an explicit retain/remove scope decision before
  work. For now it is included: removal requires a reviewed roadmap change,
  consumer/dependency reconciliation and revised completeness claims.
- Every new family has admission, bounded implementation, lifecycle, runnable
  portable public acceptance and final evidence stages. New families have at
  most seven stops; future family size remains capped by the schedule validator.
  Discovery of substantial profile complexity requires another numbered stop
  *before* coding, not a larger unreviewed implementation commit.

## Scope and API rules

“Complete” refers to each exact named source/profile and operation matrix,
not every research idea or every possible cryptographic API. Admission must
resolve all variants, normative dependencies and security assumptions before
implementation. A source ambiguity blocks that profile; it is not permission
to omit it, invent an algorithm or mark a partial family fully implemented.
Drafts and submissions retain their exact identity and research status until
the final source and security review are admitted. There is no automatic
FIPS 140-3 validation, approval or modern-default routing for a new algorithm.

The v0.197.0 TLS configuration freeze no longer implies a ban on the intended
standalone family APIs, or completion of optional families scheduled later.
Unchecked internals remain private, and ordinary API availability never
confers FIPS-module approval. Final integration still follows every family.

First-party Rust cryptography and the no_std, narrow-graph design are unchanged.
Package names in the register are ownership proposals, not instructions to
make the facade depend on all packages. Small related internals may share a
leaf, but modern, legacy, research and noncryptographic result types remain
distinct. Optional application/framework adapters stay downstream. Reference
implementations are test oracles, never C-backed production dependencies.

Backfills cover current hash identities with typed digest codecs, multi-digest,
bounded batch/scatter input, carefully scoped ordinary reset/fork and XOF IO.
Detached tags, scatter/gather crypto, algorithm-specific batch verification,
Merkle proofs, manifests, authenticated streaming and durable nonce/state
reservation have their own owners. Missing public APIs are future additions;
released milestones are not rewritten to pretend they already exist.

Every secret-bearing API owns cleanup of its inaccessible state and temporaries
from its first implementation. It uses Brynja's existing compiler-resistant
sanitization boundary and sealed hardened capabilities, including output
classification, partial failure, cancellation, recoverable unwind and Drop.
An optional sanitization adapter cannot be the sole cleanup mechanism.
Registers, compiler copies, aborts, mem::forget and OS/hardware remnants retain
their honest residual limitations; callers still own their original inputs.

Portable external consumer tests come before optional backend work and final
evidence. A scalar-only implementation can be complete; acceleration cannot be
claimed from compilation or QEMU. New unsafe, parsers, authentication, secrets,
durable state and trust boundaries retain exceptional pentest triggers.
Scheduled publication remains every fifth minor .0, including intervening
patches in the cumulative delta. RISC-V native/community qualification is the
only explicitly retained post-1.0 work from these inventories.

## Important corrections and authoritative anchors

- [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) defines general
  SHA-512/t IV derivation, not only the already implemented named variants.
  New typed output and security policy distinguish short t values from the
  standard named SHA-2 API set; arbitrary t does not imply approved service.
- [CT v2](https://www.rfc-editor.org/rfc/rfc9162.html) signature and tree-proof
  verification must not stop at framing, or conflate CT v1 and v2 encodings.
- [Ascon SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/final) supplies the
  final AEAD128 identity; old submission profiles are not interchangeable.
- [FF1 revision draft](https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd) removes
  FF3 and tightens rules. Track its status; keep historical FF3/FF3-1 separate
  and never present draft text as a final standard.
- [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380.html),
  [RFC 9496](https://www.rfc-editor.org/rfc/rfc9496.html) and
  [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html) precede reusable
  OPRF and [OPAQUE](https://www.rfc-editor.org/rfc/rfc9807.html) consumers.
- [FROST](https://www.rfc-editor.org/rfc/rfc9591.html) does not provide a
  blanket DKG protocol. Dealer and separately accepted DKG key establishment
  are explicit, with different trust models and one-use nonce handling.
- [LMS/HSS](https://www.rfc-editor.org/rfc/rfc8554.html) and
  [XMSS](https://www.rfc-editor.org/rfc/rfc8391.html) need durable state before
  signing, not merely private-key serialization after signing.
- HOTP compatibility retains a separate SHA-1/HMAC adapter. SHA-1 collision
  status is not equated to an HMAC attack, but the existing no-legacy-in-modern
  graph policy remains enforced; SHA-256/512 TOTP has a modern owner.
- FN-DSA/Falcon and HQC require
  [current NIST source admission](https://csrc.nist.gov/projects/post-quantum-cryptography)
  at implementation. Pending standardization is never treated as completed.
- [PKCS12 PBMAC1 RFC 9879](https://www.rfc-editor.org/rfc/rfc9879.html) is
  included instead of relying solely on the older PFX protection profile.

## Family and API ownership

The ranges below map every approved finding to the new detailed implementation
chain. Group 1 closes family gaps; 2 adds general cryptography; 3 adds reusable
APIs; 4 covers obscure/legacy/research families; 5 covers formats and protocols.

| Group | Family or API | Version range | Proposed owner |
| --- | --- | --- | --- |
| 1 | General SHA-512/t | v0.24.24–v0.24.29 | `brynja-hash-sha2` |
| 1 | Certificate Transparency verification | v0.100.1–v0.100.6 | `brynja-pki-ct` |
| 3 | Existing hash API backfill | v0.351.0–v0.351.6 | `brynja-hash` |
| 1 | Original Keccak | v0.352.0–v0.352.5 | `brynja-hash-keccak` |
| 1 | Ascon-AEAD128 | v0.353.0–v0.353.5 | `brynja-aead-ascon` |
| 1 | Xoodyak keyed Cyclist | v0.354.0–v0.354.5 | `brynja-crypto-xoodyak` |
| 1 | Salsa20 and XSalsa20 | v0.355.0–v0.355.6 | `brynja-crypto-salsa20` |
| 1 | AES key wrap with padding | v0.356.0–v0.356.5 | `brynja-crypto-keywrap` |
| 2 | POLYVAL | v0.357.0–v0.357.5 | `brynja-crypto-polyval` |
| 2 | AES-GCM-SIV | v0.358.0–v0.358.5 | `brynja-aead-gcm-siv` |
| 2 | AES-SIV | v0.359.0–v0.359.5 | `brynja-aead-siv` |
| 2 | XChaCha20-Poly1305 | v0.360.0–v0.360.5 | `brynja-aead-xchacha20poly1305` |
| 2 | XTS-AES | v0.361.0–v0.361.5 | `brynja-crypto-xts` |
| 2 | FF1 format-preserving encryption | v0.362.0–v0.362.5 | `brynja-crypto-fpe` |
| 2 | Legacy FF3 family | v0.363.0–v0.363.5 | `brynja-legacy-fpe` |
| 2 | SP 800-108 KDFs | v0.364.0–v0.364.6 | `brynja-kdf-sp800108` |
| 2 | SP 800-56C derivation | v0.365.0–v0.365.5 | `brynja-kdf-sp80056c` |
| 3 | Durable nonce and one-time state | v0.366.0–v0.366.6 | `brynja-state` |
| 3 | Detached and scatter-gather crypto APIs | v0.367.0–v0.367.6 | `brynja-crypto` |
| 3 | Authenticated stream and file encryption | v0.368.0–v0.368.6 | `brynja-secretstream` |
| 3 | Reusable Merkle proofs | v0.369.0–v0.369.5 | `brynja-merkle` |
| 3 | Checksum manifests and multi-hash tools | v0.370.0–v0.370.5 | `brynja-hash-tools` |
| 2 | secp256k1 | v0.371.0–v0.371.6 | `brynja-crypto-secp256k1` |
| 1 | Brainpool curves | v0.372.0–v0.372.6 | `brynja-legacy-ec-brainpool` |
| 1 | Historical prime-field SEC curves | v0.373.0–v0.373.5 | `brynja-legacy-ec-sec` |
| 1 | Binary-field arithmetic | v0.374.0–v0.374.5 | `brynja-legacy-field-binary` |
| 1 | Binary and Koblitz curves | v0.375.0–v0.375.6 | `brynja-legacy-ec-binary` |
| 4 | BLS12-381 pairing substrate | v0.376.0–v0.376.5 | `brynja-research-pairing` |
| 2 | Hash to field and curve | v0.377.0–v0.377.6 | `brynja-crypto-hash-to-curve` |
| 2 | ristretto255 and decaf448 | v0.378.0–v0.378.5 | `brynja-crypto-prime-groups` |
| 2 | OPRF VOPRF and POPRF | v0.379.0–v0.379.5 | `brynja-oprf` |
| 2 | OPAQUE | v0.380.0–v0.380.6 | `brynja-pake-opaque` |
| 2 | SPAKE2 | v0.381.0–v0.381.5 | `brynja-pake-spake2` |
| 2 | SPAKE2+ | v0.382.0–v0.382.5 | `brynja-pake-spake2plus` |
| 2 | HOTP and TOTP | v0.383.0–v0.383.6 | `brynja-auth-otp` |
| 4 | Verifiable secret sharing | v0.384.0–v0.384.5 | `brynja-research-vss` |
| 4 | Threshold key establishment | v0.385.0–v0.385.5 | `brynja-research-dkg` |
| 2 | FROST threshold signatures | v0.386.0–v0.386.6 | `brynja-crypto-frost` |
| 2 | Verifiable random functions | v0.387.0–v0.387.5 | `brynja-crypto-vrf` |
| 2 | RSA blind signatures | v0.388.0–v0.388.5 | `brynja-crypto-rsa-blind` |
| 2 | LMS and HSS | v0.389.0–v0.389.6 | `brynja-sign-lms` |
| 2 | XMSS and XMSSMT | v0.390.0–v0.390.6 | `brynja-sign-xmss` |
| 2 | FN-DSA and Falcon profiles | v0.391.0–v0.391.6 | `brynja-research-fn-dsa` |
| 2 | HQC | v0.392.0–v0.392.6 | `brynja-research-kem-hqc` |
| 4 | Serpent | v0.393.0–v0.393.5 | `brynja-legacy-cipher-serpent` |
| 4 | RC6 | v0.394.0–v0.394.5 | `brynja-legacy-cipher-rc6` |
| 4 | CAST6 | v0.395.0–v0.395.5 | `brynja-legacy-cipher-cast6` |
| 4 | TEA | v0.396.0–v0.396.5 | `brynja-legacy-cipher-tea` |
| 4 | XTEA | v0.397.0–v0.397.5 | `brynja-legacy-cipher-xtea` |
| 4 | XXTEA | v0.398.0–v0.398.5 | `brynja-legacy-cipher-xxtea` |
| 4 | SAFER | v0.399.0–v0.399.5 | `brynja-legacy-cipher-safer` |
| 4 | Skipjack | v0.400.0–v0.400.5 | `brynja-legacy-cipher-skipjack` |
| 4 | Noekeon | v0.401.0–v0.401.5 | `brynja-legacy-cipher-noekeon` |
| 4 | SHACAL-2 | v0.402.0–v0.402.5 | `brynja-legacy-cipher-shacal-2` |
| 4 | CLEFIA | v0.403.0–v0.403.5 | `brynja-legacy-cipher-clefia` |
| 4 | Kalyna | v0.404.0–v0.404.5 | `brynja-legacy-cipher-kalyna` |
| 4 | LEA | v0.405.0–v0.405.5 | `brynja-legacy-cipher-lea` |
| 4 | HIGHT | v0.406.0–v0.406.5 | `brynja-legacy-cipher-hight` |
| 4 | PRESENT | v0.407.0–v0.407.5 | `brynja-legacy-cipher-present` |
| 4 | MISTY1 | v0.408.0–v0.408.5 | `brynja-legacy-cipher-misty1` |
| 4 | KASUMI | v0.409.0–v0.409.5 | `brynja-legacy-cipher-kasumi` |
| 4 | Rabbit | v0.410.0–v0.410.5 | `brynja-legacy-stream-rabbit` |
| 4 | HC-128 | v0.411.0–v0.411.5 | `brynja-legacy-stream-hc-128` |
| 4 | HC-256 | v0.412.0–v0.412.5 | `brynja-legacy-stream-hc-256` |
| 4 | SOSEMANUK | v0.413.0–v0.413.5 | `brynja-legacy-stream-sosemanuk` |
| 4 | Trivium | v0.414.0–v0.414.5 | `brynja-legacy-stream-trivium` |
| 4 | Grain | v0.415.0–v0.415.5 | `brynja-legacy-stream-grain` |
| 4 | SNOW | v0.416.0–v0.416.5 | `brynja-legacy-stream-snow` |
| 4 | ZUC | v0.417.0–v0.417.5 | `brynja-legacy-stream-zuc` |
| 4 | Cellular confidentiality and integrity | v0.418.0–v0.418.5 | `brynja-legacy-cellular` |
| 4 | CubeHash | v0.419.0–v0.419.5 | `brynja-legacy-hash-cubehash` |
| 4 | Shabal | v0.420.0–v0.420.5 | `brynja-legacy-hash-shabal` |
| 4 | Luffa | v0.421.0–v0.421.5 | `brynja-legacy-hash-luffa` |
| 4 | Fugue | v0.422.0–v0.422.5 | `brynja-legacy-hash-fugue` |
| 4 | Hamsi | v0.423.0–v0.423.5 | `brynja-legacy-hash-hamsi` |
| 4 | ECHO | v0.424.0–v0.424.5 | `brynja-legacy-hash-echo` |
| 4 | SHAvite-3 | v0.425.0–v0.425.5 | `brynja-legacy-hash-shavite-3` |
| 4 | SIMD | v0.426.0–v0.426.5 | `brynja-legacy-hash-simd` |
| 4 | BMW | v0.427.0–v0.427.5 | `brynja-legacy-hash-bmw` |
| 4 | yescrypt | v0.428.0–v0.428.5 | `brynja-password-yescrypt` |
| 4 | Unix crypt compatibility | v0.429.0–v0.429.6 | `brynja-legacy-password-crypt` |
| 4 | TLSH | v0.430.0–v0.430.5 | `brynja-similarity-tlsh` |
| 4 | ssdeep | v0.431.0–v0.431.5 | `brynja-similarity-ssdeep` |
| 4 | sdhash | v0.432.0–v0.432.5 | `brynja-similarity-sdhash` |
| 4 | BLS signatures | v0.433.0–v0.433.5 | `brynja-research-sign-bls` |
| 4 | Commitment schemes | v0.434.0–v0.434.5 | `brynja-research-commitment` |
| 4 | Paillier | v0.435.0–v0.435.5 | `brynja-research-paillier` |
| 4 | Proof transcript and circuit substrate | v0.436.0–v0.436.5 | `brynja-research-proof-core` |
| 4 | Groth16 | v0.437.0–v0.437.5 | `brynja-research-zk-groth16` |
| 4 | Bulletproofs | v0.438.0–v0.438.5 | `brynja-research-zk-bulletproofs` |
| 4 | PLONK | v0.439.0–v0.439.5 | `brynja-research-zk-plonk` |
| 4 | Lattice HE arithmetic | v0.440.0–v0.440.5 | `brynja-research-he-core` |
| 4 | BFV | v0.441.0–v0.441.6 | `brynja-research-he-bfv` |
| 4 | BGV | v0.442.0–v0.442.6 | `brynja-research-he-bgv` |
| 4 | CKKS | v0.443.0–v0.443.6 | `brynja-research-he-ckks` |
| 4 | TFHE | v0.444.0–v0.444.6 | `brynja-research-he-tfhe` |
| 4 | Oblivious transfer | v0.445.0–v0.445.5 | `brynja-research-ot` |
| 4 | Garbled-circuit two-party computation | v0.446.0–v0.446.6 | `brynja-research-mpc-2pc` |
| 4 | Arithmetic MPC | v0.447.0–v0.447.6 | `brynja-research-mpc-arithmetic` |
| 5 | Bounded JSON and CBOR codecs | v0.448.0–v0.448.6 | `brynja-encoding` |
| 5 | CMS signed and authenticated containers | v0.449.0–v0.449.6 | `brynja-cms` |
| 5 | CMS encrypted recipients | v0.450.0–v0.450.6 | `brynja-cms` |
| 5 | PKCS12 PFX | v0.451.0–v0.451.6 | `brynja-pkcs12` |
| 5 | JOSE keys and signatures | v0.452.0–v0.452.6 | `brynja-jose` |
| 5 | JOSE encryption | v0.453.0–v0.453.5 | `brynja-jose` |
| 5 | COSE keys signatures and MACs | v0.454.0–v0.454.5 | `brynja-cose` |
| 5 | COSE encryption and tokens | v0.455.0–v0.455.5 | `brynja-cose` |
| 5 | SSH transport | v0.456.0–v0.456.6 | `brynja-ssh` |
| 5 | SSH authentication and key formats | v0.457.0–v0.457.6 | `brynja-ssh` |
| 5 | SSH connection services | v0.458.0–v0.458.6 | `brynja-ssh` |
| 5 | Noise framework | v0.459.0–v0.459.6 | `brynja-noise` |
| 5 | WireGuard handshake | v0.460.0–v0.460.5 | `brynja-wireguard` |
| 5 | WireGuard tunnel | v0.461.0–v0.461.6 | `brynja-wireguard` |
| 5 | MLS tree and key packages | v0.462.0–v0.462.5 | `brynja-mls` |
| 5 | MLS group transitions | v0.463.0–v0.463.6 | `brynja-mls` |
| 5 | MLS messaging and lifecycle | v0.464.0–v0.464.6 | `brynja-mls` |
| 5 | SRTP and SRTCP | v0.465.0–v0.465.6 | `brynja-srtp` |
| 5 | EDHOC | v0.466.0–v0.466.6 | `brynja-edhoc` |
| 5 | OSCORE | v0.467.0–v0.467.6 | `brynja-oscore` |
| 5 | IKEv2 negotiation and authentication | v0.468.0–v0.468.6 | `brynja-ikev2` |
| 5 | IKEv2 lifecycle | v0.469.0–v0.469.6 | `brynja-ikev2` |
| 5 | IPsec ESP and AH | v0.470.0–v0.470.6 | `brynja-ipsec` |
| 5 | IPsec policy and integration | v0.471.0–v0.471.6 | `brynja-ipsec` |
| 5 | S-MIME | v0.472.0–v0.472.6 | `brynja-smime` |
| 5 | Timestamping | v0.473.0–v0.473.5 | `brynja-timestamp` |
| 5 | WebAuthn relying-party verification | v0.474.0–v0.474.6 | `brynja-webauthn` |

## Validation and limitations

The schedule retains old stable IDs and exact reviewed prerequisite edges.
The expansion validator checks each family, operation, stage, package owner,
source/test contract, dependency and late-protocol ordering. Mutation tests
exercise omission, wrong owner, missing acceptance, scope drift and dependency
regressions. Existing catalogue and requirement-history controls stay enabled.

Exact primary-source acquisition, redistribution review and per-clause mapping
are mandatory admission deliverables for the new families, not falsely claimed
as completed by this planning pass. The normative authority count therefore
does not increase merely because a future source URL appears in a roadmap.
