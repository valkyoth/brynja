# Brynja Post-1.0 Hashing Expansion Plan

Status: non-normative post-1.0 design plan; no versions assigned

This document records only genuinely independent catalogue expansion beyond
Brynja's complete pre-1.0 TLS, RFC 9580 OpenPGP, and transitive primitive
scope. It is deliberately low priority: `1.0.0` has no deadline or version-count
limit, and no standardized family member, named construction, mandatory
algorithm, or implementation dependency of a pre-1.0 capability may be left
here merely to shorten the pre-1.0 line. It does not add an
implementation claim, reserve crates.io names, authorize an algorithm, or
change the v1 secure-protocol scope.
Actual versions, ordering, release trains, and publication selections will be
assigned only after `v1.0.0`.

The inventory starts with Wikipedia's
[List of hash functions](https://en.wikipedia.org/wiki/List_of_hash_functions)
as retrieved on 2026-08-09 at page revision `1341431385`. That page explicitly
describes itself as incomplete and mixes checksums, universal hashes,
non-cryptographic hashes, MACs, perceptual hashes, and cryptographic hashes.
It is therefore an inventory aid, never a normative or security authority.
Every implementation must instead lock an authoritative specification,
reference or original-design source, errata, parameter set, vectors, rights
disposition, and security status before code is admitted.

## Outcome

The intended result is a collection of independently selectable `no_std`
families sharing small stable interfaces and never forcing an application to
compile every algorithm. TLS consumes the same SHA-2, SHA-3, SHAKE, and HMAC
implementations exposed to standalone users; no algorithm is reimplemented in
the protocol stack.

The ordinary `brynja` crate may eventually expose a default-off `hash` module
for a small curated modern facade. Direct dependencies on the family crate
remain the preferred path. The main facade never re-exports the complete
catalogue, and no `all-hashes` feature is added to it.

Implementing an obsolete or non-cryptographic algorithm means implementing
its specified behavior, not endorsing it for security. Type names, package
names, documentation, compile-time boundaries, and diagnostics must make that
distinction visible.

## Golden Rules

- Every implementation, compression function, permutation, tree mode, MAC,
  checksum engine, CPU kernel, and FIPS service is first-party Rust source.
  No C, C++, assembly file, system library, vendor library, foreign ABI, or
  delegated provider is permitted.
- Portable implementations are dependency-free and `no_std`, require no
  allocator, and remain usable from Rust 1.90.0 unless a later major policy
  explicitly changes the project-wide MSRV.
- Family crates depend only on their narrowly required Brynja interface crate.
  They never depend on TLS, PKI, a facade, another unrelated family, a legacy
  aggregate, runtime detection, or a FIPS facade.
- No source file exceeds 500 lines. Compression, padding, parameters,
  streaming state, vectors, CPU kernels, and proof harnesses remain separate.
- Fixed-output digests, extendable-output functions, rolling hashes, keyed
  functions, MACs, checksums, check digits, universal families, and perceptual
  hashes use different traits. Similar byte output is not type equivalence.
- Deprecated and broken cryptographic algorithms live under
  `brynja-legacy-hash-*`; experimental or insufficiently specified work lives
  under `brynja-research-hash-*`. Neither can enter `brynja`, `brynja-hash`,
  TLS, PKI, a default feature, or the FIPS module.
- Non-cryptographic results cannot satisfy a cryptographic digest, MAC,
  signature-prehash, transcript, certificate, KDF, password-hash, or integrity
  policy trait.
- Algorithm names are not security claims. Every crate README carries its
  collision, preimage, length-extension, keyed-use, parameter, truncation,
  deprecation, independent-review, and FIPS status.
- No implementation is FIPS validated merely because its algorithm appears in
  a NIST standard. FIPS use requires an exact certificate-bound module
  artifact, approved service, parameter set, self-test, operational
  environment, and service indicator.
- Before assigning a post-1.0 version, mechanically prove that the item is not
  a missing member, named instantiation, normative dependency, compatibility
  dependency, or advertised consumer of any pre-1.0 family. If it is, update
  the normative pre-1.0 plans instead.

## Dependency Architecture

```text
brynja (TLS facade; optional curated hash re-export only after 1.0)
└── brynja-hash (small modern convenience facade; no catalogue-wide default)
    └── brynja-hash-core (traits and value types; no algorithm)

direct modern family crates
├── brynja-hash-sha2       ─┐
├── brynja-hash-sha3        │ depend only on brynja-hash-core
├── brynja-hash-blake       │ and their own admitted CPU boundary
├── brynja-hash-blake2      │
├── brynja-hash-blake3      │
├── brynja-hash-ascon       │
└── later admitted families ─┘

separate semantic domains
├── brynja-mac-core and brynja-mac-*
├── brynja-checksum-core and brynja-checksum-*
├── brynja-hash-universal-*
├── brynja-hash-noncrypto-*
└── brynja-perceptual-hash-*

isolated compatibility and research
├── brynja-legacy-hash-*
└── brynja-research-hash-*
```

`brynja-hash-core` owns only interfaces such as fixed output, extendable
output, incremental update, finalization, reset policy, checked message length,
algorithm identity, output size, and closed errors. It contains no algorithm
registry switch, heap allocation, stringly selected algorithm, trait object,
CPU detection, or protocol behavior.

The curated `brynja-hash` facade should initially contain only independently
reviewed modern families with stable specifications and credible use cases. A
catalogue algorithm is selected by depending on its family crate. This avoids
one optional dependency per historical algorithm in the main facade and keeps
`cargo build --all-features` from silently becoming an all-algorithm build.

`brynja-checksum` is deliberately not named `brynja-hash-chksum`. Checksums do
not provide cryptographic collision or adversarial-integrity guarantees.
`brynja-mac` is separate because keyed authentication has secret-lifecycle,
verification, tag-length, replay-context, and misuse requirements absent from
an unkeyed digest.

CPU implementations reuse the pre-1.0 sealed backend contract. Scalar family
crates remain authoritative. Separately selected `no_std` ISA packages and the
opt-in `std` detector may accelerate an exact operation without causing a
scalar-only user to pull unrelated algorithms or host services.

## Complete Wikipedia Baseline Inventory

Every name below must receive one machine-readable disposition: `modern`,
`utility`, `legacy`, `research`, `blocked-source`, `rejected`, or
`caller-profile`. A grouped row still requires an individual parameter and
vector record for every named variant.

### Cyclic Redundancy Checks

| Inventory item | Planned home and disposition |
| --- | --- |
| Unix `cksum` | `brynja-checksum-crc`; utility profile including appended length |
| CRC-8 | Parameterized `brynja-checksum-crc`; utility |
| CRC-16 | Parameterized `brynja-checksum-crc`; utility |
| CRC-32 | Parameterized `brynja-checksum-crc`; utility |
| CRC-64 | Parameterized `brynja-checksum-crc`; utility |

CRC width alone is not an algorithm identity. Each admitted profile records
width, polynomial, initial value, input/output reflection, output XOR, residue,
check value, byte/bit order, augmentation rule, and canonical name.

### Checksums And Check Digits

| Inventory item | Planned home and disposition |
| --- | --- |
| BSD Unix checksum | `brynja-checksum-sum`; utility compatibility |
| System V Unix checksum | `brynja-checksum-sum`; utility compatibility |
| `sum8`, `sum24`, `sum32` | `brynja-checksum-sum`; explicitly parameterized utility |
| Internet checksum | `brynja-checksum-internet`; exact one's-complement profile |
| Fletcher-4, Fletcher-8, Fletcher-16, Fletcher-32 | `brynja-checksum-fletcher`; utility |
| Adler-32 | `brynja-checksum-adler`; utility |
| `xor8` | `brynja-checksum-sum`; weak utility only |
| Luhn | `brynja-checksum-checkdigit`; decimal validation only |
| Verhoeff | `brynja-checksum-checkdigit`; decimal validation only |
| Damm | `brynja-checksum-checkdigit`; exact quasigroup profile |

### Universal And Rolling Families

| Inventory item | Planned home and disposition |
| --- | --- |
| Rabin fingerprint | `brynja-hash-universal-rabin`; exact polynomial/profile required |
| Tabulation hashing | `brynja-hash-universal-tabulation`; caller-keyed utility |
| Universal one-way hashing | Research umbrella term until a concrete construction is named |
| Zobrist hashing | `brynja-hash-universal-zobrist`; caller-owned table/key material |
| Buzhash | `brynja-hash-noncrypto-rolling`; content-defined utility |

### Non-Cryptographic Hashes

| Inventory item | Planned home and disposition |
| --- | --- |
| Pearson hashing | `brynja-hash-noncrypto-classic`; exact table profile |
| SuperFastHash | `brynja-hash-noncrypto-classic`; compatibility |
| FNV-1/FNV-1a, 32/64/128/256/512/1024 | `brynja-hash-noncrypto-fnv`; each width and offset basis explicit |
| Jenkins families | Split one-at-a-time; never treat the surname as one algorithm |
| Bernstein `djb2` variants | `brynja-hash-noncrypto-classic`; each add/XOR variant named |
| PJW and ELF hash | `brynja-hash-noncrypto-classic`; distinct profiles |
| MurmurHash variants | `brynja-hash-noncrypto-murmur`; exact version, width, and seed |
| Fast-Hash | Research until the exact referenced design is source-locked |
| SpookyHash | `brynja-hash-noncrypto-spooky`; exact version and output width |
| CityHash | Source/rights-reviewed compatibility family |
| FarmHash | Source/rights-reviewed compatibility family |
| MetroHash | Source/rights-reviewed compatibility family |
| Numeric hash (`nhash`) | Research until a stable specification and use profile exist |
| xxHash | `brynja-hash-noncrypto-xxhash`; exact XXH32/XXH64 profiles |
| t1ha | Source/rights-reviewed family with exact version and mode |
| GxHash | Research/CPU-specific; AES capability and fallback must be explicit |
| SDBM | `brynja-hash-noncrypto-classic`; 32/64-bit profiles |
| OSDB hash | Research until the exact algorithm and source are locked |
| komihash | Source/rights-reviewed family with exact version and seed policy |
| `pHash` and `dhash` | `brynja-perceptual-hash-*`; normalized-media profiles, not byte digests |

### Keyed Cryptographic Functions And MACs

| Inventory item | Planned home and disposition |
| --- | --- |
| Keyed BLAKE2 | `brynja-hash-blake2`; typed keyed mode, never confused with HMAC |
| Keyed BLAKE3 | `brynja-hash-blake3`; keyed and derive-key modes separated |
| HMAC | Reuse the complete pre-1.0 `brynja-mac-hmac`; post-1.0 work may add only independently admitted hash adapters or convenience facades |
| KMAC | `brynja-mac-kmac`; KMAC128/KMAC256 and customization explicit |
| Keyed MD6 | `brynja-legacy-hash-md6` or research depending security review |
| OMAC/CMAC | `brynja-mac-cmac`; exact block-cipher and tag parameters |
| PMAC | `brynja-mac-pmac`; separately reviewed construction |
| Poly1305-AES | `brynja-legacy-mac-poly1305-aes`; never replace modern Poly1305 use |
| SipHash | `brynja-mac-siphash`; PRF/hash-table defense, not collision-resistant digest |
| HighwayHash | `brynja-mac-highway`; exact output and CPU/scalar profiles |
| UMAC | `brynja-mac-umac`; exact nonce and tag profiles |
| VMAC | `brynja-mac-vmac`; exact nonce and tag profiles |

### Unkeyed Cryptographic Hashes

| Inventory item | Planned home and disposition |
| --- | --- |
| BLAKE-256 and BLAKE-512 | `brynja-hash-blake`; historical but not automatically insecure |
| BLAKE2s, BLAKE2b, BLAKE2X | `brynja-hash-blake2`; modern family with each parameter tree explicit |
| BLAKE3 | `brynja-hash-blake3`; hash, XOF, keyed, derive-key, and tree modes separated |
| ECOH | Research or legacy after source/security review |
| FSB | Research/NIST-competition history; no modern facade by default |
| GOST hash | Split GOST R 34.11-94 from Streebog; legacy compatibility only |
| Grøstl | Standalone family after source and security review |
| HAS-160 | `brynja-legacy-hash-has160` |
| HAVAL | `brynja-legacy-hash-haval`; passes and output sizes explicit |
| JH | Standalone competition family after review |
| LSH | Standalone family with LSH-256/LSH-512 parameters explicit |
| MD2 and MD4 | Separate post-1.0 `brynja-legacy-hash-md2` and `brynja-legacy-hash-md4` crates with hard warnings; MD5 already has one complete pre-1.0 compatibility implementation and must only be re-exported, never reimplemented |
| MD6 | Research/legacy family; tree and keyed modes separated |
| RadioGatún | Research family with word width and output profile explicit |
| RIPEMD, RIPEMD-128/160/256/320 | `brynja-legacy-hash-ripemd`; variants never aliased |
| SHA-1 | Reuse the complete pre-1.0 `brynja-legacy-sha1` implementation; a post-1.0 legacy hash facade may re-export it only after a numbered consumer-specific admission and fresh audit, never by reimplementation |
| SHA-224/256/384/512 and SHA-512/224/256 | Reuse the complete six-member pre-1.0 `brynja-hash-sha2`; post-1.0 may add only a convenience facade or a separately standardized future SHA-2 extension |
| SHA-3 and SHAKE | Reuse the complete pre-1.0 FIPS 202 SHA3-224/256/384/512 and SHAKE128/256 family; post-1.0 may add only derived standards such as SP 800-185, not missing FIPS 202 members |
| Skein | Standalone family with state/output/tree parameters explicit |
| Snefru | Legacy/research family with security status documented |
| Spectral Hash | Research until stable authority, rights, and vectors are admitted |
| Streebog-256/512 | Standalone GOST R 34.11-2012 family after authority review |
| SWIFFT | Research family; do not infer general-purpose security from its proof claim |
| Tiger | `brynja-legacy-hash-tiger`; Tiger and Tiger2 padding distinguished |
| Whirlpool | Standalone or legacy family after current security review |

## Important Omissions From The Wikipedia Table

The source page is not complete. The following additions must enter the
machine inventory before implementation planning closes. This is an initial
gap list, not a claim that no other hash exists.

| Missing family or variant | Required disposition |
| --- | --- |
| SHA-0 | Legacy/research compatibility, isolated from SHA-1 |
| Future standardized SHA-2 extensions | Only algorithms published after the pre-1.0 FIPS 180-4 closure; SHA-512/224, SHA-512/256, and the required SHA-512/t derivation rules are already pre-1.0 |
| Future standardized FIPS 202 extensions | Only algorithms outside the complete pre-1.0 SHA3-224/256/384/512 and SHAKE128/256 family |
| cSHAKE128/256, TupleHash128/256, ParallelHash128/256 | NIST SP 800-185 derived-function family |
| TurboSHAKE128/256 and KT128/KT256 | RFC 9861 family; separate domain and tree modes |
| Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128 | NIST SP 800-232 lightweight family |
| BLAKE-224 and BLAKE-384 | Complete original BLAKE family |
| BLAKE2bp and BLAKE2sp | Parallel BLAKE2 profiles, distinct from BLAKE2X |
| SM3 | Current standardized family; exact national and RFC profile authorities required |
| Kupyna/DSTU 7564 | Standalone national-standard family after source-rights review |
| PANAMA, MDC-2, MDC-4, MASH-1, MASH-2, N-Hash, VSH | Legacy/research candidates with exact source and patent review |
| Xoodyak and Xoodoo-based hashing | Modern lightweight research/standard profile review |
| Haraka | Fixed-input research family; never exposed as a generic streaming digest |
| Gimli-based hash modes | Research until exact frozen mode and security claim are selected |
| Poseidon/Poseidon2, Rescue/Rescue-Prime, MiMC, Pedersen, Sinsemilla | Separate field/ZK-hash domain with field, curve, arity, round, and proof parameters |
| CRC-32C and the named CRC catalogue | Parameter registry over one checked engine; never infer a polynomial from width |
| Fletcher-64 and rolling rsync checksum | Checksum/rolling domain, not cryptographic hash domain |
| XXH3-64/128, wyhash, rapidhash, SeaHash, FxHash | Modern non-cryptographic candidates with version/seed rules |
| aHash, MeowHash, CLHash, PolymurHash, MumHash, CrapWow | Source/rights/CPU-reviewed non-cryptographic candidates |
| HalfSipHash and SipHash parameter variants | MAC/PRF domain with rounds, key, and output explicit |
| GMAC | Reuse the complete pre-1.0 SP 800-38D GMAC implementation; post-1.0 may add only convenience adapters |
| Poly1305 without AES | Modern one-time authenticator; separate from historical Poly1305-AES |
| KangarooTwelve's related experimental tree profiles | Research-only unless a stable authority is admitted |
| Password hashing: scrypt, bcrypt, PBKDF2, Balloon | Separate future `brynja-password-hash-*` domain; never implement through Digest. Reuse the complete pre-1.0 Argon2d/i/id implementation rather than reimplementing Argon2 |
| Content-defined chunking: Gear and FastCDC | Rolling/chunking domain with caller-owned chunk policy |
| Consistent/rendezvous/jump hashing | Placement algorithms, not byte-hash implementations |
| Perceptual aHash, wHash, color hash, PDQ and video profiles | Media-profile domain with exact normalization and distance thresholds |

Proprietary algorithms without implementable public specifications or lawful
test material receive `blocked-source` or `rejected`, not a guessed compatible
implementation. Broad labels such as Jenkins, pHash, GOST, CRC-32, or SHA-3
must be decomposed into exact algorithms and parameter profiles.

## Authority Baseline

At minimum, the admission process must consider the current final form and
errata of:

- [FIPS 180-4, Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
  for SHA-1 and SHA-2 variants;
- [FIPS 202, SHA-3 Standard](https://csrc.nist.gov/pubs/fips/202/final)
  for SHA-3 and SHAKE;
- [NIST SP 800-185](https://csrc.nist.gov/pubs/sp/800/185/final) for cSHAKE,
  KMAC, TupleHash, and ParallelHash;
- [NIST SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/final) for the Ascon
  hash and XOF family;
- [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html) for BLAKE2;
- [RFC 9861](https://www.rfc-editor.org/rfc/rfc9861.html) for TurboSHAKE and
  KangarooTwelve;
- the original BLAKE3 specification and versioned official vector corpus;
- the applicable ISO, IEC, ITU, national-standard, original-author, and
  competition-final specifications for every remaining family.

NIST has announced revisions of some current hash publications. A post-1.0
milestone must refresh these links, versions, errata, transition guidance, and
parameter decisions rather than treating this 2026 snapshot as permanent.

## Unversioned Implementation Sequence

### 1. Inventory And Admission Register

- Create one machine-readable record per exact algorithm or parameter profile.
- Record category, security use, authority, source hash, errata, rights,
  output semantics, key semantics, state size, block/rate, length bound,
  endian rules, padding/domain suffix, reset behavior, and known attacks.
- Reject aliases, ambiguous names, missing vectors, unavailable specifications,
  and a generic family row that hides distinct algorithms.
- Assign crate owner, implementation symbol, test target, proof target, CPU
  policy, FIPS disposition, independent-review status, and residual gaps.

### 2. Interface Freeze

- Freeze separate fixed-digest, XOF reader, seekable-XOF where justified,
  rolling, universal, checksum, check-digit, perceptual, and MAC interfaces.
- Use caller-owned output buffers and checked lengths; allocation is never
  required by an algorithm core.
- Make finalization ownership explicit. Prevent accidental repeated finalization,
  output-length truncation, keyed-to-unkeyed conversion, state cloning, and
  secret-bearing formatting.
- Provide first-party interoperability adapters only in separately reviewed
  downstream crates; do not add the external RustCrypto `digest` crate to the
  dependency-free core graph.

### 3. Pre-1.0 Completeness And Reuse Audit

- Confirm all six SHA-2 functions live in `brynja-hash-sha2`, all six FIPS 202
  SHA-3/SHAKE functions live in `brynja-hash-sha3`, complete generic HMAC lives
  in `brynja-mac-hmac`, and legacy SHA-1, MD5, HMAC-SHA-1 and HMAC-MD5 retain
  their exact isolated pre-1.0 owners.
- Confirm complete AES-128/192/256 forward and inverse operations, GCM/GMAC,
  RFC 7748/8032 curves, HPKE modes, Argon2d/i/id, OCB3 and EAX remain reused by
  any catalogue-facing adapters instead of gaining parallel implementations.
- Confirm `brynja-crypto`, TLS, PKI, ML-KEM, and FIPS consume those exact
  symbols rather than private copies.
- Freeze the compression/permutation boundary so later variants reuse the
  proven implementation without exposing unsafe raw-state manipulation.
- Preserve the existing scalar, CPU, KAT, quarantine, and exact FIPS symbol
  identities when standalone facades are introduced.

### 4. Checksums And Non-Cryptographic Utilities

- Implement the parameterized CRC engine first, followed by locked profiles.
- Add sums, Internet checksum, Fletcher, Adler, and check-digit crates.
- Add classic, rolling, universal, and modern non-cryptographic families in
  independently reviewable groups.
- Test every byte alignment, seed, endian, incremental split, overflow,
  combination, rolling removal, and reference differential boundary.
- Make adversarial non-suitability impossible to miss in API docs and examples.

### 5. Modern Cryptographic Families

- Re-export or adapt the already complete pre-1.0 SHA-2 and FIPS 202 families;
  do not create a second implementation or defer a named standardized member.
- Add cSHAKE/TupleHash/ParallelHash, TurboSHAKE/KangarooTwelve, Ascon,
  BLAKE2, BLAKE3, and other admitted modern families one family at a time.
- Separate fixed digest, XOF, keyed, derive-key, personalization,
  customization, salt, tree, and parallel modes with typed parameters.
- Require official KATs, independent differentials, every padding/rate/tree
  boundary, long-message handling, chunk equivalence, misuse tests, fuzzing,
  model checking, emitted-code review, timing evidence, and independent audit.

### 6. MAC Families

- Reuse the complete pre-1.0 HMAC, Poly1305, and GMAC owners; keep future KMAC,
  CMAC, PMAC, SipHash, HighwayHash, UMAC, and VMAC in MAC packages even when
  the catalogue calls them keyed hashes.
- Type keys, nonces, one-time-key consumption, tag sizes, verification, and
  truncation policy; comparisons are constant-time.
- A general hash facade never offers a MAC through an unkeyed Digest trait.

### 7. Legacy Cryptographic Catalogue

- Implement only after modern families and their audit infrastructure are
  stable.
- Give each broken/deprecated family a `brynja-legacy-hash-*` name, warning,
  risk table, compile-time separation, and positive compatibility use case.
- Do not provide generic negotiation, automatic fallback, password storage,
  certificate acceptance, signature creation, or modern-protocol integration.
- Require an exceptional security review before any legacy algorithm becomes
  externally publishable, even if the implementation is mathematically small.

### 8. Research, Perceptual, Password, And Field Hashes

- Use research crates until specifications, parameter generation, rights,
  interoperability, and security claims are stable enough for admission.
- Perceptual hashes accept an exact normalized pixel/sample representation;
  image/video decoding and allocation-heavy preprocessing remain downstream.
- Password hashing receives a separate memory-hard API, resource policy,
  salt/parameter encoding, upgrade, and denial-of-service threat model.
- Field/ZK hashes bind field modulus, arity, round constants, generation
  transcript, circuit/native equivalence, and proof-system assumptions.

### 9. Hardware Acceleration

- Admit acceleration per operation and parameter set, never per marketing
  architecture name.
- Preserve scalar references and force every x86_64, AArch64, Apple Arm,
  qualifying RISC-V, and later architecture path independently.
- Require exact feature bundles, native vectors/differentials, KAT quarantine,
  unsupported-instruction negative processes, emitted-code and side-channel
  evidence, performance thresholds, and honest scalar-only decisions.
- Parallel multi-buffer APIs are separate from single-message streaming APIs;
  AVX/NEON lanes cannot silently change semantics or memory ownership.

### 10. Facades And Publication

- Publish family crates only when independently useful and changed.
- Publish `brynja-hash-core` before dependent families and the curated
  `brynja-hash` facade last.
- Add a default-off `brynja/hash` convenience surface only after dependency
  graphs prove it pulls the curated facade and no legacy, research,
  non-cryptographic, perceptual, password, CPU-std, or FIPS package.
- Never create a main-crate `all-hashes` feature. A deliberately heavy
  catalogue test workspace may exist but is repository-only.
- Supporting family crates keep independent SemVer and publication selection,
  following the existing Brynja release script policy.

## Per-Family Exit Criteria

A family is complete only when:

- every named variant and parameter has a locked authority and vector corpus;
- the scalar implementation is first-party Rust, `no_std`, allocation-free,
  dependency-minimal, and within file-size policy;
- streaming/fixed/XOF behavior, length exhaustion, domain separation,
  truncation, reset, clone, redaction, and zeroization policies are explicit;
- positive KATs, negative/malformed cases, boundary matrices, incremental
  partition tests, differentials, fuzzing, model checking, and target evidence
  match the claim;
- CPU implementations are independently identified and cannot run without
  their exact admitted capability;
- security status, known attacks, appropriate/inappropriate uses, review
  status, FIPS status, and residual risk are visible in every relevant README;
- package graphs prove that selecting this family pulls no unrelated family,
  legacy aggregate, TLS engine, runtime detector, platform adapter, or FIPS
  claim; and
- a pentest and specialist cryptographic review occur at the risk-appropriate
  integration gate before a production recommendation.

## Deferred Versioning Decision

After `v1.0.0`, the inventory will be refreshed and split into small numbered
milestones. Version assignment must consider implementation complexity,
authority availability, security relevance, independent-review capacity,
hardware evidence, and crates.io publication order. The sequence above is an
architectural dependency order, not a promise that every obscure or blocked
algorithm will be published.
