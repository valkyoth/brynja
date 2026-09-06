# Component Verification Status

This document preserves Brynja's crate-level assurance inventory. It answers
which internal package owns a security-sensitive scope; it does not claim
that every listed scope is implemented or that an internal boundary is a
consumer-usable cryptographic capability. The concrete, public capability
tables in the [project README](../README.md#cryptography-verification-status)
are the primary implementation-status summary.

No cryptographic or protocol component in this repository has been
independently reviewed. A component only moves from ❌ to ✅ when a named
independent reviewer signs off and linked evidence identifies the exact
reviewed implementation. Passing the project's own tests, CI, Kani, Miri,
sanitizers, fuzzing, differential testing, or pentests does not by itself
constitute independent cryptographic or protocol verification.

Repository-local acceptance hashes detect drift; they are not signatures or
independent review attestations. A contributor able to change both source and
its hash inventory can make them agree. Review of both changes remains necessary;
a signed commit or tag identifies its signing key, not independent approval.

FIPS validation is a separate official claim. Brynja has no FIPS 140-3
validation, certificate, validated module, approved security policy, or
certificate-bound operational-environment claim.

| Component | Cryptographic or protocol scope | Independent review or official validation status |
| --- | --- | --- |
| `brynja-core` | Constant-time operations plus provider, CPU-backend, entropy, secure-random, clock, pending-operation, FIPS-aware state, and mandatory security-outcome contracts | ❌ Not verified |
| `brynja-hash-sha2` | All six fully implemented FIPS 180-4 ordinary and hardened byte-oriented and canonical arbitrary-bit SHA-2 algorithms with forced optional ordinary CPU candidate APIs, compiler-resistant cleanup evidence, and combined package-external acceptance | ❌ Not verified |
| `brynja-hash-sha3` | All six fully implemented FIPS 202 ordinary/hardened byte and arbitrary-bit functions plus complete SP 800-185 encodings and cSHAKE128/cSHAKE256 ordinary/hardened byte and arbitrary-bit APIs; hardened owners classify public versus typed-secret output | ❌ Not verified |
| `brynja-mac-kmac` | Complete KMAC128/KMAC256 and KMACXOF128/KMACXOF256 with strength-only default APIs, feature-gated exact conformance, hardened in-place source clearing, typed output, and constant-time tag verification | ❌ Not independently verified |
| `brynja-hash-tuple` | Complete TupleHash128/TupleHash256 and TupleHashXOF128/TupleHashXOF256 with structural whole or exact-length streamed items, arbitrary-bit inputs and outputs, and ordinary or hardened ownership | ❌ Not independently verified |
| `brynja-hash-parallel` | Complete ParallelHash128/ParallelHash256 and ParallelHashXOF128/ParallelHashXOF256 with allocation-free sequential streaming, arbitrary-bit input/output, hardened ownership, and ordered caller-scheduled leaves | ❌ Not independently verified |
| `brynja-hash-parallel-std` | Optional zero-dependency worker/leaf-budgeted native-thread executor with one fail-closed operation at a time per executor, reusable worker-sized storage, and fallible scoped launch over the portable leaf-job and ordered-collector API | ❌ Not independently verified; excluded from FIPS boundaries |
| Future `brynja-mac-*` | Other reusable MACs | ❌ Not implemented or verified |
| `brynja-crypto` | Provider contracts, cryptographic composition, AEADs, KDFs, RSA, and ECC | ❌ Not verified |
| `brynja-crypto-cpu` | Five SHA-2 plus x86_64 AVX2 and AArch64 SHA3 Keccak candidates implemented but unadmitted; x86 SHA-512 and RISC-V Keccak are explicit scalar-only decisions | ❌ Not independently verified; native admission evidence incomplete |
| `brynja-crypto-cpu-std` | Implemented opt-in SHA-2 host detection/reporting, opportunistic scalar fallback and fail-closed required modes; RISC-V auto-detection disabled | ❌ Not independently verified; accelerated candidates remain unadmitted |
| `brynja-pki` | ASN.1, DER, X.509, path validation, and revocation | ❌ Not verified |
| `brynja-protocol` | Shared TLS and DTLS record-envelope parsing and encoding | ❌ Not verified |
| `brynja-tls` | Modern TLS version routing and policy | ❌ Not verified |
| `brynja-tls12` | TLS 1.2 record and handshake engine | ❌ Not verified |
| `brynja-tls13` / `brynja-tls13-handshake` | TLS 1.3 record and handshake engine | ❌ Not verified |
| `brynja-quic-tls` | QUIC/TLS handshake integration | ❌ Not verified |
| `brynja-dtls` | DTLS record and handshake engines | ❌ Not verified |
| Future `brynja-openpgp-core` / `brynja-openpgp-armor` / `brynja-openpgp` | RFC 9580 packet, armor, certificate, key, signature, encryption, compression, and message processing | ❌ Not implemented or verified |
| Future `brynja-openpgp-legacy` | Explicitly isolated deprecated OpenPGP read, decrypt, or verify compatibility | ❌ Not implemented or verified |
| `brynja-legacy-sha1` | Portable ordinary/hardened byte/bit SHA-1; collision-broken legacy compatibility | ❌ Not verified |
| `brynja-legacy-md5` | Portable ordinary/hardened byte/bit MD5; collision-broken legacy compatibility | ❌ Not verified |
| `brynja-sanitization` | Fixed-size secret ownership and explicit Brynja-region copies | ❌ Not verified |
| `brynja-legacy` / `brynja-legacy-*` | TLS 1.1/1.0, SSL, WTLS, PCT, and SNP obsolete-protocol boundaries | ❌ Not verified |
| `brynja-research-ssl1` | Unpublished SSL 1.0 provenance reconstruction | ❌ Not verified |
| Future `brynja-fips-module` / `brynja-fips` | FIPS 140-3 cryptographic module and policy boundary | ❌ Not FIPS validated |

The implemented portion currently consists of all six portable FIPS 180-4
SHA-2 byte-oriented and canonical arbitrary-bit algorithms with separately packaged downstream acceptance;
all six portable FIPS 202 SHA-3 and SHAKE ordinary byte and arbitrary-bit functions over one
private Keccak-f[1600] owner with separately packaged downstream acceptance;
all four SP 800-185 encodings and complete ordinary/hardened cSHAKE128 and
cSHAKE256 with package-external and independent-oracle acceptance; all four
KMAC/KMACXOF identities with hardened ownership and typed verification;
all four TupleHash/TupleHashXOF identities with structural whole or streamed
items, arbitrary-bit input/output, hardened in-place ownership, and borrowing
incremental readers;
all four ParallelHash/ParallelHashXOF identities with exact `B` and leaf-count
encoding, allocation-free sequential streaming, arbitrary-bit final leaves,
hardened output, indexed caller scheduling, ordered collection, and a separate
bounded `std` executor;
one frozen package-external portable acceptance contract across all fourteen
SP 800-185 identities, their official outputs, ordinary and hardened profiles,
streaming, arbitrary-bit, zero-length, exact-item, scheduled-leaf, real-data,
Rust-version, and declared bare-metal paths;
the shared alert/failure,
bounded numeric/resource, borrowed-read, transactional caller-buffer write,
workspace/arena, secret-lifetime, zeroization, fixed-width constant-time,
provider, entropy/secure-random, typed-clock, and pending-operation foundations;
the shared TLS/DTLS record-envelope boundary; bounded DER framing and admitted
canonical ASN.1 values; and the separately selected sanitization adapter.

The SHA-2 and FIPS 202 ordinary and hardened byte/arbitrary-bit APIs are usable,
and the combined v0.24.11 cross-family acceptance has passed. Both expanded
families are therefore **Fully implemented**. Their accelerated candidates
remain unadmitted, and neither family is independently reviewed or FIPS 140-3
validated. No cryptographic primitive outside those six portable SHA-2
algorithms, the six named portable FIPS 202 functions, both cSHAKE strengths,
the four KMAC/KMACXOF identities, four TupleHash/TupleHashXOF identities, and
four ParallelHash/ParallelHashXOF identities, schema-driven ASN.1
processor, X.509 validator, handshake parser, or complete protocol engine in
this inventory is currently implemented. Independent-review status cannot be
inferred from implementation, testing, formal proof, pentest, or release
status. The derived SP 800-185 family is **Fully implemented** after v0.24.17
replayed the frozen portable contract, completed the required local release
checks and reviewed same-commit AMD, Intel, AWS ARM and Apple M2 observations.
All backend and parallel execution routes have passing or explicit unadmitted
dispositions. No CPU backend admission, independent verification or FIPS
validation follows from this acceptance.
