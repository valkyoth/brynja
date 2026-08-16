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

FIPS validation is a separate official claim. Brynja has no FIPS 140-3
validation, certificate, validated module, approved security policy, or
certificate-bound operational-environment claim.

| Component | Cryptographic or protocol scope | Independent review or official validation status |
| --- | --- | --- |
| `brynja-core` | Constant-time operations plus provider, CPU-backend, entropy, secure-random, clock, pending-operation, FIPS-aware state, and mandatory security-outcome contracts | ❌ Not verified |
| `brynja-hash-sha2` | All six complete portable FIPS 180-4 SHA-2 algorithms with forced optional CPU candidate APIs | ❌ Not verified |
| Future `brynja-hash-sha3` / `brynja-mac-*` | Reusable SHA-3, XOFs, and MACs | ❌ Not implemented or verified |
| `brynja-crypto` | Provider contracts, cryptographic composition, AEADs, KDFs, RSA, and ECC | ❌ Not verified |
| `brynja-crypto-cpu` | Five implemented but unadmitted SHA-2 candidates across x86_64 SHA, AArch64 SHA2/SHA-512, and RV64 Zknh plus explicit x86 SHA-512 scalar-only policy | ❌ Not independently verified; native admission evidence incomplete |
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
| Future `brynja-legacy-sha1` | Complete isolated SHA-1 implementation for explicit legacy compatibility | ❌ Not implemented or verified |
| `brynja-sanitization` | Fixed-size secret ownership and explicit Brynja-region copies | ❌ Not verified |
| `brynja-legacy` / `brynja-legacy-*` | TLS 1.1/1.0, SSL, WTLS, PCT, and SNP obsolete-protocol boundaries | ❌ Not verified |
| `brynja-research-ssl1` | Unpublished SSL 1.0 provenance reconstruction | ❌ Not verified |
| Future `brynja-fips-module` / `brynja-fips` | FIPS 140-3 cryptographic module and policy boundary | ❌ Not FIPS validated |

The implemented portion currently consists of all six complete portable FIPS
180-4 SHA-2 algorithms; the shared alert/failure,
bounded numeric/resource, borrowed-read, transactional caller-buffer write,
workspace/arena, secret-lifetime, zeroization, fixed-width constant-time,
provider, entropy/secure-random, typed-clock, and pending-operation foundations;
the shared TLS/DTLS record-envelope boundary; bounded DER framing and admitted
canonical ASN.1 values; and the separately selected sanitization adapter.

No cryptographic primitive outside those six portable SHA-2 algorithms, schema-driven ASN.1
processor, X.509 validator, handshake parser, or complete protocol engine in
this inventory is currently implemented. Independent-review status cannot be
inferred from implementation, testing, formal proof, pentest, or release
status.
