# External Reference Provenance

Status: initial source inventory

These non-RFC sources are required for first-party cryptography, PKI, or
historical-protocol research. They default to local-only under
references/local/ and are gitignored until a document-specific redistribution
review approves tracking. Recording a URL does not grant a license. The exact
official NIST URLs are allowlisted in LOCAL_SOURCES and their inspected local
bytes are pinned by LOCAL_SHA256SUMS.

| Source | Purpose | Repository policy |
| --- | --- | --- |
| NIST FIPS 180-4 | SHA-2 | downloaded local-only; NIST has announced a future revision |
| NIST FIPS 197-upd1 | AES | local-only PDF; track derived test vectors with provenance only |
| NIST SP 800-38D | GCM/GHASH | downloaded local-only; NIST has announced a future revision |
| NIST FIPS 186-5 and SP 800-186 | ECDSA/RSA and curve parameters | downloaded local-only; errata must be checked before use |
| NIST SP 800-56A Rev. 3 | ECC key establishment | downloaded local-only |
| NIST SP 800-90A Rev. 1 | entropy-provider/DRBG review | downloaded local-only; platform RNG remains caller-provided |
| NIST SP 800-107 Rev. 1 | hash usage and strength | downloaded local-only |
| NIST CAVP vector archives | algorithm known-answer tests | review each archive before tracking |
| ITU-T X.690 | ASN.1 BER/CER/DER | local-only licensed standard |
| ITU-T X.509 | certificate model | local-only licensed standard; RFC 5280 drives Internet PKI |
| SSL 3.0 specification | historical brynja-ssl3 research | local-only pending provenance/rights review |
| SSL 2.0 specification | historical brynja-ssl2 research | local-only pending provenance/rights review |
| SSL 1.0 surviving material | brynja-ssl1-research only | local-only, provenance and authenticity required |
| WAP WTLS specifications | historical brynja-wtls research | local-only pending rights review |
| PCT and SNP specifications | historical research | local-only pending rights review |

Historical and licensed standards still require URLs, hashes, retrieval dates,
versions, and rights decisions before an implementation milestone consumes
them. Unverified web mirrors are never normative.
