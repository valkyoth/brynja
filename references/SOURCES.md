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
| FIPS 140-3, ISO/IEC 19790:2012, and ISO/IEC 24759:2017 | module requirements and test assertions | FIPS local-only; ISO documents local-only licensed inputs with independently recorded provenance |
| NIST SP 800-140 and SP 800-140A through 140F | CMVP derived tests, documentation, security policy, approved functions, SSP establishment, authentication, and non-invasive guidance | local-only dated submission baseline; recheck online supplemental lists |
| Current FIPS 140-3 CMVP Management Manual, Implementation Guidance, RFG and CMVP resolutions | validation process and current interpretations | mutable official sources require retrieval timestamps, hashes, change review, and a pinned submission baseline |
| NIST SP 800-90B and SP 800-90C | entropy sources, health tests, and RBG constructions | local-only; bind exact editions and errata to ESV and module evidence |
| CMVP ESVTS guidance and production evidence | SP 800-90B entropy and SP 800-90C RBG validation | record dated protocol, tool, environment, validation identifiers, and caveats; demo results never support a claim |
| NIST SP 800-52 Rev. 2 and successors | approved TLS deployment profile | local-only; the 2026 revision process and final successor must be reviewed before profile freeze |
| NIST SP 800-131A Rev. 2, SP 800-133 Rev. 2, and SP 800-56C Rev. 2 | transitions, key generation, and key derivation | local-only; current CMVP supplemental lists govern approval |
| NIST FIPS 203 and SP 800-227 | ML-KEM and KEM use | local-only; errata, CMVP approval, and final TLS group standards remain separate gates |
| NIST CAVP vector archives | algorithm known-answer tests | review each archive before tracking |
| ITU-T X.690 | ASN.1 BER/CER/DER | local-only licensed standard |
| ITU-T X.509 | certificate model | local-only licensed standard; RFC 5280 drives Internet PKI |
| TLS 1.0, TLS 1.1, and historical SSL 3.0 RFC publications | brynja-tls10, brynja-tls11, and brynja-ssl3 baselines | tracked under `rfc/` as RFC 2246, RFC 4346, and RFC 6101; current prohibition documents remain mandatory context |
| Original SSL 3.0 specification | historical brynja-ssl3 provenance comparison | local-only pending provenance/rights review; compare with RFC 6101 before implementation |
| SSL 2.0 specification | historical brynja-ssl2 research | local-only pending provenance/rights review |
| SSL 1.0 surviving material | brynja-ssl1-research only | local-only, provenance and authenticity required |
| WAP WTLS specifications | historical brynja-wtls research | local-only pending rights review |
| PCT and SNP specifications | historical research | local-only pending rights review |

Historical and licensed standards still require URLs, hashes, retrieval dates,
versions, and rights decisions before an implementation milestone consumes
them. Unverified web mirrors are never normative.
