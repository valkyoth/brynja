# Brynja 0.3.0 Release Notes

Status: pentest remediation complete; awaiting clean retest

Brynja 0.3.0 is a standards source-ledger milestone. It does not implement
TLS, cryptography, PKI, QUIC, DTLS, platform services, or legacy protocols and
must not be used to secure network traffic.

The release joins all 103 checksum-locked RFCs and eight local-only NIST
authorities to explicit lifecycle, domain, and roadmap ownership. Current,
compatibility, legacy, exclusion, caller-owned, and evidence sources cannot be
silently interchanged. The RFC Editor index projection preserves current
status plus updated-by and obsoleted-by relationships; every relationship that
leaves the locked set has a reviewed, machine-enforced exclusion.

Eight exact IANA XML snapshots cover the registries needed by planned TLS,
DTLS, QUIC, HPKE, ECH, Certificate Transparency, PKIX, OCSP, and DNS work.
The errata register covers all 103 RFCs and records 285 official entries:
112 verified, 82 held for document update, 42 reported, and 49 rejected.
Verified entries are implementation inputs; held and reported entries remain
tracked without altering requirements; rejected entries do not apply.

Normal repository checks are fully offline. They validate all source and
snapshot hashes, complete ownership, lifecycle consistency, roadmap
references, RFC relationship closure, errata dispositions, IANA identity, the
hybrid admission blocker, and byte-for-byte ledger reproducibility. Sixteen
positive and broken fixtures prove the principal failure paths. The release
gate separately queries official sources and fails if the RFC index, errata,
or any registry has drifted.

The initial pentest found three standards-ingestion weaknesses. Refresh-time
hash generation has been replaced by independently reviewed pins anchored to
the signed pre-pentest candidate; RFC and NIST lock scripts can no longer
compute or overwrite their own trust anchors. Exact HTTPS host/path and
redirect allowlists are now executable controls. All upstream responses are
bounded, and XML containing DTD or entity declarations is rejected before
parsing. The standards regression suite now contains 26 positive and broken
fixtures covering the new failure paths.

Concrete ECDHE-ML-KEM groups remain blocked until both a final Standards Track
RFC and final IANA code points are available. RFC 9954's generic construction,
draft text, provisional values, or private values cannot satisfy admission.

Only `brynja 0.3.0` is selected for crates.io publication. All unchanged
modern support crates remain exact-pinned at their published `0.1.0` versions.
