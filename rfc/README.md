# RFC Reference Copies

This directory contains exact, unmodified RFC Editor plain-text publications
used for requirements, implementation review, test vectors, errata decisions,
and security analysis.

Brynja claims no copyright in the RFCs. Each retains its own notices and IETF
Trust legal terms and is not licensed as Brynja software. The RFC Editor makes
the official formats available and the IETF Trust provisions govern permitted
reproduction. Files must remain byte-for-byte unchanged; project annotations
belong in docs or a future requirements ledger.

RFC 9846 is the current TLS 1.3 base. RFC 8446 is not copied because RFC 9846
obsoletes it; RFC 8448 remains for official TLS 1.3 example traces. RFC 5246,
7627, and 8422 remain as explicitly labeled obsolete TLS 1.2 inputs because the
hardened TLS 1.2 profile and migration tests need historical requirements in
combination with RFC 9846's current TLS 1.2 updates.

RFC 9954 supplies the generic hybrid key-exchange construction. Concrete
ECDHE-ML-KEM groups remain blocked on their final Standards Track RFC and final
IANA code points; Internet-Draft bytes and provisional identifiers are never
release inputs.

SOURCES is the reviewed HTTPS allowlist. SHA256SUMS pins exact downloaded bytes.
verify-rfcs.sh rejects missing, extra, changed, empty, or unlisted RFCs. Build
scripts never download standards. RFC text is excluded from every crate package.

Non-RFC standards and historical specifications are handled by
references/SOURCES.md. They remain local-only until an explicit redistribution
review says otherwise.
