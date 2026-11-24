# v0.29.1 — Portable GMAC (candidate)

Enable `gmac` on `brynja-crypto` or `brynja` for authentication without
encryption. `Aes128Gmac`, `Aes192Gmac` and `Aes256Gmac` return a reserved IV
and a detached `GmacTag`; `for_verify` constructs a receiver without sending
authority. No raw AES or GHASH features, heap allocation or hardware backend
are required. Use a dedicated key, fix one tag width per key and persist
disjoint sender reservations across reimports and restarts. GMAC does not
encrypt data, prevent replay or supply protocol domain separation.

The [verification and review checklist](../docs/assurance/gmac-development.md)
records the portable public API, selected cleanup checks, 6,750 applicable
NIST records and 2,730 independently generated boundary messages. These are
host functional results; Cortex-M was compiled, not executed. No timing or
certification claim. Scoped review and the final gate remain pending.
