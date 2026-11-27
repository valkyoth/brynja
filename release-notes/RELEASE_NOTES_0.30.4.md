# v0.30.4 — standalone GHASH (internal development)

Enable `hazmat-ghash` on `brynja-universal-hash-ghash` to use
`brynja_universal_hash_ghash::ghash`. Existing `brynja_crypto::ghash` and
`brynja::crypto::ghash` callers use the same types. No change to block
representation, framing, caller-owned storage or the secret result. This
does not add POLYVAL or turn raw GHASH into a MAC.

AES-GCM and GMAC use an internal composition interface without enabling the
normal raw import. This is API separation, not access control. Native selection
remains explicit, and portable construction does not require a hosted detector.
No new hardware timing qualification or crates.io publication is claimed.
