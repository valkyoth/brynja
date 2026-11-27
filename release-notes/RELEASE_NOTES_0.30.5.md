# v0.30.5 — standalone AES-GCM and GMAC (internal development)

The optional `brynja-aead-gcm` crate owns the existing detached AES-GCM and GMAC implementations. Enable `aes-gcm` or `gmac` independently; explicit execution features retain the existing paired-backend contracts. Existing `brynja_crypto` and `brynja::crypto` callers keep the same types and reservation semantics. No new primitive, platform qualification or crates.io publication.
