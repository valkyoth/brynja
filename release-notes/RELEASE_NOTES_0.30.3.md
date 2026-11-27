# v0.30.3 — standalone AES block cipher (internal development)

Use `brynja_cipher_aes::aes` with `hazmat-aes-block` for standalone raw
blocks, or keep `brynja_crypto::aes` and `brynja::crypto::aes`. All
three routes expose the same AES-128/192/256 key and schedule types. The
portable constructors remain portable and hardware execution remains explicit.
External-key lifecycle contracts do not require a driver or hardware.

Enabling AES-GCM, GMAC, or their paired execution features does not enable
the standalone raw `aes` or raw `aes::execution` import. Modes use a
separate, forward-only bridge into clearing storage. Like every cross-crate
Rust interface, that bridge is callable if named; it is not access control.
Cargo still unifies any *explicit* raw AES opt-in in the same build graph.

This guarantee is about the cipher crate and its façade imports, not the
separate low-level `brynja-crypto-cpu` crate. As in v0.30.2, selecting
`aes-gcm-execution` or `gmac-execution` enables the CPU crate's static AES
feature. A direct CPU-crate dependency can then call `aes::Session` for key
expansion, encryption **and decryption**, even if it requested no features
itself. CPU admission still applies; callers of that API must clear their own
state and schedules. Portable `aes-gcm` and `gmac` alone do not enable it.

No new AES arithmetic, mode, timing qualification or hardware admission is
claimed. GHASH, AES-GCM and GMAC have not been extracted in this milestone.
No crates.io publication is selected.
