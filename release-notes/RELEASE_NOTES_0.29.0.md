# v0.29.0 — Portable AES-GCM (candidate)

The default-off `aes-gcm` feature adds detached, allocation-free
AES-128/192/256-GCM to `brynja_crypto::aes_gcm` and `brynja::crypto::aes_gcm`.
Use `from_reserved_range` for a sending key dedicated to 96-bit IVs,
`from_reserved_invocations` for general or mixed IV lengths, or `for_open`
for a receive-only key. Both open APIs accept only the owner's IV width
(default 12 bytes); select general IVs explicitly, e.g. `Aes256Gcm::<16, 60>`
for a 60-byte IV. Fix the tag length per key at 12–16 bytes (default 16).
Neither raw AES/GHASH access nor a native backend is required.

Seal and open accept exact in-place or disjoint buffers and require a
separate message-sized scratch buffer. Open authenticates before releasing
plaintext. Admission errors do not spend a nonce; after keyed sealing begins,
an error or unwind spends it without publishing partial ciphertext. Applications
must persist disjoint reservations across restarts and key imports, enforce the
key-wide budget for general IVs, and handle replay protection.

The [verification checklist](../docs/assurance/aes-gcm-development.md)
records 33,750 applicable NIST GCMVS cases and 11,025 independent differential
messages on Rust 1.90.0 and 1.100.0, archive consumers, a bounded 0–17-byte
output-commit proof, and injected AES subkey failure before GHASH. These are
functional checks, not CAVP validation or timing qualification. Cortex-M
coverage is compile-only. Integrated hardware acceleration and a dedicated
GMAC API are outside this milestone.

Candidate for scoped review against v0.28.3; no final approval, signed tag
or crates.io publication is claimed.
