# v0.30.1 — Standalone ChaCha20 and opt-in acceleration (internal candidate)

Existing users of `brynja_crypto::chacha20::ChaCha20` need no migration. It
re-exports the portable owner from `brynja-cipher-chacha`. In that leaf crate,
enable `hazmat-chacha20` for portable use, or explicitly choose
`ChaCha20Sse2` (`chacha20-sse2`, x86-64 with SSE2) or `ChaCha20Neon`
(`chacha20-neon`, little-endian AArch64 with NEON). Neither façade selects
SIMD. No threads are spawned: four full blocks are processed in parallel on
the calling thread, and partial blocks use the scalar path.

RV64 stays scalar. The [native RVV comparison](../assurance/chacha20-parallel/README.md)
passed correctness but was slower at representative record sizes. The
[verification record](../docs/assurance/chacha20-development.md) distinguishes
packaged and emulated comparisons from native observations. These results do
not qualify timing or register/spill erasure.

This is a raw stream, not authenticated encryption. Callers must allocate
unique nonces per key across owners. No crates are selected for publication;
the planned crates.io checkpoint is v0.30.6. Candidate status is not release
approval.
