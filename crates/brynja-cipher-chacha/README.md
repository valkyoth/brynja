# brynja-cipher-chacha

A standalone, portable `no_std` implementation of the RFC 8439 ChaCha20
stream cipher. Enable `hazmat-chacha20` to import `brynja_cipher_chacha::ChaCha20`.
The same type is available as `brynja_crypto::chacha20::ChaCha20` under the
matching feature. No CPU backend, allocator or hosted runtime is required.

On x86-64 builds with SSE2, opt in to the separate `chacha20-sse2` feature and
construct `brynja_cipher_chacha::ChaCha20Sse2::new(key, nonce, counter)`.
On little-endian AArch64 builds with NEON, enable `chacha20-neon` and use
`brynja_cipher_chacha::ChaCha20Neon::new(key, nonce, counter)` instead.
Both owners process four whole blocks in parallel on the calling thread.
Fragmented prefixes and short tails stay scalar. Enabling the feature does
not change `ChaCha20::new`, and neither facade forwards it.

This is raw encryption, **not authenticated encryption**. The caller must
allocate unique nonces per key and own the key's storage. The owner accepts
a 32-byte key, 12-byte nonce and explicit 32-bit initial block counter. It
never wraps that counter: an oversized request returns an error before
consuming stream bytes or changing the destination.
