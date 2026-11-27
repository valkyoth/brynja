# Test ChaCha20 as an installed downstream consumer

On Linux x86-64 run `python3 scripts/cryptography/check-chacha20-archive.py --installed`
from the repository root, or select `chacha20/ietf-installed-consumer` in
`brynja-verify`. The runner uses Rust 1.90.0 and 1.100.0, their AArch64
Linux musl and Cortex-M standard libraries, rust-lld, qemu-aarch64, llvm-nm,
and the OpenSSL CLI. OpenSSL produces public test data only; no library
consumer depends on it. Local Cargo archives and temporary installation roots
are used; nothing is downloaded or installed into the user's bin directory.

| Import | Feature on that dependency | Installed route |
| --- | --- | --- |
| `brynja_crypto::chacha20::ChaCha20` | `hazmat-chacha20` | scalar |
| `brynja_cipher_chacha::ChaCha20` | `hazmat-chacha20` | scalar |
| `brynja_cipher_chacha::ChaCha20Sse2` | `chacha20-sse2` | Linux x86-64 SSE2 |
| `brynja_cipher_chacha::ChaCha20Neon` | `chacha20-neon` | Linux AArch64 NEON under QEMU |

Each installed binary reports a fixture-defined label for its imported type
(the SIMD fixture will not compile if its owner aliases the scalar type), replays 302 public oracle
records in disjoint and fragmented in-place layouts, checks its remaining byte
budget and must independently reject changed expected bytes from a full
four-block group and from the last legal scalar block. The runner checks for
the exact selected packed text symbol in the unstripped installed binary
(neither symbol on scalar routes). Symbol presence is not an execution trace.
It also runs archived RFC and exhaustion tests and checks
compiler rejection of 8- and 24-byte nonces, a 64-bit counter, and overlapping
safe borrows against a positive control; the latter checks Rust's borrowing
rules at the public signature. Required SIMD owners cannot silently
fall back when their feature or target is absent. Choose the portable owner
for a portable build; there is no runtime dispatch or hardware attestation.

These checks test usability, not native ARM speed, key erasure or resistance
to timing attacks. Raw ChaCha20 does not authenticate messages.
