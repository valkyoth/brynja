# Portable IETF ChaCha20 (v0.30.0)

This is the raw RFC 8439 stream needed by the planned authenticated construction,
not a secure messaging API. It is available only when the direct
`brynja-crypto/hazmat-chacha20` feature is enabled. Cargo feature unification
can make the module visible through the facade's existing crate re-export;
the facade provides no feature that selects it.

The owner borrows a 256-bit key and takes a 96-bit nonce and explicit 32-bit
starting counter. A successful call consumes exactly the requested bytes.
The last byte of block 0xffffffff is usable. Empty calls consume nothing,
including after exhaustion. Length mismatch or exhaustion leaves both output
and stream position unchanged. Use the in-place method for identical buffers;
the disjoint method does not accept partially overlapping safe borrows.

Each block uses ten column/diagonal double rounds. A fragmented call can
regenerate its first block, skipping only the bytes already consumed. No
keystream cache persists in the owner. Named working arrays are cleared on
drop, not the caller's key, plaintext, output or possible compiler copies.
The caller must not reuse overlapping portions of a stream under the same
key and nonce, including across process restarts. Never act on unauthenticated
plaintext. There is no original 64-bit nonce variant, XChaCha20, Poly1305,
AEAD, hardware dispatch, or target timing qualification in this milestone.

## Reproduce the independent checks

Run `brynja-verify run chacha20 --needed` from the repository. No network
access or keys from an application are needed.

- **Archive:** builds a direct consumer from local Cargo archives on Rust
  1.90.0 and 1.100.0. It checks the RFC block and cipher examples and all eight
  Appendix A.1/A.2 vectors, partitions, final-counter behavior, and import and
  overlap restrictions. Cortex-M is a compile check, not device execution.
- **Differential:** the optional OpenSSL CLI encrypts 302 deterministic public
  fixtures (eight start counters, lengths from zero to 16 KiB, two seeds).
  The four state words are encoded as little-endian counter followed by the
  12 nonce bytes. No case crosses the RFC counter limit. On each compiler the
  archived library encrypts into a separate buffer and decrypts the oracle
  output in-place across partitions. A corrupted expected answer must fail.
  OpenSSL is not linked, and its behavior on overflow is not the oracle.
- **Kani:** checks that admission accepts exactly representable ranges through
  the end of the stream, and that the first and last block of every admitted
  nonempty range fit in 32 bits. This is not a proof of the round function.
- **Sanitizers:** executes the four public vector and boundary tests under
  ASan/LSan on Linux x86-64. This is host memory-safety evidence, not a
  measurement of key erasure, physical leakage or compiler timing.
