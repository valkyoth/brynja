<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://github.com/valkyoth/brynja/tree/main/crates/brynja-cipher-chacha">Source (unpublished)</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/crates/brynja-cipher-chacha/src/lib.rs">API source</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md">Release Plan</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md">Threat Model</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/brynja">
    <img width="840" src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
  </a>
</p>

# brynja-cipher-chacha

A standalone, portable `no_std` implementation of the RFC 8439 ChaCha20
stream cipher. Enable `hazmat-chacha20` to import `brynja_cipher_chacha::ChaCha20`.
The same type is available as `brynja_crypto::chacha20::ChaCha20` under the
matching feature. No CPU backend, allocator or hosted runtime is required.

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Portable IETF ChaCha20, including fragmented input | Yes | No independent certification |
| Four-block SIMD on supported targets | Explicit opt-in | No blanket hardware qualification |

## Use a stream

Enable `hazmat-chacha20` (off by default). Keep the same owner when processing
successive fragments: constructing another owner at the original counter
would restart the keystream. The public test inputs below illustrate splitting
one stream; real senders must never reuse a nonce with the same key.

```rust
use brynja_cipher_chacha::{ChaCha20, Error};

fn main() -> Result<(), Error> {
    let key = [0; 32];
    let nonce = [0; 12];
    let mut stream = ChaCha20::new(&key, nonce, 0);
    let mut prefix = [0; 4];
    stream.apply_keystream_in_place(&mut prefix[..1])?;
    stream.apply_keystream_in_place(&mut prefix[1..])?;
    assert_eq!(prefix, [0x76, 0xb8, 0xe0, 0xad]);
    Ok(())
}
```

## Hardware and SIMD

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

MIT OR Apache-2.0.
