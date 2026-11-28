<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://github.com/valkyoth/brynja/tree/main/crates/brynja-aead-chacha20poly1305">Source (unpublished)</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/crates/brynja-aead-chacha20poly1305/src/lib.rs">API source</a>
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

# brynja-aead-chacha20poly1305

> [Official Brynja crate directory](https://github.com/valkyoth/brynja#workspace) · [Modern façade on crates.io](https://crates.io/crates/brynja).
> In the development checkout enable `chacha20poly1305` on `brynja` for `brynja::crypto::chacha20poly1305`, or use this leaf directly. Neither the leaf nor the façade feature is published yet.

| Capability | Implemented | Independent verification |
| --- | --- | --- |
| RFC 8439 detached seal/open, 96-bit nonces and full tags | ✅ Implemented | ❌ Not independently verified |
| Explicit Linux x86-64 SSE2 ChaCha20 + AVX2 Poly1305 | ✅ Implemented in checkout | ❌ Not independently verified |
| Explicit AArch64 Linux/macOS NEON pair | ✅ Implemented in checkout | ❌ Not independently verified |

Borrow a 32-byte key with `Sealer::from_reserved_range` for sending or
`Opener::new` for receiving. Allocate nonoverlapping ranges durably per key:
a nonce is four prefix bytes followed by an eight-byte big-endian counter.
Never reuse a key/nonce pair, including after restart or across processes.
The key stays yours to clear. Replay protection is a protocol responsibility.
This sender does not implement a static-IV XOR sequence or a little-endian
wire counter. Do not simulate those schemes by repeatedly constructing senders
for individual messages; use a reviewed protocol-specific nonce allocator.

Counter capacity is not a traffic allowance. Enforce the protocol's limits on
records, bytes and failed authentications, and its rules for rekeying or closing
the connection. Cap untrusted AAD and payload lengths before allocating scratch;
authentication work grows with both, even for messages that fail verification.

Use `seal` and `open` for separate input and output, or `seal_in_place` and
`open_in_place` for exact overlap. Safe Rust excludes partial overlap.
Provide scratch exactly as long as the payload. Length rejection leaves
scratch and the destination untouched. Once admitted, the operation clears
scratch before returning or on unwind, and changes the destination only on
success. A sender burns a nonce before keyed work. Tags are always 16 bytes.
Clearing does not cover aborts, registers, compiler copies or caller-owned keys.

```rust
use brynja_aead_chacha20poly1305::{Error, Opener, Sealer};

// The application supplies a secret key and an already reserved invocation.
fn round_trip(key: &[u8; 32], prefix: [u8; 4], counter: u64) -> Result<(), Error> {
    let mut sender = Sealer::from_reserved_range(key, prefix, counter, 1)?;
    let mut message = *b"hello";
    let mut scratch = [0; 5];
    let (nonce, tag) = sender.seal_in_place(b"header", &mut message, &mut scratch)?;
    Opener::new(key).open_in_place(nonce, b"header", &tag, &mut message, &mut scratch)?;
    assert_eq!(&message, b"hello");
    Ok(())
}
# assert!(round_trip(&[0x42; 32], *b"demo", 1).is_ok());
```

## Hardware and SIMD

Ordinary `seal` and `open` remain portable. In the checkout, enable
`chacha20poly1305-x86` on the leaf or either façade for the Linux x86-64
pair. Call `execution::X86Pair::probe()` once and use
`sender.with_pair(&mut pair)?` or `opener.with_pair(&mut pair)?` before
calling the same seal/open methods. Binding borrows the sender's existing
reservation; it does not allocate more nonces. There is no implicit fallback.

On AArch64 Linux/macOS, enable `chacha20poly1305-neon` and use
`execution::ArmPair::probe()` with the same binding methods. This requires a
little-endian target compiled with NEON; the startup check tests arithmetic,
not CPU migration or OS affinity. Neither binding allocates threads.

On Linux x86-64, an unsupported CPU returns `AdmissionError::Unavailable`. A failed startup
test returns `Quarantined`; an internal failure or unwind during keyed work
retires that pair. A peer's bad tag returns `Error::Authentication` and does
not retire it. The host must maintain the advertised ISA wherever the thread
may run. Short inputs can be slower; block-zero derivation stays scalar.
There is no target-specific timing or fault-resistance claim.
