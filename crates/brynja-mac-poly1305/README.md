<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://github.com/valkyoth/brynja/tree/main/crates/brynja-mac-poly1305">Source (unpublished)</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/crates/brynja-mac-poly1305/src/lib.rs">API source</a>
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

# brynja-mac-poly1305

> [Official Brynja crate directory](https://github.com/valkyoth/brynja#workspace) · [Modern façade on crates.io](https://crates.io/crates/brynja).
> In the development checkout, enable `poly1305` on the façade for `brynja::crypto::poly1305`, or depend on this leaf directly. Neither the leaf nor the façade feature is published yet.

| Capability | Implemented | Independent verification |
| --- | --- | --- |
| Portable streaming Poly1305, full 16-byte tags | ✅ Implemented | ❌ Not independently verified |
| Explicit Linux x86-64 AVX2 message owner (development checkout) | ✅ Implemented | ❌ Not independently verified |
| ChaCha20-Poly1305 or key derivation | Not provided | Not applicable |

Use a fresh, unpredictable 32-byte one-time key for **every** message. Never
use a long-lived application key directly. `OneTimeKey::new` takes a mutable
borrow of the key bytes; finishing, failing verification or dropping the owner
clears that storage. Import rejects a zero clamped multiplier, including a
buffer already cleared by an earlier owner, and clears rejected keys too.
The explicitly named `from_rfc8439_key` accepts the entire RFC input domain,
including test vectors with zero multiplier. A fresh owner over a caller-created
copy bypasses the single-use restriction. The caller must prevent this,
including after restart.

Call `start`, feed zero or more chunks with `update`, then consume the state
with either `finalize` (sign) or `verify` (check a full tag). Message boundaries
matter, update boundaries do not. There is no nonce parameter, replay
protection, encryption or message framing. Clearing does not cover registers,
spills, forgotten owners, aborts or caller-created copies. The two reviewed
Linux x86-64 builds also copied the owner state when moving it into verification;
do not assume earlier stack copies were erased.

```rust
use brynja_mac_poly1305::{Error, OneTimeKey};

// Supply a different one-time key for every call; this function clears it.
fn verify_record(key: &mut [u8; 32], record: &[u8], tag: &[u8; 16]) -> Result<(), Error> {
    let mut mac = OneTimeKey::new(key)?.start();
    mac.update(record)?;
    mac.verify(tag)
}
```

## Hardware and SIMD

Ordinary `start()` is portable, even when the standalone crate's default-off
`poly1305-avx2` feature is enabled. On Linux x86-64, probe once with
`execution::Avx2::probe()`, then use `OneTimeKey::new(key)?.start_avx2(&mut cpu)?`
for each fresh key. Only a missing ISA is `AdmissionError::Unavailable`; a
failed startup test or interrupted native computation is not a fallback signal.
The host must maintain AVX2 support for the lifetime of the handle. Updates
with fewer than 1024 contiguous bytes after completing any buffered block use
scalar arithmetic. For many tiny updates prefer the portable owner. This does
not accelerate AEAD or establish target timing qualification.
In particular, a 32-bit target can lower wide products to instructions or
runtime helpers with operand-dependent latency. A Cortex-M compile check
does not qualify its multiplier. Use `verify` for received tags, not `==`
on the bytes returned by `finalize`.
