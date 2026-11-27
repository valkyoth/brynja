<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja-aead-gcm">Crates.io</a>
  |
  <a href="https://docs.rs/brynja-aead-gcm">Docs.rs</a>
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

# brynja-aead-gcm

Enable `aes-gcm` for detached authenticated encryption or `gmac` for AAD-only authentication. No features are enabled by default. Each API supports AES-128, AES-192 and AES-256 without allocation. For example, import `brynja_aead_gcm::aes_gcm::Aes256Gcm` or `brynja_aead_gcm::gmac::Aes256Gmac`. The existing `brynja_crypto` and `brynja::crypto` imports refer to the same owners.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Detached AES-GCM (encrypts the message; authenticates ciphertext and associated data) | ✅ Implemented | ❌ Not independently verified |
| Standalone GMAC (authenticates associated data without encrypting it) | ✅ Implemented | ❌ Not independently verified |

## Open an authenticated record

With `aes-gcm` enabled, a receiver needs the key, IV, associated data, and
detached tag. It does **not** need a sending reservation. In this public
AES-128-GCM known-answer example, the decrypted block is all zeros:

```rust
use brynja_aead_gcm::aes_gcm::{Aes128Gcm, GcmError};

fn main() -> Result<(), GcmError> {
    let mut schedule = [0; 176];
    let receiver = Aes128Gcm::<16>::for_open(&[0; 16], &mut schedule)?;
    let mut data = 0x0388dace60b6a392f328c2b971b2fe78u128.to_be_bytes();
    let tag = 0xab6e47d42cec13bdf53a67b21257bddfu128.to_be_bytes();
    let mut scratch = [0; 16]; // Same length as the message.
    receiver.open_in_place(&[0; 12], &[], &tag, &mut data, &mut scratch)?;
    assert_eq!(data, [0; 16]);
    Ok(())
}
```

For GMAC, enable `gmac` and use `for_verify` and `verify` with a `GmacTag`.
A tag imported from the wire is not authenticated until verification succeeds.
For example, this public NIST vector verifies a 12-byte tag with a one-byte
IV (the `GmacTag` type fixes the tag width, not the IV width):

```rust
use brynja_aead_gcm::gmac::{Aes128Gmac, GmacError, GmacTag};

fn main() -> Result<(), GmacError> {
    let key = 0x553b17055a29da863d83575213c012c9u128.to_be_bytes();
    let aad = 0x5ca5f3756fb3738666d28bda57361b00u128.to_be_bytes();
    let tag = GmacTag::from_bytes([0xa9, 0x3b, 0x0d, 0xc0, 0x40, 0x86,
                                   0xda, 0x30, 0x2d, 0x84, 0xd1, 0xf3]);
    let mut schedule = [0; 176];
    let verifier = Aes128Gmac::<12, 1>::for_verify(&key, &mut schedule)?;
    verifier.verify(&[0x72], &aad, &tag)?;
    assert_eq!(verifier.verify(&[0x72], &[], &tag), Err(GmacError::Authentication));
    Ok(())
}
```

## Sending and nonce ownership

Reserve disjoint IV ranges durably before sending. Do not reuse a nonce under the same key, including across processes, restarts or GCM/GMAC use. Opening does not provide replay protection.

A 64-bit counter is an IV format, not permission to send that much traffic. Limit records, total data and failed authentications across all owners of a key according to the protocol, and rotate the key before its limit. These senders construct prefix-and-counter IVs, not the static-IV XOR sequence numbers used by TLS 1.3 and QUIC.

Use the documented mode features rather than depending on the primitive crates' hidden `__mode` bridges. Those bridges are implementation interfaces, not stable public contracts or access controls.

## Hardware and SIMD

Portable constructors never dispatch automatically. The separate
`aes-gcm-execution` and `gmac-execution` features expose paired AES-NI/PCLMUL
on Linux/Windows x86-64 and AES/PMULL on Linux/macOS ARM64. They do not
establish timing qualification; see the
[paired execution notes](https://github.com/valkyoth/brynja/blob/main/docs/assurance/aead-accelerated-development.md).

MIT OR Apache-2.0.
