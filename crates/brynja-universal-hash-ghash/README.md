<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja-universal-hash-ghash">Crates.io</a>
  |
  <a href="https://docs.rs/brynja-universal-hash-ghash">Docs.rs</a>
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

# brynja-universal-hash-ghash

Enable `hazmat-ghash` for allocation-free, incremental GHASH on pre-framed
blocks. The default build exposes no primitive. The caller supplies the hash
subkey, a 16-byte workspace, a byte budget and separate output storage.
`SecretHash` is an intermediate, not a tag: GHASH alone does not authenticate
messages. Use AES-GCM or GMAC for those constructions. This is not POLYVAL.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Portable `no_std` GHASH over complete 16-byte blocks | ✅ Implemented | ❌ Not independently verified |
| Explicit native multiplication on supported targets | ✅ Implemented | ❌ Not independently verified |

Arm PMULL timing remains unqualified; see the [timing observations](https://github.com/valkyoth/brynja/blob/main/docs/assurance/ghash-pmull-order-control.md).

## Use framed input

Chunks need not end at a block boundary, but the complete input must.
`finish` rejects a partial last block; it does not add message padding or
length fields for you. Here a public field-identity subkey makes the expected
one-block product easy to check:

```rust
use brynja_universal_hash_ghash::ghash::{Error, Ghash};

fn main() -> Result<(), Error> {
    let h = (1u128 << 127).to_be_bytes();
    let block = [0xab; 16];
    let mut workspace = [0; 16];
    let mut hash = Ghash::new(&h, &mut workspace, 16);
    hash.update(&block[..5])?;
    hash.update(&block[5..])?;
    let mut output = [0; 16];
    let result = hash.finish(&mut output)?;
    assert_eq!(result.expose(), &block);
    result.clear();
    assert_eq!(output, [0; 16]);
    Ok(())
}
```

## Hardware and SIMD

Portable construction never selects native execution. The optional
`ghash-runtime-execution` feature adds explicit backend selection with the
same platform and timing limitations as the compatibility API. The
`__mode` interfaces are for Brynja composition and are not stable user APIs.
Any dependent can name them when their features are enabled, including by
Cargo feature unification. They expose GHASH framing, not a security boundary.
Use `hazmat-ghash` for the supported raw API; `cpu` alone exposes no API.

MIT OR Apache-2.0.
