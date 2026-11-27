<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://github.com/valkyoth/brynja/tree/main/crates/brynja-legacy-hkdf">Source (unpublished)</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/crates/brynja-legacy-hkdf/src/lib.rs">API source</a>
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

# brynja-legacy-hkdf

Explicit, allocation-free `no_std` RFC 5869 HKDF-SHA-1 compatibility for
historical protocols. Do not use this crate for new protocols. It is separate
from the modern Brynja facade and requires `LegacyUse::acknowledge()` when
extracting or importing a pseudorandom key (PRK).

`Sha1Prk` supports Extract, imported PRKs, Expand and multipart `expand_parts`.
Multipart info is plain concatenation: it adds no framing or domain separation.
Callers must encode unambiguous protocol context themselves. Expansion is
limited to 255 SHA-1 blocks (5100 bytes). There is no MD5 HKDF, TLS key schedule,
TLS label helper or modern algorithm fallback.

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Portable HKDF-SHA-1 Extract and Expand | Yes, with explicit legacy acknowledgement | No independent certification |
| Multipart info without allocation | Yes | No independent certification |

## Derive a legacy protocol key

Depend directly on this crate; no feature flag is required. This example
uses the public inputs and first eight expected output bytes from RFC 5869
Appendix A, test case 4. The derived key is borrowed, not returned as an
unmanaged copy.

```rust
use brynja_legacy_hkdf::{Error, LegacyUse, Sha1Prk};

fn main() -> Result<(), Error> {
    let salt = core::array::from_fn::<_, 13, _>(|i| i as u8);
    let info = core::array::from_fn::<_, 10, _>(|i| 0xf0 + i as u8);
    let mut prk_storage = [0; 20];
    let prk = Sha1Prk::extract(LegacyUse::acknowledge(), Some(&salt), &[0x0b; 11], &mut prk_storage)?;
    let mut output = [0; 8];
    let key = prk.expand(&info, &mut output)?;
    assert_eq!(key.expose(), &[0x08, 0x5a, 0x01, 0xea, 0x1b, 0x10, 0xf3, 0x69]);
    drop(key);
    assert_eq!(output, [0; 8]);
    Ok(())
}
```

PRK and output owners borrow caller-provided storage and clear it on ordinary
drop and recoverable unwind. Caller-created copies, forgotten owners, compiler
spills, registers, paging, crash dumps and aborts are outside that guarantee.
Applications must bound attacker-controlled input lengths and multipart part
counts; this API does not impose a processing-work quota. HKDF is not password
hashing and cannot create entropy absent from its input.

## Hardware and verification

This crate uses legacy HMAC-SHA-1. It offers no hardware selector or
automatic modern-algorithm fallback.

Project tests are not independent cryptographic certification or deployment
approval. HKDF-specific independent review and target/compiler side-channel
qualification remain separate requirements. See the repository's
[verification status](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md)
and [public API assurance notes](https://github.com/valkyoth/brynja/blob/main/docs/assurance/hkdf-public-api.md).

## License

Licensed under either the [Apache License, Version 2.0](https://github.com/valkyoth/brynja/blob/main/crates/brynja-legacy-hkdf/LICENSE-APACHE)
or the [MIT license](https://github.com/valkyoth/brynja/blob/main/crates/brynja-legacy-hkdf/LICENSE-MIT), at your option.
