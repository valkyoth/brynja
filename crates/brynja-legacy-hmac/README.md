<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja">Crates.io</a>
  |
  <a href="https://docs.rs/brynja">Docs.rs</a>
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
    <img src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
  </a>
</p>

# brynja-legacy-hmac

Explicit, allocation-free `no_std` HMAC-SHA-1 and HMAC-MD5 compatibility.
Do not use these algorithms for new protocols. This package is deliberately
absent from modern facades, defaults, protocol negotiation and approved services.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| HMAC-SHA-1 and HMAC-MD5 | Portable initial implementation | ❌ No |
| Streaming, long keys, explicit byte truncation and verification | Initial implementation with author tests | ❌ No |
| Public tags and clearing secret tags | Implemented; composition cleanup qualification pending | ❌ No |
| Hardware acceleration and SIMD HMAC | Not yet implemented | ❌ No |

No independent qualification or FIPS approval is claimed. Existing hash
qualification does not qualify this new keyed composition. Caller copies,
compiler frames, registers, spills, paging, dumps and fatal abort are outside
owned-memory destruction. No protected-memory promise is made.

## Hardware and SIMD

This initial API always uses the portable hardened legacy hash owners, even if
another dependency enables their CPU features. Explicit SHA-1 accelerated and
MD5 SIMD composition needs separate implementation and qualification; do not
infer support from the underlying hash crates.

## Use

Install explicitly with `cargo add brynja-legacy-hmac` once published; until then,
use the reviewed workspace path. Nothing is added to `brynja::crypto`.

```rust
use brynja_legacy_hmac::{Hmac, LegacyUse, Sha1};
let key = [0x42; 32]; // Example only; real keys require adequate unpredictability.
let mut state = Hmac::<Sha1>::new(LegacyUse::acknowledge(), &key)?;
state.update(b"legacy message")?;
let mut bytes = [0; 20];
let tag = state.finalize_tag(&mut bytes)?;
let mut verifier = Hmac::<Sha1>::new(LegacyUse::acknowledge(), &key)?;
verifier.update(b"legacy message")?;
assert!(verifier.verify(tag.as_bytes())?.expose_public());
# Ok::<(), brynja_legacy_hmac::Error>(())
```

`LegacyUse` is a caller acknowledgement, not runtime provenance enforcement.
Full tags are the default. `with_tag_length` selects 10 bytes (80 bits) through
the full digest width before message processing, including the historical
12-byte (96-bit) profile. Modern HMAC's minimum is unchanged. Never select the
width from an untrusted incoming tag. Applications enforce work limits and
failed-verification quotas.

`finalize_secret` returns an affine clearing output owner. Public-output errors
leave the destination unchanged; secret-output errors clear the destination.
Typed `BitString` finalization accepts canonical high-order final message bits.
Keys and truncation are byte-aligned. There is no reset, key export, snapshot,
public preflight length oracle, or ordinary/modern digest conversion.
