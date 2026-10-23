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
| Explicit hardened SHA-1 execution | Opt-in `sha1-execution`; x86 author tests, qualification pending | ❌ No |
| MD5 SIMD HMAC | Not yet implemented | ❌ No |

No independent qualification or FIPS approval is claimed. Existing hash
qualification does not qualify this new keyed composition. Caller copies,
compiler frames, registers, spills, paging, dumps and fatal abort are outside
owned-memory destruction. No protected-memory promise is made.

## Hardware and SIMD

`Hmac<Sha1>` and `Hmac<Md5>` always use portable hardened legacy hash owners,
even if another dependency enables their CPU features. The separate
`sha1-execution` feature exposes `execution::Sha1Hmac`, borrowing an already
accelerated `execution::Sha1Executor` for normalization, inner and outer hashing.
It rejects portable executors, admits all empty streams before key absorption,
and never falls back after failure. Source-owned inner and outer state are both
dropped on fatal update or recoverable unwind; atomic length rejection preserves
them. This does not promise whole-frame or fatal-abort erasure.

The caller establishes the executor's complete lifetime-wide CPU/OS contract;
the Cargo feature alone does not enable instructions. Static selection needs
the complete build target features. A hosted legacy SHA-1 adapter may instead
supply its hardened executor, subject to its platform restrictions. Neither a
route report nor cached feature detection proves safe CPU/VM migration.
MD5 SIMD composition remains unimplemented. No underlying hash qualification
automatically qualifies either HMAC composition.

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
