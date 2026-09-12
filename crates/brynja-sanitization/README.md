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

# brynja-sanitization

Optional `no_std` secret-storage adapter around the separately admitted
`sanitization` package. Its exact dependency and disabled default features are
recorded in Cargo metadata and the admission review, not a README version pin.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Fixed-size secret ownership and explicit Brynja-region copies | ✅ Implemented | ❌ No |
| TLS, hash/cipher algorithms or a FIPS module | Not provided | Not applicable |

No named independent review or FIPS validation is claimed. This adapter is
not a facade/default dependency or a future validated-module component.
It is not required for Brynja's internal mandatory `brynja-core` clearing.

## Use

For the published adapter:

```sh
cargo add brynja-sanitization --no-default-features
```

Use a local path for the current checkout's admitted dependency update.

```rust
use brynja_sanitization::SanitizedSecret;
let secret = SanitizedSecret::<4>::try_from_fn(|index| index as u8).unwrap();
assert_eq!(secret.inspect(|bytes| bytes.len()), 4);
secret.clear();
```

The owner is non-copyable with redacted debugging, closure-scoped inspection,
transactional replacement and explicit clearing. Named methods copy to/from
`brynja-core` secret regions; copies are never implicit. Rich source errors
cannot cross the boundary. Inspection can create caller-owned copies, which
the adapter cannot erase.

## Hardware and SIMD

No hash/cipher acceleration is provided. Clearing is a memory-lifecycle
operation, not cryptographic SIMD. Registers, compiler copies, caches, swap,
dumps, forgotten owners, abort and forced termination are outside the guarantee.

See the [dependency admission and residual risks](https://github.com/valkyoth/brynja/blob/main/docs/sanitization-admission-review.md).
MIT OR Apache-2.0.
