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

# brynja-hash-core

Small allocation-free `no_std` interfaces shared by fixed-output and
extendable-output hash implementations. No hash algorithm, runtime dispatch,
I/O or protocol is implemented in this crate.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Incremental hash and XOF interfaces | ✅ Implemented | ❌ No |
| Canonical borrowed MSB-first bit strings | ✅ Implemented | ❌ No |
| Cryptographic algorithms | Not this crate's responsibility | Not applicable |

Interface tests are not independent cryptographic verification or FIPS validation.

## Use

Use this unpublished workspace interface package directly only when composing
or implementing compatible APIs:

```sh
cargo add brynja-hash-core --path /path/to/brynja/crates/brynja-hash-core --no-default-features
```

```rust
use brynja_hash_core::BitString;
let bits = BitString::new(&[0b0110_0000], 3).unwrap();
assert_eq!(bits.bit_len(), 3);
assert_eq!(bits.split(), (&[][..], Some((0b0110_0000, 3))));
assert!(BitString::new(&[0b0110_0001], 3).is_err());
```

Empty strings use zero valid tail bits; nonempty byte-aligned strings use
eight. SHA-3's FIPS 202 low-bit convention uses the different descriptor
provided by `brynja-hash-sha3`, not this MSB-first type.

- `Update` absorbs a complete byte slice or returns a closed error.
- `FixedOutput` consumes a state into its algorithm-specific digest.
- `ExtendableOutput` consumes absorption into a distinct reader.
- `XofReader` fills incremental output slices.

## Hardware and SIMD

None: these are backend-neutral interfaces. Select acceleration and hardened
ownership through the implementing leaf; an interface or borrowed bit string
does not itself zeroize storage or establish secret provenance.

MIT OR Apache-2.0.
