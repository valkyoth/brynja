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

# brynja-hash-sha3

First-party, allocation-free `no_std` SHA-3, SHAKE and cSHAKE over Brynja's
Keccak-f[1600] implementation. Ordinary and hardened owners are separate.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| SHA3-224/256/384/512 and SHAKE128/256 | ✅ Fully implemented | ❌ No |
| Byte/bit input and arbitrary-bit SHAKE output | ✅ Fully implemented | ❌ No |
| cSHAKE128/256 and SP 800-185 encodings | ✅ Fully implemented | ❌ No |
| Hardened states and classified outputs | ✅ Implemented | ❌ No |
| Ordinary and hardened accelerated execution | ✅ Opt-in, platform-limited | ❌ No |

FIPS 202 and SP 800-185 specify these algorithms; they do not confer FIPS
140-3 validation. Brynja has no named independent cryptographic review or FIPS
validation. KMAC, TupleHash and ParallelHash live in their own leaf crates,
not as separate algorithms implemented in this crate.

## Use

These APIs include unpublished workspace functionality. Use a local checkout:

```sh
cargo add brynja-hash-sha3 --path /path/to/brynja/crates/brynja-hash-sha3 --no-default-features
```

```rust
use brynja_hash_sha3::{Sha3_256, sha3_256};
let mut hash = Sha3_256::new();
hash.update(b"a").unwrap();
hash.update(b"bc").unwrap();
assert_eq!(hash.finalize(), sha3_256(b"abc").unwrap());

let mut output = [0; 64];
brynja_hash_sha3::shake256(b"abc", &mut output).unwrap();
```

Unlike SHA-2's bit representation, FIPS 202 stores meaningful tail bits in the
low end of the final byte. Output clears unused high bits.

```rust
use brynja_hash_sha3::{Fips202BitString, Fips202Output, shake128_bits};
let input = Fips202BitString::new(&[0b0001_0011], 5).unwrap();
let mut output = [0xff; 13];
let destination = Fips202Output::new(&mut output, 4).unwrap();
shake128_bits(input, destination).unwrap(); // Exactly 100 output bits.
assert_eq!(output[12] & 0xf0, 0);
```

cSHAKE supports explicit function-name and customization domains. Empty name
and customization give exactly SHAKE.

```rust
let mut output = [0; 32];
brynja_hash_sha3::cshake128(&[0, 1, 2, 3], b"", b"Email Signature", &mut output).unwrap();
assert_eq!(&output[..4], &[0xc1, 0xc3, 0x69, 0x25]);
```

For secret-bearing input, use `HardenedSha3_*`, `HardenedShake*` or
`HardenedCshake*`, not the ordinary examples above:

```rust
use brynja_hash_sha3::HardenedSha3_256;
let mut output = [0; 32];
{
    let mut hash = HardenedSha3_256::new();
    hash.update(b"confidential input").unwrap();
    let secret = hash.finalize_secret(&mut output).unwrap();
    assert_eq!(secret.expose().len(), 32);
}
assert_eq!(output, [0; 32]);
```

## Hardware and SIMD

Defaults are portable. Default-off `static-execution` adds ordinary
`execution::Sha3_*`, `Shake*` and `Cshake*`; `runtime-execution`
adds hosted selection. `hardened-execution` enables separate affine
secret-bearing execution owners with private clearing permutation scratch.

x86-64 supports AVX2 Keccak; AArch64 supports SHA3/NEON instructions.
Static execution requires the complete compiler feature bundle and a
compatible deployment. Hosted execution requires supported AArch64
system-wide feature guarantees; generic x86 hosted requests fall back before
execution or fail when required. RISC-V Keccak and AVX-512 are not implemented.

Ordinary execution requires explicit `Public`/`PublicBits` input markers;
these record intent, not proof that bytes are public. Caller scratch supports
allocation-free transactional output. Kernel failures do not silently select
another backend.

- [Ordinary SHA-3/SHAKE](https://github.com/valkyoth/brynja/blob/main/docs/sha3-ordinary-execution.md)
- [Ordinary cSHAKE and hosted sponge](https://github.com/valkyoth/brynja/blob/main/docs/cshake-ordinary-execution.md)
- [Hardened Keccak execution](https://github.com/valkyoth/brynja/blob/main/docs/hardened-keccak-execution.md)

## Security boundaries

Ordinary hash/XOF states do not erase private input remnants. Hardened owners
clear source-declared lanes, counters, staging and scratch on terminal paths;
secret destinations clear on failure and Drop, while public output requires
explicit declassification. Consumed or wiped construction owners cannot reopen
as fresh SHAKE states. Callers remain responsible for their buffers and copies.

No erasure guarantee covers registers, compiler copies/spills, caches, dumps,
swap, forgotten owners, abort or termination. SHA-3 is not raw Keccak, a MAC,
password hashing or an authentication protocol.

MIT OR Apache-2.0.
