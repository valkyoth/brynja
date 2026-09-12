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

# brynja-hash-tuple

First-party, allocation-free `no_std` TupleHash128/256 and
TupleHashXOF128/256 from NIST SP 800-185. The implementation reuses Brynja's
hardened cSHAKE owner, without duplicating Keccak. It has no third-party dependency.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| TupleHash / TupleHashXOF, all four identities | ✅ Fully implemented | ❌ No |
| Byte/bit tuples, streamed items and hardened outputs | ✅ Implemented | ❌ No |
| Hardened accelerated execution | ✅ Opt-in, platform-limited | ❌ No |

Implementation is not independent assurance. No named independent
cryptographic review or FIPS 140-3 validation is claimed.

## Use

Use the unpublished workspace leaf from a local checkout:

```sh
cargo add brynja-hash-tuple --path /path/to/brynja/crates/brynja-hash-tuple --no-default-features
```

```rust
use brynja_hash_tuple::tuple_hash128;
let mut first = [0; 32];
let mut second = [0; 32];
tuple_hash128(&[b"ab", b"c"], b"application-v1", &mut first).unwrap();
tuple_hash128(&[b"a", b"bc"], b"application-v1", &mut second).unwrap();
assert_ne!(first, second);
```

Tuple boundaries and order are part of the input: `("ab", "c")`,
`("a", "bc")` and a single `"abc"` item are distinct. Exact arbitrary-bit
items and affine streamed item writers preserve those boundaries. Declare an
item's exact size before writing it. Dropping or forgetting an incomplete
writer cannot yield a valid completed hash.

Use ordinary types for public tuples and output; choose distinct `Hardened*`
types for confidential items or derived state. The public API exposes fixed
output and incremental XOF readers with explicit public declassification or
typed secret destinations.

## Hardware and SIMD

Defaults are portable. Default-off `hardened-execution` exposes
`execution::TupleHash128/256`, `TupleHashXof128/256` and separate
`Hardened*` variants. `runtime-execution` adds hosted support while the
leaf remains `no_std`.

Static x86-64 AVX2 and AArch64 SHA3/NEON use hardened Keccak. Hosted acceleration
requires qualifying AArch64 system-wide feature guarantees; generic x86 hosted
requests cannot establish that authority. Preferred selection falls back only
when no authority was supplied, never after a kernel error. Fixed finalizers
consume state; writers and XOF readers retain exclusive borrows.

See [execution, scratch and platform examples](https://github.com/valkyoth/brynja/blob/main/docs/tuplehash-accelerated-execution.md).

## Secret ownership

Brynja clears its source-declared sponge, encoded lengths, tuple metadata,
staging and readers. Secret-output failures clear the destination; public
output is transactional. In-place finalization prevents reopening a vacated
cSHAKE owner. Observable tuple counters are cleared on successful finalization.

Callers own their original inputs and output copies. Cleanup does not promise
erasure of registers, compiler copies/spills, caches, dumps, swap, forgotten
owners, aborts or forced termination. Hashing a tuple is not authentication.

MIT OR Apache-2.0.
