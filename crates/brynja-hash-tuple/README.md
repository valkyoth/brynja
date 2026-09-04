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

`brynja-hash-tuple` implements all four SP 800-185 tuple-hashing functions:
`TupleHash128`, `TupleHash256`, `TupleHashXOF128`, and `TupleHashXOF256`.
It is `no_std`, allocation-free, contains no third-party dependency, and reuses
Brynja's hardened cSHAKE owner rather than duplicating Keccak.

```rust
use brynja_hash_tuple::tuple_hash128;

let items: &[&[u8]] = &[b"ab", b"c"];
let mut digest = [0_u8; 32];
tuple_hash128(items, b"application-v1", &mut digest)?;
# Ok::<(), brynja_hash_tuple::TupleHashError>(())
```

Tuple identity is structural: `("ab", "c")`, `("a", "bc")`, one `"abc"`
item, and reordered items produce distinct inputs to the construction. Exact
arbitrary-bit items and affine streamed items are also supported. The parent
state arms its item-open latch before returning a writer, so abandoning,
forgetting, or manually suppressing destruction of an incomplete item cannot
yield output.

The ordinary API classifies output as public. Use the distinct `Hardened*`
states when tuple items or derived state are secret-bearing; all crate-owned
sponge, staging, byte-backed tuple metadata, encoded-length owners, and reader
state are cleared through Brynja's compiler-resistant cleanup boundary.
Finalization changes the embedded cSHAKE state in place: fixed-output methods
borrow their state and XOF methods return a lifetime-bound reader, avoiding a
by-value transfer of the secret-bearing owner. Final bit output clears that
exact embedded allocation before return.
Caller-owned inputs and copied outputs remain the caller's responsibility.

## Cryptography Verification Status

| Function family | Implemented | Independently verified | FIPS 140-3 validated |
| --- | --- | --- | --- |
| TupleHash / TupleHashXOF | ✅ Fully implemented | ❌ No | ❌ No |

Implementation status is not independent assurance. Only a named independent
reviewer with linked evidence can change that status. The repository's tests,
CI, Kani, Miri, fuzzing, sanitizers, differential campaigns, and pentests do
not constitute independent cryptographic review or FIPS validation.

License: MIT OR Apache-2.0.
