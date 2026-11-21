# Portable GHASH consumer

Run `python3 scripts/ghash/check-packaged-api.py` from the repository root.
The runner builds local Cargo archives, checks their contents, and compiles
this consumer twice: through `brynja_crypto::ghash` and through
`brynja::crypto::ghash`. Both require the explicit `hazmat-ghash` feature;
the example uses the direct spelling. Neither configuration selects a CPU backend.

```rust
use brynja_crypto::ghash::{Error, Ghash};

# fn example() -> Result<(), Error> {
// Public fixture: the multiplicative identity in GHASH wire order.
let h = (1_u128 << 127).to_be_bytes();
let (mut workspace, mut out) = ([0; 16], [0; 16]);
let mut g = Ghash::new(&h, &mut workspace, 16);
g.update(&[0x42; 7])?;
g.update(&[0x42; 9])?;
let secret = g.finish(&mut out)?;
assert_eq!(secret.expose(), &[0x42; 16]);
secret.clear();
assert_eq!(out, [0; 16]);
# Ok(()) }
# example().unwrap();
```

The input must already be framed. There is no implicit padding, tag masking,
or authentication decision. Never publish a raw GHASH result as a MAC.
Cleanup checks inspect live caller buffers, not registers or compiler spills.
