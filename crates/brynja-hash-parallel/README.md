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

# brynja-hash-parallel

`brynja-hash-parallel` implements `ParallelHash128`, `ParallelHash256`,
`ParallelHashXOF128`, and `ParallelHashXOF256` from NIST SP 800-185. It is
`no_std`, allocation-free, contains no third-party dependency, and uses the
length of a caller-owned leaf workspace as the positive block-size parameter
`B`.

```rust
let mut workspace = [0_u8; 8];
let mut digest = [0_u8; 32];
brynja_hash_parallel::parallel_hash128(
    b"a long message split into leaves",
    &mut workspace,
    b"application-v1",
    &mut digest,
)?;
# Ok::<(), brynja_hash_parallel::ParallelHashError>(())
```

Streaming, canonical arbitrary-bit, incremental XOF, hardened secret-bearing,
and caller-scheduled ordered-leaf APIs are included. A distinct optional
`brynja-hash-parallel-std` package supplies separately selected native threads
with explicit worker/leaf budgets and recoverable launch failures, without
entering this portable package, Brynja defaults, or a FIPS module boundary.

## Cryptography Verification Status

| Function family | Implemented | Independently verified | FIPS 140-3 validated |
| --- | --- | --- | --- |
| ParallelHash / ParallelHashXOF | ✅ Fully implemented | ❌ No | ❌ No |

Implementation status is not independent assurance. Only a named independent
reviewer with linked evidence can change that status. The repository's tests,
CI, Kani, Miri, fuzzing, sanitizers, differential campaigns, and pentests do
not constitute independent cryptographic review or FIPS validation.

License: MIT OR Apache-2.0.
