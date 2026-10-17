# Modern facade features

`brynja` and `brynja-crypto` forward the same algorithm features. The examples
below use `brynja::crypto`; users of `brynja-crypto` replace that prefix with
`brynja_crypto`. Existing flat portable functions and types are unchanged.
These APIs require the current unpublished checkout until the planned
publication checkpoint. No crate version is implied by these examples.

```sh
cargo add brynja --path /path/to/brynja/crates/brynja --no-default-features --features sha2-hardened-execution
```

## Feature selection

All features below are default-off. They expose existing implementations, not
new kernels. Every execution/batch feature also exposes the `cpu` namespace
for explicit no_std authority construction; `general-sha512-t` alone does not.

| Feature(s) on either facade | Namespace/API | Profile |
| --- | --- | --- |
| `cpu` | `cpu` | Low-level no_std authority and candidate inventory; not host detection |
| `general-sha512-t` | `sha2::Sha512T`, `sha2::sha512_t` | General-t extension, including existing hardened portable APIs |
| `sha2-static-execution`, `sha2-runtime-execution` | `sha2::execution` | Ordinary public-data single-stream execution |
| `sha2-hardened-execution` | `sha2::hardened_execution` | Explicit secret-bearing execution |
| `sha256-batch`, `sha512-batch` | `sha2::batch`, `sha2::batch512` | Ordinary public-data independent-message SIMD |
| `sha256-hardened-batch`, `sha512-hardened-batch` | `sha2::hardened_batch`, `sha2::hardened_batch512` | Distinct clearing batch owners |
| `sha3-static-execution`, `sha3-runtime-execution` | `sha3::execution` | Ordinary SHA-3/SHAKE/cSHAKE execution |
| `sha3-hardened-execution` | `sha3::hardened_execution` | Hardened SHA-3/SHAKE/cSHAKE owners |
| `keccak-batch`, `keccak-hardened-batch` | `sha3::batch`, `sha3::hardened_batch` | Distinct ordinary/clearing independent-state SIMD |
| `kmac-hardened-execution`, `kmac-runtime-execution` | `kmac::execution` | Hardened KMAC/KMACXOF |
| `tuplehash-hardened-execution`, `tuplehash-runtime-execution` | `tuplehash::execution` | Hardened TupleHash/TupleHashXOF |
| `parallelhash-hardened-execution`, `parallelhash-runtime-execution` | `parallelhash::execution` | Hardened serial/caller-scheduled ParallelHash/ParallelHashXOF |
| `parallelhash-hardened-batch` | `parallelhash::execution::batch` | Hardened grouped leaves; threading remains a hosted concern |

Byte/bit input, streaming, fixed/XOF output and general-t types retain the leaf
API contracts. A runtime feature permits importing a runtime authority; it
does not install a detector or select a backend automatically. The portable
flat functions remain portable even if another dependency enables execution.

## Explicit portable execution

With `sha2-hardened-execution`, select the ordinary or hardened type explicitly:

```rust
use brynja::crypto::sha2::{execution as ordinary, hardened_execution as hardened};
let result = ordinary::Sha256::hash(ordinary::Execution::portable(), b"abc").unwrap();
assert_eq!(result.digest, brynja::crypto::sha256(b"abc").unwrap());

let mut output = [0; 32];
{
    let secret = hardened::Sha256::hash_secret(
        hardened::Execution::portable(), b"private input", &mut output).unwrap();
    assert_eq!(secret.digest.expose().len(), 32);
}
assert_eq!(output, [0; 32]);
```

For leaf-only dependencies, select the leaf's corresponding feature and use
its crate name directly: for example `brynja-hash-sha2/hardened-execution` and
`brynja_hash_sha2::hardened_execution`. Reexports do not wrap or weaken owners.

## Hosted and protected profiles stay separate

Use `brynja-crypto-cpu-std` for hosted CPU selection and operation-specific
preferred/required authorities, and `brynja-hash-parallel-std` for bounded
joined workers. Their features are independent opt-ins; the no_std facades
never activate them. See the [hosted adapter](../crates/brynja-crypto-cpu-std/README.md)
and [ParallelHash executor](../crates/brynja-hash-parallel-std/README.md) examples.
Required acceleration must reject when unavailable; a backend failure never
authorizes silent fallback. Static deployment must establish ISA support before
constructing authority. A Cargo feature alone is not that guarantee.

Protected/resident profiles have different guarantees and platform limits;
they are not enabled by these execution features. For a protected-only API
surface use [brynja-strict](../crates/brynja-strict/README.md) and enforce your
application's dependency policy. Legacy SHA-1/MD5 must be selected from their
separate leaf/hosted packages, never through the modern facade.

## Security and Cargo unification

Ordinary state/workspaces accept public data only and do not erase secret
remnants. Classification markers are caller assertions, not provenance checks.
Hardened APIs retain their bounded cleanup guarantees and documented residuals;
facade reachability is not independent verification, FIPS approval or a stronger
protection profile. Existing candidate backends retain their admission status.

Cargo features are additive across dependents. A leaf feature selected elsewhere
can appear through its facade namespace even without the matching facade flag.
That is intentional namespace reexport behavior, not a secrecy boundary.
Independent package tests must not rely on workspace-root feature unification.

## Focused verification

`python3 scripts/repository/check-facade-package.py` packages and extracts the
modern closure, compiles isolated opt-ins for `x86_64-unknown-none`, checks
default isolation and rejects absent APIs. `--toolchain 1.90.0` checks the MSRV.
Debug/release checks exercise portable output equivalence and clearing owners;
they do not stand in for native accelerated qualification or a full sweep.
