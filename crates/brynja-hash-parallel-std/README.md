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

# brynja-hash-parallel-std

Optional bounded OS-thread scheduling for all four Brynja ParallelHash
identities. All cryptography stays in the first-party leaf crates; this
package owns scheduling, resource admission and local worker selection.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Bounded portable ParallelHash/ParallelHashXOF worker executor | ✅ Implemented | ❌ No |
| Independently selected hardened root/worker acceleration | 🚧 In progress: qualification pending | ❌ No |

Brynja is not FIPS 140-3 validated. Threading and project tests do not constitute
independent verification. This `std` package is absent from the modern facade's
defaults, bare-metal builds and FIPS module boundaries.

## Use from a checkout

The package is currently unpublished. Select it separately:

```sh
cargo add brynja-hash-parallel-std --path /path/to/brynja/crates/brynja-hash-parallel-std --no-default-features
```

### Portable bounded executor

```rust
let executor = brynja_hash_parallel_std::ParallelHashExecutor::new(
    4,     // maximum simultaneous workers
    4096,  // maximum leaves admitted for one operation
)?;
# Ok::<(), brynja_hash_parallel_std::ParallelHashExecutorError>(())
```

Its four fixed/XOF operations include canonical bit-input/output variants.
Public output is transactional. Allocation, launch, worker panic, cancellation
and work-limit failures are typed errors. Completion order does not determine
merge order. Temporary leaf storage is bounded by the smaller of the leaf and
worker counts, and every started worker is joined.

### Explicit root and worker selection

Enable `runtime-execution` for `execution::Executor`. Also add the local
`brynja-hash-parallel` leaf for its request types.

```rust
use brynja_hash_parallel::{Fips202BitString, execution::Identity};
use brynja_hash_parallel_std::{
    CancellationToken,
    execution::{Config, Error, Executor, Preference, Request},
};
let executor = Executor::new(Config {
    workers: 2,
    max_leaves: 64,
    root: Preference::Prefer,
    leaves: Preference::Prefer,
})?;
let request = Request {
    identity: Identity::ParallelHash128,
    input: Fips202BitString::new(b"message", 8).map_err(|_| Error::Limits)?,
    block_size: 8,
    customization: Fips202BitString::new(&[], 0).map_err(|_| Error::Limits)?,
};
let mut output = [0; 32];
let mut scratch = [0; 32];
let report = executor.hash_public(
    &request, &mut output, &mut scratch, &CancellationToken::new(),
)?;
assert_eq!(report.leaves, 1);
assert_eq!(scratch, [0; 32]);
# Ok::<(), Error>(())
```

Use `hash_secret`/`hash_secret_bits` for typed clearing output ownership.
The entire secret destination and public staging are cleared on errors;
caller-owned input/customization and copies remain the caller's responsibility.

## Hardware and SIMD

`Portable` never probes a CPU. Hosted `Prefer` permits an observable portable
route only when acceleration is unavailable before processing; `Require`
rejects that absence. `RequireStatic` instead requires a target-specialized
binary and deployment-wide feature guarantees. x86-64 AVX2 and AArch64 SHA3
Keccak sessions are created inside each executing thread, never transferred
from a parent thread. Generic x86 hosted selection remains unavailable.

The report separates root route, actual accelerated leaves and thread width.
Threads are not SIMD lanes. A backend error never authorizes fallback.
The new execution profile still requires final qualification and native evidence;
see the [execution guide](https://github.com/valkyoth/brynja/blob/main/docs/parallelhash-execution.md).

## Resource and cleanup boundaries

Share one executor across work governed by its limits. Concurrent calls on that
executor fail without waiting; creating an executor per request creates separate
budgets. No unbounded nested pool is created. Cancellation is cooperative
between operations, not preemption of a running compression call.

Worker slots, retained state and staging have explicit clearing owners.
Register, compiler-spill, cache, dump, swap, abort and caller-copy erasure are
not guaranteed. The adapter does not impose global process or memory-lock policy.

License: MIT OR Apache-2.0.
