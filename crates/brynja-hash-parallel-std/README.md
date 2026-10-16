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
| Scoped portable root with bounded borrowed-leaf thread handoff | 🚧 Implemented; qualification pending | ❌ No |
| Scoped root/leaf storage with independently selected threaded acceleration | 🚧 Implemented; qualification pending | ❌ No |
| Independently selected hardened root/worker acceleration | 🚧 In progress: qualification pending | ❌ No |
| Hardened multibuffer worker groups with clearing result transport | 🚧 Implemented; qualification pending | ❌ No |
| Scoped multibuffer workers with guarded parent slots and scoped root | 🚧 Implemented; qualification pending | ❌ No |
| Strict protected scalar root, concurrent leaf stacks, CVs and output | 🚧 Implemented; qualification pending | ❌ No |
| Strict protected accelerated root and single/SIMD leaf workers | 🚧 Implemented; qualification pending | ❌ No |
| Apple Silicon resident scalar/Arm/NEON root and bounded concurrent leaf workers; no dump exclusion | 🚧 Implemented; qualification pending | ❌ No |

Brynja is not FIPS 140-3 validated. Threading and project tests do not constitute
independent verification. This `std` package is absent from the modern facade's
defaults, bare-metal builds and FIPS module boundaries.

## Use from a checkout

On Apple Silicon macOS, the distinct default-off `macos-resident` feature adds
`macos_resident::Session`. It uses preacquired guarded, wired, fork-excluded
root/worker stacks, CV slots, staging and output; all started workers join before
the complete stack payloads are cleared. **It does not exclude core dumps and is
not the strict profile.** Unsupported targets fail rather than falling back.
The independent `macos-resident-acceleration` feature adds `CompiledSession` with
explicit Arm Keccak roots and single-Arm or NEON batch leaves. Build-wide
`-C target-feature=+neon,+sha3` and a compatible lifetime-wide deployment are
required; enabling the Cargo feature alone does not grant instruction support.
Partial/ineligible SIMD leaf groups use declared resident scalar tails, never
fallback after an authority failure. Sessions and output loans are affine;
inputs and copies made via `expose()` remain the caller's responsibility.

```rust
# #[cfg(all(feature = "macos-resident", target_os = "macos", target_arch = "aarch64"))] {
use brynja_hash_parallel_std::macos_resident::{Algorithm, Limits, Session};
let mut session = Session::new(Algorithm::ParallelHash256(256), Limits {
    workers: 4, max_leaves: 128, max_block_bytes: 4096,
    max_customization_bytes: 1024, max_output_bits: 4096,
    stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
    max_buffer_mapping_bytes: 1048576,
})?;
let digest = session.hash(b"message", 1024, b"example")?;
assert_eq!(digest.expose().len(), 32);
drop(digest); // clears the resident result before reuse
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

Native resource failure is an error, never a weaker allocation. Recoverable
worker unwinding joins and clears owned memory, but panic hooks/OS TLS, fatal
aborts, snapshots, dumps and arbitrary register capture are outside this
contract. Do not fork, cancel native workers, or revoke admitted protections
during use. Qualification and independent retest remain pending.

The separate, default-off `strict-execution` feature provides
`strict_execution::Session` for complete bounded requests. It preacquires
resident, dump/fork-excluded storage and joined worker stacks on native GNU/Linux
x86-64/little-endian AArch64; unsupported targets reject, without fallback.
`Session` is scalar. The separate default-off `strict-acceleration` feature adds
`CompiledSession`: an explicitly selected compiled AVX2/Arm Keccak root and
single-state or SIMD-group leaf workers. Incomplete SIMD groups and unequal tails
use explicit clearing scalar work on protected stacks; backend failures never
authorize fallback. Deployment must guarantee the compiled feature bundle
throughout scheduling/migration. Inputs remain caller-owned; lengths and scheduling
are public. Native GNU/Linux protection and independent qualification are pending.

See the [compiled strict Session example](https://github.com/valkyoth/brynja/blob/main/crates/brynja-hash-parallel-std/src/strict_execution/mod.rs)
and [strict-profile limitations](https://github.com/valkyoth/brynja/blob/main/docs/strict-hardening-profile.md).

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

### Scoped portable threaded collection

`with128`/`with256` and their `_bits` variants borrow a caller-owned empty
collector workspace. Workers compute leaves in disjoint clearing slots; only
typed plan/output borrows cross back to the calling thread. The root never
leaves that thread. All workers join and merge in order before the callback,
which can consume the completed collector for fixed or incremental XOF output.

```rust
use brynja_hash_parallel::{ParallelHash128Plan, hardened_in_place::ParallelHash128CollectorWorkspace};
use brynja_hash_parallel_std::{CancellationToken, ParallelHashExecutor};
let executor = ParallelHashExecutor::new(4, 4096)?;
let plan = ParallelHash128Plan::new(b"message split into leaves", 8)?;
let mut workspace = ParallelHash128CollectorWorkspace::new();
let mut output = [0; 32];
let secret = executor.with128(
    &mut workspace, &plan, b"example", &CancellationToken::new(),
    |root| root.finalize_secret(&mut output),
)??;
assert_eq!(secret.expose().len(), 32);
drop(secret);
assert_eq!(output, [0; 32]);
# Ok::<(), brynja_hash_parallel_std::ParallelHashExecutorError>(())
```

These methods select portable processing only, not automatic acceleration.
The callback cannot return the root/reader but can return a typed output borrowing
its own destination. Admission/worker failures skip the callback: destinations
captured only by that callback are **not** automatically cleared. Cancellation
is checked before the callback; subsequent reader use is controlled by the caller.
The executor's nonblocking gate remains held through the callback. Recoverable
callback unwinding clears the workspace and poisons the gate; the workspace may
be reused with a different executor. Forgetting a scoped root/reader does not
bypass its outer workspace cleanup. Abort, register/spill and caller-copy limits
remain unchanged. These callback methods are portable-only; use the separate
scoped execution adapter below for accelerated workers.

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

### Scoped accelerated threaded execution

With `runtime-execution`, select `execution::in_place::Executor` for the same
four identities and independent root/leaf preferences using scoped storage
throughout. Authorities and empty workspaces are initialized on the thread
that uses them; only completed plan/output borrows return from workers.

```rust
use brynja_hash_parallel::{Fips202BitString, execution::Identity};
use brynja_hash_parallel_std::{CancellationToken, execution::{Config, Error, Preference, Request, in_place::Executor}};
let executor = Executor::new(Config {
    workers: 4, max_leaves: 4096,
    root: Preference::Prefer, leaves: Preference::Prefer,
})?;
let request = Request {
    identity: Identity::ParallelHashXof256,
    input: Fips202BitString::new(b"input", 8).map_err(|_| Error::Limits)?,
    block_size: 8,
    customization: Fips202BitString::new(b"application", 8).map_err(|_| Error::Limits)?,
};
let mut output = [0; 64];
let (secret, report) = executor.hash_secret(&request, &mut output, &CancellationToken::new())?;
assert_eq!(report.leaves, 1);
drop(secret);
assert_eq!(output, [0; 64]);
# Ok::<(), Error>(())
```

The byte/bit `hash_public` methods use caller staging covering the complete
output, preserve destinations on failure and clear all supplied staging. Secret
methods clear the entire destination even on admission or worker failure.
Reports distinguish root routing, actual accelerated leaves and thread width;
zero-leaf messages do not create workers or claim a leaf route. The executor gate
stays held through public output commit. Required routes reject unavailable
authority; a backend error never authorizes fallback. Static deployment and
cached hosted-detection limitations remain the same as the other adapters.
This adapter is single-state-per-worker, not multibuffer execution. Complete
compiler-copy/register/spill qualification remains pending. Scoped multibuffer
execution is available through the separate adapter below; existing executors
are unchanged.

### Threaded multibuffer execution

Enable the separate default-off `runtime-batch-execution` feature for
`execution::batch::{Config, Executor}`. Its
[runnable secret-output example](https://github.com/valkyoth/brynja/blob/main/crates/brynja-hash-parallel-std/src/execution/batch.rs)
uses the same request identities and explicit root/worker preferences as above.
Groups contain up to four leaves. `workers` bounds concurrent groups;
`max_leaves` bounds the complete input; `max_group_permutations` separately
bounds each group's leaf work, not root construction/output. Set a positive
`minimum_permutations` crossover. Required routes reject ineligible groups,
including incomplete final groups; Prefer explicitly permits clearing tails.

Workers create their own clearing authority/workspace and return only completed,
plan-bound CV loans. Every started worker is joined, results merge in order, and
unmerged results clear on failures. Reports separate actual vector/scalar work,
groups, accelerated leaves and submitted thread width. This is implemented
development functionality, not complete native/compiler qualification.

For scoped root and worker storage, use
`execution::batch::in_place::Executor` with the same `Config` and `Request`.
Its [runnable example](https://github.com/valkyoth/brynja/blob/main/crates/brynja-hash-parallel-std/src/execution/batch/in_place.rs)
shows secret output and cleanup. The four `hash_public[_bits]` and
`hash_secret[_bits]` methods preserve the same bounds and route choices.
Authority and empty leaf workspaces are constructed inside each worker; only
completed exact-plan CV loans cross back. The coordinator merges in submission
order even when completion is reversed. Parent-owned slots clear after all
workers join, including spawn failure, cancellation, panic or forgotten results.
Public output commits under the executor gate and all staging clears; secret
errors clear the whole supplied destination. This is owned-storage protection,
not a register/spill/compiler-copy erasure guarantee. Abort cannot run Drop.

## Hardware and SIMD

`Portable` never probes a CPU. Hosted `Prefer` permits an observable portable
route only when acceleration is unavailable before processing; `Require`
rejects that absence. `RequireStatic` instead requires a target-specialized
binary and deployment-wide feature guarantees. x86-64 AVX2 and AArch64 SHA3
Keccak sessions are created inside each executing thread, never transferred
from a parent thread. Generic x86 hosted selection remains unavailable.

The report separates root route, actual accelerated leaves and thread width.
Threads are not SIMD lanes. A backend error never authorizes fallback.
Multibuffer workers instead use four-state AVX2 or two-state NEON kernels;
their root still uses independently selected single-state execution.
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
