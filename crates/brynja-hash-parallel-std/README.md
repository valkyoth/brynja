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

This opt-in `std` package runs exact `brynja-hash-parallel` leaf jobs on a
bounded number of native threads and an explicit maximum-leaf work budget. It
contains no cryptographic primitive or third-party dependency. Temporary leaf
storage is limited to the smaller of the admitted leaf count and worker count;
OS thread-launch failures, worker panics, cancellation, allocation failure and
work-budget exhaustion are typed failures that release no output. Completion
order never controls merge order. One executor permits exactly one operation
at a time, so simultaneous calls cannot multiply its configured thread budget;
a competing call fails immediately with `ResourceExhausted`.

```rust
let executor = brynja_hash_parallel_std::ParallelHashExecutor::new(
    4,     // maximum concurrent native workers
    4096,  // maximum leaves admitted for one operation
)?;
# Ok::<(), brynja_hash_parallel_std::ParallelHashExecutorError>(())
```

Callers must choose both limits as trusted deployment policy and share that
executor across the work governed by those limits. Constructing a separate
executor per request creates separate resource budgets and is the caller's
responsibility. Cancellation is cooperative after workers start and is checked
before work admission or allocation.

It is intentionally absent from `brynja`, default features, bare-metal builds,
and any FIPS module boundary.

License: MIT OR Apache-2.0.
