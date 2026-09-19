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

Allocation-free, `no_std` ParallelHash128/256 and ParallelHashXOF128/256
implementations from NIST SP 800-185. The leaf workspace length is the positive
block-size parameter `B`. Cryptographic code is first-party Rust.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| All four portable ParallelHash/ParallelHashXOF identities | ✅ Fully implemented | ❌ No |
| Byte/bit input, streaming, scheduled leaves and hardened secret output | ✅ Implemented | ❌ No |
| Caller-owned portable scoped fixed-output/XOF workspaces | 🚧 Implemented; complete residue qualification pending | ❌ No |
| Opt-in accelerated scheduling and streaming | 🚧 In progress: qualification pending | ❌ No |
| Hardened scheduled/streaming leaf SIMD groups | 🚧 Implemented; qualification pending | ❌ No |

Brynja is not FIPS 140-3 validated. Project tests and pentests are not named
independent cryptographic review. See the
[verification inventory](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md).

## Use from a checkout

This package's APIs are currently unpublished. Use an explicit local dependency:

```sh
cargo add brynja-hash-parallel --path /path/to/brynja/crates/brynja-hash-parallel --no-default-features
```

### Hash a message

```rust
let mut workspace = [0_u8; 8];
let mut digest = [0_u8; 32];
brynja_hash_parallel::parallel_hash128(
    b"a long message split into leaves",
    &mut workspace,
    b"application",
    &mut digest,
)?;
# Ok::<(), brynja_hash_parallel::ParallelHashError>(())
```

The API also includes canonical arbitrary-bit messages/customization, fixed
bit-length output, incremental XOF readers and ordered caller-scheduled leaf
jobs. Select `HardenedParallelHash*` types for confidential inputs and
`finalize_secret` or secret squeezing for confidential results. Secret-output
owners clear their destination on Drop; public output requires an explicit
declassification decision.

### Keep fixed-output state in caller-owned storage

The portable `hardened_in_place` API borrows an empty workspace before accepting
input. Scope cleanup also covers forgotten handles and recoverable unwind.
This API supports ParallelHash128/256 and ParallelHashXOF128/256, not scoped
scheduled, threaded or accelerated execution. Complete register/spill clearing
is not guaranteed; `panic = "abort"` does not run destructors.

```rust
use brynja_hash_parallel::hardened_in_place::ParallelHash128Workspace;

let mut workspace = ParallelHash128Workspace::new();
let mut block = [0; 8]; // B = 8
let mut output = [0; 32];
let secret = workspace.with(&mut block, b"application", |mut state| {
    state.update(b"first chunk")?;
    state.update(b"second chunk")?;
    state.finalize_secret(&mut output)
})??;
assert_eq!(block, [0; 8]);
assert_eq!(secret.expose().len(), 32);
drop(secret);
assert_eq!(output, [0; 32]);
# Ok::<(), brynja_hash_parallel::ParallelHashError>(())
```

Use `with_bits` and `finalize_bits_secret`/`finalize_bits_public` for canonical
partial-bit customization, final input and output. Public output requires
`ParallelHashPublicDeclassification`; secret outputs can leave the scope while
retaining their separate destination borrow. Failed secret finalization clears
the destination; public errors preserve it.

### Incremental scoped XOF output

XOF finalization retains the workspace borrow, not an inline sponge copy. It
clears absorption counters, the leaf output and the block before squeezing.
Readers cannot escape the callback, but typed outputs borrowing a separate
destination may. Drop/cancel clears the reader; the outer scope also covers
forgotten readers and recoverable unwind.

```rust
use brynja_hash_parallel::{
    hardened_in_place::ParallelHashXof256Workspace,
    ParallelHashPublicDeclassification,
};
let mut workspace = ParallelHashXof256Workspace::new();
let mut block = [0; 64];
let mut public = [0; 17];
let mut output = [0; 32];
let secret = workspace.with(&mut block, b"application", |mut state| {
    state.update(b"message")?;
    let mut reader = state.finalize_xof()?;
    reader.squeeze_public(&mut public, ParallelHashPublicDeclassification::acknowledge())?;
    reader.squeeze_final_bits_secret(&mut output, 3)
})??;
assert_eq!(block, [0; 64]);
assert_eq!(secret.expose().len(), 32);
drop(secret);
assert_eq!(output, [0; 32]);
# Ok::<(), brynja_hash_parallel::ParallelHashError>(())
```

Use `finalize_bits_xof` for canonical final input bits. Byte reads can mix public
and secret destinations; a partial-bit output consumes the reader. Empty final
output requires zero valid bits, otherwise specify 1..=8. Reader errors are
terminal, including subsequent empty reads; they preserve public destinations
and clear secret destinations.

### Incremental execution

Enable `hardened-execution` explicitly for the execution API. This example
selects portable hardened work; selecting a CPU session is a separate choice.

```rust
use brynja_hash_parallel::execution::{
    Error, Identity, Mode, Stream, StreamConfig, WorkerPolicy,
};
let mut workspace = [0; 64];
let mut stream = Stream::new(
    StreamConfig {
        identity: Identity::ParallelHash128,
        max_leaves: 64,
        workers: WorkerPolicy::Mixed,
    },
    Mode::Portable,
    &mut workspace,
    b"application",
)?;
stream.update(b"first chunk", |_| Ok(Mode::Portable))?;
stream.update(b"second chunk", |_| Ok(Mode::Portable))?;
let mut output = [0; 32];
let secret = stream.finalize_secret(&mut output, |_| Ok(Mode::Portable))?;
assert_eq!(secret.expose().len(), 32);
drop(secret);
assert_eq!(output, [0; 32]);
assert_eq!(workspace, [0; 64]);
# Ok::<(), Error>(())
```

## Hardware, SIMD and threads

Defaults stay portable. `hardened-execution` accepts explicit hardened Keccak
sessions: x86-64 AVX2 SIMD or AArch64 SHA3 instructions. Static authority
requires a correctly target-specialized binary; `runtime-execution` permits
separately established hosted authority on supported platforms. Generic x86
hosted detection cannot establish a migration guarantee and fails closed.
Required or failed supplied sessions never silently become portable work.

Root and leaf selection are independent. Completed leaves are bound to the
exact plan, index and input length; roots merge them in order. The leaf crate
does not allocate or spawn threads. For bounded OS threads, select the separate
`brynja-hash-parallel-std` package. Thread counts are not SIMD lane counts.

The separate default-off `hardened-batch-execution` feature adds
`execution::batch::{Workspace, Executor}` and `Plan::batch` for groups of up to
four contiguous leaves. `Collector::execute_batched` performs ordered merging;
`merge_batch` consumes plan-bound secret results. See the runnable
[`execution::batch` example](https://github.com/valkyoth/brynja/blob/main/crates/brynja-hash-parallel/src/execution/batch.rs).
Distinct clearing AVX2 four-state and NEON two-state kernels are available on
correctly specialized targets. Require mode applies to each group and rejects
incomplete tails; Prefer explicitly permits clearing scalar tails. Actual
per-leaf participation is reported, not inferred from the selected authority.
`execution::batch::Stream` buffers exactly four B-byte leaves across small
updates using caller-owned storage. Its borrowed executor, cumulative leaf work
control, exact final leaf-count proof and clearing XOF reader preserve the same
secret-output contract. See the
[streaming example](https://github.com/valkyoth/brynja/blob/main/crates/brynja-hash-parallel/src/execution/stream/batch.rs).
Neither scheduled nor streaming batching creates threads. The std adapter's
separate `runtime-batch-execution` feature adds bounded worker-local batching.
`Leaves::transfer` consumes completed CVs into clearing, plan-bound transport
loans; `Collector::merge_transferred` consumes them in exact order. Only these
completed results may cross threads, never authorities or unfinished state.
The existing single-leaf stream is unchanged.

The new execution profile still needs its complete milestone acceptance and
reviewed native evidence. See the
[execution guide](https://github.com/valkyoth/brynja/blob/main/docs/parallelhash-execution.md).

## Secret ownership

Hardened owners clear source-declared state, temporary encodings, pending
workspace and staging on completion, error, cancellation, recoverable unwind
and Drop. Callers remain responsible for original inputs and copied results.
This does not guarantee register, compiler-copy/spill, cache, dump, swap,
DMA or physical erasure; `mem::forget`, abort and forced termination can
prevent destruction. No OS pinning or process-wide policy is imposed.

License: MIT OR Apache-2.0.
