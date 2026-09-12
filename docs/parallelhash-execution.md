# ParallelHash execution

Status: **exceptional pentest and remediation retest passed, not
release-qualified**. Scoped repository, compiler-cleanup, packaged/adversarial,
Miri and AddressSanitizer development checks passed. Final release checks
remain required. The three native lanes below have now
passed capture and source-bound artifact review. Independent-review/FIPS claims
are unchanged.

## API boundaries

`brynja-hash-parallel::execution` is enabled by `hardened-execution`. It keeps
the leaf package allocation-free and `no_std`. `runtime-execution` additionally
enables hosted authority integration; neither feature is on by default.

- `Identity` explicitly distinguishes all four SP 800-185 functions.
- `Plan::new` / `new_bits` borrow a complete input, positive block size and
  admitted leaf budget. Plans do not copy or erase the caller's input.
- `Plan::job` produces a bounded input loan. Workers create their own execution
  authority, then call `Job::execute` into a caller-owned chaining-value buffer.
- `Leaf` owns clearing of the completed value and binds it to the exact plan,
  index, bit length and historical route/generation report. It may cross a
  thread boundary; an unfinished sponge or execution authority may not.
- `Collector` owns the hardened root. `merge` accepts only the next result for
  that exact plan; errors close and clear the root. `execute_serial` supplies a
  constant-storage sequential scheduler with explicit per-leaf selection.
- Fixed finalization consumes the collector. XOF finalization returns an
  exclusive reader whose drop closes the retained root. Secret destinations
  use clearing output owners; public output requires explicit declassification
  and transactional staging. Partial-bit outputs retain canonical FIPS packing.

Root selection and leaf selection are independent. `Mode::Portable` never
requests acceleration, `Prefer(None)` permits portable processing before work,
and `Require(None)` rejects. A supplied failing/quarantined session never grants
portable fallback. `WorkerPolicy` can require accelerated results or explicitly
permit mixed results. Route reports are observations, not execution authority.

The optional `brynja-hash-parallel-std::execution::Executor` accepts independent
root/worker preferences, a positive leaf budget and 1–64 worker slots. It uses
fallible bounded allocations and thread creation, joins every started worker,
and combines results in input order even when completion order differs.
Cancellation is cooperative between jobs/merges; it does not preempt a running
compression operation. Thread width is reported separately from ISA execution
and is never described as a SIMD lane count. Concurrent use of one executor is
rejected without waiting rather than creating nested work queues.

`Preference::RequireStatic` is distinct from hosted `Require`: it creates a
target-specialized authority inside each worker. On x86 this enables the AVX2
route when the binary is built with the complete target-feature bundle;
deployment must guarantee that bundle throughout scheduling and VM migration.
Generic x86 hosted detection still fails closed. Arm can use reviewed hosted
authority or explicitly target-specialized execution. No worker borrows a CPU
session created on another thread.

The existing portable incremental-input APIs remain unchanged. Execution
`Stream` accepts irregular byte updates and a canonical final bit string using
a caller-provided, clearing leaf workspace. Its budget includes the pending
partial leaf. A callback selects each leaf's execution authority on the current
thread; fixed finalization consumes the stream, while an exclusive XOF reader
keeps the root in place. Errors, cancellation and recoverable unwind clear the
workspace and terminate the stream. `Plan` remains the complete-input option
for scheduled workers. No existing API is silently rerouted.

Streaming root finalization requires a private, consuming completed-input token.
Only the stream module can construct it, after checking an empty pending buffer
and an exact merged-leaf count of `ceil(input_bits / (8 * B))`. The token loans
that root exclusively; it cannot authorize a sibling root. Ordinary collector
finalization rejects streaming bindings, even if the work limit is satisfied.
This is an internal completion invariant, not a new public API or secret owner.

## Execution owner inventory

The execution layer composes the existing sealed hardened cSHAKE/Keccak
owners. It supplements, rather than replaces, the portable `ParallelCore`
contract in the general API register. Its additional owned regions are:

| Owner / region | Classification and cleanup boundary | Evidence |
| --- | --- | --- |
| `backend::State` | Secret-derived portable or accelerated sponge; every variant is wiped before drop | Shared hardened cSHAKE/Keccak checks and execution MIR variant inspection |
| `Collector` metadata | Secret-derived merged count, accelerated count, output bit count (16 bytes each), phase (1 byte); cancel clears all four and the sponge | Region tests, compiled deletion mutants, MIR field provenance and LLVM widths |
| `Stream` workspace and metadata | Secret leaf bytes in the caller loan, used count and input bit count (16 bytes each); cancel clears all and the collector | Workspace/budget/error/unwind tests; MIR receiver-field checks and LLVM widths |
| `Encoded` | Secret-derived integer encoding (17 bytes) and width (1 byte); drop clears both | MIR/LLVM/assembly destruction checks |
| `Leaf` / worker output | Secret chaining value in `SecretOutput`; job errors clear the complete supplied destination; merge/drop releases the clearing owner | Leaf provenance, success/error/panic and all-slot clearing tests |
| `Clear` / output staging | Secret intermediate bytes borrowed exclusively; drop clears the entire loan | Public-output transaction/error tests and MIR clearing call |
| `Reader` / `StreamReader` | Exclusive parent loan, no independent sponge copy; drop cancels parent | Ownership negatives, forgotten-reader/terminal/error tests and MIR parent-call binding |
| std `worker::Storage` | At most 64 initialized 64-byte slots; drop calls clear on every byte of every live slot before deallocation | Empty/1/2/3/64-slot tests, compiled no-clear mutant, MIR drop binding and LLVM/assembly loop inspection |

Plan identity, block size, admitted limits, route reports, thread handles and
operation-completion flags are public control/provenance, not secret buffers.
The plan borrows caller input without assuming ownership of that input. The
std storage vector never grows after initialization; unused capacity never
holds secrets. Started workers are joined before storage is released.
Successful output remains secret-owned unless explicitly declassified.

Recoverable unwind executes non-panicking RAII cleanup; injected worker panic,
spawn failure, cancellation and poisoned/reentrant executor cases are tested.
This inventory does not promise destructor execution after forget, abort or
forced termination, or erasure of compiler-generated copies. The source policy
binds the owner inventory and its source/test/compiler checks.

## Current checks and remaining acceptance

Implemented checks cover all twelve official NIST examples, arbitrary-bit
serial/scheduled/threaded comparisons, all four identities, ordered plan
provenance, bounded work, unavailable routes, output clearing, metadata
clearing, worker failure/panic/cancellation, permit re-entry/poisoning and
ownership compile failures. The execution oracle reuses the independent Python
SP 800-185 model, not the portable Rust backend. Run:

```sh
python3 scripts/parallelhash/check-parallelhash-execution-differential.py
```

Preferred routes may be portable. `--native` additionally requires accelerated
roots and all nonempty leaves, but a passing command alone is not a reviewed
native evidence artifact. Reviewed matching-platform artifacts are recorded below.

The development campaigns completed 3,584 independent comparisons (256 cases
across seven modes, debug and release). A separate local AMD AVX2 campaign
included three required-static modes: 5,120 comparisons in total, including
1,536 required-static comparisons with accelerated roots and nonempty leaves.
Packaged crate tests rejected nineteen compiled mutations in each profile
(38 rejections), plus eight compiled completion-token privacy/consumption probes.
Twenty ownership compile-fail tests passed. All 35 Rust
examples across the 39 crate READMEs passed on Rust 1.90.0 and 1.98.1.
Rust 1.90 checked the hosted executor and the hardened leaf on
`thumbv7em-none-eabi`. MIR/LLVM/assembly cleanup checks passed for x86-64 on
both compiler endpoints and AArch64 on 1.98.1, with nine emitted-code mutants
rejected per run, including std storage destruction. The completed
streaming/threaded implementation passed fresh affected AddressSanitizer and
Miri campaigns. Miri and Kani also passed the real two-shard
[detached collection/reuse demonstration](detached-verification.md), bound to
its frozen development snapshot. The scoped repository gate, supported-compiler
matrix, all-feature/default-off workspace checks and package checks passed.
This is development evidence, not the final release gate. Unavailable preferred
routes do not count as accelerated execution.

Native capture followed the green pentest/retest on commit
`7d101cb78c648c8c433d0c36065b3c8c6b7184fc`. All 309 evidence-bound inputs match
the current implementation. The [native index](../security/parallelhash-execution-native.json)
binds the unmodified artifacts, compiler identity, CPU identity, capture commit,
results and project-owned review. No personal hostname or checkout path is included.

| Native lane | CPU | Required acceleration exercised | Oracle comparisons |
| --- | --- | --- | --- |
| Linux x86-64 | Intel Xeon Platinum 8488C | Static AVX2 | 8,704 |
| Linux AArch64 | Arm Neoverse-V1 | Hosted and static Arm Keccak | 13,824 |
| Apple AArch64 | Apple M2 Pro | Hosted and static Arm Keccak | 13,824 |

Each lane ran debug/release baseline and required-static campaigns; Arm lanes
also ran required-hosted campaigns. Counts include portable/preferred controls,
not exclusively accelerated calls. Each lane additionally passed four kernel
lifecycle tests and the actual-kernel marker for 1,024 permutations. Generic
x86 hosted execution remains unavailable; this evidence does not change routing.
The records are native execution observations with operator attestation, not
remote hardware attestation, migration/side-channel qualification, independent
cryptographic verification or FIPS validation. Schema regression fixtures remain
separate from real records.

Still required: remote detached-runner hand-off qualification and the final
release gate on the reviewed source.
The README audit and local detached Miri/shard/reuse acceptance are complete;
they do not replace those remaining release checks.

Owned cleanup cannot guarantee erasure of registers, compiler-created copies,
spills, caches, crash/suspend images, swap, DMA-visible copies, caller-owned
inputs or copied outputs. `mem::forget`, abort and forced termination may skip
destructors. This work does not assert independent verification, FIPS validation
or suitability for classified deployments.
