# Accelerated HMAC caller destruction checks

Development evidence, not independent review or release qualification.

`assurance/hmac-execution-cleanup` instantiates real public accelerated HMAC
consumers for ten named SHA-2/SHA-3 algorithms and general SHA-512/t at 129 and
511 bits. It enables `runtime-execution`, which also enables static execution.
The fixture does not create CPU authority or execute an instruction kernel.
The static-only feature configuration is not qualified by this fixture.

```sh
python3 scripts/hmac/check-hmac-execution-cleanup.py
python3 scripts/hmac/check-hmac-execution-cleanup.py --target aarch64-unknown-linux-gnu
python3 scripts/hmac/check-hmac-execution-cleanup.py --target aarch64-apple-darwin
python3 scripts/hmac/test-hmac-execution-cleanup.py
```

The checker emits MIR, LLVM IR and assembly under Rust 1.90.0 and 1.99.1,
with `panic=abort` and `panic=unwind`. The graph inspection is of optimized
LLVM IR, not a second independent MIR/assembly proof. Both AArch64 targets
can be cross-compiled; inspection is not native execution or CPU qualification.

## Checked boundary

There are 24 consumers: cancellation and consuming update-then-cancel for each
of the twelve identities. The latter inserts an opaque observer after successful
update, exercising a caller's recoverable unwind.

The graph checks cover:

- Both retained and already-empty engines, with static and runtime authority
  discriminants. Empty engines must not dispatch destruction of nonexistent owners.
- Complete logical-owner transfers through exact-size copies. Each copy retains
  the same logical obligations, not a new owner or a claim of erased source bytes.
- Destruction dispatch for both inner and outer hash cores and both CPU scratch
  regions, at the expected offsets, before normal return, recoverable propagation,
  or the copied owner's lifetime end.
- Actual emitted bodies of outlined drop helpers, including nested hash helpers.
  Neither a symbol containing `drop` nor a successful normal path substitutes
  for inspecting recoverable unwind paths.
- The update consumer's terminal-error cleanup, empty-state transitions,
  unchanged input arguments, and observer-unwind cleanup. Result comparisons and
  switches retain constraints on the same SSA value; unknown results are explored
  conservatively. Compiler assumptions do not waive cleanup.

The reviewed layouts differ between the two compiler versions: the SHA-2 empty
option niche is `3` on the MSRV and `-1` on the current compiler. Layouts and leaf
cleanup identities are explicit; missing owners, unsupported instructions,
unexpected writes, unknown callees, unresolved aliases and cyclic graphs reject.

The update probe **consumes** the HMAC. It establishes eventual owner destruction,
not the independent promise that a borrowed HMAC becomes immediately terminal
after an error. The [execution fault campaign](hmac-execution-checks.md) checks
that promise and atomic length-error reuse separately.

## Regression controls

The tests mutate emitted copy extents, sources, field offsets, enum values,
helper bodies, cleanup paths, lifetimes, input pointers and fatal terminals.
They also check the ARM switch/result relationship.

Four source mutants must compile successfully and then fail inspection:

1. Forget the accelerated HMAC on cancellation.
2. Take but forget the retained engine in guard destruction.
3. Forget the consuming HMAC after an update error.
4. Suppress destruction during the observer's unwind with `ManuallyDrop`.

Each private mutant is restored and its baseline rebuilt and checked. A compiler
error is not successful mutation detection. Runtime crate source and packaging
are unchanged by these tests.

## Premises and remaining work

This is **dispatch evidence**, not a proof that a throwing cleanup callee erased
memory. The separately reviewed hash/core/CPU cleanup contracts, non-panicking
destruction and valid safe-Rust input values remain premises. A cleanup call is
counted as attempted on either invoke edge. A second panic during unwinding is
fatal and outside the recoverable-return guarantee; its exact core terminal is
not accepted on ordinary entry.

CPU update bodies retain their separately reviewed mutation/layout contracts.
These checks do not prove update arithmetic, kernel correctness, constructor
admission, consuming-finalizer scratch cleanup, or protected/resident worker
placement. They do not erase compiler-created copies, caller registers/spills,
interrupt state, dumps, snapshots or fatal-abort state. Those accepted limits
are not reopened here.

Accelerated construction/finalization and hosted worker compiler qualification
remain pending, alongside timing/native qualification and independent review.
No strict-facade admission or global qualification status is promoted by this
bounded check.
