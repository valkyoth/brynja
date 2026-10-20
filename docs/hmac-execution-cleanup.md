# Accelerated HMAC caller destruction and scratch checks

Development evidence, not independent review or release qualification.

`assurance/hmac-execution-cleanup` instantiates real public accelerated HMAC
consumers for ten named SHA-2/SHA-3 algorithms and general SHA-512/t at 129 and
511 bits. It enables `runtime-execution`, which also enables static execution.
The fixture borrows authority; it does not create authority or execute an instruction kernel.
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

There are 120 consumers. Twenty-four cover cancellation and consuming update-then-cancel for each
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

## Constructor and finalizer scratch

The other 96 consumers cover both static/runtime constructors and six consuming
finalizers for every identity: public output, secret output and verification,
each with byte-only or typed final-bit input. Each constructor wrapper must
forward its actual authority, key pointer/length and static/runtime selector
to the emitted `Hmac::create` body. Finalizers resolve their actual emitted
`Engine` method, not an unrelated function with matching cleanup text.

The optimized graphs check the local 144-byte key pad, 64-byte normalized key,
64-byte inner digest, 64-byte full tag and one-byte comparison accumulator,
where applicable. Every live scratch region must dispatch its exact full-size
clear before lifetime end, ordinary/error return or recoverable unwind.
Unknown calls and writes conservatively invalidate a previous clear. A fatal
cleanup terminal is permitted only on an unwind path, not ordinary entry.

Construction drops its separate iterator of admitted hash owners after clearing
the pad. The checker recognizes only the typed three-element
`Flatten<IntoIter<Option<accelerated hash>>>` destructor, with an emitted
definition and one pointer to its distinct local `states` allocation of the
matching extent. Safe-Rust non-aliasing and that typed destructor's inability
to reach the independent pad/normalized allocation are premises. This
exception is **not** a proof of the iterator's hash-owner destruction.

This completes the local scratch checks for these consumers, not the complete
accelerated constructor/finalizer owner-transfer review. Admission sequencing,
hash states transferred through adapters/closures, and public-wrapper terminal
states retain their separate behavioral checks; their remaining compiler
qualification must not be inferred from scratch checks. Arbitrary truncation
widths and all 383 general SHA-512/t identities are not covered by this fixture.

## Regression controls

The tests mutate emitted copy extents, sources, field offsets, enum values,
helper bodies, cleanup paths, lifetimes, input pointers and fatal terminals.
They also check the ARM switch/result relationship.

Nine source mutants must compile successfully and then fail inspection:

1. Forget the accelerated HMAC on cancellation.
2. Take but forget the retained engine in guard destruction.
3. Forget the consuming HMAC after an update error.
4. Suppress destruction during the observer's unwind with `ManuallyDrop`.
5. Suppress key-pad destruction with `ManuallyDrop`.
6. Suppress normalized-key destruction.
7. Suppress inner-digest destruction.
8. Suppress full-tag destruction.
9. Suppress comparison-accumulator destruction.

Emitted-code mutations also exercise all scratch roles, exact pointers/extents,
live-scratch unwind bypasses, post-clear writes, method/alias substitution,
constructor forwarding and the independent-iterator exception. Each rejection
is paired with a passing baseline at the same inspection boundary.

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
admission/owner transfer, consuming-finalizer owner transfer, or protected/resident worker
placement. They do not erase compiler-created copies, caller registers/spills,
interrupt state, dumps, snapshots or fatal-abort state. Those accepted limits
are not reopened here.

Remaining accelerated construction/finalization owner and hosted worker compiler qualification
remain pending, alongside timing/native qualification and independent review.
No strict-facade admission or global qualification status is promoted by this
bounded check.
