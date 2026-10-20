# HMAC caller cleanup checks

The [engine checker](../scripts/hmac/check-hmac-engine-cleanup.py) compiles
real public HMAC consumers from the
[unpublished fixture](../assurance/hmac-engine-cleanup/src/lib.rs).
It checks optimized LLVM control flow, not source comments or PASS markers.
It is author-operated development verification, not independent qualification.

The twelve identities are the ten named SHA-2/SHA-3 adapters and general
SHA-512/t at 129 and 511 bits. The general-parameter differential campaign
covers all 383 admitted parameters; these twelve compiler identities must
not be described as 383 distinct emitted-code inspections.

## Checked caller obligations

| Population | Obligation |
| --- | --- |
| 12 cancellation consumers | Both inner and outer hash destruction dispatches precede return, recoverable resume and the owning lifetime end. |
| 12 update consumers | Update/error and observer-unwind paths dispatch both owners; outlined drop helpers are inspected. |
| 84 construction/finalization scratch consumers | Exact pad, normalization, inner-digest, tag and comparison scratch ranges receive clearing dispatch before their live lifetime ends or the function exits. |
| 72 byte/bit finalizer consumers | Each logical inner/outer hash owner reaches its consuming hash finalizer or destruction on every feasible normal/error/recoverable-unwind exit. |
| 12 constructor consumers | Long-key normalization is consumed; successful construction returns the exact live inner/outer fields; error and recoverable-unwind exits dispatch every state successfully created on that path. |

The finalizer population includes public output, secret output and verification,
each with byte and typed-bit finalization. A compiler can share their actual
Engine method: the checker resolves the emitted call/alias and inspects that
definition. Counts describe public consumers, not necessarily unique bodies.

### Consuming finalizers

The [finalizer checker](../scripts/hmac/hmac_engine_final.py) follows complete
state copies, constant field offsets and closure captures. Each copy retains
the provenance of one logical owner; copying does not create permission to
consume or destroy it twice. Partial copies, wrong pointers, overwritten
state, unknown calls, unsupported owner-pointer arithmetic and undispatched
exit paths are rejected.

The outer state can be finalized in an outlined `finish` callback. Its name
alone does not discharge the obligation: the actual definition is recursively
checked, including outer update errors and callback unwind. An inlined
callback is checked in the caller graph instead. Reused SSA branch conditions
retain their path facts; values redefined in a loop lose their previous facts.
This avoids accepting an unchecked exception for compiler-shared unwind paths.

The checker is deliberately bounded to the emitted forms in the supported
matrix. It is not a general LLVM verifier, arbitrary pointer-alias analysis,
or proof of cryptographic framing. Unknown relevant forms fail the check and
need review; a compiler upgrade is not automatically accepted.

### Constructors

These twelve consumers instantiate the full-tag `Hmac::new` constructor.
They are not separate emitted-code inspections of every admitted truncation
width; tag-policy variants remain covered by runtime and package tests.

The [constructor checker](../scripts/hmac/hmac_engine_construct.py) models
three emitted creation forms separately: fallible named SHA-2 adapter results,
direct general SHA-512/t construction, and inline zero-initialized SHA-3
owners. A fallible call splits into successful creation, error without a
state, and (when emitted) unwind before ownership reaches the caller.
The constructor's result loads and branches must agree with that distinction.
The general constructor's parameter is checked, not inferred from its label.

The compiler can move a state using a one-byte load/store plus a copy of the
remaining bytes. The [range model](../scripts/hmac/hmac_constructor_state.py)
tracks these fragments back to one creation. Before update, finalization,
destruction or successful return, it requires a complete, ordered state
without missing or overlapping fragments. Both returned owner fields must
match their roles, and the return discriminant must declare success. Returning
an error does not excuse a previously created owner from cleanup.

Creation and hash-method semantics remain callee premises; this does not
re-prove SHA-2/SHA-3 internals. The check detects caller ownership regressions,
not all possible functional defects or arbitrary LLVM aliasing. Short-key
construction, long-key normalization, partial construction, pad/update
failures and recoverable-unwind paths are included. Abort is still excluded.

## Premises and limits

- Safe Rust's borrowing/non-aliasing rules and the compiled input's validity
  remain premises. This does not validate malicious compiler output.
- Consuming hash finalizers own cleanup on success, error and recoverable
  unwind. The existing hash/core destruction contracts are non-panicking.
  This checker proves caller dispatch to those callees, not their internal
  erasure implementation. Both edges of such a consuming call discharge the
  caller's ownership obligation.
- Fatal double-panic cleanup is recognized only by the exact core panic
  identity. Process abort and other fatal termination do not imply cleanup.
- LLVM may retain physical copies after a logical move. Moved-from buffers,
  caller frames, registers and spills are **not** claimed erased by this
  provenance check. No whole-frame/whole-image erasure claim is made.
- This portable fixture does not qualify accelerated or hosted HMAC callers.
  Constructor scratch and owner transfer are checked. The
  [development inventory](hmac-development-inventory.md) retains
  these limits and does not promote the global assurance register.
  Separate [execution composition checks](hmac-execution-checks.md) exercise
  accelerated admission/lifecycle and hosted native fallback behavior; those
  tests do not substitute for emitted-code inspection.

MIR and assembly are emitted alongside LLVM for review. The graph obligations
above are LLVM obligations; they are not separate assembly control-flow proofs.

## Reproduction and regression controls

```sh
python3 scripts/hmac/check-hmac-engine-cleanup.py
python3 scripts/hmac/check-hmac-engine-cleanup.py --target aarch64-unknown-linux-gnu
python3 scripts/hmac/test-hmac-engine-cleanup.py
```

Each checker command covers Rust 1.90.0 and 1.99.1 with `panic=abort` and
`panic=unwind`. AArch64 here is cross-compiled inspection, not native execution.

Regression tests modify real emitted graphs: copy bounds/pointers, missing
paths, duplicate consumption, closure bodies and aliases, unknown calls,
pointer escapes and repeated-branch cleanup. They also compile private
copies with seven source mutants: forgotten cancellation, missing/partial
scratch clearing, update-error and observer-unwind leaks, output-length
rejection forgetting the whole HMAC, and a `ManuallyDrop` outer state lost
when inner finalization fails. Each compiled mutant is bounded by passing
original/restored builds. Compilation failure is not counted as detection.
Production source and runtime crate archives are not modified by these tests.

Constructor regressions additionally corrupt creation/result branches, first-byte
and bulk-copy provenance, returned fields/status, normalization pointers and
unwind cleanup. Three more private source mutants deliberately forget the
normalization state after update failure, the inner state after outer creation
failure, and the outer state after its update failure. All must compile before
the checker rejects the lost owner; original/restored builds must pass.
