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
accelerated constructor owner-transfer review. Admission sequencing and
public-wrapper terminal states retain their separate behavioral checks;
the wrapper compiler check below is additional to scratch inspection.
Arbitrary truncation
widths and all 383 general SHA-512/t identities are not covered by this fixture.

## Consuming Engine owner transfers

For the 72 finalizer consumers, the checker additionally starts at the actual
called `Engine::public`, `Engine::secret` or `Engine::verify` definition with a
valid inner and outer accelerated hash owner. It follows full-owner copies,
actual emitted `Backend::finish_cpu` and closure bodies, and actual outlined
drop helpers. A function name alone does not establish consumption.

The model keeps separate obligations for each hash's core and CPU scratch.
Each normal/error return and recoverable unwind must discharge both owners,
by exact hash-finalizer dispatch or both core and CPU-scratch destruction.
It checks both static/runtime discriminants, early output rejection, inner
finalizer failure, outer update error/unwind, callback error/unwind and helper
unwind. The outer callback's state and the inner hash's state retain distinct
provenance. Partial/out-of-bounds copies, duplicate consumption, wrong leaf
identities, unsupported owner aliases/escapes, post-consumption reads, and
normal-entry fatal exemptions reject.

The hash finalizers themselves remain separately reviewed consuming-callee
contracts; this is not another transitive proof of their implementations.
Likewise, safe-Rust input validity and non-aliasing are premises. Logical moves
do not establish erasure of the compiler's physical source copies.

Byte-only and final-bit public wrappers often share one emitted Engine body.
Within one artifact, after both authority routes pass, an identical body for
the same identity can reuse that result. Recursive adapter checks likewise
reuse only completed identical body/owner bindings within one inspection.
There is no persistent cache, cross-artifact reuse or release-evidence waiver.

This Engine check begins **after** extraction of a valid Engine. The following
wrapper check joins that boundary to the real public consumer.

## Public wrapper handoff

All 72 public finalizer consumers additionally undergo byte-range provenance
tracking from their consumed HMAC state (which borrows CPU authority) to the exact
called Engine method. The compiler splits `Retained::take` into two memory
copies plus scalar loads/stores on the reviewed configurations. The checker
requires complete, ordered Engine bytes, including the tag-length metadata;
it does not infer a complete owner from a matching pointer or one large copy.

Both static/runtime retained variants and the already-empty variant are
explored. Missing, shortened, overlapping or out-of-bounds copy fragments,
forged scalar pieces, unsupported aliases or scalar escapes, duplicate dispatch
and reads after consumption reject. Empty variants may read the option niche,
not an absent Engine payload, and must not dispatch a finalizer. Secret-output
rejection must call `clear_owned_region` with the original whole destination.
The original output/candidate pointer and length, typed final-bit pointer, or
byte-only `None` input are bound to the Engine call.

The combined driver checks that actual Engine body and its adapter/cleanup
graphs as described above. The wrapper model does not independently prove the
returned Tag/SecretTag destructor, result values, cryptographic correctness or
erasure of physical source copies. The fixture's empty output-observer assembly
is allowed only without an Engine-derived pointer. Unknown owner operations
fail closed; compiler assumptions do not prune obligations.

Constructor iterator consumption, the separate static-only feature layout and
protected/resident worker placement remain separate work.

## Constructor admission and state-pool handoff

The 24 constructor consumers additionally check the actual emitted `create`
graph up to initialization of the local key pad, before key bytes are accessed.
The static/runtime public wrappers bind their authority and route as described
above. The resolved constructor's formal result, authority, route and key-slice
arguments must also match the model; unbound pointer names are rejected.
The admission model explores both authority variants and the short/long
key partition defined by the algorithm's exact block size. It requires that exact
length comparison; it does not sample a few key lengths and extrapolate.

Each successful named factory call creates one logical empty hash owner. General
SHA-512/t first creates a 752-byte CPU session, then passes that exact session and
the selected `t` to its hash constructor. Session/hash factories remain typed
callee contracts: failed construction or unwinding does not return a live
owner, and the general hash constructor consumes its session on both edges.
This caller check does not independently prove factory internals or CPU admission.

The caller graph tracks complete ordered bytes across split memory copies and
scalar moves. A later admission error or recoverable unwind must dispatch both
hash-core and CPU-scratch destruction for every earlier owner. Actual outlined
cleanup bodies are inspected, and implicit helper unwind cannot abandon a
remaining owner. Fatal double-panic terminals are accepted only while already
unwinding. A normal error return must have the failure discriminant, not an
uninitialized/success result; exact error-code translation is not proved here.

At the pre-key boundary, the state pool must contain the first and second
admitted owners in order, plus the third owner only for long keys. The iterator's
active range must be `0..3`, both cached optional states empty, and the short-key
third entry empty. Metadata can be emitted as scalar stores or an exact constant
two-lane integer vector; neither form is ignored. The model rejects unknown
callees, key-pointer use before this handoff, partial/overwritten owner bytes,
wrong authority/session/algorithm parameters, and missing cleanup.

This completes **admission to the pool**, not the iterator's subsequent
normalization/inner/outer transfers, its final destruction, or the returned
HMAC-field handoff. Existing scratch checks and behavioral fault campaigns do
not substitute for that remaining compiler work. Reuse of an identical checked
constructor body is limited to the same identity within one artifact, after all
four route/key-class combinations pass.

## Regression controls

The tests mutate emitted copy extents, sources, field offsets, enum values,
helper bodies, cleanup paths, lifetimes, input pointers and fatal terminals.
They also check the ARM switch/result relationship.

Eighteen source mutants must compile successfully and then fail inspection:

1. Forget the accelerated HMAC on cancellation.
2. Take but forget the retained engine in guard destruction.
3. Forget the consuming HMAC after an update error.
4. Suppress destruction during the observer's unwind with `ManuallyDrop`.
5. Suppress key-pad destruction with `ManuallyDrop`.
6. Suppress normalized-key destruction.
7. Suppress inner-digest destruction.
8. Suppress full-tag destruction.
9. Suppress comparison-accumulator destruction.
10. Forget the captured outer owner instead of invoking the successful inner callback.
11. Forget that callback on inner hash-finalization failure.
12. Forget the outer owner on outer-update error.
13. Suppress outer-owner destruction during update unwinding with `ManuallyDrop`,
    restoring ownership on ordinary return.
14. Forget a taken Engine and return a terminal error instead of transferring it.
15. Omit whole-destination clearing on both empty-state secret finalizers.
16. Forget the first admitted owner when second admission returns an error.
17. Forget both earlier owners when third admission returns an error.
18. Read a key byte before the first admission.

Emitted-code mutations also exercise all scratch roles, exact pointers/extents,
live-scratch unwind bypasses, post-clear writes, method/alias substitution,
constructor forwarding and the independent-iterator exception. Each rejection
is paired with a passing baseline at the same inspection boundary.
The four finalizer mutants must also fail the new Engine owner checker directly,
not merely an earlier scratch or cancellation check. Emitted-code regressions
cover the real outer-owner copy, inner/outer argument substitutions, helper and
adapter bodies, inner-error/outer-unwind exits, both cleanup components and
unsupported pointer escape. Cancellation-only mutations run the cancellation
checker; full compiled mutants still run the combined checker.
The two wrapper mutants must fail the public-wrapper check directly. All-identity
wrapper mutations also remove each scalar/copy fragment, change source offsets
and input/output arguments, corrupt the option niche, bypass empty-output
clearing and attempt duplicate dispatch or pointer escape.
The three admission mutants must fail the admission checker directly as well
as the combined checker. Emitted admission mutations cover factory identity,
authority/session/result pointers, general `t`, scalar/copy fragments, key-length
partitioning, iterator metadata (including actual Arm vector stores), earlier-owner
error/unwind cleanup, real helper bodies and normal-entry fatal exemptions.

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
These checks do not prove update arithmetic, kernel correctness, factory
internals, post-admission iterator/returned-owner transfer, or protected/resident worker
placement. They do not erase compiler-created copies, caller registers/spills,
interrupt state, dumps, snapshots or fatal-abort state. Those accepted limits
are not reopened here.

Remaining accelerated constructor iterator/returned-owner and hosted worker compiler qualification
remain pending, alongside timing/native qualification and independent review.
No strict-facade admission or global qualification status is promoted by this
bounded check.
