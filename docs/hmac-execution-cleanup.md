# Accelerated HMAC caller destruction and scratch checks

Development evidence, not independent review or release qualification.

`assurance/hmac-execution-cleanup` instantiates real public accelerated HMAC
consumers for ten named SHA-2/SHA-3 algorithms and general SHA-512/t at 129 and
511 bits. By default it enables `runtime-execution`, which also enables static execution.
The fixture borrows authority; it does not create authority or execute an instruction kernel.
The separate static-only build uses `--no-default-features`; its narrower checked
scope is described below. Neither configuration is release qualification.

```sh
python3 scripts/hmac/check-hmac-execution-cleanup.py
python3 scripts/hmac/check-hmac-execution-cleanup.py --target aarch64-unknown-linux-gnu
python3 scripts/hmac/check-hmac-execution-cleanup.py --target aarch64-apple-darwin
python3 scripts/hmac/test-hmac-execution-cleanup.py
python3 scripts/hmac/check-hmac-static-cleanup.py
python3 scripts/hmac/check-hmac-static-cleanup.py --target aarch64-unknown-linux-gnu
python3 scripts/hmac/check-hmac-static-cleanup.py --target aarch64-apple-darwin
python3 scripts/hmac/test-hmac-static-cleanup.py
```

The checker emits MIR, LLVM IR and assembly under Rust 1.90.0 and 1.99.1,
with `panic=abort` and `panic=unwind`. The graph inspection is of optimized
LLVM IR, not a second independent MIR/assembly proof. Both AArch64 targets
can be cross-compiled; inspection is not native execution or CPU qualification.

## Separate static-only build

Both drivers inspect Cargo's actual resolved feature graph before compilation.
The static driver requires `hardened-execution` and rejects `runtime-execution`
in the fixture or any dependency. The runtime driver requires both features in
each of the four accelerated owner crates. Missing, duplicate or registry owner
identities reject. This prevents feature unification from silently substituting
the already-reviewed runtime layout for a static-only build.

The static fixture has 108 consumers (no runtime constructor). Its checker
covers 24 cancellation/update consumers, scratch, complete Engine handoffs and
consuming Engine/adapter graphs for 72 finalizers, and 12 constructors.
It checks actual outlined destructors, retained/empty states, normal/error and
recoverable unwind paths,
full copy extents, split scalar moves, original input/output arguments and
whole-destination clearing on empty secret-output rejection.

Static-only layout differs materially: one-byte boolean niches identify empty
retained engines, and SHA-2's underlying portable/CPU enum uses a nullable pointer
niche. Each inner/outer boolean and pointer-niche combination is explored
independently. This is a conservative superset of static HMAC admission, **not**
permission to fall back or evidence of a portable runtime execution. A present
CPU variant must dispatch its scratch destructor; the absent CPU variant must
not invent a scratch owner. Both hash cores remain obligations. SHA-3 scratch
is unconditional. Metadata loads require the reviewed exact type and offset;
pointer values are only nullness facts, never addresses available for dereference.
Borrowed hash update implementations remain callee contracts, including
preservation of the selected execution variant; this is not a transitive
re-proof of hash updates. The opaque observer has no state reference under the
safe-Rust non-aliasing premise.

The consuming model follows inner/outer owner moves through the actual emitted
adapter bodies, including error and recoverable-unwind cleanup. Typed hash
finalizers remain consuming callee contracts, not transitive proofs of their
implementations. A null CPU-niche read after core destruction is allowed only
as enclosing cleanup metadata; a read after a consuming finalizer or adapter
is rejected. Completed body/seed reuse stays within the same artifact and
metadata population; the driver only reuses an identical consumer body after
all sixteen populations pass.

The shared walkers keep feature layouts explicit; no global layout override or
rewriting of emitted IR is used. Regression tests reject wrong-width metadata,
altered helper bodies/leaf identities, missing/short copies, forged scalar
fragments, diverted observer unwind, missing empty-output clearing and feature
contamination. Eighteen private-source mutants must compile and then reject:
forgotten cancellation, retained error leakage, skipped update-error cleanup,
observer unwind leakage, suppressed inner-digest/tag/comparison clearing,
forgotten success/error consume callbacks, a forgotten outer owner on update
error and an outer owner hidden from recoverable-unwind destruction. Seven
constructor mutants additionally test leaked earlier admissions, key access
before admission, skipped iterator entries, forgotten remaining iterator
owners, swapped returned owners and an inner owner forgotten on outer-pad error.
Each restored focused baseline must pass; the unmodified artifact also runs
the complete static checker. A compiled mutant is never accepted as rejected
merely because it fails to compile.

### Static-only constructors

The static entry has four bound parameters (result, authority and key slice),
with `create` inlined into the actual fixture body. A new outline edge is not
accepted implicitly. Scratch allocations and clearing are checked separately
from logical hash ownership. Exact role allocations are resolved without
rewriting the compiler's instructions or variable names.

Admission explores failures and recoverable unwinding before key access, then
checks the ordered state pool. The post-admission model follows iterator
cursors, normalization, both pad updates and complete returned inner/outer
owners. Actual iterator and cleanup helper bodies are inspected, including
every remaining suffix and both normal/already-unwinding destruction. Static
boolean niches use byte loads; homogeneous byte structs in the older compiler
are handled explicitly, not mistaken for the runtime layout's i64 structs.
Rust 1.90 and 1.99 use different cached-option/result error values; each is
checked against its own layout.

Eight independent hash-health populations cover the three admitted owners.
Successful static factory calls are typed callee contracts requiring CPU
sessions; nullable-pointer metadata therefore means present CPU scratch here,
unlike the conservative retained-owner population above. Session backend kind
is opaque: its metadata may only select the Result error/non-error edge, not a
backend-dependent branch. General SHA-512/t's temporary session is tracked
through complete scalar/aggregate moves into the consuming hash constructor.
Factory internals and borrowed updates remain separate callee premises. The
same source-bound non-unwinding clearing premise described below applies.

Hosted protected/resident worker placement remains a separate pending boundary.

## Checked boundary

The runtime-enabled build has 120 consumers. Twenty-four cover cancellation and consuming update-then-cancel for each
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

The constructor checks below describe the runtime-enabled layout. The
static-only variant is covered separately above; protected/resident worker
placement remains pending.

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

The admission model supplies its actual successful graph states to the
post-admission model below, rather than manufacturing an unrelated passing
initial state. Reuse of an identical checked
constructor body is limited to the same identity within one artifact, after all
four route/key-class combinations pass.

## Iterator consumption and returned owners

The post-admission model follows the same emitted constructor through inlined
iterator operations, normalization, pad updates, cleanup and return. Concrete
public cursor arithmetic, option discriminants, pointer/scalar phis and array
strides identify exactly which admitted owner moves into each role. Short keys
use owners 0/1 for inner/outer; long keys consume owner 0 for normalization and
return owners 1/2. Partial copies and scalar fragments must preserve each
complete ordered owner; a lost fragment, wrong role, duplicated consumption or
owner passed to an unrelated callee rejects.

General SHA-512/t's outlined borrowed-update adapter is resolved and checked to
forward its original state and input once, without additional pointer effects.
Its normalization adapter uses the existing consuming-finalizer checker.
Hash update/finalization internals remain separate callee premises.

The iterator destructor is no longer accepted solely by name in this ownership
check. Its actual emitted body and nested helpers are interpreted with concrete
cursor/option metadata. Remaining array entries must dispatch both core and
CPU-scratch destruction; already extracted entries must not be destroyed again.
Both cached option entries must remain empty. Regressions additionally exercise
every cursor from 0 through 3, short/long populations, both authority variants
and ordinary/already-unwinding entry. LLVM named array types are accepted only
with parsed homogeneous-i64 layouts; unknown layout and unbounded cycles reject.
Split metadata updates retain only the unmodified bytes of earlier packed stores.

On success the complete inner/outer owners must occupy the returned HMAC fields
in the expected order, with the full tag width used by these consumers. On
failure or recoverable unwind all admitted logical owners must have dispatched
destruction/consuming finalization. Kernel-report metadata and exact error-code
translation are not proved here. Custom tag-length constructors are covered by
behavioral tests, not by these full-length compiler consumers.

There is one explicit non-unwinding premise:
`brynja_core::clear_owned_region` currently performs an empty-slice check, volatile
slice clearing and a compiler fence, with no allocation, callbacks, indexing or
panic path. The constructor checker pins that source file,
`secret_memory_volatile.rs` and their `lib.rs` module binding by raw-byte SHA-256;
drift rejects pending
review. LLVM can retain a conservative invoke edge to that external function
after the returned Engine has been assembled. The model does not treat that
infeasible unwind edge as a real caller obligation. This is a source-reviewed
callee premise, not an independently proved whole-program no-unwind property.
The pins detect drift, not authorization; reviewer control remains necessary.
Other modeled recoverable invoke edges are retained.

## Regression controls

The tests mutate emitted copy extents, sources, field offsets, enum values,
helper bodies, cleanup paths, lifetimes, input pointers and fatal terminals.
They also check the ARM switch/result relationship.

Twenty-two source mutants must compile successfully and then fail inspection:

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
19. Skip an admitted iterator entry instead of taking the next one.
20. Forget the remaining iterator on Engine-construction failure.
21. Swap the returned inner and outer owners.
22. Forget the inner owner when outer-pad update fails.

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
The four post-admission mutants must also fail the constructor-transfer checker
directly. Its emitted-code tests corrupt return copies/tag metadata, cursor
stores, array indices, destructor bodies/aliases/cleanup calls and the general
borrowed-update adapter. Changing any non-unwinding premise source rejects.

Each private mutant is restored and its baseline rebuilt and checked. A compiler
error is not successful mutation detection. Runtime crate source and packaging
are unchanged by these tests.

## Hosted captures, factory placement, join and reclamation

`assurance/hmac-hosted-cleanup` emits 48 real consumers: compute and verify,
scalar and explicitly accelerated, for the same twelve identities. It resolves
24 distinct executor bodies and 24 concrete worker callbacks. It does not
enable `runtime-execution`; Cargo metadata rejects missing/duplicate owners,
registry dependencies and runtime-feature contamination before compilation.

```sh
python3 scripts/hmac/check-hmac-hosted-cleanup.py
python3 scripts/hmac/check-hmac-hosted-cleanup.py --target aarch64-unknown-linux-gnu
python3 scripts/hmac/check-hmac-hosted-cleanup.py --target aarch64-apple-darwin
python3 scripts/hmac/test-hmac-hosted-cleanup.py
```

This bounded compiler check covers Rust 1.90.0 and 1.99.1, both panic modes,
Linux x86-64/Arm and Apple Arm. Stable v0 symbol mangling retains concrete
generic identities. `llvm-cxxfilt`, or GNU `c++filt --format=rust --no-verbose`,
decodes those identities; an unsupported demangler fails the population check.
Explicit x86 SHA/SHA512/AVX2 and Arm NEON/SHA2/SHA3/AES build features prevent
unavailable-only accelerated stubs from being mistaken for exercised graphs.
No instruction kernel is executed by this compiler check.

The emitted host CFG must join the handle loaded from the actual created-worker
slot. Failed creation and successful join must clear the same stack mapping
used for native attributes before job/handle lifetime end or host return.
No write, other call, or return is accepted between creation and join, and a
failed join must terminate rather than reclaim a still-live worker. Other
status branches are explored conservatively. Each callback must resolve and
belong to its exact instantiated executor type.

Source-bound premises in `hmac_hosted_contracts.py` cover native join, attribute
destruction, mapping clear and module routing. These non-unwinding C-ABI or
value-only Rust paths can have conservative LLVM `invoke` edges; the checker
does not invent recoverable unwinds from them. The shared core volatile-clear
premise is reused. Raw-byte changes, including CRLF, reopen the premise review.
Pins detect drift; they do not authenticate a reviewer or prove OS behavior.

The launch-record check traces every meaningful initialized byte back to its
source. It requires the original request descriptor, candidate slice descriptor,
cancellation reference, result slot, public policy and (for compiled sessions)
kernel selector. Staging and output pointers/lengths must come from their
distinct session mappings. Local declarations remain borrowed descriptors and
resource owners, not embedded keyed state. Missing, overlapping, non-dominating,
late, extra or unrecognized initialization rejects. A captured local's lifetime
must not end on a path leading to launch. Padding in the copied
request descriptor is not classified as a secret owner or claimed erased.

The selected worker-factory check follows the captured key pointer and length
to the exact instantiated scalar Engine or accelerated Hmac constructor. Its
destination must fit an actual worker-local allocation. Accelerated authority
construction must also target worker-local storage and use the captured kernel;
the authority borrowed by Hmac construction must be worker-local. Optimizers
can merge the Full/Bytes constructor sites, so one or two calls are inspected.
This selected-call check does **not** prove post-construction retained keyed-owner lifetime
or inner worker cleanup. Indirect
panic-payload destruction is outside this selected-call check. Constructor
internals retain their separate qualification and valid-Rust premises.

For the twelve accelerated callbacks, a separate authority-transfer check
requires the complete 16-byte constructor result to reach the one worker-local
authority borrowed by HMAC. Byte order, split scalar stores and copies, extent,
uniqueness and dominance are checked, not merely allocation size. The constructor's
normal return must precede reads; its error branch cannot reach a checkpoint,
authority read or HMAC construction. Rust 1.90.0 and 1.99.1 use different error
niches, bound to the requested compiler and emitted compiler identity rather
than accepting either discriminator indiscriminately.

Only the named checkpoints, HMAC constructors and inspected copies/lifetime
intrinsics may receive authority pointers. Unrecognized aliases, pointer
escapes, constructor-result overwrites and later authority writes reject.
Lifetime ends cannot precede subsequent result reads, authority uses or direct
HMAC consumer calls, including along error/unwind edges. Constructor semantics
and the underlying CPU authority checks remain reviewed-callee premises; the
checkpoint caller and helper checks below bind their ordering and results.
Authority metadata and padding are not asserted to be secret or zeroized. This
does not yet trace the authority reference through every retained HMAC field or certify all indirect
worker destruction. The check is admission/transfer/lifetime evidence, not
whole-worker erasure. It binds the initial value and storage identity, not
immutability after a borrowed callee legitimately changes health/generation.

The keyed-state admission check follows the constructor Result representation
through every intermediate copy into the retained allocation shared by the
verify and secret-finalization consumers. Scalar Results have a separate tag
and payload; accelerated Results use compiler-specific error niches. The
bounded control-flow exploration models successful and failed construction,
normal returns and unwind edges, split copies, scalar loads/stores and storage
lifetime ends. Every path that reaches the completed retained representation
must carry one complete, ordered constructor payload; unknown bytes, mixed
constructors, premature reads, pointer escapes and changed copy extents reject.
Every selected factory must have a successful path to that completion point.
Retained-state reads and calls must follow it. No compiler-local variable name
is used to identify the retained owner: it is traced backwards from the actual
verify and secret-finalization arguments.
The two subsequent by-value handoffs must use full-size copies of that retained
allocation into distinct, live local storage, followed by the exact algorithm's
consumer. Additional writes, unreviewed uses, pointer escapes or a lifetime end
before consumption reject. This binds the call boundary, not erasure inside
the consumer or destruction of the source representation after a move.

Constructor behavior is a separately checked callee premise. Representation
provenance includes padding without claiming that padding is initialized secret
data. Successful accelerated values are modeled as distinct from the error
niche, not as one assumed live-engine variant. Other branch conditions are
conservatively explored. The control-flow provenance model stops at admission;
the separate terminal-handoff checks bind the consumer arguments. Neither
establishes subsequent updates, complete cleanup of every error/unwind path,
or clearing of compiler-created temporary copies.

Regressions alter every emitted executor on all three targets: the existing
792 lifecycle mutations plus 2,700 launch-field and 648 worker-factory mutations.
Source-declaration and dependency drift are rejected. Four real Rust mutants
remove join/stack clearing; ten more swap staging/output, replace captured
policy, or substitute tail bytes for the key on Linux and Darwin. Each must
compile before rejection is credited, and restored baselines must pass again.
Authority-specific regressions additionally mutate every accelerated callback
and compile a real premature-quarantine change on Linux and Darwin; the new
checker itself must reject it, independently of source pins.
Keyed-state regressions alter copy chains, constructor admission and lifetimes
in all 24 callbacks on each target, including the older compiler's distinct
error niche. Four additional compiled safe-Rust mutants replace the constructed
state with an unrelated key (scalar and accelerated on Linux and Darwin).
The keyed checker itself must reject the emitted mutant; the restored baseline
must pass. Compilation failure is not counted as a successful rejection.

### Retained storage and worker cleanup dispatch

The post-admission storage check follows the retained allocation and its actual
consumer/cleanup transfers. Access extents must fit distinct local allocations;
the lifetime start and initialization must dominate uses. An ended allocation
cannot be used again without its lifetime restarting. This includes older
compiler output that reuses a cleanup temporary in a loop. Unknown pointer
aliases, escapes, overlapping/interior transfers and changed extents reject.
Lifetime intrinsics are storage-use evidence, not evidence of physical erasure.

The scalar worker graph tracks the inner and outer logical owners from admission
through update, cancellation, error, verification and secret-output handoffs.
The accelerated graph additionally tracks retained-present/empty discriminants,
transfers into cleanup slots, and core/scratch destruction. A moved representation
is not counted as an additional logical owner. Updates must borrow the exact
algorithm's live state. Every normal or recoverable-unwind exit must dispatch
both scalar owners or the expected accelerated core/scratch owners, or reach the
separately checked consuming finalizer. Missing, duplicate and wrong-owner
cleanup rejects. Empty accelerated slots cannot be used as live engines.

Actual outlined helper bodies are inspected, including nested helpers and all
sixteen static metadata populations. When cleanup is inlined in a worker, the
caller graph explores those same populations. Byte comparisons and switches
retain constraints across branches, so an error cannot later become a successful
update merely because the checker forgot its discriminator. Loop definitions
do not retain the previous iteration's branch facts. This is deliberately a
conservative metadata model, not execution of secret inputs or a proof of hash
arithmetic. Unknown cleanup shapes fail closed.

Tests mutate retained lifetimes and transfer extents, live cleanup sites and
their actual helper bodies, including Rust 1.90's inlined destruction. Four
additional safe-Rust mutants forget the retained state on cancellation
(scalar/accelerated, Linux/Darwin). They must compile and pass the prior keyed
admission and storage checks, then fail this cleanup-dispatch check; restored
baselines must pass. Changes to unreachable cleanup code are not counted as
live-path regression detection.

### Returned secret output and destination provenance

The output check follows the actual worker arguments from the captured job:
comparison uses its candidate pointer/length; secret finalization uses the
staging mapping; copying uses the separate destination mapping. Substituted
fields, truncated lengths, unrecognized aliases and descriptor escapes reject.
The returned secret descriptor must initialize one distinct local owner with
the original pointer and length. Its storage and Result allocation must be
live and large enough for every observed access.

The successful Result branch must dominate owner construction, copying and
destruction. Some Rust 1.90 x86 emissions speculate descriptor loads before
that branch. The checker permits those loads and pure null normalization, not
admission: their values may only feed the guarded owner and output copy, never
escape through an error path. Empty exposure must pair the dangling pointer
with zero length under the same returned-pointer condition. It cannot combine
the empty pointer with the nonempty length or use another source buffer.

From completed owner construction, the emitted graph must dispatch destruction
on every normal and recoverable-unwind exit, including cancellation and copy
failure. Missing or duplicate dispatch, early lifetime end, late reads/copies,
and calls lacking a recoverable unwind edge while the owner is live reject.
As elsewhere, destruction is counted as attempted on both invoke edges; fatal
double-panic cleanup and erasure by a throwing callee are not proved.

Regressions mutate all 24 workers on each target, including the captured
pointer/length paths, Result admission, exposure pairs, owner lifetimes and
each cleanup site. Older-compiler regressions inject error-path escapes of
speculatively loaded descriptor values. Eight additional safe-Rust mutants
forget the returned owner on cancellation or truncate the finalizer's staging
slice (scalar/accelerated, Linux/Darwin). They must compile and pass prior
keyed admission, then fail the output checker itself. Restored baselines must
pass; compile errors are not counted as successful rejection.

### Hosted input iteration and fractional-tail handoff

The emitted input check follows the captured slice-of-slices pointer and count,
the complete-byte prefix of the final bit string, and both nested iterators.
Pointer/length phis must have matching actual predecessors. The descriptor
cursor advances by one 16-byte slice descriptor; the final prefix is consumed
once. Each nonempty part passes its original pointer and
`min(remaining, 4096)` length to the selected update call, advances both by that
same amount, and reenters the loop only on the compiler-specific successful
Result discriminant. The nonempty-part path rejects a second update before
advancement. Update error edges cannot restart iteration or finalize.
For Rust 1.90's rotated Arm loops, entry and backedge emptiness guards must
agree, and byte-discriminant constraints distinguish genuine error exits from
unreachable success edges left behind merged cleanup.
Finalizers must be dominated by exhaustion of the outer iterator.

The complete/partial split is checked symbolically for empty versus arbitrary
positive length and eight versus non-eight valid bits. It must retain all bytes
for a whole-byte tail and exclude exactly the final byte for a nonempty
fractional tail. This is not a sample of a few message lengths. Both branch/phi
and compiler-generated select, signed-boolean and saturating-subtraction forms
are checked against that partition. Whole-tail validation uses the captured
pointer, length and bit count. The second constructor receives the advanced
pointer, only the unabsorbed fractional byte, and zero bits for an empty tail.

The constructor Result must be admitted before state construction and use.
Both finalizers must receive the exact 32-byte typed-tail representation from
that admitted partial-tail result, including any intermediate scalar loads or
copies. Missing, duplicate, reordered, conditional or overwritten transfers
reject. Raw descriptor padding is not treated as semantic input. These are
caller dataflow checks; the separately reviewed bit-string constructors and
hash arithmetic remain premises.

Regression tests mutate actual worker emissions on all three targets and both
reviewed compilers. Additional safe-Rust mutants change the part bound, absorb
the entire fractional tail twice, alter the split predicate, or substitute the
partial bit count; another repeats updates according to the supplied bit count.
Each mutant must compile, retain the prior keyed-admission
check, and be rejected by the input checker; restored baselines must pass.

### Worker checkpoint admission and error transport

The hosted fixture now binds all six scalar checkpoints and all seven compiled
checks (including cancellation before authority construction) to the captured
cancellation reference. Compiled checkpoints must borrow the same exact local
authority as HMAC construction. Each call must return the reviewed two-byte
Result ABI and admit its actual success discriminator before continuation.

Placement follows emitted iterator and output landmarks: initial admission,
each selected chunk including empty chunks, each nonempty part of at most
4096 bytes, input exhaustion before either finalizer, successful secret
finalization before copying, and the final post-copy/post-comparison check.
The loop-local checks cannot be hoisted out of repeated iterations. Failed
checks cannot reach another checkpoint, input validation, state construction,
update, finalizer or output copy. A separate byte-flow walk follows their
normally returned error categories through actual PHIs and result stores;
an error cannot become success or a different error category. The final
checkpoint's successful continuation must store success. This walk covers
the one captured Result pointer and rejects additional loads, aliases, escapes
or overwrites of that result. It checks the discriminator, not every variant's
payload, and does not count a cleanup
unwind as a normal Result return; the separate panic flag and existing cleanup
walkers retain their distinct scope.

The fresh-build driver also emits the hosted dependency itself. It resolves
the scalar checkpoint and cancellation aliases and interprets the actual
checkpoint helper bodies for both cancellation states and both authority
outcomes. Cancellation must read the exact atomic reference with acquire
ordering. The compiled helper must call `Authority::session` with its exact
borrowed owner first, inspect the initialized Result while its slot is live,
and return a backend failure with its original payload without reading
cancellation. Only successful authority admission permits the cancellation
read. Unknown instructions, extra calls, unreviewed paths, loops and malformed
result construction reject. `Authority::session`'s own health/generation and
platform checks remain the existing CPU implementation premise; this is not
a new proof of that implementation or scheduler/VM migration behavior.

Regressions mutate emitted checkpoint arguments, success/error branches,
result categories, atomic ordering and backend-error payloads on all three
targets and both compilers. Forty additional safe-Rust mutants must compile:
thirty remove or ignore worker checkpoints, and ten weaken the helper's
atomic/order/error handling. These use private copied source trees, restore
the original files, and require restored emitted baselines to pass. They do
not execute deliberately broken cryptography on a native host.

### Joined host output transaction and buffer destruction

The host checker binds the initial output and staging clears to the two actual
session mappings and the buffer guard's output, staging and keep fields. Both
initial clears must dominate launch and every normal/recoverable-unwind exit.
The guard starts with `keep = false`; only one later commit store is allowed,
after the joined worker's stack clear. Host writes cannot overwrite the worker's
Result. A separate lifecycle walk requires one guard destruction before each
exit from an initialized guard, including recoverable unwinding. Fatal aborts
remain excluded, not interpreted as successful cleanup.

Starting at that joined-and-cleared boundary, a bounded emitted-IR interpreter
checks 180 cases per executor: compute/verify requests, complete/panic flags,
both final cancellation outcomes, all eleven host error categories, all ten
valid nested HMAC error discriminants, every current resource/backend error
payload, and all three `Option<bool>` values. Unit-error padding remains
symbolically unknown and cannot justify a branch or admission.
The host cannot inspect a worker Result before successful completion/panic
admission. It must reject a result shape inconsistent with compute/verify,
preserve the comparison decision, propagate error categories and meaningful
worker-error payloads, and retain destination bytes only for an uncancelled
successful compute. The scalar and compiled APIs' deliberately different
shape-check/cancellation order is checked explicitly. Unknown SSA values,
instructions, extra calls, loops, writes or undefined admission bits reject.

For compiled sessions, quarantine must be armed before launch. It is released
only after a valid successful worker result, cancellation, invalid bits or the
specific nested `MessageTooLong` outcome. Worker panic/incompletion, backend
failure, unexpected result shape and other internal failures retain quarantine.
Late host cancellation after a valid result clears the output while preserving
executor reuse, as the API intends.

The fresh dependency artifact also supplies the actual `Buffers::drop` body.
Its interpreter follows the emitted mapping/PID/lock conditions, requires the
exact staging region and extent to be cleared regardless of keep, and permits
retaining the output region only when keep is set. Distinct synthetic extents
prevent swapped-region checks from passing accidentally. Null/unlocked mapping
states and Darwin foreign-PID states retain the existing resource semantics;
this does not assert that foreign-process storage is writable or erased.
The volatile clearing leaf and valid resource construction remain their
separately source-bound contracts.

The actual compiled HMAC constructor referenced by each worker is now resolved
and checked with the existing static pre-key admission proof. All three hash
factories, and the three additional session factories for general SHA-512/t,
must borrow that constructor's exact authority before accessing key bytes.
This covers eight backend-owner populations and both key-length classes;
it does not duplicate or extend the hash kernel correctness claim.

Regressions mutate real host/destructor emissions on both compilers and all
three targets. Additional compiling safe-Rust mutants remove or invert the
keep decision, shape admission, late cancellation, quarantine classification
or destructor clears. An error-category remapping mutant must also fail. The
private source copies are restored and their baseline emissions must pass.
Undefined integer bits and zero extension of the `i8 -1` Result sentinel have
direct evaluator regressions.

This is **host lifecycle, admission, retained storage, input/output provenance,
checkpoint caller/callee, joined host transaction and cleanup-dispatch
evidence**, not complete worker-payload qualification. The remaining borrowed
cryptographic-callee reconciliation, public `Output` loan/declassification
linkage and final cross-check remain pending. The joined-host check is not a
proof of request-validation internals or the entire public-output API.
Valid Rust inputs, the reviewed
resource allocation/attribute implementation and OS pthread semantics remain
premises. It does not claim whole-frame erasure, fatal cleanup, native platform
execution or Mac dump exclusion, and does not admit HMAC to the strict facade.

## Premises and remaining work

This is **dispatch evidence**, not a proof that a throwing cleanup callee erased
memory. The separately reviewed hash/core/CPU cleanup contracts, non-panicking
destruction and valid safe-Rust input values remain premises. A cleanup call is
counted as attempted on either invoke edge. A second panic during unwinding is
fatal and outside the recoverable-return guarantee; its exact core terminal is
not accepted on ordinary entry.

CPU update bodies retain their separately reviewed mutation/layout contracts.
These checks do not prove update arithmetic, kernel correctness, factory
internals or protected/resident worker
placement. They do not erase compiler-created copies, caller registers/spills,
interrupt state, dumps, snapshots or fatal-abort state. Those accepted limits
are not reopened here.

Hosted worker compiler qualification remains pending, alongside timing/native
qualification and independent review.
No strict-facade admission or global qualification status is promoted by this
bounded check.
