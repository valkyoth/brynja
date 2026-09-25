# Strict hardening profile — implementation contract

Status: owner-approved implementation in progress; the protected-byte resource
and synchronous protected-stack resources are implemented for initial Linux tests,
and protected scalar SHA-2, SHA-3/SHAKE/cSHAKE, KMAC/KMACXOF and
TupleHash/TupleHashXOF and isolated legacy SHA-1/MD5 sessions are implemented.
**Strict acceleration, other families and protected ParallelHash scheduling are
not available yet**;
the combined profile remains unqualified and is not ready for independent retest.
Added after the two-testers' follow-up on v0.24.49. The current
portable APIs remain available with their existing owned-memory guarantees.
This document does not admit an execution path or change any release gate.

## Implemented resource foundation (not strict admission)

The default-off `protected-memory` feature of `brynja-crypto-cpu-std` exposes
`protected_memory::ProtectedBytes`. This is a usable byte-storage resource,
not the final strict session/token API: it cannot authorize a hash or move
ordinary caller execution onto a protected stack. `new(bytes, max_mapping_bytes)`
bounds payload rounding plus two guard pages, returns zero-initialized storage
only after all OS steps succeed, and never falls back. Explicit `close` returns
the cleared owner on release failure so the caller can retry. Drop clears before
release. The owner is not Send/Sync/Copy/Clone/Debug.

The initial adapter is Linux GNU 64-bit on x86-64/little-endian AArch64.
Other builds, including Miri/Kani models, reject with `Unsupported`. Architecture
support here means an implemented OS adapter, **not qualified strict execution**.
Native x86 checks exercise residency/dump/fork flags and guards, rollback,
zero-residency-limit rejection, padded cleanup and unwind. Native Arm protection
evidence and independent review are still outstanding. macOS/Windows must not
inherit Linux's claims.

The implementation uses [mlock](https://man7.org/linux/man-pages/man2/mlock.2.html)
for residency and [madvise](https://man7.org/linux/man-pages/man2/madvise.2.html)
with DONTDUMP/DONTFORK for exclusion. Callers must not fork while owners are
live or externally revoke protections. Unmapping releases the lock after the
full writable mapping is cleared; there is no separate unlocked interval.
These per-region controls do not protect another stack, TLS, other allocations,
privileged snapshots or hibernation. The remaining steps below are still required.

`protected_memory::ProtectedStack` preacquires the same guarded, locked mapping
before accepting work. `run` accepts a scoped `FnOnce() + Send` callback, joins
the native thread synchronously, then clears its entire stack from the calling
stack. No join handle or secret-bearing thread result is exposed. Successful
join includes native thread-local destruction. Recoverable callback panic returns
`WorkerPanicked` after cleanup; the stack can be reused. Startup failures never
run the callback or fall back. Unexpected join or attribute-destruction failure
aborts rather than returning with uncertain ownership. Aborting panic, stack
overflow and a panicking panic-payload destructor do not promise cleanup.

The initial stack reservation minimum is 64 KiB, not a promise that arbitrary
work fits: libc also uses part of the mapping. Callers must budget adequate stack
and locked-memory capacity. The callback is not a secure sandbox: captures and
inputs originate in caller storage; arbitrary heap allocations, dynamic TLS,
signal alternate stacks, panic hooks and register copies are not covered. Do not
externally cancel the native thread, fork, or revoke its mapping. Strict hash
integration must constrain these paths rather than treating this generic callback
as cryptographic admission. Concurrent protected worker pools remain pending.

The GNU pthread adapter uses the caller-stack contract of
[pthread_attr_setstack](https://man7.org/linux/man-pages/man3/pthread_attr_setstack.3.html)
and the termination guarantee of
[pthread_join](https://man7.org/linux/man-pages/man3/pthread_join.3.html).
Its private attribute ABI follows glibc's
[x86-64 definitions](https://github.com/bminor/glibc/blob/master/sysdeps/x86/nptl/bits/pthreadtypes-arch.h),
[AArch64 definitions](https://github.com/bminor/glibc/blob/master/sysdeps/aarch64/nptl/bits/pthreadtypes-arch.h)
and [public union/thread types](https://github.com/bminor/glibc/blob/master/sysdeps/nptl/bits/pthreadtypes.h).
Other libc/OS ABIs are not admitted. Native x86 tests check actual callback stack
addresses, protection flags, TLS destructor ordering, panic cleanup, scoped output
loans, repeated reuse and fatal join/destruction failures in isolated children.

## First protected hash consumer (qualification pending)

The additional default-off `strict-sha2` feature exposes
`brynja_crypto_cpu_std::strict_sha2::Session`, `Algorithm`, `Limits`, `Cancellation`
and a borrowed `Digest`. It enables the protected resources and general
SHA-512/t parameter API, not an automatic accelerated route. Session construction
requires both the native opaque-boundary target and successful OS resource
acquisition. Unsupported OS/ABI/architecture and Miri/Kani models return an error
before receiving input; ordinary portable APIs are unchanged.

All six named SHA-2 identities and all 510 general t values use scoped hardened
workspaces created inside a joined protected worker. Inputs are borrowed; their
original storage remains caller-owned. No caller callback runs during hashing.
Byte chunks and a raw canonical MSB-first final tail are supported. Tail content
validation happens on the protected worker. Work and scratch initialization,
finalization and the secret transfer to protected output all happen there. Only
public status crosses the thread join. No active workspace is moved back to the
ordinary caller. The existing scoped owner clears before the entire joined stack
is cleared, covering this operation's stack-resident staging and spills.

`Limits` bounds total input bits, chunk count (including empty chunks), and each
of the two mappings including its guards and rounding. Cancellation is checked
before work, at 4096-byte processing boundaries, and before output commit; it is
cooperative, not a forced timeout. Errors and recoverable worker unwind clear
output. The reusable session clears before each new operation; an independently
owned mapping also clears on Drop, including after a forgotten digest loan.
An output loan is neither Send/Sync/Copy/Clone/Debug nor implicitly comparable.
Explicit exposure borrows bytes without declassification; `declassify` requires
the existing public-output authority and consumes/clears the loan. Equal rounded
widths never erase the exact general-t identity.

This initial API processes a complete bounded request rather than retaining a
live streaming state across calls. It does not use SHA-NI, Arm SHA, AVX2 or other
optional acceleration. Native x86 author tests cover padding/bit/chunk boundaries,
all parameters, real mapping flags for workspace/scratch/output, cancellation,
post-write unwind, forgotten output loans, cleanup and reuse. Native Arm, new
emitted-code evidence, protected-stack sanitizer qualification, remaining-family
integration and the independent retest are still pending. Do not infer closure
of either Medium finding from this first consumer.

## Protected SHA-3/SHAKE/cSHAKE consumer (qualification pending)

The default-off `strict-sha3` feature adds `strict_sha3::Session`. It does not
enable `strict-sha2`, general SHA-512/t, or any accelerated execution feature.
All four SHA-3 identities and both strengths of SHAKE/cSHAKE create scoped
scalar workspaces on the protected worker. `Algorithm` retains the exact XOF
output-bit count, including zero; all outputs use canonical low-order final bits.
`hash_chunks` accepts byte chunks and a raw LSB-first `Bits` tail;
`hash_customized_chunks` also accepts arbitrary-bit N/S for cSHAKE. Nonempty N/S
on another algorithm is rejected, never ignored. Canonicality validation reads
secret tail bytes only on the protected worker. N/S are per-request caller
storage, not retained by the session or encoded in the returned algorithm label.

Construction checks the explicit output-bit and mapping bounds and acquires
both resources before input. Empty output uses a one-byte protected placeholder
but exposes/declassifies exactly zero bytes. Request limits independently bound
message bits, combined customization bits, and chunk count. N/S prefix setup is
bounded by that budget and checked for cancellation before/after setup; it is
not interruptible internally. Message and XOF output processing check cancellation
at 4096-byte boundaries. XOF output is staged in a fixed-size protected-stack
buffer, not an output-sized allocation. Each typed staging loan clears before
reuse, and the whole protected output clears on any failure even after earlier
fragments were written. Session/output ownership, explicit declassification,
forgotten-loan cleanup and joined-stack clearing follow the SHA-2 contract above.

Native x86 author tests compare all identities to the existing portable APIs,
cover rate/padding/chunk boundaries, all tail widths, N/S framing boundaries,
partial/empty/multifragment XOF output, cancellation and post-write unwind.
They also inspect actual workspace/staging/output protection flags. These are
author integration tests, not a new independent cryptographic oracle or native
Arm qualification. Neither Medium finding is closed by this partial integration;
strict acceleration, other families and protected ParallelHash remain pending.

## Protected KMAC/KMACXOF consumer (qualification pending)

Default-off `strict-kmac` adds `strict_kmac::Session`, using the existing scoped
KMAC implementation through an optional first-party dependency. It does not
enable strict SHA-2/SHA-3 session features or any accelerated route. All four
identities retain exact output-bit width. Construction requires full-strength
fixed output; all operations require a full-strength key even when the workspace
has enabled conformance-testing elsewhere. Short/empty XOF derivation remains
possible, but verification requires full-strength output and exact candidate
bit width. Keys and customization are supplied afresh, not retained by sessions.

Three resources are preacquired: a protected stack, protected staging, and
protected output. Fixed KMAC finalization requires a contiguous complete
destination, so its staging is output-sized protected storage, not a variable
stack or ordinary heap buffer. XOF staging is at most 4096 bytes. Mapping limits
apply separately to all three resources (not an aggregate process quota).
Key/customization setup and fixed finalization are bounded but not internally
cancellable; message/XOF processing and tag comparison check cancellation at
4096-byte boundaries. The request separately bounds setup bits, message bits,
output bits and chunk count. Canonical key/message/customization and candidate
bit checks run only on the protected worker.

`authenticate` is the byte convenience operation; `compute` accepts a borrowed
`Request` with bit strings and message chunks. Both return a protected affine
`Output`; explicit `declassify` is required to copy a public authenticator.
`verify` performs the complete operation on the protected worker, compares
canonical equal-width candidates using the existing borrowed constant-time
primitives, and explicitly returns only a public Boolean decision. Computed
tags, comparison scratch, staging and the joined stack are cleared; no tag is
returned to the ordinary caller during verification. Malformed public shapes
can reject early. Any failure/cancellation/recoverable unwind clears previous
fragments. Forgotten output loans cannot suppress session cleanup.

Author tests compare all identities to the existing portable KMAC APIs, exercise
bit keys/customization/message/output, production key boundaries, wrong-width
and noncanonical candidates, equal work for early/late mismatches, cancellation
during comparison, post-write unwind, real mapping flags, and resource failure.
These tests do not constitute independent cryptographic review, native Arm
evidence or machine-level timing qualification. Strict acceleration, legacy
SHA-1/MD5, TupleHash and protected ParallelHash integration remain unfinished;
both Medium findings stay open pending the combined implementation and retest.

## Scope and admission

The new profile must be explicit and opt-in, named for its actual guarantees,
not advertised as military certification. Selecting a Cargo feature only makes
its API available; it is not evidence of platform qualification.

Use a separate fallible strict entry point and private-field capabilities:

- Admit only a target with the reviewed opaque scalar/transfer boundaries:
  initially x86-64 and little-endian AArch64, subject to the exact compiler/ABI
  coverage. An unsupported target returns an explicit error before accepting
  secret input. Do not silently select the ordinary Rust fallback.
- Miri/Kani can test separate reference/lifecycle models. A model build cannot
  manufacture production strict admission.
- Bind optional accelerated routes to their existing complete feature bundles,
  authority lifetimes and quarantine rules. Failure cannot switch to a less
  protected route.
- Require the protected-memory and protected-execution resources below before
  constructing a strict state. A target check alone is insufficient admission.
- Keep normal all-feature compilation and the existing portable API contract
  intact on other platforms: compiling the strict API may succeed there, but
  opening a strict session must fail closed. Do not break workspace compatibility
  merely because Cargo's all-features mode includes the new optional profile.

These are requirements for the implementation, not names of shipped types.
Public names/signatures must be finalized with the first functional consumer,
not an unused capability token or a Boolean assertion exposed as enforcement.

## Protected resources

Protected storage is a live resource, not an arbitrary caller slice named
"protected". Its owner must acquire and retain platform protections before
secret initialization, provide exclusive borrowed access, and clear before
unlock/free. Cloning, formatting, exporting raw ownership or resizing populated
storage must not bypass that lifetime.

The resource contract covers at least:

1. Resident pages with locking failure propagated; no fallback to ordinary heap.
2. Dump exclusion for the allocation with failure propagated. Page locking does
   not itself exclude core dumps, and a platform without an enforceable adapter
   must report unsupported protection.
3. Stable aligned storage for sponge/hash workspaces, secret framing scratch,
   chaining-value slots, staging and strict secret outputs.
4. Independently owned cleanup after cancellation, errors and recoverable unwind,
   including forgotten inner output/worker loans.
5. Explicit resource/byte/worker limits and checked sizes, alignment and page
   rounding before allocation; acquisition rollback before secret admission.

Platform FFI belongs in isolated first-party hosted adapters, not the no_std
cryptographic leaves. No third-party crypto/native implementation is introduced.
Each OS adapter needs actual failure-path tests and its own evidence; Linux
semantics cannot be assigned to macOS or Windows by changing constants.

## Protected scalar TupleHash sessions (qualification pending)

The default-off `strict-tuplehash` feature adds `strict_tuplehash::Session` for
TupleHash128/256 and TupleHashXof128/256 with exact output-bit identities.
Construction acquires a protected stack and separate protected staging/output
mappings before any input. Each mapping has an explicit budget; these are
per-resource limits, not a process-wide residency quota. GNU/Linux x86-64 and
little-endian AArch64 native builds are the only implemented targets; other
platforms and Miri/Kani models reject. Strict acceleration remains pending.

`Item` describes one tuple element using borrowed byte chunks and a raw LSB-first
final bit tail. The worker derives the exact checked bit length and completes
the scoped item writer before starting another. Chunk boundaries are not tuple
boundaries: the empty tuple, one empty element and two empty elements differ.
Content validation, scoped sponge state, framing and secret transfer run on the
protected stack. No populated state or secret thread result returns to the
ordinary caller. Inputs and their preexisting copies remain caller-owned.

Limits bound total item bits, customization bits, output bits, item count and
total chunk descriptors, including empty chunks/items. Cancellation is checked
at item/chunk and 4096-byte processing boundaries. Customization setup and fixed
finalization are bounded but not internally cancellable. Fixed output uses a
protected full-width staging map; XOF uses at most 4096 staging bytes. Empty
output reserves a hidden protected byte without exposing it. The affine output
loan preserves fixed/XOF and exact-bit identity; explicit public release consumes
and clears it. Errors, wrong item completion, cancellation and recoverable unwind
clear both buffers; the joined stack is independently cleared. Forgotten loans
cannot suppress the session owner's cleanup.

Author tests compare against the existing TupleHash implementation, not an
independent oracle. Native x86 protection flags, cancellation and output-fragment
unwind are covered. Native Arm execution, new emitted-code/platform qualification,
protected-stack sanitizer validation and independent retest remain pending.
This addition does not close M1 or M2 or change release rules.

## Protected legacy MD5 (qualification pending)

The isolated `brynja-legacy-md5-std` adapter adds default-off `strict-execution`.
`strict_execution::Session` preacquires a protected stack and sixteen-byte output
mapping. Only GNU/Linux native x86-64 and little-endian AArch64 are implemented;
other targets and Miri/Kani models reject. The portable MD5 leaf keeps its
core/hash-core dependency closure; no modern consumer acquires a legacy edge.

The existing scoped scalar MD5 workspace and sixteen-byte staging are created
on the protected worker, not populated and moved from an ordinary caller stack.
Byte chunks and a canonical raw MSB-first tail are supported. Total length uses
checked u128 arithmetic; MD5's final encoding retains the low 64 bits, without
imposing SHA-1's smaller message domain. Public budgets bound input bits, chunk
count and mappings; cancellation checks occur at most every 4096 input bytes.
Output is an affine protected loan. Rejection, cancellation, recoverable unwind,
explicit declassification, forgotten-loan reuse and owner Drop retain independent
cleanup. The joined worker stack is cleared before return or reuse.

This is scalar compatibility support, not strict SIMD admission, collision
resistance, whole-process erasure or independent qualification. MD5 remains
collision-broken and unsuitable for new authentication or password hashing.
Caller inputs/copies and the resource contract's OS, abort and interruption
limits remain. Native x86 author tests cover RFC byte vectors, a million-byte
message, bit/chunk boundaries and real mapping protections. Native Arm, new
emitted-code/protected-stack sanitizer qualification and independent retest are
pending. Both Medium findings remain open for the combined profile.

## Protected legacy SHA-1 (qualification pending)

The legacy hosted adapter's default-off `strict-execution` feature exposes
`brynja_legacy_sha1_std::strict_execution::Session`. The dependency direction is
legacy adapter to shared protected resources, never modern facade to legacy.
The portable leaf dependency closure remains core/hash-core only. No external
dependency or new cryptographic implementation is introduced by this wrapper.

A session acquires its stack and twenty-byte output mapping before accepting
input. The scoped scalar workspace and twenty-byte staging are initialized and
consumed on the protected worker; only public status crosses its synchronous
join. Requests accept borrowed chunks and a canonical MSB-first final tail,
with checked u64 message-domain and public budget admission before launch.
Content canonicality is checked on the protected worker. Cancellation is checked
at 4096-byte boundaries and before output commit; it is not forced termination.
Errors, recoverable worker panic and forgotten output loans cannot suppress
resource cleanup. Output exposure is an explicit borrow; public release requires
the legacy declassification authority and clears the consumed loan. A wrong
public destination width preserves its contents while clearing secret output.

The GNU/Linux native-target limits match the protected resource adapter; other
targets and Miri/Kani models reject. Hardware/SIMD routing is not enabled by this
feature. Native Arm, emitted-code/protected-stack sanitizer qualification and
independent review remain pending. SHA-1 is still collision-broken and unsuitable
for new authentication/signatures; memory protection does not change that.

## Execution and ParallelHash

Protecting CV slots alone is not sufficient: worker stacks and all secret
workspace/staging allocations also need protected lifetimes.

- Run strict secret work only on a protected execution stack. Do not accept
  std::thread::Builder::stack_size as proof of locking or dump exclusion.
- Acquire bounded worker stacks/slots before jobs receive secret input. If a
  protected worker cannot start, join every already-started worker and clear
  owned resources; do not fall back to the ordinary scheduler.
- Retain disjoint output loans, exact plan provenance and submission-order merge.
  No secret array may be returned by value through a thread result.
- Join before unlocking or freeing worker stacks and CV slots. Stack cleanup
  must occur from a different live stack after the worker has terminated, not
  by wiping a stack that still contains executing frames.
- Root/coordinator secret processing needs the same protection as leaves.
  Protect callback execution or keep callbacks outside the secret execution
  boundary; an arbitrary caller stack cannot silently become strict.
- Avoid hidden ordinary allocations for populated secret storage. Public thread
  handles and scheduling metadata are separate from secret payloads.
- Strict output remains tied to protected storage until explicit declassification.
  Caller-supplied inputs and any copies made before entering the strict profile
  retain an explicit caller/deployment responsibility.

An unsafe external platform provider, if supported, must carry this full
lifetime/resource contract. A safe free-form acknowledgment cannot qualify
unprotected pages or stacks. Built-in adapters must enforce their measurable
obligations instead of relying on that escape hatch.

## Limits that must not be overclaimed

Page residency and dump exclusion do not prevent privileged inspection,
hypervisor snapshots, arbitrary hibernation, physical capture or copies already
made by callers. OS deployment policy must address those threats. Portable
library code must not claim to defeat them.

Likewise, a protected stack does not prove register erasure across every
instruction, asynchronous signal or process abort. The existing normal-return
opaque boundaries retain their exact scope. This profile must state separately
what happens on recoverable unwind, fatal abort, native thread failure and
protection loss. Unsupported cases must not produce a qualifying success.

## Implementation order and acceptance

1. Define the fallible target/resource admission API and negative target/model
   tests, with existing portable callers unchanged.
2. Implement protected regions and execution stacks in isolated platform
   adapters; test allocation, locking, dump-control and cleanup rollback.
3. Integrate scoped strict hashing and protected outputs without active-owner
   moves or ordinary secret staging.
4. Integrate protected ParallelHash root/leaf/batch scheduling across all four
   identities and relevant routes, including every-started-worker join.
5. Test actual OS protection failures, resource exhaustion, insufficient slots,
   wrong target, unavailable backend, cancellation, revocation, partial worker
   launch, panic and forgotten loans. Exercise canaries and destruction order.
6. Run correctness/oracle comparisons, ownership-negative tests, emitted-code
   checks and the affected platform/sanitizer campaigns. Record unsupported
   OS/compiler/architecture combinations honestly.
7. Obtain independent retest for both new Medium findings, then collect final
   native evidence and use the unchanged approved release process.

The raw reports remain until these findings have an implementation disposition
and the combined candidate is ready for retest. The AVX-transition and SDE
workflow corrections are separate, smaller fixes; they do not close these
two Medium findings.
