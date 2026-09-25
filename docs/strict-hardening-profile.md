# Strict hardening profile — implementation contract

Status: implementation complete for independent retest; the protected-byte resource
and synchronous protected-stack resources are implemented for initial Linux tests,
and protected scalar SHA-2, SHA-3/SHAKE/cSHAKE, KMAC/KMACXOF and
TupleHash/TupleHashXOF, isolated legacy SHA-1/MD5, and protected scalar
ParallelHash/ParallelHashXOF sessions are implemented.
Compiled SHA-2, SHA-3/SHAKE/cSHAKE, KMAC/KMACXOF, TupleHash/TupleHashXOF,
legacy SHA-1 and legacy MD5 SIMD batch wrappers are implemented, as are
protected modern SIMD batches and accelerated ParallelHash root/worker integration;
the combined profile remains unqualified pending independent retest and final
native platform evidence. This is not release approval.
Added after the two-testers' follow-up on v0.24.49. The current
portable APIs remain available with their existing owned-memory guarantees.
This document does not admit an execution path or change any release gate.
The consolidated integration section below supersedes the earlier incremental
notes about remaining families; those notes retain the original validation scope.

## Consolidated strict acceleration integration

### Strict-only facade

Applications can depend on [brynja-strict](../crates/brynja-strict/README.md)
instead of selecting individual strict features. Its protected dependencies are
mandatory even with default features disabled. It exposes only modern protected
SHA-2, SHA-3/SHAKE/cSHAKE, KMAC, TupleHash, ParallelHash and batch APIs; no ordinary
owners, legacy APIs, raw execution authority or generic protected-stack callbacks
are re-exported. The normal `brynja` facade and its defaults are unchanged.
This is application-level selection, not proof that other dependencies or caller
copies comply. No new cryptographic implementation or admission gate is added.
Unsupported targets compile but constructors reject before accepting input.

Use a bounded session pool created at startup and exclusive loans per operation.
Drop output loans before reuse and retire quarantined compiled sessions. Mapping
limits are per resource, not a global process quota: budget all concurrent sessions
and workers against RLIMIT_MEMLOCK. On 4 KiB pages a SHA-256 session with a 256 KiB
stack locks 266240 bytes (stack plus one digest page), excluding virtual-only guard
pages. ParallelHash additionally reserves root/worker stacks and CV/staging/output
mappings. Construction failure is an error, never an unprotected fallback.
The facade does not detect ASan fake-stack instrumentation: diagnostic builds are
still not qualified to process secrets, and placement/residency tests are necessary
to validate the stated diagnostic configuration, not a production sandbox.

### Leaf integrations

All wrappers remain separate, default-off APIs. Scalar constructors do not
silently become accelerated. Compiled constructors require the exact build-wide
feature bundle and a deployment that preserves it; they do not establish CPU
affinity, detect live migration or guarantee arbitrary platform snapshots.

| Package / feature | Protected API | Execution policy |
| --- | --- | --- |
| `brynja-crypto-cpu-std` / `strict-tuplehash-acceleration` | `strict_tuplehash::CompiledSession` | Required AVX2/Arm Keccak; exact tuple completion, fixed/XOF staging and output |
| `brynja-crypto-cpu-std` / `strict-batch` | `strict_batch::Session` | SHA-224/256, complete SHA-512 family including general t, SHA-3/SHAKE/cSHAKE; explicit portable or required AVX2/NEON groups |
| `brynja-legacy-sha1-std` / `strict-acceleration` | `strict_execution::CompiledSession` | Required SHA-NI or Arm SHA-1; canonical MSB-first final bits |
| `brynja-legacy-md5-std` / `strict-acceleration` | `strict_execution::batch::Session` | Required AVX2/NEON SIMD groups; incomplete groups reject |
| `brynja-hash-parallel-std` / `strict-acceleration` | `strict_execution::CompiledSession` | Required compiled root; explicit single-kernel leaves or SIMD groups with protected scalar tails |

Constructors acquire protected resources before accepting secret input. Workers
construct authority/startup checks, scoped workspaces and populated state locally
on their protected stacks. No thread-bound authority is transferred or retained
between threads. Only borrowed input descriptors, public metadata/status and
exact-plan loans into protected result mappings cross joins. Every started
ParallelHash worker joins before CVs, staging, output or worker stacks are cleared.
Its grouped CV mapping reserves four full 64-byte slots per group, including
inactive/narrow capacity, and clears that full owned allocation.

Batch inputs retain exact identities/output widths and checked bit framing.
Explicit output exposure borrows secret bytes; declassification validates every
destination before writing any public output and consumes/clears the loan.
Zero-length XOF slots remain distinct from inactive slots. Session reuse clears
forgotten output loans. Budget/canonical-input/cancellation rejection permits
reuse; backend/invariant failure and recoverable worker unwind quarantine without
fallback or reset. Error classification uses the returned error, not a concurrent
cancellation flag which could otherwise mask a backend failure.

The strict ParallelHash batch policy permits scalar incomplete/unequal tails
explicitly, on protected stacks. It is not a claim that every leaf uses SIMD.
Modern and MD5 strict batch `Require` routes instead reject ineligible work.
Public lengths, scheduling and work reports remain observable. Legacy SHA-1/MD5
remain collision-broken compatibility algorithms: stronger storage does not
restore their cryptographic security.

The next retest must evaluate the complete implementation, not just these
author checks. Native Arm protection, final source-bound evidence and independent
qualification remain separate. No military certification or all-register,
interruption, hibernation, privileged-snapshot or panic-abort erasure is claimed.

## Implemented resource foundation (not strict admission)

### Reproducing the combined pre-retest checks

On a GNU/Linux x86-64 host whose deployment guarantees AVX2/SHA/SSE2, run
`python3 scripts/cryptography/check-strict-profile-package.py --simd --attest-native-features`.
The equivalent Arm run requires NEON/SHA2/SHA3. This packages first-party crates
locally, runs debug/release tests and ownership doctests for all four strict
host adapters, and rejects sixteen compiled locking, output, cleanup and
quarantine regressions. It does not publish anything or modify release gates.
Native Arm results are still required for final qualification.

`python3 scripts/cryptography/check-protected-resource-codegen.py --toolchain 1.98.1 --target x86_64-unknown-linux-gnu`
checks retained eager-lock/clear/release calls under both panic strategies.
Repeat with `1.90.0` and `aarch64-unknown-linux-gnu` for the complete eight-row
author matrix. Seven emitted-artifact regressions per row reject missing calls,
lazy locking and comment-only evidence. These are exact-function call checks,
not a whole-CFG dominance proof or full caller-register qualification; native
mapping/rollback/join tests and packaged source mutants cover separate duties.

The combined author run passed full workspace all-feature tests; native strict
debug/release and MSRV tests; all strict ownership doctests; 85 actual protected
ASan/LeakSanitizer tests; scoped Clippy; Miri metadata/unsupported-model tests;
cross-compilation for supported Arm and rejecting Apple/Windows/RISC-V targets;
and existing batch workspace/output and SHA-1 kernel cleanup checks. ASan uses
the explicit fake-stack limitation described below. No emulated or cross-built
row is presented as native Arm evidence. Earlier per-consumer notes below are
historical progress records, superseded by this combined validation summary.

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

The implementation uses [mlock2](https://man7.org/linux/man-pages/man2/mlock.2.html)
with zero flags (eager residency, not MLOCK_ONFAULT), requiring Linux 4.4 and
glibc 2.27 or newer, and [madvise](https://man7.org/linux/man-pages/man2/madvise.2.html)
with DONTDUMP/DONTFORK for exclusion. Callers must not fork while owners are
live or externally revoke protections. Unmapping releases the lock after the
full writable mapping is cleared; there is no separate unlocked interval.
These per-region controls do not protect another stack, TLS, other allocations,
privileged snapshots or hibernation. The remaining steps below are still required.

There is no fallback to `mlock`: LLVM sanitizer runtimes can intercept that
symbol and return success without locking. Native tests inspect actual mapping
flags and zero-residency-budget rejection instead of trusting a return code.
Instrumented test builds must disable ASan's fake-stack relocation with
`detect_stack_use_after_return=0`, since those relocated locals are not on the
protected stack. This deliberately omits ASan use-after-return coverage; ordinary
bounds checking and mandatory leak detection remain enabled. Instrumented builds
are diagnostics, not deployment qualification, and must not process real secrets.
See [LLVM's interceptor](https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/sanitizer_common/sanitizer_common_interceptors.inc)
and [ASan's option documentation](https://clang.llvm.org/docs/AddressSanitizer.html).

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
as cryptographic admission. Persistent protected worker pools remain pending.

`ProtectedStack::run_group` now provides bounded concurrent resource execution:
one borrowed Send callback per preacquired stack, with 1..=64 jobs. All public
bookkeeping and native attributes are prepared before launch. Stable per-job
cells retain callback borrows while native threads write completion status.
Partial startup failure stops further launches, joins every started thread, then
clears stacks. The same owner joins during coordinator unwind; callback unwind
is caught on its worker. Unexpected native join failure aborts, never releases
live borrowed work. No caller-owned join handle can detach or forget the join.

Only job pointers/status/handles occupy ordinary bookkeeping; callers remain
responsible for callback captures and outputs. A failed group can partially
write destinations. Strict ParallelHash must retain a separate output/CV cleanup
transaction and protect its root processing; this resource alone is not that
integration. Callbacks must terminate without waiting for peers that may never
start after a launch failure. No timeout, fallback or forced cancellation is
provided. Native x86 author tests witness actual overlapping workers, distinct
protected stack addresses and mapping flags, TLS completion, every four-worker
launch failure position, worker/coordinator unwind and reuse. Native Arm and
independent qualification remain pending.

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

## Protected compiled SHA-2 hardware wrapper (qualification pending)

Default-off `strict-sha2-acceleration` exposes `strict_sha2::CompiledSession`
without changing the scalar constructor. It requires an exact narrow/wide
SHA-2 static kernel, complete build-wide features, and the same supported OS
protections. The caller must establish compatible CPU/OS execution throughout
scheduling and migration; static features are not a runtime probe or scheduler
lock. Authority and both startup tests are constructed on protected stacks, as
are scoped hash state, CPU scratch and final staging. No thread-bound authority
is moved across threads. General-t IV derivation remains public scalar work.

Only public route/health metadata persists between requests. Each request creates
fresh worker-local authority, but backend/invariant failure or recoverable worker
panic permanently quarantines the outer session, so this cannot revive failed
execution. Ordinary preflight rejection, invalid bits and cancellation preserve
health. Resource/start failures conservatively quarantine too. There is no reset,
authority export, automatic fallback, or promise of live deployment revocation.
Outputs retain the same protected affine ownership and error clearing.

Native x86 SHA-224/256 author tests witness actual SHA instructions through exact
static routes and nonzero block counts. Wide/Arm route code cross-compilation is
not native execution evidence. New emitted-code/native platform qualification,
strict acceleration for the remaining families and independent retest remain
pending; neither Medium finding is closed.

## Protected compiled SHA-3/SHAKE/cSHAKE wrapper (qualification pending)

Default-off `strict-sha3-acceleration` exposes `strict_sha3::CompiledSession`
without altering scalar `Session`. Explicit static `X86Keccak` (AVX2) or
`ArmKeccak` (NEON/SHA3) selection requires the full compiled feature bundle and
the same supported GNU/Linux protections. Establish the compatible CPU/OS
lifetime guarantee before construction; this is not runtime detection, a
scheduler lock or a migration monitor.

Authority, ordinary and hardened startup checks, scoped sponge state, erasing
session scratch and bounded 4096-byte output staging are created on protected
worker stacks. N/S and final input canonicality are checked there, not copied
onto the coordinator stack. Fixed and XOF secret outputs copy into protected
storage; even zero-bit output finalizes and checks authority. Cancellation is
checked around prefix setup, at most every 4096 message/output bytes, and before
return; prefix work is bounded by the public customization budget, not internally
interruptible. Both cSHAKE identities preserve SHAKE equivalence for empty N/S.

No populated sponge/session crosses join. Recoverable panic and backend or
invariant errors permanently quarantine the wrapper before fresh authority can
be recreated. Ordinary invalid input/cancellation permits reuse. Forgotten output
loans cannot suppress next-operation or owner-Drop clearing. There is no reset,
fallback, authority export or new whole-process/interruption/abort guarantee.
Native AVX2 differential/fault checks are implementation-author evidence, not
Arm native, emitted-code or independent qualification. Other strict accelerated
family and batch integrations remain pending; neither Medium finding is closed.

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
strict acceleration and new compiler/platform qualification remain pending.

## Protected compiled KMAC/KMACXOF wrapper (qualification pending)

Default-off `strict-kmac-acceleration` exposes `strict_kmac::CompiledSession`
without changing scalar `Session`. All four identities require an explicit
static AVX2 or Arm NEON/SHA3 Keccak kernel and the same protected GNU/Linux
target. Establish compatible CPU/OS support for the entire execution lifetime;
compiled features do not detect runtime migration or lock scheduling.

All resources are acquired before accepting a request. Authority and both
startup checks, scoped keyed state, framing and verification are created on
protected worker stacks. Fixed output uses a full-width protected staging
mapping; XOF staging is bounded to 4096 bytes and copies into protected output
in bounded chunks. Bit canonicality for keys, customization, input and candidate
tags is inspected only there. Original caller buffers remain caller-owned.

Production key/tag strength and exact verification widths are unchanged, even
when conformance-testing features are enabled elsewhere. Short XOF derivation
is allowed but is not a weak-tag verification bypass. Verification reuses the
scalar wrapper's protected full-width comparison routine: only its deliberately
declassified Boolean leaves the worker. First/middle/last mismatch tests assert
every candidate byte is compared; this is not machine-level timing evidence.
Success and mismatch both clear computed tag/output/staging. An ordinary mismatch,
malformed request or cancellation preserves reuse. Backend, scoped execution,
invariant and worker failures permanently quarantine the wrapper, preventing
fresh per-request authority from reviving it. Forgotten output loans cannot
disable next-operation or owner-Drop clearing. No reset or fallback exists.

Setup and fixed finalization are bounded by public budgets but not internally
interruptible; message/XOF work and comparison check cancellation every 4096
bytes. No whole-process, arbitrary-register, interruption or abort guarantee is
added. Native AVX2 author checks are not native Arm, new emitted-code/sanitizer
or independent qualification. Remaining strict families and batching are still
pending, and neither Medium finding is closed.

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

The default-off hosted `strict-execution` feature now connects the protected
resources to all four scalar ParallelHash identities. Construction preacquires a
root stack, 1..=64 leaf stacks, bounded CV storage, staging and output. Every CV
slot is retained in protected memory until exact-plan ordered merge; bounded
waves join completely before the next wave or root processing. This first
implementation reserves storage for the complete maximum leaf count, not only
one wave. Only borrowed descriptors and public bookkeeping traverse the ordinary
coordinator; canonicality checks, populated workspaces and output copying run
on protected stacks. Output loans cannot detach ownership. Failure clears all
CV/staging/output and permits reuse. Cancellation granularity is one bounded
leaf, merge or XOF chunk; prefix setup and fixed output are not internally
cancellable. Original inputs and public shape metadata remain caller-owned.
Native Arm, emitted-code/sanitizer qualification and strict acceleration are
still pending. This integration does not close either Medium finding.

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
