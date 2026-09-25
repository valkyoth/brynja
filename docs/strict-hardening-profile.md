# Strict hardening profile — implementation contract

Status: owner-approved design and implementation work, **not implemented or
available yet**. Added after the two-testers' follow-up on v0.24.49. The current
portable APIs remain available with their existing owned-memory guarantees.
This document does not admit an execution path or change any release gate.

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
