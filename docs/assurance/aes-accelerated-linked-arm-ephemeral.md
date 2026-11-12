# Accelerated ARM per-operation caller review

This bounded v0.27.3 development review covers six final-linked public/secret
per-operation-key callers for AES-128/192/256. It extends the
[cached caller review](aes-accelerated-linked-arm-cached.md), replaying that
entire constructor, expansion, copy, clearing and round-kernel dependency closure.
It is emulated AArch64 evidence, not native qualification or release approval.

## Reviewed configurations and behavior

The registered runner builds fresh packaged direct and facade consumers with
LTO on Rust 1.90.0 and 1.99.1, static and hosted admission, abort and unwind.
The 48 policies distinguish compiler, admission, panic strategy, output kind
and key width. Sixteen further policies distinguish session direction, compiler,
admission and panic strategy; session streams are width-independent only after
binding the correct round kernel. Direct and facade routes must match the same reviewed policy.
Public bodies are the retained package-external fixture wrappers; secret bodies
are the retained library methods. This is not coverage of every possible caller.

The complete instruction streams were inspected before pinning. They check
authority health, captured generation and the admitted backend bundle before
expansion, then check admission again before executing the AES instructions.
Hosted bodies also check the hosted bundle field. The wrappers validate the raw
owner pointer and exact 16/24/32-byte length before calling hardware-assisted
expansion. Cleared owners cannot reach its key reads. Expansion failures
quarantine the authority. The old portable expansion policies do not apply.

Temporary schedules occupy exactly 176, 208 or 240 bytes and are initialized
before expansion. Width-specific expansion and round-kernel destinations are
bound by symbol, address, executable extent and actual ELF bytes. Wide-body
review checked frame sizes, callee-save offsets, extra schedule-zero stores,
cleanup lengths and remapped local branch destinations against the corresponding
AES-128 bodies; no other control-flow/operand differences were admitted.

Public output is published only after successful dispatch, with temporary block
and schedule clearing afterward. Admission failures leave public output untouched.
Secret output is cleared before admission, guarded on failure and returned with
its clearing owner on success. The reviewed copy helper supplies successful
secret output. Both direction branches call independently reviewed sessions;
public callers inline the checks and call the round kernel directly.
Retained Rust 1.90.0 unwind
paths clear staging, schedule and secret destination as applicable, quarantine
the authority, preserve the exception pointer and call the pinned runtime
boundary. Rust 1.99.1 bodies have no such retained runtime call. This observation
does not establish exception-table dispatch correctness or qualify libunwind.

## Session admission and direction

The six `Session::encrypt/decrypt128/192/256` bodies are mandatory dependencies,
not opaque trusted calls. Each checks health and captured generation, then the
ARM backend and, for hosted builds, hosted admission. Rejected paths return an
error without executing a round kernel. Admitted paths rearrange the state and
schedule arguments, set the direction to zero for encryption or one for
decryption, and call the independently reviewed, matching-width kernel.
Their success/error discriminants are checked against the outer callers.

The 1.90.0 unwind bodies retain an exceptional path that idempotently quarantines
the authority and resumes unwinding; the caller owns scratch/schedule/destination
cleanup. Other session configurations have no retained runtime call. Current
compiler session streams match across panic strategies, but the outer wrappers
do not: their frame layouts and shared cleanup paths are separately pinned.
AES-192/256 outer-body review verified every local branch destination after the
additional schedule stores and public-wrapper register save/restore insertion.

## Fail-closed controls

`scripts/aes/aes_accelerated_linked_arm_ephemeral.py` requires the exact six-symbol
population, non-overlapping aligned extents and the exact dependency roles.
It checks whole normalized instruction and encoding hashes against
`scripts/aes/accelerated-arm-ephemeral-review.json`. Only independently bound
external call relocations are normalized; local branch encoding is retained.
Unknown instructions, altered operands/cleanup lengths, wrong-width targets,
missing helpers, unexpected calls and changed actual bytes cannot pass.
`aes_accelerated_linked_arm_sessions.py` separately enforces all six session
symbols and `accelerated-arm-session-review.json` policies, with matching-width
kernel and retained runtime binding. Failed session review prevents caller
review, and swapped encrypt/decrypt edges are rejected. There is no policy-refresh
command in the production runner.

Every fresh build replaces every caller instruction with an unknown instruction
and flips each byte in both the disassembly input and actual ELF image, requiring
each mutation to fail for the intended stream/encoding reason. The same controls
cover every session instruction and byte. The prior cached
review repeats its own mutation controls, including retained runtime bytes.
Synthetic regression policies are test-only mocks and cannot approve production
bodies. Registered inputs include the policy, reviewer, tests, this document and
all dependency-review inputs.

Run with:

```sh
brynja-verify run aes --needed --category aes-linked-arm-ephemeral
```

The executed fixture covers all widths and both raw/cached owners, successful
operations, output clearing, explicit destruction and quarantined destinations.
The review still does not claim native timing, physical protection, arbitrary
inlining, every call site, exception-dispatch qualification or register/spill
erasure. Native platform observations and the remaining development work in
[the development ledger](aes-acceleration-development.md) remain separate.
