# Windows saved-image runtime reconciliation

Package 08, pass 1 of three, is complete at **author component-review scope**.
The [observation record](../assurance/windows-protection-observations/runtime-components-20261012.json)
binds the current checkers, tests, retained reports and the frozen nineteen-route
matrix. Package 08 itself and whole-image qualification remain open. No product
code, release gate, admission policy or independent-review status changed.

## What this pass establishes

Across all nineteen original signed images, the checker binds all four reviewed
copy/fill runtime bodies, their eight dispatch tables, initial selector storage,
and the complete 661-byte CPU/OS selector initializer. Only explicitly enumerated
relative-address operands are normalized; branch instructions and all remaining
bytes must match. Every selector reference retains its actual identity, storage
permissions and non-overlap constraints.

The initializer review follows CPUID and XGETBV prerequisites: AVX selection
requires OSXSAVE, AVX and the necessary XCR0 state; higher levels retain their
additional feature/state requirements. This is a startup selection contract,
not a scheduler lock or CPU-migration guarantee.

Five complete CRT startup bodies per image (773 bytes per image) bind the actual
PE entry point through process-attach dispatch to the selector initializer.
The saved optional pre-CRT callback is null and readonly; application `DllMain`
is the constant-success leaf. Under the existing loader contract—successful
process attach before exposing application exports—the selector initialization
precedes application `DllMain`. This does not claim observation of that ordering
inside an enclave, qualification of arbitrary CRT callbacks, or exception cleanup.

Existing reviews are executed again, not inferred from old PASS labels:

- 590 direct worker memory calls in 175 callers retain their actual destinations.
- 27 transport templates retain the original image/import/SDK relationships.
- All nineteen import tables contain only the classified named libraries and
  symbols, with distinct aligned slots. The original complete image hashes
  remain mandatory; the import allowlist is not approval of a modified image.

These edge checks do not replace family proofs of buffer lengths, lifetime or
authority, and do not by themselves prove cumulative stack bounds.

## Windows execution and regressions

The consolidated 43-test suite passes on Linux and Windows without skips; freshly
parsed reports match, with 77 current checker-source bindings. Tests alter every
byte of the initializer and startup templates, actual startup edges across all
nineteen images, selector references/data, storage permissions, import slots and
the PE entry point. Feature-model tests enumerate 8,192 combinations. Existing
memory-body/table and transport regressions are also included.

A bounded isolated Windows x64 child maps the exact saved image bytes without
loading a DLL, calling `DllMain`, resolving imports or entering an enclave. It
executes only the reviewed initializer and copy/fill helpers, using public byte
patterns and guarded allocations. The initializer reported ISA level 6 on this
VM; the campaign exercises detected, SSE, SSE/REP, AVX, AVX/REP and AVX streaming
selector configurations in the private test mapping. AVX is never forced when
the real initializer does not permit it.

All **58,482** copy, fill and overlapping-copy cases passed, including zero length,
unaligned addresses, guard adjacency, small dispatch boundaries, REP thresholds
and large streaming copies. Whole-buffer comparisons check both canaries,
unchanged sources and return-pointer identity; negative tests demonstrate that
the oracle rejects corruption and missing writes. This is functional component
evidence, not an AVX-512 kernel campaign, ABI preservation proof or enclave run.

The retained SDK is `vertdll.dll` version `10.0.26100.9444`, SHA-256
`f5bfb961d19775123c93b8cdf4318238acdf9647bb4518bf009d1969b4d2612f`.
A read-only check found the same file installed on the running Windows VM.
An installed disk-file match is not proof of the module or IAT actually loaded
inside an application enclave.

## Pass 2 progress: arithmetic, probes and actual frame allocations

The [runtime-context observation](../assurance/windows-protection-observations/runtime-contexts-20261012.json)
records 61 passing tests on each host, no skips, identical parsed reports and
169 current checker-source bindings. This advances pass 2; it does **not** mark
pass 2 complete. The source bindings identify imported checker dependencies,
not 169 separately completed semantic proofs.

All 1,023 route-specific worker bodies are rebound from the original Rust archive
members to the nineteen signed images. Of those, 891 have actual PE unwind
records; their 4,758 fixed-allocation/push instruction spans are checked against
the metadata. Exception-handler flags and destinations remain explicit, rather
than being removed to make a handler-free decoder accept them. The 132 remaining
leaf bodies are recorded as requiring instruction review, **not** silently
assigned zero stack use. The largest individual fixed allocation is 13,048 bytes;
that is not a maximum cumulative stack bound. Dynamic alignment, caller home
space, direct/indirect descendants and exceptional paths require separate checks.

The exact linked `__chkstk`, `__umodti3`, `__udivti3` and `memcmp` bodies are now
bound wherever the workers reference them: respectively 15, 11, 2 and 8 images.
All 34 worker probe calls have a constant EAX request followed immediately by
the matching RSP subtraction. The probe's 16-byte R10/R11 save area and return
address are separate from the requested allocation. Its page-touch model keeps
the real OS stack-limit prerequisite explicit; a limit already below the
private window is valid and causes no new touches for an in-window request.
The wrapper's earlier bootstrap probe is not included among these worker calls.
This model does not attest the live TEB or qualify faults while growing a stack.

An isolated Windows child executes the exact saved arithmetic/compare bytes on
public inputs. All 13,302 cases pass independent Python integer/byte oracles,
including 64-/128-bit division boundaries, seeded wide operands, unaligned
comparison and guard adjacency. General-u128 differential samples are not a
general-u128 proof or proof of each caller's operand lifetime and divisor bounds.
`memcmp` and division remain variable-time, non-erasing runtime helpers.

The child also reruns all 58,482 copy/fill/overlap cases and the nineteen selector
initializers through a Win64 ABI harness. Each helper call checks sentinel
preservation for RBX, RBP, RSI, RDI, R12–R15 and the ABI-preserved low 128 bits of
XMM6–XMM15. The harness saves/restores the host's original registers on both
success and rejection. All eighteen deliberately register-clobbering callees
are rejected. This is sampled register-preservation evidence, not a proof for
every possible input or a claim to erase upper vector registers and caller spills.

No DLL loader, imported OS function, enclave entry, secret data or stack probe is
executed by this component campaign. Native enclave identities and complete
window/register retirement remain the final reconciliation's responsibility.
No production implementation or release-gate rule changed.

## Pass 2 progress: actual normal-call composition

The [stack-geometry observation](../assurance/windows-protection-observations/stack-geometry-20261012.json)
records **96 passing tests per host**, no skips, matching freshly parsed reports
and 277 checker-source bindings. These bindings include imported prerequisites;
they are not 277 separately completed semantic proofs. An initial Windows replay
failed because its transfer bundle omitted a lazily imported checker. That log
was retained, the bundle was corrected, and the full suite then passed.

The original signed images—not a newly compiled surrogate—supply the instruction
bytes. LLVM 23.1.2 disassembly is rebound instruction by instruction to those
images and their original COFF references. Windows replays the same retained
disassembly; this is a second-host analysis, **not an independent decoder**.

The analysis covers all **925 normal function instances**, separately retaining
the 98 exception-cleanup funclets. It checks finite control-flow joins, balanced
normal returns and tail transfers, saved-register push/pop order, explicit stack
adjustments, constant probes, 16-byte call alignment and both possible entry
residues for 32-byte realignment. Local jump-table targets are read from the
bound original tables. Existing family proofs of valid table indices and
pointer/storage lifetimes remain prerequisites, not consequences of this scan.

All **132 metadata-less leaves** now have instruction-level stack checks. The
only explicit stack-memory access in that population reads four bytes of the
fifth argument at entry RSP+40. Its callers must have at least 36 bytes of
allocated outgoing space, including through tail wrappers. No leaf is assigned
zero *transitive* depth merely because it lacks unwind metadata. For nonleaf
bodies, stack-alias lifetimes and argument contents continue to rely on the
completed family reviews; allocated capacity alone does not prove non-overlap.

The cumulative graph includes **6,085 direct call/tail sites** and **44 indirect
calls**. Direct edges retain exact COFF symbol identities, including folded
aliases. The three SIMD family reviews are executed again to establish the
indirect population and internal callback provenance. For stack depth, each site
conservatively admits either of its two checked stack-free internal callbacks.
No caller-provided callback or unknown function is treated as an empty leaf.

Composition accounts for nested return slots, actual alignment padding, caller
home/argument capacity, runtime saves and tail transfers without adding a second
return slot. The largest reviewed worker/runtime portion is **25,048 bytes**.
That is **not a complete protected-window bound**: the reports retain 54 distinct
named C transport, scheduler and abort boundaries, with the deepest prefix and
a witness path for each. An unresolved suffix stays unknown; it is never zero.
These are the interfaces to the existing transport/SDK reviews, not 54 new
cryptographic implementations to review.

Regressions reject missing/truncated instructions, mid-instruction branches,
incorrect indirect-call encodings, insufficient home or fifth-argument space,
misalignment, unmatched saves, unknown stack writes, growing loops, recursive
call graphs and lost external boundaries. This does not qualify arbitrary
exceptions, fatal exits, live SDK imports, final window erasure or a new enclave
execution. Package 08 remains open.

## Complete C-adapter and saved SDK-prefix join (2026-10-12)

The [bridge observation](../assurance/windows-protection-observations/stack-bridge-20261012.json)
extends the worker graph without changing production code or gates. All 54
original named C boundaries resolve by their **incoming actual RVAs** to complete
original COFF function sections. Only recorded relocation operands are
normalized; every other linked byte must match. This avoids treating a possibly
folded leaf's byte-search match as its call-site identity. Repeated references
must agree, and the closure includes the previously internal `scheduler_complete`
helper: **93 C body instances**, of which 81 have returning paths and twelve are
the two named fast-fail helpers instantiated across images.

The returning bodies are instruction/CFG checked at both entry residues. Direct
CALL/tail encodings must match their original relocation and decoded target.
The concurrent dispatch's three indirect calls must use the exact named
`CallEnclave` IAT slot. Copy thunks must be complete nonwritable six-byte jumps to
the correct named slot, and all three API names must resolve to the reviewed
exports in the saved `vertdll.dll`. These are **saved-file bindings**, not an
assertion about the currently loaded IAT or module.

Twelve complete saved SDK bodies are joined: the copy and enclave-call wrappers,
their syscall stubs, status conversion, last-error handling and diagnostic entry.
The model retains the 312-byte `RtlCallEnclave` frame, copy-status tail transfers,
error-status diagnostic calls and the conditional debug trap. No success-only
path selection hides the SDK's error behavior. Existing SDK body, thread-relative
write and helper reviews are replayed as prerequisites; this does not establish
that thread-relative storage is erased by the private window.

All **118 regressions pass on Linux and Windows**, without skips; complete parsed
reports match and bind 279 current checker files. The latter count includes
imported prerequisite checkers, not 279 independent proofs. Windows replays the
same LLVM 23.1.2 disassembly, rebound to all twenty original application/SDK
files; it is not independent decoding or fresh enclave execution.

The graph now has five explicit residual boundary categories: deeper SDK
diagnostics, copy and enclave-call OS transitions, debug traps and fast-fail
termination. Synthetic boundary edges preserve an unknown suffix; they are not
literal machine tail jumps or zero-depth returning leaves. The largest known
worker/C/SDK prefix remains **25,048 bytes**, not a full protected-window bound.
Actual outer entry geometry, deeper diagnostic/OS prerequisites and whole-window
retirement must still be reconciled. This observation does not close package 08.

## Remaining package-08 passes

1. **Finish pass 2:** reconcile the remaining SDK diagnostic/OS conditions with
   actual outer-wrapper/window entry geometry and caller/OS stack-limit
   prerequisites. The worker, C-adapter and SDK-prefix graphs above are now joined;
   they need not be restarted unless their bound inputs change. An unresolved
   diagnostic or OS suffix still prevents claiming a full-window maximum.
2. **Pass 3:** reconcile the loaded application/import contracts, complete outer
   clear/readback and register-return boundaries, and exact compiler/platform
   scope across the nineteen routes. Run targeted live observations where the
   supported claim actually requires them.

Only after those obligations are reconciled can package 08 close. Arbitrary
exceptions, fatal termination, caller-owned copies and privileged snapshots are
not silently added to the normal-return guarantee. Production consumer signing
and Windows ARM64 qualification are not established by this work.
