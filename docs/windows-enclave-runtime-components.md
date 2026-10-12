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

## Remaining package-08 passes

1. **Finish pass 2:** compose the now-bound local frames and runtime helpers with
   the actual normal-return call graph. Resolve all leaf stack accesses,
   outgoing home space, dynamic alignment and indirect-call depths; finish
   caller operand/OS-limit prerequisites. Do not count unassigned SDK edges as
   zero-depth calls or confuse an individual frame size with the whole window.
2. **Pass 3:** reconcile the loaded application/import contracts, complete outer
   clear/readback and register-return boundaries, and exact compiler/platform
   scope across the nineteen routes. Run targeted live observations where the
   supported claim actually requires them.

Only after those obligations are reconciled can package 08 close. Arbitrary
exceptions, fatal termination, caller-owned copies and privileged snapshots are
not silently added to the normal-return guarantee. Production consumer signing
and Windows ARM64 qualification are not established by this work.
