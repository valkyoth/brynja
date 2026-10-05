# Saved bounded SHA-256 borrowed-input callers

The [saved observation](../assurance/windows-protection-observations/bounded-input-20261005.json)
continues the [dispatcher review](windows-enclave-bounded-dispatch.md) into its
borrowed-input `hash` and `receive` routines. Their complete COFF bodies,
relocations and runtime extents match the saved signed image: 1,868 bytes at RVA
9,568 and 1,498 bytes at RVA 5,744 respectively. The original archive/member pins
are unchanged. No enclave was rebuilt for this inspection.

The dispatcher calls this exact `hash`; `hash` calls this exact `receive`.
Both reference the same retained owner and previously reviewed byte-clearing
leaf as the dispatcher, and both resolve the workspace-wipe symbol to the same
address. That last identity is **not** a semantic review of the wipe callee.
The recorded references retain the remaining placement-hash, C-adapter and
memory-runtime addresses as explicit follow-up work.

## Normal-return control and storage

Before accepting input, `hash` initializes its workspace and buffers and checks
that `high - low` is exactly 65,536 without underflow. It verifies the header,
snapshot, workspace, staging and observation spans, including addition overflow,
against that window. Failure clears the retained digest, quarantines a
nonterminal owner and returns status 190 without an input-copy call. Its common
return still calls the workspace wipe.

`receive` resets the workspace before requesting the fixed 32-byte header.
A returning header-copy failure selects status 121 and the complete buffer
cleanup/quarantine path. The copied header is checked for protocol identity four,
the nonzero expected sequence, a length at most 1,024, matching null/empty
conventions, and no address-plus-length wrap. The first check computes diagnostic
length; the second is the admission check before payload copying and hashing.
The ordinary saved image uses the caller's expected sequence, not the diagnostic
trust-header mutation. An empty admitted payload skips the payload-copy call.

The payload-copy call is bounded by the admitted length and writes into the
enclave snapshot. A returning copy failure does not call the placement hash.
After the placement operation or rejection, the component path clears all
1,024 snapshot bytes and the 32-byte staging region. Failure also clears the
retained digest and quarantines unless already terminal. Before the outer guard's
additional wipe, byte readbacks check snapshot, staging and all 1,170 workspace
bytes. They short-circuit on the first nonzero byte; the clean path covers every
byte, including the shorter final iterations of the emitted unrolled loops.

Dirty component storage returns 191 through cleanup and quarantine. Otherwise
the routine distinguishes success (two plus a token), header rejection (120),
copy rejection (121) and the mapped owner error. Both final branches clear the
32-byte header, 1,024-byte snapshot and 32-byte staging buffer. Only the successful
result avoids the final quarantine branch. The token is lifecycle metadata,
not the retained digest itself.

After `receive` returns, `hash` independently reads back the header, snapshot,
staging and workspace. Dirty storage or a returning observer response other
than one clears/quarantines the retained owner and suppresses the returned token.
Only after clean readback and observer acknowledgement does it forward the
status/token with bit 32 set. That bit indicates completion of this observation
path, **not** hashing success: a cleanly handled input rejection can carry it too.
All normal returns call the workspace wipe and use the same ABI epilogue.

## Compiler copies and stack boundary

With the previously reviewed dispatcher RSP at `H-464`, `hash` pushes 64 bytes
and allocates 2,520, placing its RSP at `H-3056`. `receive` pushes 64 and allocates
232, placing its RSP at `H-3360`. These fixed sizes agree with the image's unwind
records. The frame model checks the saved GPR/XMM locations, observation, result
and token copies, incoming sequence argument and the following `hash` slots:

| Slot | Offset from hash RSP | Bytes |
| --- | ---: | ---: |
| Snapshot | 238 | 1,024 |
| Header | 1,262 | 32 |
| Digest staging | 1,294 | 32 |
| Workspace | 1,326 | 1,170 |

The compiler's overlapping result/token copies and saved registers are inside
the enclosing 64-KiB clearing window. They are **not** all individually erased
by these routines' epilogues; the reviewed C-to-wrapper return remains necessary.
The geometry stops at the entry/home space of as-yet unreviewed callees. It does
not establish maximum transitive stack depth or arbitrary exception cleanup.

## Validation and remaining scope

Six focused tests pass on Linux and Windows. Reports from the same saved image
match, and all 3,366 actual body-byte mutations are rejected per host. Additional
tests reject instruction/branch changes, missing or altered relocation fields,
wrong incoming call targets, inconsistent image/storage/clearer identities,
changed frame sizes and extra unwind fragments. The geometry is checked at three
window bases. These are offline review regressions, not native cryptographic
execution, a symbolic data-flow proof or an independent security retest.

The subsequent [rehash review](windows-enclave-bounded-rehash.md) now binds its
caller and inlined retained-slot transform, including token/commit/cleanup paths.
Next: placement-hash, update/finalize/workspace-wipe callees and copy/observation
adapters, followed by the other distinct workers. SDK copy and
memory-runtime semantics are not inferred from their names or addresses.
Whole-image qualification remains open. Native campaigns were not rerun;
production code, signed images and release-gate policy are unchanged.

```sh
python3 scripts/cryptography/test-windows-enclave-bounded-input.py
python3 scripts/cryptography/windows_enclave_bounded_input.py SAVED_DIRECTORY EXTRACTED_OBJECT --mutate
```
