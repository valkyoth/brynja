# Selected Windows SDK transition frames

This is a build-specific, author-reviewed extension of the
[scheduler caller review](windows-enclave-whole-image-cleanup.md), not production
or whole-image qualification. The [observation record](../assurance/windows-protection-observations/sdk-frames-20261004.json)
binds a file copied from the development VM's `System32` directory:
`vertdll.dll`, file version `10.0.26100.9444`, SHA-256
`f5bfb961d19775123c93b8cdf4318238acdf9647bb4518bf009d1969b4d2612f`.
The copied file is saved outside `target/`, in the ignored
`release-reports/windows-local-20261004/sdk-system32-review/` directory.
No Microsoft DLL is committed or redistributed in the repository.

The offline checker binds six complete instruction bodies and the full file
hash. Six focused tests pass on Linux and Windows; 338 single-byte mutations,
missing/extra bodies and truncated/extended bodies are rejected. The actual
file inspection also passes on both platforms. These tests do not execute SDK
code or constitute a new native enclave campaign.

## What the inspected instructions show

`CallEnclave` saves RBX, allocates 32 bytes and uses a caller home-space slot
for the argument/result. It calls `RtlCallEnclave`. That routine allocates
312 bytes, saves XMM6–15 and eight nonvolatile general registers, calls an
11-byte syscall stub, then restores the saved registers before returning.
The restores do **not** erase the saved stack slots. The enclosing Brynja
normal-return window clearing remains necessary.

Using the separately bound scheduler caller geometry, with `H` the exclusive
upper address of its 64-KiB window:

| Selected location | Offset from H |
| --- | --- |
| RtlCallEnclave frame base | -12016 |
| XMM6–15 save region (160 bytes) | -11968 |
| Eight GPR saves (64 bytes) | -11768 |
| Transition syscall return address | -12024 |
| Copy entry frame base | -11488 |
| Copy syscall return address | -11496 |

The 22 selected spans, including the outer argument/result slot and saved RBX,
fit inside the cleared window. This extends the earlier entry/home-space-only
calculation for this specific file; it is not a maximum transitive stack-depth
proof. The model derives its starting positions from the previous caller model,
not a second independent set of scheduler offsets.

Both copy exports allocate 40 bytes, select a direction flag and call the same
11-byte syscall stub. The reviewed entry bodies and stubs do not load payload
bytes or create a software payload copy. They tail-call a status conversion
helper after restoring their stack pointer. The conversion helpers and
kernel-side transfer implementation are outside this selected-body review.
The follow-up below extends this selected review to their immediate status
helpers, while retaining an explicit stop at the deeper diagnostic routine.
Microsoft documents the [copy API's input and result contract](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclavecopyintoenclave),
not an internal spill-erasure guarantee. Likewise,
[CallEnclave](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-callenclave)
defines the callback/return interface, not where the kernel preserves context.

## Limits and reproduction

The System32 file hash does not establish which module bytes were loaded in a
historical enclave run. No loaded-module identity, kernel storage, arbitrary
exception/fatal cleanup, other SDK builds or other linked callees are qualified.
These are evidence limits, not a claim that the SDK has a vulnerability. The
existing full-window cleanup and scoped native transition/dump observations
remain separate evidence. Production APIs and release gates are unchanged.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-frames.py
python3 scripts/cryptography/windows_enclave_sdk_frames.py PATH_TO_SAVED_VERTDLL
```

The checker rejects any different SDK file. A Windows update requires a new
review, not rotating its hash and assuming identical behavior. The existing
limited unwind decoder does not support this SDK routine's frame encoding;
this review uses exact instruction bytes and does not relax that decoder.

## Status and error-path follow-up

The [additional status-path record](../assurance/windows-protection-observations/sdk-status-20261004.json)
binds six further complete bodies in the same saved file: the copy-result
converter, the CallEnclave error adapter, status-to-error conversion and lookup,
the last-error setter and the diagnostic entry. Eight focused tests pass on
Linux and Windows. They reject 478 single-byte body changes, missing/extra or
truncated/extended bodies, changed transfer targets and invalid code-section
mappings. Inspection of the actual saved file produces identical reports on
both platforms. This is offline inspection, not execution of those SDK paths.

The two copy exports restore RSP before tail-jumping to their converter. Its
frame therefore replaces the copy-entry frame; it is not an additional nested
call. The CallEnclave error path, by contrast, calls its adapter from inside
the existing CallEnclave frame. Both adapters call the status conversion and
lookup chain. The lookup can call the diagnostic entry three times for an
unmapped status; those calls are sequential, not three simultaneous frames.

| Selected post-prologue RSP | Copy-result path | CallEnclave error path |
| --- | --- | --- |
| Status adapter | H - 11488 | H - 11744 |
| Status-to-error converter | H - 11536 | H - 11792 |
| Lookup | H - 11584 | H - 11840 |
| Diagnostic entry | H - 11664 | H - 11920 |
| Deeper diagnostic callee entry | H - 11672 | H - 11928 |

Fifteen selected spans cover the status home-slot spill, saved RBX, diagnostic
RCX/RDX/R8/R9 home slots, varargs pointer and last-error leaf return/home area.
They fit inside the same scheduler clearing window. The diagnostic entry saves
all four argument registers, including values not established here as payload
or non-payload; this is not an argument that caller residue cannot exist.
Its deeper callee at RVA `0x16910` is explicitly outside this frame model.
Neither its frame size nor maximum transitive depth is inferred from its
entry/home-space area.

There are also **non-stack writes**: the converter stores a four-byte incoming
status at offset `0x1250` from the pointer read at `GS:0x30`; the last-error helper
stores a four-byte converted error at offset `0x68` from that pointer. Those are
status values in these inspected paths, not copied hash/key payload. Their
storage is not established as inside Brynja's clearing window and is not
claimed erased by it. The setter also has a conditional `INT3`; arbitrary
interruption/debug handling remains outside the normal-return review.

No SDK bytes, production cryptography or release gates changed. Loaded-module
identity, kernel context storage, deeper diagnostic behavior and remaining
linked callees still require separate treatment. The earlier six-body record
is preserved with its original narrower scope.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-status.py
python3 scripts/cryptography/windows_enclave_sdk_status.py PATH_TO_SAVED_VERTDLL
```
