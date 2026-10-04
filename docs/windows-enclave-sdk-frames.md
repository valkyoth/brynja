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
