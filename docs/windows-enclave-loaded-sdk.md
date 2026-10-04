# Windows enclave loaded SDK observation

The saved SDK review now has a **scoped native loaded-code comparison**, not
whole-module attestation or whole-image cleanup qualification. On the development
Windows 11 build 26300 VM, a separate public-only test-signed enclave compared
all 121,931 bytes of the loaded `vertdll.dll` `.text` virtual extent with the saved
10.0.26100.9444 DLL. All bytes matched in three repetitions.

The [observation record](../assurance/windows-protection-observations/sdk-loaded-text-20261004.json)
binds the source, generated expected bytes, compiled object, signed diagnostic,
native results and signing-key cleanup record. The signed diagnostic is not one
of the nineteen application images; those campaigns have not been relabelled.
The [saved frame review](windows-enclave-sdk-frames.md) and
[unwind review](windows-enclave-sdk-unwind.md) retain their original offline scope.

## What the diagnostic checks

`PublicSdkIdentity` executes inside the enclave and uses `GetModuleHandleExW`
with unchanged reference count, not the containing process's ordinary DLL list.
It checks the x64 image geometry and three known export RVAs, then reads every
byte of the selected loaded code through a volatile pointer. Expected public
bytes are compiled into the diagnostic from the exact hash-pinned saved DLL.
Windows lists this lookup and `GetProcAddress` among its
[supported enclave APIs](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/enclaves-available-in-vertdll).

Each repetition includes three rejection controls: change the first expected
code byte, request a nonexistent module, and pass an unsupported query. They all
reject. The probe never modifies SDK code. Eight focused tests pass on Linux and
Windows, including mismatched observations and lifecycle/cleanup failures.
The native child has a 45-second timeout; it confirms enclave termination and
deletion before emitting a successful record. No secret data is supplied.

The diagnostic used the existing two-system-import transform and a temporary
development signing key, subsequently removed. The SDK compatibility warning
remains recorded. No production code, trust policy or release gate changed.

## Limits and remaining coverage

Matching `.text` is not matching the whole file or all executable sections:
`fothk`, read-only tables, mutable SDK state and `ucrtbase_enclave.dll` are outside
this comparison. It does not prove arbitrary callees safe, clearing of SDK
globals, or that historical application runs loaded identical code. It is a
local observation under the development OS trust boundary, not remote proof.
Microsoft's separate
[attestation-report API](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclavegetattestationreport)
can report loaded-code identities; this diagnostic neither obtains nor verifies
such a report. A saved-file SHA-256 is not the enclave UniqueId.

The existing dump evidence has also been reconciled by exact signed-image hash
against the [nineteen-route inventory](../assurance/windows-protection-observations/current-image-routes-complete-20261004.json):
the six root/worker/output WER observations match only
`parallel_concurrent::Session::open_avx2`. They do not cover the other eighteen
current images. This reconciliation collected no new dumps and promotes no
route to whole-image-qualified status. Further current-image evidence and the
remaining caller/runtime cleanup review precede independent retest.
