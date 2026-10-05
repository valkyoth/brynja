# Saved root-to-SDK output return reconciliation

The [outer-root review](windows-enclave-root-return.md) traced normal output
staging cleanup but left its SDK destination explicit and unresolved. The
[new observation](../assurance/windows-protection-observations/sdk-return-20261005.json)
connects that destination to the separately reviewed, saved `vertdll.dll`
10.0.26100.9444. It rechecks the original object/image hashes and the existing
SDK body-review chain; it does not load a new enclave or change release policy.

## Exact selected chain

| Boundary | Saved-image identity |
| --- | --- |
| `PrivateWaveRoot` | Scheduler RVA `0x11c0` |
| `PrivateInputOutput` | Scheduler RVA `0x7160` |
| Six-byte import tail thunk | Scheduler RVA `0xb57f`, `ff25231b0000` |
| Import-address slot | Scheduler RVA `0xd0a8`, named `vertdll.dll!EnclaveCopyOutOfEnclave` |
| Named SDK export | Saved SDK RVA `0x40b0` |
| Copy syscall stub | Saved SDK RVA `0x1cc70` |
| Copy status tail destination | Saved SDK RVA `0x3c8c` |

The import descriptor, lookup table, initial on-disk IAT, terminated symbol
identity and export name/ordinal/function tables are checked together. The
selected export must resolve directly to nonwritable executable code, not a
forwarder. The thunk is an exact RIP-relative indirect tail jump to the named
slot, with no local stack allocation or overlapping runtime-function entry.
This parser deliberately supports this saved, unbound named-import layout; it
is not a general PE loader or an image-admission replacement.

The SDK export allocates 40 bytes, sets the outbound direction argument to zero,
calls the reviewed syscall stub, moves its returned status into the status
argument, restores its own frame and tail-jumps to the reviewed status helper.
The tail jump adds neither another return address nor a second copy frame.
On a normal return, the result therefore reaches the already-bound native
adapter and root success/error staging-clear paths. It does not bypass those
paths through a differently named or forwarded SDK routine in the saved files.

The existing status/diagnostic inspection chain is rechecked, not replaced with
a success-only assumption. It retains its unresolved fatal-diagnostic boundary
and all exception, runtime-feature, external-handler and OS-storage limitations.
The detailed body and storage accounts remain in the
[SDK frame review](windows-enclave-sdk-frames.md).

## Storage and scope

For the selected root path, the existing frame model gives root RSP at window
high minus 11,392, output adapter RSP at minus 11,440 and SDK copy RSP at minus
11,488. The status tail uses that last frame depth rather than adding a nested
copy frame. Status conversion, lookup and diagnostic-entry frames are recorded
separately. These are instruction-derived positions in the admitted 64-KiB
window, not a new measurement or a maximum transitive stack-depth proof.

SDK helpers restore saved registers rather than erasing all of their former
contents. Status conversion can write a 32-bit status through the SDK's
thread-local pointer; this storage is not established as inside Brynja's clear
window. System-call transfer/context storage is also outside this qualification.
The enclosing normal-return window/register cleanup remains necessary; neither
the import thunk nor the SDK copy routine substitutes for it.

The host destination receives **explicitly declassified public output**. Copying
is still nontransactional: failure can leave a partial host write, while the
root clears its own staging on normal return and the native export reservation
prevents retry. Fatal exits and arbitrary exceptions do not acquire a new
cleanup guarantee from this linkage review.

Saved import/export identity is **not runtime IAT attestation**. The earlier
[loaded SDK diagnostic](windows-enclave-loaded-sdk.md) matched the saved text in
a separate diagnostic enclave. It does not retrospectively prove the loaded
IAT or complete module identity for every historical application-image run.
Both limitations remain false qualification flags in this record.

## Validation and next boundary

Six focused tests pass on Linux and Windows, with identical parsed inspection
reports. They cover import/export identity, missing/duplicate/unterminated
entries, ordinals and bounds, mismatched initial IAT entries, forwarders,
ambiguous/writable code, thunk byte/target changes and copy direction/frame/
syscall/status-tail changes. All existing SDK inspection suites and the seven
outer-root regressions also pass on Linux. These tests are parser/linkage
regressions, not live SDK execution or cryptographic comparisons.

The selected saved-file output-return chain is now reconciled. Final C-body to
clearing-wrapper return reconciliation and the other image families remain
before the whole-image scope can be finalized for independent retest. The
completed native and dump campaigns were not repeated; no production code,
signed image or release-gate policy changed.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-return.py
python3 scripts/cryptography/windows_enclave_sdk_return.py SAVED_RUST_OBJECT SAVED_C_OBJECT SAVED_IMAGE SAVED_SDK
```
